# Linux 崩溃栈还原服务

值班员提交崩溃栈各帧的 **ELF Build ID** 与**扣除装载偏移后的地址**，服务凭报告号返回
函数名与源码行；CI 可整批补传带 Build ID 与 DWARF 调试信息的 x86-64 ELF。
修复版发布后可开启**复发观察**：以一份前两帧已还原的旧报告为基准，按修复版 Build ID
锁定样本，比对前两帧的源码文件名与函数名，判断同一种崩溃是否复发。

## 设计要点

| 需求 | 实现 |
| --- | --- |
| Build ID 从文件读取 | pyelftools 解析 `SHT_NOTE` 中的 `NT_GNU_BUILD_ID`，不信任文件名 |
| 整批退回 | 先做纯内存校验（非 ELF / 非 x86-64 / 缺 Build ID / 缺 `.debug_info`），再核对同批与已发布内容；任一不合格返回 422，无任何落盘或数据库变更 |
| 同号内容冲突 | Build ID → sha256 唯一映射，哈希不同即退回，已发布内容不可变 |
| 相同文件重传成功 | 幂等：计入 `redundant`，版本号不前进；同批内重复文件按去重处理 |
| 查询期间可发布 | 全局符号版本号每次有效发布 +1；查询在开始时取一次版本快照，只解析 `version <= 快照版本` 的 ELF |
| 未解析帧保留原地址 | 帧原样持久化，响应中带 `status=unresolved` 与原因；补传后用同一报告号再查即可 |
| 重启后可查 | 报告/帧、Build ID 映射、版本号全部存 SQLite（WAL）；ELF 按 sha256 内容寻址落盘；启动时核对并清理悬挂映射 |
| 查栈与发布并行 | 发布仅持短写锁，查询走只读快照；ELF 解析结果按 Build ID 惰性缓存且不可变，可跨线程共享 |
| 复发观察样本锁定 | 开启时冻结基准四项与报告 ID 水位；停止时才按“水位之间入库 + 首帧 Build ID 相符 + ≥2 帧”选样并固化，重复停止/重启沿用同一范围 |
| 复发判定快照 | 每次凭观察号核查在开始时取一次符号版本快照，只解析快照内已发布符号；任一已知项不同即排除，四项全同判复发，无已知差异但缺信息列入待补 |
| Docker Compose | 单服务 + 命名卷 `symbol-data:/data`，`/docs` 提供 Swagger 演示 |

### 目录结构

```
app/
  config.py        运行期配置（SYMBOL_DATA_DIR）
  elftools_ext.py  ELF 校验 + DWARF 符号化（函数/源码行，兼容 DWARF v4/v5、PIC）
  storage.py       SQLite 持久化、原子批量发布、版本快照、重启恢复
  main.py          FastAPI 路由与模型
scripts/
  build_fixtures.sh  构造固定 Build ID 的测试 ELF
  ci_upload.py       CI 批量上传客户端
tests/             pytest 自测（含真实 uvicorn 并发交错测试）
```

## 启动

```bash
docker compose up --build
# 文档与演示： http://localhost:8000/docs
# 健康检查：    http://localhost:8000/health
```

本地无 Docker 时：

```bash
pip install -r requirements.txt
SYMBOL_DATA_DIR=./data uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/reports` | 提交崩溃帧（`build_id` 可空、`address` 支持 0x 十六进制或十进制），返回报告号与首次解析结果 |
| GET  | `/reports/{id}` | 凭报告号查询；每次查询绑定开始时的符号版本快照 |
| GET  | `/reports/{id}/raw` | 查看原始帧（地址原样保留） |
| POST | `/symbols/batch` | multipart 整批上传 ELF；整批不合格返回 422 及逐文件原因 |
| GET  | `/symbols` | 当前符号版本与已发布 Build ID 列表 |
| POST | `/observations` | 开启复发观察（旧报告号 + 修复版 Build ID），冻结前两帧四项基准 |
| POST | `/observations/{id}/stop` | 停止并锁定样本范围；重复停止/重启后范围不变（幂等） |
| GET  | `/observations/{id}` | 凭观察号查结论；运行中返回 409，每次核查绑定开始时符号快照 |
| GET  | `/observations` | 列出全部观察（含运行中） |
| GET  | `/health` | 健康检查 |

未解析原因：`frame_missing_build_id` / `build_id_not_published_at_snapshot` /
`address_not_found_in_elf` / `invalid_address`。

### 示例

```bash
# 1) 值班员提交
curl -X POST localhost:8000/reports -H 'Content-Type: application/json' \
  -d '{"frames":[{"build_id":"aaaa…aaaa","address":"0x401140"}]}'

# 2) CI 整批补传
python scripts/ci_upload.py http://localhost:8000 ./build-artifacts/

# 3) 用原报告号再查
curl localhost:8000/reports/1
```

## 复发观察

用于确认“修复版是否还会出现同一种崩溃”。

### 语义

1. **开启** `POST /observations`，入参 `reference_report_id`（旧报告号）与
   `fixed_build_id`（修复版 Build ID）。旧报告前两帧必须已在当前符号下解析出
   源码文件名与函数名，四项缺一即 422；开启时冻结这四项基准，并记录当前报告 ID 水位。
2. **停止** `POST /observations/{id}/stop` 时才锁定样本，样本仅取开启与停止之间
   **已入库**、**首帧 Build ID 与修复版相符**（大小写不敏感）且**至少两帧**的报告，
   按报告原顺序固化。重复停止或进程重启后沿用同一范围；停止后新上报的报告不入样，
   报障接收与符号补传照常进行，之后仍可为样本中的报告补传符号。
3. **查结论** `GET /observations/{id}`（停止后可用，运行中 409）。每次核查在开始时
   取一次符号版本快照，只使用该快照下已发布的符号，按报告原顺序逐份比对前两帧的
   四项（两帧各自的源码文件名 + 函数名）：
   - 任一项**已知不同** → 排除该报告（`excluded_report_ids`）；
   - 四项**都已知且全部相同** → 复发，证据报告号见 `recurrence_evidence_report_ids`；
   - 没有已知差异但仍有未解析项 → 待补信息（`pending_report_ids`），补传后再查即可。

结论状态：`recurrence_detected`（有复发证据）/ `awaiting_symbols`（无证据、仍有缺信息
报告）/ `no_recurrence_all_excluded`（样本全部因已知差异排除）/ `no_samples`（无样本，
与“全排除”区分，不单独列“未见复发”）。

### 示例

```bash
# 1) 以前两帧已还原的旧报告 7 为基准，修复版 Build ID 为 d1d1…
curl -X POST localhost:8000/observations -H 'Content-Type: application/json' \
  -d '{"reference_report_id": 7, "fixed_build_id": "d1d1…d1d1"}'

# 2) 观察期内服务照常接收报障；停止并锁定样本
curl -X POST localhost:8000/observations/1/stop

# 3) 停止后 CI 仍可补传修复版 ELF，再凭观察号查结论
python scripts/ci_upload.py http://localhost:8000 ./build-artifacts/
curl localhost:8000/observations/1
```

## 自测

```bash
bash scripts/build_fixtures.sh tests/fixtures/built   # 构造测试 ELF（需要 gcc）
pip install -r requirements-dev.txt
pytest -q
```

固件包含：固定 Build ID 的可执行文件与共享库、DWARF v4/v5 各一份、同 Build ID 冲突文件、
无 Build ID 文件、strip 调试信息文件、非 ELF 文件，以及复发观察用三份修复版 ELF
（四项全同 / 仅文件名不同 / 仅函数名不同）。

## 余项 / 已知边界

- 本机未安装 Docker，Compose 文件仅做 YAML 静态校验；容器路径已在同等 uvicorn 进程下端到端验证
  （含复发观察的停止后继续上报/补传、进程重启沿用样本范围两个场景）。
- 仅接受 `EM_X86_64`；其它架构在入库校验阶段明确退回。
- 符号化依赖 DWARF（`.debug_info`/`.debug_line`）；无调试信息的 ELF 不允许入库。
- 复发观察只比对前两帧的源码文件名与函数名，不比较源码行号与地址；文件名按 DWARF
  还原出的完整路径字面量比较（同一次构建内路径前缀一致，相等性判定确定）。
- 未做上传鉴权与文件大小配额，按内网服务假设；如需暴露公网应在网关层补齐。
- 当前为单实例 + 本地卷部署；多实例横向扩展需把数据层换成共享存储/数据库。
