"""FastAPI 入口：崩溃栈提交、按报告号查询、CI 批量补传 ELF。"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from . import __version__
from .config import settings
from .storage import (
    BatchRejected,
    ObservationNotFound,
    ObservationStillRunning,
    ObservationValidationError,
    Store,
)

_store: Optional[Store] = None


def get_store() -> Store:
    # 测试可通过 dependency_overrides 替换
    if _store is None:
        raise RuntimeError("Store 尚未初始化")
    return _store


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store
    _store = Store()
    yield
    if _store is not None:
        _store.close()
        _store = None


app = FastAPI(
    title="Linux 崩溃栈还原服务",
    version=__version__,
    description=(
        "值班员提交各帧的 ELF Build ID 与扣除装载偏移后的地址，凭报告号查询函数与源码行；"
        "CI 可批量补传带 Build ID 与 DWARF 调试信息的 x86-64 ELF。"
        "查询绑定开始解析时的符号版本快照，查栈与发布可并行。"
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# 请求/响应模型
# ---------------------------------------------------------------------------
class FrameIn(BaseModel):
    build_id: Optional[str] = Field(
        default=None,
        description="GNU Build ID（十六进制，不带 0x）；未知时可留空，该帧保留原地址",
    )
    address: str = Field(
        ...,
        description="已扣除装载偏移的地址，支持 0x 前缀十六进制或十进制字符串",
    )


class ReportIn(BaseModel):
    frames: List[FrameIn] = Field(..., min_length=1, description="崩溃栈各帧，自底向上或自顶向下均可，按提交顺序保存")


class FrameOut(BaseModel):
    position: int
    build_id: Optional[str]
    address: str
    status: str
    reason: Optional[str]
    function: Optional[str]
    source_file: Optional[str]
    source_line: Optional[int]


class ReportOut(BaseModel):
    report_id: int
    created_at: str
    snapshot_symbol_version: int
    current_symbol_version: int
    frame_count: int
    resolved_count: int
    frames: List[FrameOut]


class BatchResult(BaseModel):
    accepted: int
    new_build_ids: List[str]
    redundant: int
    symbol_version: int


# ---------------------------------------------------------------------------
# 复发观察模型
# ---------------------------------------------------------------------------
class ObservationIn(BaseModel):
    reference_report_id: int = Field(
        ..., description="旧报告号：其前两帧在当前符号下已解析出源码文件名与函数名"
    )
    fixed_build_id: str = Field(
        ..., description="修复版 Build ID（十六进制，不带 0x）；样本仅取首帧 Build ID 相符的报告"
    )


class ObservationReference(BaseModel):
    frame0_source_file: str
    frame0_function: str
    frame1_source_file: str
    frame1_function: str


class FrameComparison(BaseModel):
    position: int
    reference_source_file: str
    reference_function: str
    actual_source_file: Optional[str]
    actual_function: Optional[str]


class SampleOut(BaseModel):
    report_id: int
    position: int
    state: str = Field(
        ...,
        description="recurrence=四项全同；excluded=任一已知项不同；pending=无已知差异但仍缺信息",
    )
    comparisons: List[FrameComparison]


class ObservationOut(BaseModel):
    observation_id: int
    created_at: str
    stopped_at: Optional[str]
    status: str = Field(
        ...,
        description=(
            "running=观察中；recurrence_detected=发现复发（附证据报告号）；"
            "awaiting_symbols=无复发证据、仍有缺信息报告；"
            "no_recurrence_all_excluded=样本全部因已知差异排除；no_samples=无样本"
        ),
    )
    fixed_build_id: str
    reference_report_id: int
    reference: ObservationReference
    created_symbol_version: int
    snapshot_symbol_version: Optional[int]
    sample_count: int
    recurrence_evidence_report_ids: List[int]
    excluded_report_ids: List[int]
    pending_report_ids: List[int]
    samples: List[SampleOut]


# ---------------------------------------------------------------------------
# 接口
# ---------------------------------------------------------------------------
@app.get("/health", tags=["运维"])
def health():
    store = get_store()
    return {
        "status": "ok",
        "version": __version__,
        "symbol_version": store.symbol_version,
        "published_build_ids": len(store.list_build_ids()),
        "data_dir": settings.data_dir,
    }


@app.post("/reports", response_model=ReportOut, status_code=201, tags=["崩溃报告"])
def submit_report(payload: ReportIn):
    """提交崩溃栈并立即按当前已发布符号做一次解析，返回报告号。"""
    store = get_store()
    frames = [f.model_dump() for f in payload.frames]
    report_id = store.create_report(frames)
    return store.resolve_report(report_id)


@app.get("/reports/{report_id}", response_model=ReportOut, tags=["崩溃报告"])
def get_report(report_id: int):
    """凭报告号查询；补传 ELF 后用同一报告号再查即可得到新解析结果。

    每次查询只使用本次开始解析时已发布的符号版本（快照）。
    """
    store = get_store()
    result = store.resolve_report(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"报告 {report_id} 不存在")
    return result


@app.get("/reports/{report_id}/raw", tags=["崩溃报告"])
def get_report_raw(report_id: int):
    """查看报告原始帧（地址原样保留）。"""
    store = get_store()
    raw = store.get_report_raw(report_id)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"报告 {report_id} 不存在")
    return raw


@app.post("/symbols/batch", response_model=BatchResult, tags=["符号发布"])
def upload_batch(files: List[UploadFile] = File(..., description="一批 x86-64 ELF 文件")):
    """CI 整批补传 ELF。

    - Build ID 从文件内部的 NT_GNU_BUILD_ID 注释读取；
    - 任一文件缺标识、缺调试信息、非 x86-64，或与同 Build ID 已发布/同批文件内容不同，
      整批退回（422），不留任何部分结果；
    - 相同文件重传视为成功，计入 redundant。

    同步端点：阻塞式校验/落盘由 Starlette 放到线程池执行，不卡住事件循环。
    """
    if not files:
        raise HTTPException(status_code=422, detail="未上传任何文件")
    blobs: list[tuple[str, bytes]] = []
    for upload in files:
        blob = upload.file.read()
        if not blob:
            raise HTTPException(status_code=422, detail=f"文件 {upload.filename} 为空")
        blobs.append((upload.filename or "unnamed", blob))

    store = get_store()
    try:
        return store.publish_batch(blobs)
    except BatchRejected as exc:
        raise HTTPException(status_code=422, detail={"message": "整批退回", "errors": exc.errors})


@app.get("/symbols", tags=["符号发布"])
def list_symbols():
    """列出当前已发布的 Build ID。"""
    store = get_store()
    return {"symbol_version": store.symbol_version, "build_ids": store.list_build_ids()}


# ---------------------------------------------------------------------------
# 复发观察
# ---------------------------------------------------------------------------
@app.post(
    "/observations",
    response_model=ObservationOut,
    status_code=201,
    tags=["复发观察"],
)
def create_observation(payload: ObservationIn):
    """开启复发观察。

    校验旧报告前两帧在当前符号下都已解析出源码文件名与函数名，冻结四项基准；
    样本在停止时才锁定，仅取开启与停止之间入库、首帧 Build ID 与修复版相符、
    至少两帧的报告。
    """
    store = get_store()
    try:
        return store.create_observation(
            payload.reference_report_id, payload.fixed_build_id
        )
    except ObservationValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/observations/{observation_id}/stop", response_model=ObservationOut, tags=["复发观察"])
def stop_observation(observation_id: int):
    """停止观察并锁定样本范围；重复停止或进程重启后沿用同一范围（幂等）。

    停止后照常接收报障与补传，但新报告不再进入该观察的样本；
    之后仍可为样本中的报告补传符号，再查结论即可获得最新判定。
    """
    store = get_store()
    try:
        return store.stop_observation(observation_id)
    except ObservationNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ObservationStillRunning as exc:  # 理论不可达：stop 内部会先停止
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/observations/{observation_id}", response_model=ObservationOut, tags=["复发观察"])
def get_observation(observation_id: int):
    """凭观察号查结论。

    每次核查在开始时取一次符号版本快照，只解析该快照下已发布的符号；
    观察运行中返回 409；无复发证据时列出仍缺信息且未被排除的报告号。
    """
    store = get_store()
    try:
        return store.get_observation(observation_id)
    except ObservationNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ObservationStillRunning as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/observations", response_model=List[ObservationOut], tags=["复发观察"])
def list_observations():
    """列出全部观察（运行中的也会出现，status=running）。"""
    store = get_store()
    return store.list_observations()
