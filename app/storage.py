"""持久化与发布控制。

- ELF 按 sha256 内容寻址存放，Build ID -> 内容哈希映射写入 SQLite；
- 每次整批发布把全局版本号 +1，查询只绑定解析开始时的版本快照；
- 发布全程持写锁并在同一事务内完成，任何一文件不合格则整批退回、不落盘；
- 重启后从 SQLite 恢复映射并核对磁盘文件，报告与帧同样持久化，可继续查询。
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from typing import Optional

from .config import settings
from .elftools_ext import ELFValidationError, FrameSymbol, Symbolizer, inspect_blob

_HEX_BUILD_ID = re.compile(r"^[0-9a-f]+$")


class ObservationError(Exception):
    """复发观察相关错误的基类。"""


class ObservationNotFound(ObservationError):
    """观察号不存在。"""


class ObservationStillRunning(ObservationError):
    """观察尚未停止，结论不可用。"""


class ObservationValidationError(ObservationError, ValueError):
    """开启观察的入参/基准报告不满足条件。"""


@dataclass(frozen=True)
class StoredELF:
    build_id: str
    sha256: str
    path: str
    version: int  # 首次发布时的版本（+1 后的值）


class BatchRejected(Exception):
    """整批退回，message 为面向调用方的逐文件原因列表字符串。"""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class Store:
    def __init__(self, data_dir: Optional[str] = None) -> None:
        # 动态读取环境变量，避免 config 在导入时冻结路径
        self.data_dir = data_dir or os.environ.get("SYMBOL_DATA_DIR", settings.data_dir)
        self.elf_dir = os.path.join(self.data_dir, settings.elf_dir_name)
        self.db_path = os.path.join(self.data_dir, settings.db_name)
        os.makedirs(self.elf_dir, exist_ok=True)
        # 粗粒度锁：发布互斥；查询用快照版本号，不阻塞发布
        self._lock = threading.RLock()
        self._symbolizer = Symbolizer()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL");
        self._conn.execute("PRAGMA foreign_keys=ON");
        self._init_schema()
        self._reconcile_disk()

    # ------------------------------------------------------------------
    # schema 与启动恢复
    # ------------------------------------------------------------------
    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS elfs (
                    build_id TEXT PRIMARY KEY,
                    sha256   TEXT NOT NULL,
                    path     TEXT NOT NULL,
                    version  INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS frames (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER NOT NULL REFERENCES reports(id),
                    position  INTEGER NOT NULL,
                    build_id  TEXT,
                    address   TEXT NOT NULL,
                    UNIQUE(report_id, position)
                );
                CREATE TABLE IF NOT EXISTS observations (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                    stopped_at       TEXT,
                    fixed_build_id   TEXT NOT NULL,
                    reference_report INTEGER NOT NULL REFERENCES reports(id),
                    ref_frame0_file  TEXT NOT NULL,
                    ref_frame0_func  TEXT NOT NULL,
                    ref_frame1_file  TEXT NOT NULL,
                    ref_frame1_func  TEXT NOT NULL,
                    last_report_id   INTEGER NOT NULL,
                    symbol_version   INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS observation_samples (
                    observation_id INTEGER NOT NULL REFERENCES observations(id),
                    report_id      INTEGER NOT NULL REFERENCES reports(id),
                    position       INTEGER NOT NULL,
                    PRIMARY KEY (observation_id, report_id)
                );
                """
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('symbol_version', 0)"
            )

    def _reconcile_disk(self) -> None:
        """重启后核对：磁盘缺失的内容文件删除其映射，保证不悬挂。"""
        with self._lock, self._conn:
            for row in self._conn.execute("SELECT build_id, path FROM elfs").fetchall():
                if not os.path.isfile(row["path"]):
                    self._conn.execute("DELETE FROM elfs WHERE build_id=?", (row["build_id"],))
                    self._symbolizer.evict(row["build_id"])

    @property
    def symbol_version(self) -> int:
        return int(self._conn.execute("SELECT value FROM meta WHERE key='symbol_version'").fetchone()["value"])

    # ------------------------------------------------------------------
    # 批量发布
    # ------------------------------------------------------------------
    def publish_batch(self, files: list[tuple[str, bytes]]) -> dict:
        """原子发布一批 ELF。

        files 为 (原始文件名, 文件字节)。任一文件不合格或同 Build ID 内容冲突，
        抛 BatchRejected，整批退回（无任何落盘/数据库变更）。
        内容完全相同的重复文件（含同批内重复）按成功处理（幂等）。
        """
        if not files:
            raise BatchRejected(["批次为空：未收到任何文件"])

        errors: list[str] = []
        # 第一阶段：纯内存校验 + 同批去重，不落盘
        unique: dict[str, tuple[str, bytes, str]] = {}  # build_id -> (filename, blob, sha256)
        in_batch_duplicates = 0
        for filename, blob in files:
            try:
                build_id, _ = inspect_blob(blob)
            except ELFValidationError as exc:
                errors.append(f"{filename}: {exc}")
                continue
            digest = hashlib.sha256(blob).hexdigest()
            prev = unique.get(build_id)
            if prev is not None:
                if prev[2] != digest:
                    errors.append(
                        f"{filename}: Build ID {build_id} 与同批文件 {prev[0]} 内容不同"
                    )
                else:
                    in_batch_duplicates += 1  # 同批内完全相同的重复文件
                continue
            unique[build_id] = (filename, blob, digest)

        with self._lock:
            # 第二阶段：与已发布内容核对冲突
            existing = {
                r["build_id"]: r
                for r in self._conn.execute("SELECT build_id, sha256 FROM elfs").fetchall()
            }
            for build_id, (filename, _blob, digest) in unique.items():
                row = existing.get(build_id)
                if row is not None and row["sha256"] != digest:
                    errors.append(
                        f"{filename}: Build ID {build_id} 已发布且文件内容不同"
                    )

            if errors:
                raise BatchRejected(sorted(set(errors)))

            # 第三阶段：先把所有新内容文件暂存落盘（rename 原子可见），
            # 再用单个数据库事务写入映射与版本号；任一步失败则清理暂存并整体回滚。
            new_entries: list[tuple[str, str, str]] = []  # (build_id, sha256, path)
            redundant = in_batch_duplicates
            staged_paths: list[str] = []
            for build_id, (filename, blob, digest) in unique.items():
                if build_id in existing:
                    redundant += 1
                    continue
                final_path = os.path.join(self.elf_dir, f"{digest}.elf")
                if not os.path.exists(final_path):
                    tmp_path = os.path.join(
                        self.elf_dir, f".tmp-{os.getpid()}-{threading.get_ident()}-{digest}"
                    )
                    with open(tmp_path, "wb") as fh:
                        fh.write(blob)
                    os.replace(tmp_path, final_path)
                    staged_paths.append(final_path)
                new_entries.append((build_id, digest, final_path))

            if new_entries:
                next_version = self.symbol_version + 1
                try:
                    with self._conn:  # 单事务：映射与版本号一起提交
                        self._conn.executemany(
                            "INSERT INTO elfs(build_id, sha256, path, version)"
                            " VALUES(?,?,?,?)",
                            [(bid, digest, path, next_version) for bid, digest, path in new_entries],
                        )
                        self._conn.execute(
                            "UPDATE meta SET value=? WHERE key='symbol_version'",
                            (next_version,),
                        )
                except BaseException:
                    for path in staged_paths:
                        try:
                            os.remove(path)
                        except OSError:
                            pass
                    raise

        return {
            "accepted": len(files),
            "new_build_ids": sorted(bid for bid, _d, _p in new_entries),
            "redundant": redundant,
            "symbol_version": self.symbol_version,
        }

    # ------------------------------------------------------------------
    # 报告
    # ------------------------------------------------------------------
    def create_report(self, frames: list[dict]) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute("INSERT INTO reports DEFAULT VALUES")
            report_id = cur.lastrowid
            for pos, frame in enumerate(frames):
                self._conn.execute(
                    "INSERT INTO frames(report_id, position, build_id, address)"
                    " VALUES(?,?,?,?)",
                    (report_id, pos, frame.get("build_id"), str(frame["address"])),
                )
            return report_id

    def get_report_raw(self, report_id: int) -> Optional[dict]:
        report = self._conn.execute(
            "SELECT id, created_at FROM reports WHERE id=?", (report_id,)
        ).fetchone()
        if report is None:
            return None
        frames = self._conn.execute(
            "SELECT position, build_id, address FROM frames"
            " WHERE report_id=? ORDER BY position",
            (report_id,),
        ).fetchall()
        return {
            "report_id": report["id"],
            "created_at": report["created_at"],
            "frames": [
                {"position": f["position"], "build_id": f["build_id"], "address": f["address"]}
                for f in frames
            ],
        }

    # ------------------------------------------------------------------
    # 快照符号化
    # ------------------------------------------------------------------
    def snapshot_paths(self, version: int) -> dict[str, StoredELF]:
        """取 <= version 的已发布 ELF 映射（查询开始时调用一次）。"""
        rows = self._conn.execute(
            "SELECT build_id, sha256, path, version FROM elfs WHERE version <= ?",
            (version,),
        ).fetchall()
        return {
            r["build_id"]: StoredELF(r["build_id"], r["sha256"], r["path"], r["version"])
            for r in rows
        }

    def resolve_report(self, report_id: int, snapshot_version: Optional[int] = None) -> Optional[dict]:
        version = self.symbol_version if snapshot_version is None else snapshot_version
        raw = self.get_report_raw(report_id)
        if raw is None:
            return None
        available = self.snapshot_paths(version)
        resolved_frames = []
        for frame in raw["frames"]:
            item = {
                "position": frame["position"],
                "build_id": frame["build_id"],
                "address": frame["address"],
                "status": "unresolved",
                "reason": None,
                "function": None,
                "source_file": None,
                "source_line": None,
            }
            build_id = frame["build_id"]
            if not build_id:
                item["reason"] = "frame_missing_build_id"
            else:
                stored = available.get(build_id.lower())
                if stored is None:
                    item["reason"] = "build_id_not_published_at_snapshot"
                else:
                    try:
                        address = int(frame["address"], 0)
                    except ValueError:
                        item["reason"] = "invalid_address"
                        resolved_frames.append(item)
                        continue
                    sym: FrameSymbol = self._symbolizer.symbolize(
                        stored.path, stored.build_id, address
                    )
                    item["function"] = sym.function
                    item["source_file"] = sym.file
                    item["source_line"] = sym.line
                    item["status"] = "resolved" if sym.resolved() else "unresolved"
                    if not sym.resolved():
                        item["reason"] = "address_not_found_in_elf"
            resolved_frames.append(item)
        resolved_count = sum(1 for f in resolved_frames if f["status"] == "resolved")
        return {
            "report_id": report_id,
            "created_at": raw["created_at"],
            "snapshot_symbol_version": version,
            "current_symbol_version": self.symbol_version,
            "frame_count": len(resolved_frames),
            "resolved_count": resolved_count,
            "frames": resolved_frames,
        }

    def list_build_ids(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT build_id, sha256, version FROM elfs ORDER BY build_id"
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # 复发观察
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_build_id(raw: str) -> str:
        if not isinstance(raw, str):
            raise ObservationValidationError("修复版 Build ID 必须为十六进制字符串")
        build_id = raw.strip().lower()
        if not _HEX_BUILD_ID.fullmatch(build_id):
            raise ObservationValidationError(
                "修复版 Build ID 非法：只允许十六进制字符（0-9a-f），不带 0x 前缀"
            )
        return build_id

    def _get_observation_row(self, observation_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM observations WHERE id=?", (observation_id,)
        ).fetchone()

    def create_observation(
        self, reference_report_id: int, fixed_build_id: str
    ) -> dict:
        """开启复发观察。

        - 基准报告必须存在、至少两帧，且前两帧在当前符号版本下都已解析出
          源码文件名与函数名（四项缺一即 422，先补传 ELF 再开启）；
        - 冻结基准四项与开启时的报告 ID 水位、符号版本；
        - 样本在停止时才锁定，开启与停止之间入库的报告才参与选样。
        """
        build_id = self._normalize_build_id(fixed_build_id)
        with self._lock, self._conn:
            raw = self.get_report_raw(reference_report_id)
            if raw is None:
                raise ObservationValidationError(
                    f"基准报告 {reference_report_id} 不存在"
                )
            if len(raw["frames"]) < 2:
                raise ObservationValidationError(
                    f"基准报告 {reference_report_id} 至少需要两帧，"
                    f"实际 {len(raw['frames'])} 帧"
                )
            version = self.symbol_version
            resolved = self.resolve_report(
                reference_report_id, snapshot_version=version
            )
            frozen: list[tuple[str, str]] = []
            missing: list[str] = []
            for frame in resolved["frames"][:2]:
                pos = frame["position"]
                file_name = frame["source_file"]
                function = frame["function"]
                if file_name is None:
                    missing.append(f"第 {pos + 1} 帧源码文件名")
                if function is None:
                    missing.append(f"第 {pos + 1} 帧函数名")
                frozen.append((file_name or "", function or ""))
            if missing:
                raise ObservationValidationError(
                    "基准报告前两帧尚未解析出"
                    + "、".join(missing)
                    + "；请先补传对应 ELF 再开启观察"
                )
            last_report_id = int(
                self._conn.execute(
                    "SELECT COALESCE(MAX(id), 0) AS m FROM reports"
                ).fetchone()["m"]
            )
            cur = self._conn.execute(
                "INSERT INTO observations("
                "fixed_build_id, reference_report, ref_frame0_file, ref_frame0_func,"
                " ref_frame1_file, ref_frame1_func, last_report_id, symbol_version)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (
                    build_id,
                    reference_report_id,
                    frozen[0][0],
                    frozen[0][1],
                    frozen[1][0],
                    frozen[1][1],
                    last_report_id,
                    version,
                ),
            )
            observation_id = cur.lastrowid
        return self._running_view(self._get_observation_row(observation_id))

    @staticmethod
    def _running_view(obs: sqlite3.Row) -> dict:
        """运行中观察的视图：不锁定样本、不出具结论，也不抛 409。"""
        return {
            "observation_id": obs["id"],
            "created_at": obs["created_at"],
            "stopped_at": None,
            "status": "running",
            "fixed_build_id": obs["fixed_build_id"],
            "reference_report_id": obs["reference_report"],
            "reference": {
                "frame0_source_file": obs["ref_frame0_file"],
                "frame0_function": obs["ref_frame0_func"],
                "frame1_source_file": obs["ref_frame1_file"],
                "frame1_function": obs["ref_frame1_func"],
            },
            "created_symbol_version": obs["symbol_version"],
            "snapshot_symbol_version": None,
            "sample_count": 0,
            "recurrence_evidence_report_ids": [],
            "excluded_report_ids": [],
            "pending_report_ids": [],
            "samples": [],
        }

    def stop_observation(self, observation_id: int) -> dict:
        """停止观察并锁定样本范围（幂等：重复停止/重启后沿用同一范围）。

        选样条件：开启与停止之间已入库（报告 ID 落在水位区间内）、首帧
        Build ID 与修复版相符（大小写不敏感）、至少两帧；按报告原顺序固化。
        停止后新上报的报告不再入样，符号补传不受影响。
        """
        with self._lock:
            obs = self._get_observation_row(observation_id)
            if obs is None:
                raise ObservationNotFound(f"观察 {observation_id} 不存在")
            if obs["stopped_at"] is not None:
                return self.get_observation(observation_id)  # 幂等：原范围不变

            max_report_id = int(
                self._conn.execute(
                    "SELECT COALESCE(MAX(id), 0) AS m FROM reports"
                ).fetchone()["m"]
            )
            candidates = self._conn.execute(
                """
                SELECT r.id AS report_id
                FROM reports r
                WHERE r.id > ? AND r.id <= ?
                  AND (
                        SELECT COUNT(*) FROM frames f WHERE f.report_id = r.id
                      ) >= 2
                  AND LOWER(COALESCE((
                        SELECT f.build_id FROM frames f
                        WHERE f.report_id = r.id ORDER BY f.position LIMIT 1
                      ), '')) = ?
                ORDER BY r.id
                """,
                (obs["last_report_id"], max_report_id, obs["fixed_build_id"]),
            ).fetchall()

            with self._conn:  # 样本固化与停止标记同一事务
                self._conn.executemany(
                    "INSERT INTO observation_samples(observation_id, report_id, position)"
                    " VALUES(?,?,?)",
                    [
                        (observation_id, row["report_id"], pos)
                        for pos, row in enumerate(candidates)
                    ],
                )
                self._conn.execute(
                    "UPDATE observations SET stopped_at="
                    "strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                    (observation_id,),
                )
        return self.get_observation(observation_id)

    def get_observation(self, observation_id: int) -> dict:
        """凭观察号查结论。

        停止后每次调用在核查开始时取一次符号版本快照，整次核查只使用
        version <= 快照版本 的已发布符号；运行中查询抛 ObservationStillRunning。
        """
        obs = self._get_observation_row(observation_id)
        if obs is None:
            raise ObservationNotFound(f"观察 {observation_id} 不存在")

        reference = {
            "frame0_source_file": obs["ref_frame0_file"],
            "frame0_function": obs["ref_frame0_func"],
            "frame1_source_file": obs["ref_frame1_file"],
            "frame1_function": obs["ref_frame1_func"],
        }
        if obs["stopped_at"] is None:
            raise ObservationStillRunning(
                f"观察 {observation_id} 尚未停止：停止后才能锁定样本并出具结论"
            )

        result = {
            "observation_id": obs["id"],
            "created_at": obs["created_at"],
            "stopped_at": obs["stopped_at"],
            "status": "running",
            "fixed_build_id": obs["fixed_build_id"],
            "reference_report_id": obs["reference_report"],
            "reference": reference,
            "created_symbol_version": obs["symbol_version"],
            "snapshot_symbol_version": None,
            "sample_count": 0,
            "recurrence_evidence_report_ids": [],
            "excluded_report_ids": [],
            "pending_report_ids": [],
            "samples": [],
        }

        # 核查开始时取一次快照，期间新发布的符号本次不可见
        snapshot = self.symbol_version
        ref_pairs = [
            (obs["ref_frame0_file"], obs["ref_frame0_func"]),
            (obs["ref_frame1_file"], obs["ref_frame1_func"]),
        ]
        sample_rows = self._conn.execute(
            "SELECT report_id, position FROM observation_samples"
            " WHERE observation_id=? ORDER BY position",
            (observation_id,),
        ).fetchall()

        evidence: list[int] = []
        excluded: list[int] = []
        pending: list[int] = []
        samples: list[dict] = []
        for srow in sample_rows:
            report_id = srow["report_id"]
            resolved = self.resolve_report(report_id, snapshot_version=snapshot)
            frames = resolved["frames"][:2]  # 选样已保证 >=2 帧
            comparisons = []
            known_difference = False
            missing_info = False
            for idx in range(2):
                ref_file, ref_func = ref_pairs[idx]
                actual_file = frames[idx]["source_file"]
                actual_func = frames[idx]["function"]
                # 任何一项“已知不同”即排除；未知项（未解析）不参与差异判定
                if actual_file is not None and actual_file != ref_file:
                    known_difference = True
                if actual_func is not None and actual_func != ref_func:
                    known_difference = True
                if actual_file is None or actual_func is None:
                    missing_info = True
                comparisons.append(
                    {
                        "position": idx,
                        "reference_source_file": ref_file,
                        "reference_function": ref_func,
                        "actual_source_file": actual_file,
                        "actual_function": actual_func,
                    }
                )
            if known_difference:
                state = "excluded"
                excluded.append(report_id)
            elif missing_info:
                state = "pending"
                pending.append(report_id)
            else:  # 四项均已知且全部相同
                state = "recurrence"
                evidence.append(report_id)
            samples.append(
                {
                    "report_id": report_id,
                    "position": srow["position"],
                    "state": state,
                    "comparisons": comparisons,
                }
            )

        if evidence:
            status = "recurrence_detected"
        elif not sample_rows:
            status = "no_samples"  # 无样本单列，不与“全被排除”混淆
        elif len(excluded) == len(sample_rows):
            status = "no_recurrence_all_excluded"
        else:
            status = "awaiting_symbols"

        result.update(
            {
                "status": status,
                "snapshot_symbol_version": snapshot,
                "sample_count": len(sample_rows),
                "recurrence_evidence_report_ids": evidence,
                "excluded_report_ids": excluded,
                "pending_report_ids": pending,
                "samples": samples,
            }
        )
        return result

    def list_observations(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id FROM observations ORDER BY id"
        ).fetchall()
        items = []
        for row in rows:
            try:
                items.append(self.get_observation(row["id"]))
            except ObservationStillRunning:
                # 列表视图里运行中的观察给出运行态，不抛 409
                items.append(self._running_view(self._get_observation_row(row["id"])))
        return items

    def close(self) -> None:
        self._conn.close()
