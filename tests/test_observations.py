"""复发观察自测：基准冻结、样本选样窗口、四值比对、停止锁定、补传与重启。"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from app.storage import (
    ObservationStillRunning,
    ObservationValidationError,
    Store,
)

FIX = Path(__file__).resolve().parent / "fixtures" / "built"
BID_OLD = "a" * 40
BID_FIX_RECUR = "d1" * 20
BID_FIX_RENAMED = "d2" * 20
BID_FIX_FUNC = "d3" * 20

ALL_FIXTURES = [
    "demo-aaaa.elf",
    "fixed-recur-d1d1.elf",
    "fixed-renamed-d2d2.elf",
    "fixed-func-d3d3.elf",
]
BID_OF = {
    "demo-aaaa.elf": BID_OLD,
    "fixed-recur-d1d1.elf": BID_FIX_RECUR,
    "fixed-renamed-d2d2.elf": BID_FIX_RENAMED,
    "fixed-func-d3d3.elf": BID_FIX_FUNC,
}
FUNCS_OF = {
    "demo-aaaa.elf": ("helper_add", "crash_here"),
    "fixed-recur-d1d1.elf": ("helper_add", "crash_here"),
    "fixed-renamed-d2d2.elf": ("helper_add", "crash_here"),
    "fixed-func-d3d3.elf": ("helper_add_v2", "crash_here_v2"),
}


def publish(store: Store, *names: str) -> None:
    for name in names:
        store.publish_batch([(name, (FIX / name).read_bytes())])


def publish_all(store: Store) -> None:
    publish(store, *ALL_FIXTURES)


def func_address(elf_name: str, func: str) -> int:
    with open(FIX / elf_name, "rb") as fh:
        elf = ELFFile(fh)
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_SYMTAB":
                continue
            for sym in section.iter_symbols():
                if sym.name == func and sym["st_info"]["type"] == "STT_FUNC":
                    return sym["st_value"]
    raise AssertionError(f"符号 {func} 未在 {elf_name} 中找到")


def make_two_frame_report(store: Store, elf_name: str, build_id: str | None = None) -> int:
    f0, f1 = FUNCS_OF[elf_name]
    bid = BID_OF[elf_name] if build_id is None else build_id
    return store.create_report(
        [
            {"build_id": bid, "address": hex(func_address(elf_name, f0))},
            {"build_id": bid, "address": hex(func_address(elf_name, f1))},
        ]
    )


def make_reference(store: Store) -> int:
    """旧版崩溃报告：前两帧在旧版符号下解析出 demo.c 的两个函数。"""
    return make_two_frame_report(store, "demo-aaaa.elf")


# ---------------------------------------------------------------------------
# 1. 开启观察的校验
# ---------------------------------------------------------------------------
def test_create_observation_validates_inputs(store):
    publish(store, "demo-aaaa.elf")
    ref = make_reference(store)

    with pytest.raises(ObservationValidationError):
        store.create_observation(99999, BID_FIX_RECUR)  # 报告不存在

    single = store.create_report(
        [{"build_id": BID_OLD, "address": hex(func_address("demo-aaaa.elf", "crash_here"))}]
    )
    with pytest.raises(ObservationValidationError, match="两帧"):
        store.create_observation(single, BID_FIX_RECUR)

    for bad in ("", "0x" + BID_FIX_RECUR, "g" * 40, "abc def"):
        with pytest.raises(ObservationValidationError):
            store.create_observation(ref, bad)


def test_create_observation_requires_resolved_first_two_frames(store):
    # 未发布任何符号：前两帧没有函数名/文件名，不允许开启
    ref = make_reference(store)
    with pytest.raises(ObservationValidationError, match="补传"):
        store.create_observation(ref, BID_FIX_RECUR)

    publish(store, "demo-aaaa.elf")
    obs = store.create_observation(ref, BID_FIX_RECUR)
    assert obs["status"] == "running"
    assert obs["reference"] == {
        "frame0_source_file": "/workspace/demo.c",
        "frame0_function": "helper_add",
        "frame1_source_file": "/workspace/demo.c",
        "frame1_function": "crash_here",
    }
    assert obs["sample_count"] == 0


def test_running_observation_cannot_be_evaluated(store):
    publish(store, "demo-aaaa.elf")
    ref = make_reference(store)
    obs = store.create_observation(ref, BID_FIX_RECUR)
    with pytest.raises(ObservationStillRunning):
        store.get_observation(obs["observation_id"])


# ---------------------------------------------------------------------------
# 2. 样本选样：时间窗、首帧 Build ID、至少两帧、原顺序
# ---------------------------------------------------------------------------
def test_sample_selection_window_buildid_framecount_and_order(store):
    publish_all(store)
    ref = make_reference(store)  # 开启前的旧报告，永远不入样
    obs_id = store.create_observation(ref, BID_FIX_RECUR)["observation_id"]

    recur1 = make_two_frame_report(store, "fixed-recur-d1d1.elf")  # 入样
    # 单帧：帧数不足，不入样
    store.create_report(
        [{"build_id": BID_FIX_RECUR, "address": hex(func_address("fixed-recur-d1d1.elf", "crash_here"))}]
    )
    # 大写 Build ID：大小写不敏感，入样
    recur_upper = make_two_frame_report(
        store, "fixed-recur-d1d1.elf", build_id=BID_FIX_RECUR.upper()
    )
    # 首帧 Build ID 不符：不入样
    make_two_frame_report(store, "fixed-renamed-d2d2.elf")
    # 首帧缺 Build ID：不入样
    store.create_report(
        [
            {"build_id": None, "address": "0x100"},
            {"build_id": BID_FIX_RECUR, "address": "0x200"},
        ]
    )

    stopped = store.stop_observation(obs_id)
    assert stopped["sample_count"] == 2
    assert [s["report_id"] for s in stopped["samples"]] == [recur1, recur_upper]

    # 停止后新上报的报告不进入样本（范围锁定）
    after_stop = make_two_frame_report(store, "fixed-recur-d1d1.elf")
    again = store.stop_observation(obs_id)  # 重复停止：范围不变
    assert again["sample_count"] == 2
    assert after_stop not in [s["report_id"] for s in again["samples"]]


def test_no_samples_is_distinct_status(store):
    publish_all(store)
    ref = make_reference(store)
    obs_id = store.create_observation(ref, BID_FIX_RECUR)["observation_id"]
    result = store.stop_observation(obs_id)
    assert result["status"] == "no_samples"
    assert result["sample_count"] == 0
    assert result["recurrence_evidence_report_ids"] == []


# ---------------------------------------------------------------------------
# 3. 四值比对：复发 / 任一已知不同即排除 / 缺信息待补
# ---------------------------------------------------------------------------
def test_recurrence_detected_with_evidence_when_all_four_match(store):
    publish_all(store)
    ref = make_reference(store)
    obs_id = store.create_observation(ref, BID_FIX_RECUR)["observation_id"]
    evidence = make_two_frame_report(store, "fixed-recur-d1d1.elf")

    result = store.stop_observation(obs_id)
    assert result["status"] == "recurrence_detected"
    assert result["recurrence_evidence_report_ids"] == [evidence]
    sample = result["samples"][0]
    assert sample["state"] == "recurrence"
    for cmp in sample["comparisons"]:
        assert cmp["actual_source_file"] == cmp["reference_source_file"]
        assert cmp["actual_function"] == cmp["reference_function"]


def test_known_difference_in_any_item_excludes_report(store):
    publish_all(store)
    ref = make_reference(store)

    # 仅源码文件名不同
    obs_renamed = store.create_observation(ref, BID_FIX_RENAMED)["observation_id"]
    renamed = make_two_frame_report(store, "fixed-renamed-d2d2.elf")
    r1 = store.stop_observation(obs_renamed)
    assert r1["status"] == "no_recurrence_all_excluded"
    assert r1["excluded_report_ids"] == [renamed]
    assert r1["pending_report_ids"] == []
    cmp0 = r1["samples"][0]["comparisons"][0]
    assert cmp0["actual_source_file"] != cmp0["reference_source_file"]
    assert cmp0["actual_function"] == cmp0["reference_function"]  # 函数名仍相同

    # 仅函数名不同（源文件名同为 demo.c）
    obs_func = store.create_observation(ref, BID_FIX_FUNC)["observation_id"]
    func_renamed = make_two_frame_report(store, "fixed-func-d3d3.elf")
    r2 = store.stop_observation(obs_func)
    assert r2["status"] == "no_recurrence_all_excluded"
    assert r2["excluded_report_ids"] == [func_renamed]
    cmp0 = r2["samples"][0]["comparisons"][0]
    assert cmp0["actual_source_file"] == cmp0["reference_source_file"]
    assert cmp0["actual_function"] != cmp0["reference_function"]


def test_pending_report_resolved_after_symbol_upload_post_stop(store):
    """停止后补传符号：pending -> recurrence，且停止后的新报告不扩样。"""
    publish(store, "demo-aaaa.elf")  # 只发旧版符号
    ref = make_reference(store)
    obs_id = store.create_observation(ref, BID_FIX_RECUR)["observation_id"]
    pending_report = make_two_frame_report(store, "fixed-recur-d1d1.elf")

    stopped = store.stop_observation(obs_id)
    assert stopped["status"] == "awaiting_symbols"
    assert stopped["pending_report_ids"] == [pending_report]
    assert stopped["recurrence_evidence_report_ids"] == []
    sample = stopped["samples"][0]
    assert sample["state"] == "pending"
    assert sample["comparisons"][0]["actual_function"] is None  # 信息缺失而非误判

    # 停止后照常接收报障：新报告不进入已锁定样本
    later_report = make_two_frame_report(store, "fixed-recur-d1d1.elf")
    before_upload = store.get_observation(obs_id)
    assert before_upload["sample_count"] == 1
    assert later_report not in before_upload["pending_report_ids"]

    # 停止后照常补传符号，再查结论即更新
    publish(store, "fixed-recur-d1d1.elf")
    after_upload = store.get_observation(obs_id)
    assert after_upload["status"] == "recurrence_detected"
    assert after_upload["recurrence_evidence_report_ids"] == [pending_report]
    assert after_upload["pending_report_ids"] == []


def test_evaluation_uses_snapshot_taken_at_evaluation_start(store, monkeypatch):
    """核查进行中发布的符号本次不可见，下次核查才生效。"""
    publish(store, "demo-aaaa.elf")
    ref = make_reference(store)
    obs_id = store.create_observation(ref, BID_FIX_RECUR)["observation_id"]
    make_two_frame_report(store, "fixed-recur-d1d1.elf")
    store.stop_observation(obs_id)

    barrier = threading.Event()
    orig_resolve = store.resolve_report

    def slow_resolve(report_id, snapshot_version=None):
        if not barrier.is_set():
            barrier.set()
            time.sleep(0.3)  # 给另一线程留出发布窗口
        return orig_resolve(report_id, snapshot_version=snapshot_version)

    monkeypatch.setattr(store, "resolve_report", slow_resolve)

    def publish_during_evaluation():
        barrier.wait(timeout=5)
        publish(store, "fixed-recur-d1d1.elf")

    t = threading.Thread(target=publish_during_evaluation)
    t.start()
    result = store.get_observation(obs_id)  # 快照在发布前取定
    t.join()
    assert result["status"] == "awaiting_symbols"  # 本次看不到新符号

    monkeypatch.undo()
    again = store.get_observation(obs_id)  # 新一次核查取新快照
    assert again["status"] == "recurrence_detected"


# ---------------------------------------------------------------------------
# 4. 重启持久化
# ---------------------------------------------------------------------------
def test_observation_survives_restart_and_keeps_locked_sample(data_dir):
    s1 = Store(data_dir=data_dir)
    publish(s1, "demo-aaaa.elf")
    ref = make_reference(s1)
    obs_id = s1.create_observation(ref, BID_FIX_RECUR)["observation_id"]
    pending_report = make_two_frame_report(s1, "fixed-recur-d1d1.elf")
    stopped1 = s1.stop_observation(obs_id)
    assert stopped1["sample_count"] == 1
    s1.close()

    # 进程重启：样本范围、基准四项、运行结论全部沿用
    s2 = Store(data_dir=data_dir)
    try:
        got = s2.get_observation(obs_id)
        assert got["status"] == "awaiting_symbols"
        assert got["pending_report_ids"] == [pending_report]
        assert got["reference"]["frame0_function"] == "helper_add"
        # 重启后重复停止仍是同一范围
        again = s2.stop_observation(obs_id)
        assert [s["report_id"] for s in again["samples"]] == [pending_report]
        # 重启后补传仍可改变结论
        publish(s2, "fixed-recur-d1d1.elf")
        final = s2.get_observation(obs_id)
        assert final["status"] == "recurrence_detected"
        assert final["recurrence_evidence_report_ids"] == [pending_report]
    finally:
        s2.close()


# ---------------------------------------------------------------------------
# 5. HTTP 接口
# ---------------------------------------------------------------------------
def test_http_observation_lifecycle_and_errors(client):
    c, store = client
    publish(store, "demo-aaaa.elf")
    ref = make_reference(store)

    created = c.post(
        "/observations",
        json={"reference_report_id": ref, "fixed_build_id": BID_FIX_RECUR},
    )
    assert created.status_code == 201
    obs_id = created.json()["observation_id"]
    assert created.json()["status"] == "running"

    # 非法入参
    bad = c.post(
        "/observations",
        json={"reference_report_id": ref, "fixed_build_id": "not-hex!!"},
    )
    assert bad.status_code == 422

    # 运行中查结论 -> 409
    running = c.get(f"/observations/{obs_id}")
    assert running.status_code == 409

    make_two_frame_report(store, "fixed-recur-d1d1.elf")
    stopped = c.post(f"/observations/{obs_id}/stop")
    assert stopped.status_code == 200
    assert stopped.json()["sample_count"] == 1

    # 观察号不存在
    assert c.get("/observations/99999").status_code == 404
    assert c.post("/observations/99999/stop").status_code == 404

    # 停止后继续上报与补传，服务照常接收，样本范围不变
    later = c.post(
        "/reports",
        json={
            "frames": [
                {"build_id": BID_FIX_RECUR, "address": hex(func_address("fixed-recur-d1d1.elf", "helper_add"))},
                {"build_id": BID_FIX_RECUR, "address": hex(func_address("fixed-recur-d1d1.elf", "crash_here"))},
            ]
        },
    )
    assert later.status_code == 201
    with open(FIX / "fixed-recur-d1d1.elf", "rb") as fh:
        up = c.post(
            "/symbols/batch",
            files=[("files", ("fixed.elf", fh.read(), "application/octet-stream"))],
        )
    assert up.status_code == 200

    conclusion = c.get(f"/observations/{obs_id}").json()
    assert conclusion["sample_count"] == 1  # 停止后的报告未入样
    assert conclusion["status"] == "recurrence_detected"

    listed = c.get("/observations")
    assert listed.status_code == 200
    assert any(o["observation_id"] == obs_id for o in listed.json())
