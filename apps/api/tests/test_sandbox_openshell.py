"""OpenShellSandbox 제어 흐름 테스트. 실제 openshell/nemoclaw 없이 가짜 실행기로 명령 순서와 정책 수명주기를 검증한다.

핵심 보증: 어떤 실패에서도 조사용 정책은 제거된다(F9), 허용 밖 호스트는 프리셋에 들어가지 않는다.
"""
import json

import pytest
import yaml

from app.sandbox import CmdResult, OpenShellSandbox, SandboxError, extract_tools, first_json, render_preset

AGENT_OK = json.dumps({"status": "ok", "result": {"payloads": [{"text": '{"status":"done"}'}], "meta": {
    "durationMs": 14210, "toolSummary": {"tools": ["read", "exec", "exec"]}, "sessionId": "s1", "model": "nemotron"}}})


class FakeRunner:
    """호출 기록을 남기고 명령별로 응답을 돌려준다. 정책 add/remove를 추적한다."""

    def __init__(self, agent_stdout=AGENT_OK, fail=None, chain=None, remove_fail_times=0):
        self.calls: list[list[str]] = []
        self.active_policies: set[str] = set()
        self.agent_stdout, self.fail, self.remove_fail_times = agent_stdout, fail or {}, remove_fail_times
        self.chain = chain
        self.download_files: dict[str, dict] = {}

    def __call__(self, args, timeout=None):
        self.calls.append(args)
        for pat, act in self.fail.items():
            if pat in " ".join(args):
                if act == "timeout":
                    raise TimeoutError("timeout")
                return CmdResult(1, "", str(act))
        if args[:2] == ["nemoclaw", "my-assistant"] and args[2:4] == ["policy", "add"]:
            data = yaml.safe_load(open(args[args.index("--from-file") + 1], encoding="utf-8"))
            self.active_policies.update(data["network_policies"].keys())
            return CmdResult(0, "added", "")
        if args[2:4] == ["policy", "remove"]:
            if self.remove_fail_times > 0:
                self.remove_fail_times -= 1
                return CmdResult(1, "", "boom")
            self.active_policies.discard(args[4])
            return CmdResult(0, "removed", "")
        if args[:3] == ["openshell", "sandbox", "exec"] and "openclaw" in args:
            return CmdResult(0, "Node warning\n" + self.agent_stdout, "")
        if args[:3] == ["openshell", "sandbox", "download"]:
            dest = args[-1]
            from pathlib import Path

            for name, obj in self.download_files.items():
                p = Path(dest) / args[-2].rsplit("/", 1)[-1] / f"{name}.json"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps(obj), encoding="utf-8")
            return CmdResult(0, "", "")
        if args[2:4] == ["policy", "list"]:
            return CmdResult(0, "job-abc123  active\nspike-old  active\nother-preset", "")
        return CmdResult(0, "", "")


def sb(runner, tmp_path):
    return OpenShellSandbox(runner=runner, name="my-assistant", workdir=tmp_path)


def payload():
    return {"job_id": "j_1", "url": "https://a.test/x", "kb_candidates": [], "kb_official_domains": []}


def order(runner):
    kinds = []
    for c in runner.calls:
        j = " ".join(c)
        if "sandbox upload" in j:
            kinds.append("upload")
        elif "policy add" in j:
            kinds.append("add")
        elif "openclaw" in j:
            kinds.append("agent")
        elif "policy remove" in j:
            kinds.append("remove")
        elif "sandbox download" in j:
            kinds.append("download")
    return kinds


def test_happy_path_order_and_policy_removed(tmp_path):
    r = FakeRunner()
    r.download_files = {"parse_url": {"ok": True}, "claim": {"ok": True, "at": "2026-09-24T00:00:01+00:00"}}
    res = sb(r, tmp_path).investigate("j_1", payload(), "a.test", True)
    assert order(r) == ["upload", "add", "agent", "remove", "download"]
    assert r.active_policies == set() and not res.residual_policy and res.incomplete is None
    assert [e["kind"] for e in res.events] == ["open", "close"]
    assert res.agent["tool_calls"] == ["read", "exec", "exec"] and res.agent["duration_ms"] == 14210
    assert res.files["parse_url"]["ok"] is True


def test_agent_command_uses_session_message_json_and_timeout(tmp_path):
    r = FakeRunner()
    sb(r, tmp_path).investigate("j_1", payload(), "a.test", True)
    agent = next(c for c in r.calls if "openclaw" in c)
    assert agent[:5] == ["openshell", "sandbox", "exec", "-n", "my-assistant"]
    assert "--json" in agent and agent[agent.index("--session-id") + 1] == "j_1-inv"
    assert agent[agent.index("--timeout") + 1] == "60"
    assert "phishing-investigator" in agent[agent.index("--message") + 1]


def test_agent_timeout_marks_incomplete_and_still_removes_policy(tmp_path):
    r = FakeRunner(fail={"openclaw": "timeout"})
    res = sb(r, tmp_path).investigate("j_1", payload(), "a.test", True)
    assert res.incomplete == "agent_timeout" and r.active_policies == set()
    assert order(r).count("remove") == 1


def test_agent_error_and_overload(tmp_path):
    r = FakeRunner(fail={"openclaw": "Error 429 rate limit"})
    assert sb(r, tmp_path).investigate("j_1", payload(), "a.test", True).incomplete == "overloaded"
    r = FakeRunner(agent_stdout="not json at all")
    res = sb(r, tmp_path).investigate("j_2", payload(), "a.test", True)
    assert res.incomplete == "agent_error" and r.active_policies == set()


def test_policy_add_failure_skips_agent_and_never_leaves_policy(tmp_path):
    r = FakeRunner(fail={"policy add": "denied"})
    res = sb(r, tmp_path).investigate("j_1", payload(), "a.test", True)
    assert res.incomplete == "policy_error" and "agent" not in order(r)


def test_remove_retry_then_success(tmp_path):
    r = FakeRunner(remove_fail_times=1)
    res = sb(r, tmp_path).investigate("j_1", payload(), "a.test", True)
    assert order(r).count("remove") == 2 and r.active_policies == set() and not res.residual_policy


def test_remove_failure_is_flagged_residual(tmp_path):
    r = FakeRunner(remove_fail_times=5)
    res = sb(r, tmp_path).investigate("j_1", payload(), "a.test", True)
    assert res.residual_policy is True


def test_ip_or_private_host_opens_no_policy(tmp_path):
    r = FakeRunner()
    res = sb(r, tmp_path).investigate("j_1", payload(), "1.2.3.4", False)
    assert "add" not in order(r) and "remove" not in order(r) and not res.events


def test_preset_is_limited_to_target_host_get_python3():
    data = yaml.safe_load(render_preset("j_abc123", "account-check.test"))
    pol = data["network_policies"]["job-j_abc123"]
    assert {(e["host"], e["port"]) for e in pol["endpoints"]} == {("account-check.test", 443), ("account-check.test", 80)}
    assert all(rule["allow"]["method"] == "GET" for e in pol["endpoints"] for rule in e["rules"])
    assert [b["path"] for b in pol["binaries"]] == ["/usr/bin/python3", "/usr/bin/python3.13"]


def test_preset_rejects_unsafe_host():
    with pytest.raises(SandboxError):
        render_preset("j_1", "a.test\n    - host: evil.test")


def test_prepare_removes_only_job_and_spike_presets(tmp_path):
    r = FakeRunner()
    removed = sb(r, tmp_path).prepare()
    assert set(removed) == {"job-abc123", "spike-old"}


def test_first_json_skips_node_warnings_and_tools_extraction():
    assert first_json("(node:1) Warning: x\n{\"a\": 1}\ntrailing") == {"a": 1}
    assert first_json("no json") is None
    assert extract_tools({"toolSummary": [{"name": "read"}, {"name": "exec"}]}) == ["read", "exec"]
    assert extract_tools({"executionTrace": {"steps": [{"tool": "web_fetch"}]}}) == ["web_fetch"]


def test_unexpected_tools_are_reported(tmp_path):
    out = json.dumps({"status": "ok", "result": {"meta": {"toolSummary": {"tools": ["read", "web_fetch", "exec"]}}}})
    res = sb(FakeRunner(agent_stdout=out), tmp_path).investigate("j_1", payload(), "a.test", True)
    assert res.agent["unexpected_tools"] == ["web_fetch"]


def test_explain_parses_agent_payload_text(tmp_path):
    body = {"headline": "x", "recommended_action": "y"}
    out = json.dumps({"status": "ok", "result": {"payloads": [{"text": json.dumps(body)}]}})
    assert sb(FakeRunner(agent_stdout=out), tmp_path).explain("j_1", {"verdict": "safe"}) == body
    assert sb(FakeRunner(agent_stdout="garbage"), tmp_path).explain("j_1", {}) is None
