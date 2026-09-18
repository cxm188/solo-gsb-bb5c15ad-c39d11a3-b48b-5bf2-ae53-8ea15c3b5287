"""有状态防火墙模拟核心逻辑的单元测试。"""
import pytest

from app.firewall import (
    DEFAULT_SESSION_TIMEOUT,
    FIREWALL_EVENTS_MAX,
    FIREWALL_RULES_MAX,
    SESSION_TIMEOUT_MAX,
    SESSION_TIMEOUT_MIN,
    DuplicateSessionKeyError,
    FirewallTimeOrderError,
    InvalidPortError,
    InvalidProtocolError,
    five_tuple_key,
    format_five_tuple,
    normalize_port,
    normalize_protocol,
    normalize_session_timeout,
    reverse_key,
    simulate_firewall,
    validate_port_protocol,
)
from app.analyzer import InvalidCIDRError
from app.router import InvalidIPv4AddressError


TCP_RULE_ALLOW = ("allow", "10.0.0.0/24", "10.0.1.0/24", "tcp", 80, 80)
TCP_RULE_DENY_ALL = ("deny", "0.0.0.0/0", "0.0.0.0/0", "tcp", 0, 65535)


def tcp_event(time, src, sp, dst, dp):
    return (time, src, sp, dst, dp, "tcp")


def icmp_event(time, src, dst):
    return (time, src, None, dst, None, "icmp")


def simulate(events, rules=(TCP_RULE_ALLOW, TCP_RULE_DENY_ALL), default="deny", timeout=30):
    return simulate_firewall(list(rules), default, events, timeout)


# ---------- 规范化辅助 ----------

def test_normalize_protocol():
    assert normalize_protocol("TCP") == "tcp"
    assert normalize_protocol(" Udp ") == "udp"
    assert normalize_protocol("icmp") == "icmp"
    for bad in ["sctp", "", "   ", 6, None, True]:
        with pytest.raises(InvalidProtocolError):
            normalize_protocol(bad)


def test_normalize_port():
    assert normalize_port(0) == 0
    assert normalize_port(65535) == 65535
    for bad in [-1, 65536, 1.5, "80", True, None]:
        with pytest.raises(InvalidPortError):
            normalize_port(bad)


def test_validate_port_protocol_combinations():
    assert validate_port_protocol("icmp", None, None) == (None, None)
    assert validate_port_protocol("tcp", 1, 65535) == (1, 65535)
    with pytest.raises(InvalidPortError):
        validate_port_protocol("icmp", 0, 0)
    with pytest.raises(InvalidPortError):
        validate_port_protocol("udp", None, 53)
    with pytest.raises(InvalidPortError):
        validate_port_protocol("udp", 53, None)


def test_normalize_session_timeout():
    assert normalize_session_timeout(1) == 1
    assert normalize_session_timeout(SESSION_TIMEOUT_MAX) == SESSION_TIMEOUT_MAX
    for bad in [0, -1, SESSION_TIMEOUT_MAX + 1, 1.5, True, "30"]:
        with pytest.raises(ValueError):
            normalize_session_timeout(bad)


def test_five_tuple_and_reverse_key():
    key = five_tuple_key("tcp", 0x0A000001, 1234, 0x0A000101, 80)
    rev = reverse_key(key)
    assert rev == ("tcp", 0x0A000101, 80, 0x0A000001, 1234)
    assert reverse_key(rev) == key
    assert reverse_key(five_tuple_key("icmp", 1, None, 2, None)) == (
        "icmp", 2, None, 1, None
    )


def test_format_five_tuple():
    assert format_five_tuple("tcp", "10.0.0.1", 1234, "10.0.0.2", 80) == (
        "tcp 10.0.0.1:1234 -> 10.0.0.2:80"
    )
    assert format_five_tuple("icmp", "10.0.0.1", None, "10.0.0.2", None) == (
        "icmp 10.0.0.1 -> 10.0.0.2"
    )


# ---------- 基本规则匹配 ----------

def test_first_matching_rule_wins_and_default():
    events = [
        tcp_event(0, "10.0.0.1", 1234, "10.0.1.1", 80),   # allow
        tcp_event(0, "10.0.0.1", 1234, "10.0.1.1", 81),   # 端口不匹配 -> deny-all
        tcp_event(0, "10.0.2.1", 1234, "10.0.1.1", 80),   # 源网段不匹配 -> deny-all
        tcp_event(0, "10.0.0.1", 1234, "8.8.8.8", 80),    # 目的网段不匹配 -> deny-all
    ]
    out = simulate(events)
    assert [(r["decision"], r["rule_index"], r["action"]) for r in out["results"]] == [
        ("rule", 0, "allow"),
        ("rule", 1, "deny"),
        ("rule", 1, "deny"),
        ("rule", 1, "deny"),
    ]


def test_default_action_when_no_rule_matches():
    events = [
        tcp_event(0, "8.8.8.8", 1, "9.9.9.9", 1),
        icmp_event(0, "8.8.8.8", "9.9.9.9"),
    ]
    out = simulate_firewall([], "allow", events)
    assert all(r["decision"] == "default" and r["action"] == "allow" for r in out["results"])
    # 默认 allow 不建立会话
    assert all(r["session"] is None for r in out["results"])
    assert out["summary"]["sessions_new"] == 0


def test_action_and_protocol_case_insensitive_at_core():
    rule = ("ALLOW", "10.0.0.0/24", "0.0.0.0/0", "TCP", 0, 65535)
    out = simulate_firewall([rule], "deny", [tcp_event(0, "10.0.0.1", 1, "8.8.8.8", 8)])
    assert out["results"][0]["action"] == "allow"
    assert out["default_action"] == "deny"


def test_dst_port_range_inclusive_and_src_port_ignored():
    rule = ("allow", "0.0.0.0/0", "0.0.0.0/0", "udp", 100, 200)
    events = [
        (0, "1.1.1.1", 100, "2.2.2.2", 100, "udp"),
        (0, "1.1.1.1", 200, "2.2.2.2", 200, "udp"),
        (0, "1.1.1.1", 150, "2.2.2.2", 201, "udp"),
        (0, "1.1.1.1", 99, "2.2.2.2", 100, "udp"),   # 源端口不参与匹配
    ]
    out = simulate_firewall([rule], "deny", events)
    assert [r["action"] for r in out["results"]] == ["allow", "allow", "deny", "allow"]


def test_protocol_must_match():
    rule = ("allow", "0.0.0.0/0", "0.0.0.0/0", "tcp", 0, 65535)
    out = simulate_firewall([rule], "deny", [icmp_event(0, "1.1.1.1", "2.2.2.2")])
    assert out["results"][0]["decision"] == "default"


def test_icmp_rule_and_events():
    rule = ("allow", "10.0.0.0/24", "10.0.1.0/24", "icmp", None, None)
    out = simulate_firewall(
        [rule], "deny",
        [icmp_event(0, "10.0.0.1", "10.0.1.9"),
         icmp_event(5, "10.0.1.9", "10.0.0.1")],
    )
    assert [r["action"] for r in out["results"]] == ["allow", "allow"]
    assert out["results"][0]["session_state"] == "new"
    assert out["results"][1]["decision"] == "stateful"
    assert out["results"][1]["direction"] == "reverse"


# ---------- 会话建立 / 反向放行 / 超时 ----------

def test_forward_allow_creates_session():
    out = simulate([tcp_event(10, "10.0.0.1", 1234, "10.0.1.1", 80)])
    result = out["results"][0]
    assert result["decision"] == "rule"
    assert result["direction"] == "forward"
    assert result["session_state"] == "new"
    session = result["session"]
    assert session["key"] == "tcp 10.0.0.1:1234 -> 10.0.1.1:80"
    assert session["rule_index"] == 0
    assert session["created_at"] == 10
    assert session["last_seen_at"] == 10
    assert session["expires_at"] == 10 + DEFAULT_SESSION_TIMEOUT
    assert session["age"] == 0
    assert session["established_by_event"] == 0
    assert result["expired_sessions"] == []
    assert out["summary"]["sessions_new"] == 1
    assert out["summary"]["active_sessions"] == 1


def test_reverse_packet_stateful_within_ttl_refreshes_last_seen():
    out = simulate([
        tcp_event(10, "10.0.0.1", 1234, "10.0.1.1", 80),
        tcp_event(20, "10.0.1.1", 80, "10.0.0.1", 1234),
    ])
    reverse = out["results"][1]
    assert reverse["decision"] == "stateful"
    assert reverse["rule_index"] == 0          # 回填建会话规则
    assert reverse["action"] == "allow"
    assert reverse["direction"] == "reverse"
    assert reverse["session_state"] == "established"
    assert reverse["session"]["age"] == 10
    assert reverse["session"]["last_seen_at"] == 20
    assert reverse["session"]["expires_at"] == 40  # 截止时间不随刷新滑动
    assert out["summary"]["sessions_new"] == 1


def test_session_boundary_time_still_alive():
    # created_at=1, timeout=30 => expires_at=31；t=31 仍存活，t=32 过期
    out = simulate([
        tcp_event(1, "10.0.0.1", 1, "10.0.1.1", 80),
        tcp_event(31, "10.0.1.1", 80, "10.0.0.1", 1),
    ])
    assert out["results"][1]["decision"] == "stateful"
    assert out["results"][1]["session_state"] == "established"


def test_expired_reverse_packet_goes_through_rules_and_can_rebuild():
    out = simulate([
        tcp_event(1, "10.0.0.1", 1234, "10.0.1.1", 80),
        # 反向在 t=32（expires_at=31）到达：过期清除，重新走规则
        tcp_event(32, "10.0.1.1", 80, "10.0.0.1", 1234),
        # 按新方向再反向一次：新会话存活，stateful
        tcp_event(33, "10.0.0.1", 1234, "10.0.1.1", 80),
    ])
    expired = out["results"][1]
    assert expired["decision"] == "rule"
    assert expired["rule_index"] == 1
    assert expired["action"] == "deny"
    assert expired["direction"] == "forward"
    assert expired["session_state"] == "expired"
    assert expired["session"] is None
    assert len(expired["expired_sessions"]) == 1
    stale = expired["expired_sessions"][0]
    assert stale["expires_at"] == 31
    assert stale["established_by_event"] == 0

    # 被 deny 后没有新会话；t=33 的正向包重新命中 allow，再建会话
    rebuilt = out["results"][2]
    assert rebuilt["session_state"] == "new"
    assert rebuilt["session"]["created_at"] == 33
    assert rebuilt["session"]["expires_at"] == 63
    assert out["summary"] == {
        "allow": 2, "deny": 1, "sessions_new": 2,
        "sessions_expired": 1, "active_sessions": 1,
    }


def test_expired_reverse_reallowed_rebuilds_in_new_direction():
    # 反向包超时后，规则也允许该方向，直接按新方向重建
    rules = [
        ("allow", "10.0.0.0/24", "10.0.1.0/24", "tcp", 80, 80),
        ("allow", "10.0.1.0/24", "10.0.0.0/24", "tcp", 1234, 1234),
    ]
    out = simulate_firewall(rules, "deny", [
        tcp_event(0, "10.0.0.1", 1234, "10.0.1.1", 80),
        tcp_event(31, "10.0.1.1", 80, "10.0.0.1", 1234),  # expires_at=30 已过
    ])
    assert out["results"][1]["session_state"] == "new"
    assert out["results"][1]["rule_index"] == 1
    assert out["results"][1]["session"]["key"] == (
        "tcp 10.0.1.1:80 -> 10.0.0.1:1234"
    )
    assert out["summary"]["sessions_new"] == 2
    assert out["summary"]["sessions_expired"] == 1


def test_deny_does_not_create_session_and_reverse_rematched():
    out = simulate([
        tcp_event(0, "8.8.8.8", 1, "9.9.9.9", 1),    # deny-all
        tcp_event(1, "9.9.9.9", 1, "8.8.8.8", 1),    # 无会话可命中 -> deny-all
    ])
    assert [r["action"] for r in out["results"]] == ["deny", "deny"]
    assert [r["session_state"] for r in out["results"]] == ["none", "none"]
    assert out["summary"]["sessions_new"] == 0


def test_default_allow_does_not_create_session():
    rules = [TCP_RULE_ALLOW]
    out = simulate_firewall(rules, "allow", [
        tcp_event(0, "8.8.8.8", 1, "9.9.9.9", 1),    # 默认 allow
        tcp_event(1, "9.9.9.9", 1, "8.8.8.8", 1),    # 反向但无会话 -> 再走默认 allow
    ])
    assert [r["decision"] for r in out["results"]] == ["default", "default"]
    assert out["summary"]["sessions_new"] == 0


def test_forward_packet_during_live_session_is_not_stateful():
    # 同方向重复正向包在存活期内不走 stateful：再次命中 allow => 重叠会话键
    with pytest.raises(DuplicateSessionKeyError) as excinfo:
        simulate([
            tcp_event(1, "10.0.0.1", 1234, "10.0.1.1", 80),
            tcp_event(2, "10.0.0.1", 1234, "10.0.1.1", 80),
        ])
    conflict = excinfo.value.conflicts[0]
    assert conflict["index"] == 1
    assert conflict["rule_index"] == 0
    assert conflict["key"] == "tcp 10.0.0.1:1234 -> 10.0.1.1:80"
    assert conflict["existing"]["created_at"] == 1
    assert conflict["existing"]["established_by_event"] == 0


def test_forward_reallow_after_expiry_rebuilds_session():
    out = simulate([
        tcp_event(1, "10.0.0.1", 1234, "10.0.1.1", 80),
        tcp_event(32, "10.0.0.1", 1234, "10.0.1.1", 80),  # 过期正向重建
    ])
    assert out["results"][1]["session_state"] == "new"
    assert out["results"][1]["expired_sessions"][0]["expires_at"] == 31
    assert out["summary"]["sessions_new"] == 2
    assert out["summary"]["sessions_expired"] == 1
    assert out["summary"]["active_sessions"] == 1


def test_independent_sessions_can_coexist():
    out = simulate([
        tcp_event(0, "10.0.0.1", 1111, "10.0.1.1", 80),
        tcp_event(1, "10.0.0.2", 2222, "10.0.1.1", 80),
        tcp_event(2, "10.0.1.1", 80, "10.0.0.1", 1111),
        tcp_event(3, "10.0.1.1", 80, "10.0.0.2", 2222),
    ])
    assert [r["session_state"] for r in out["results"]] == [
        "new", "new", "established", "established"
    ]
    assert out["summary"]["active_sessions"] == 2


def test_active_sessions_excludes_expired_at_last_event_time():
    out = simulate([
        tcp_event(0, "10.0.0.1", 1, "10.0.1.1", 80),    # expires 30
        tcp_event(100, "10.0.0.2", 2, "10.0.1.1", 80),  # expires 130, active
    ])
    # 第一个会话未被任何后续事件碰到：不计 expired，但在 t=100 已不存活
    assert out["summary"]["sessions_expired"] == 0
    assert out["summary"]["active_sessions"] == 1


def test_counts_invariant_allow_plus_deny_equals_events():
    out = simulate([
        tcp_event(0, "10.0.0.1", 1, "10.0.1.1", 80),
        tcp_event(1, "10.0.1.1", 80, "10.0.0.1", 1),
        tcp_event(2, "8.8.8.8", 1, "9.9.9.9", 1),
        tcp_event(40, "10.0.1.1", 80, "10.0.0.1", 1),
    ])
    summary = out["summary"]
    assert summary["allow"] + summary["deny"] == out["event_count"]


# ---------- 时间顺序校验 ----------

def test_equal_timestamps_allowed():
    out = simulate([
        tcp_event(5, "10.0.0.1", 1, "10.0.1.1", 80),
        tcp_event(5, "10.0.0.2", 2, "10.0.1.1", 80),
    ])
    assert out["event_count"] == 2


def test_time_out_of_order_reports_all_violations():
    with pytest.raises(FirewallTimeOrderError) as excinfo:
        simulate([
            tcp_event(5, "10.0.0.1", 1, "10.0.1.1", 80),
            tcp_event(4, "10.0.0.1", 1, "10.0.1.1", 80),
            tcp_event(4, "10.0.0.1", 1, "10.0.1.1", 80),
            tcp_event(3, "10.0.0.1", 1, "10.0.1.1", 80),
        ])
    assert excinfo.value.violations == [
        {"index": 1, "time": 4, "previous_index": 0, "previous_time": 5},
        {"index": 3, "time": 3, "previous_index": 2, "previous_time": 4},
    ]


def test_negative_or_non_integer_time_rejected():
    with pytest.raises(ValueError):
        simulate([tcp_event(-1, "10.0.0.1", 1, "10.0.1.1", 80)])
    with pytest.raises(ValueError):
        simulate_firewall(
            [TCP_RULE_ALLOW], "deny",
            [(1.5, "10.0.0.1", 1, "10.0.1.1", 80, "tcp")],
        )


# ---------- 输入校验 ----------

def test_invalid_cidr_and_address_rejected():
    with pytest.raises(InvalidCIDRError):
        simulate_firewall(
            [("allow", "10.0.0.0/33", "0.0.0.0/0", "tcp", 0, 65535)],
            "deny", [tcp_event(0, "10.0.0.1", 1, "8.8.8.8", 8)],
        )
    with pytest.raises(InvalidIPv4AddressError):
        simulate([tcp_event(0, "8.8.8.8/32", 1, "9.9.9.9", 1)])
    with pytest.raises(InvalidIPv4AddressError):
        simulate([tcp_event(0, "2001:db8::1", 1, "9.9.9.9", 1)])


def test_rule_port_range_validated():
    with pytest.raises(InvalidPortError):
        simulate_firewall(
            [("allow", "0.0.0.0/0", "0.0.0.0/0", "tcp", 100, 50)],
            "deny", [tcp_event(0, "1.1.1.1", 1, "2.2.2.2", 80)],
        )
    with pytest.raises(InvalidPortError):
        simulate_firewall(
            [("allow", "0.0.0.0/0", "0.0.0.0/0", "icmp", 0, 0)],
            "deny", [icmp_event(0, "1.1.1.1", "2.2.2.2")],
        )


def test_event_protocol_port_combination_validated():
    with pytest.raises(InvalidPortError):
        simulate_firewall(
            [TCP_RULE_ALLOW], "deny",
            [(0, "10.0.0.1", 0, "10.0.1.1", None, "icmp")],
        )


def test_rule_and_event_limits():
    too_many_rules = [
        ("allow", "0.0.0.0/0", "0.0.0.0/0", "tcp", 0, 65535)
        for _ in range(FIREWALL_RULES_MAX + 1)
    ]
    with pytest.raises(ValueError):
        simulate_firewall(
            too_many_rules, "deny", [tcp_event(0, "1.1.1.1", 1, "2.2.2.2", 1)]
        )
    with pytest.raises(ValueError):
        simulate_firewall([], "deny", [])
    too_many_events = [
        tcp_event(i, "1.1.1.1", 1, "2.2.2.2", 1)
        for i in range(FIREWALL_EVENTS_MAX + 1)
    ]
    with pytest.raises(ValueError):
        simulate_firewall([], "deny", too_many_events)


def test_response_echoes_normalized_inputs():
    out = simulate([
        tcp_event(7, " 10.0.0.1 ", 1234, "10.0.1.1", 80),
    ])
    item = out["results"][0]
    assert item["src_ip"] == "10.0.0.1"
    assert item["dst_ip"] == "10.0.1.1"
    assert item["index"] == 0 and item["time"] == 7
    assert out["rule_count"] == 2
    assert out["event_count"] == 1
    assert out["session_timeout"] == 30


# ---------- 随机属性测试：逐事件不变量 ----------

def test_randomized_event_invariants():
    import random

    rng = random.Random(20260918)
    rule = ("allow", "10.0.0.0/24", "10.0.1.0/24", "tcp", 0, 65535)
    for _ in range(200):
        timeout = rng.randint(1, 10)
        n = rng.randint(1, 40)
        t = 0
        events = []
        for _ in range(n):
            t += rng.choice([0, 0, 1, 3])  # 非严格递增
            reverse = rng.random() < 0.5
            if reverse:
                src, sp, dst, dp = "10.0.1.1", 80, "10.0.0.1", 1234
            else:
                src, sp, dst, dp = "10.0.0.1", 1234, "10.0.1.1", 80
            if rng.random() < 0.2:
                src = f"8.8.{rng.randint(0, 8)}.{rng.randint(1, 254)}"
            events.append(tcp_event(t, src, sp, dst, dp))
        try:
            out = simulate_firewall([rule], "deny", events, timeout)
        except DuplicateSessionKeyError:
            # 同方向存活重建是合法的拒绝路径，跳过不变量检查
            continue

        results = out["results"]
        assert len(results) == n
        summary = out["summary"]
        assert summary["allow"] + summary["deny"] == n
        assert summary["sessions_new"] == sum(
            r["session_state"] == "new" for r in results
        )
        assert summary["sessions_expired"] == sum(
            len(r["expired_sessions"]) for r in results
        )

        # 独立的“规则判定”参照（stateful 除外）
        def brute_rule(ev):
            _, src, _, dst, dp, proto = ev
            return (
                proto == "tcp"
                and src.startswith("10.0.0.")
                and dst.startswith("10.0.1.")
                and 0 <= dp <= 65535
            )

        for ev, result in zip(events, results):
            # 过期清除必然发生在 expires_at < time 之后
            for stale in result["expired_sessions"]:
                assert stale["expires_at"] < result["time"]
            if result["decision"] == "stateful":
                assert result["action"] == "allow"
                assert result["direction"] == "reverse"
                assert result["session_state"] == "established"
                assert result["session"]["expires_at"] >= result["time"]
            elif result["decision"] == "rule":
                # simulate 的第二条 deny-all 命中所有 tcp 包
                assert brute_rule(ev) or ev[5] == "tcp"
                if result["action"] == "allow":
                    assert result["session_state"] == "new"
                    assert brute_rule(ev)
                else:
                    assert result["session_state"] in ("expired", "none")
                    assert not brute_rule(ev)
            else:
                assert result["decision"] == "default"
                assert result["action"] == "deny"
                assert result["session"] is None

        # active_sessions：独立复算（按最后事件时间）
        live = {}
        for result in results:
            for stale in result["expired_sessions"]:
                live.pop(stale["key"], None)
            if result["session_state"] == "new":
                s = result["session"]
                live[s["key"]] = s["expires_at"]
        last_time = events[-1][0]
        expected_active = sum(exp >= last_time for exp in live.values())
        assert summary["active_sessions"] == expected_active
