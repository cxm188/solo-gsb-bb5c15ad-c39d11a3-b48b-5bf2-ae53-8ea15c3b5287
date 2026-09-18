"""有状态 IPv4 防火墙模拟核心逻辑（纯标准库实现，无 Web 依赖）。

输入由两部分组成：

1. **有序规则** ``(action, src_cidr, dst_cidr, protocol, port_min, port_max)``：
   按输入顺序逐条匹配，**首条命中规则生效**；均未命中时走
   ``default_action``。``tcp`` / ``udp`` 规则带目的端口闭区间，``icmp``
   规则没有端口概念（``port_min`` / ``port_max`` 为 ``None``）。
2. **按时间非严格递增排序的数据包事件**
   ``(time, src_ip, src_port, dst_ip, dst_port, protocol)``。

会话语义：

- 首个**正向**命中 allow 规则的数据包以其五元组建立会话；
- 后续**反向**包（源/目的地址与端口整体交换、协议相同）若在会话存活时间
  （``created_at + session_timeout``）内到达，则跳过规则匹配直接放行
  （``stateful``），并刷新 ``last_seen_at``；
- 反向包到达时会话已超时，则先清除该过期会话（计入 ``sessions_expired``），
  **重新走规则匹配**：若再次命中 allow 则按新方向建立新会话，否则按规则 /
  默认动作处理；
- 存活期间的同方向（正向）包**不**享受状态化放行，仍走规则匹配；若它再次
  命中 allow 并试图为一个**仍存活**的五元组建立会话，则该请求存在重叠会话
  键，抛出 :class:`DuplicateSessionKeyError`（超时后的同五元组允许重建）。

会话过期计数采用**惰性**策略：只有当某事件实际碰到已过期的会话（反向或
同方向复用）时，该会话才在该事件上被清除并计数一次；请求结束时仍未再出现
的会话不计入 ``sessions_expired``，但会体现在最终的 ``active_sessions``
之中。时间单位由调用方约定（API 使用秒），全程为整数运算。
"""
from __future__ import annotations

from typing import Sequence

from .analyzer import ALLOW, DENY, InvalidCIDRError, normalize_action, parse_cidr_v4
from .router import InvalidIPv4AddressError, parse_address_v4

#: 单次请求允许的规则条数上限（允许 0 条，此时全部走默认动作）
FIREWALL_RULES_MAX = 500

#: 单次请求允许的事件数区间
FIREWALL_EVENTS_MIN = 1
FIREWALL_EVENTS_MAX = 2000

#: 端口取值范围
PORT_MIN = 0
PORT_MAX = 65535

#: 会话存活时间（API 约定单位：秒）
DEFAULT_SESSION_TIMEOUT = 30
SESSION_TIMEOUT_MIN = 1
SESSION_TIMEOUT_MAX = 86400

TCP = "tcp"
UDP = "udp"
ICMP = "icmp"
PROTOCOLS = (TCP, UDP, ICMP)

#: 事件裁决来源：命中规则 / 默认动作 / 状态化放行
FROM_RULE = "rule"
FROM_DEFAULT = "default"
FROM_STATEFUL = "stateful"

#: 包方向（相对已建立会话的正向五元组）
FORWARD = "forward"
REVERSE = "reverse"

#: 事件处理后的会话状态
SESSION_NEW = "new"
SESSION_ESTABLISHED = "established"
SESSION_EXPIRED = "expired"
SESSION_NONE = "none"


class InvalidPortError(ValueError):
    """端口不是 0～65535 的整数，或协议与端口组合不合法。"""


class InvalidProtocolError(ValueError):
    """协议不是 tcp / udp / icmp。"""


class FirewallTimeOrderError(ValueError):
    """事件时间不是非严格递增（出现逆序）。

    ``violations`` 给出全部逆序位置，每条形如
    ``{"index": i, "time": t_i, "previous_index": i-1,
    "previous_time": t_{i-1}}``。
    """

    def __init__(self, violations: list[dict]) -> None:
        self.violations = violations
        super().__init__(f"{len(violations)} 处事件时间逆序")


class DuplicateSessionKeyError(ValueError):
    """试图为一个仍存活的五元组重复建立会话（重叠会话键）。

    ``conflicts`` 给出全部冲突（模拟在首个冲突处中止，故通常为 1 条），
    每条形如 ``{"index", "key", "rule_index", "existing"}``，其中
    ``existing`` 描述仍存活的旧会话（``rule_index`` / ``created_at`` /
    ``established_by_event``）。
    """

    def __init__(self, conflicts: list[dict]) -> None:
        self.conflicts = conflicts
        super().__init__(f"{len(conflicts)} 处重叠会话键")


def normalize_protocol(protocol: object) -> str:
    """规范化协议：去空白、转小写；非 tcp/udp/icmp 抛出 ValueError。"""
    if not isinstance(protocol, str):
        raise InvalidProtocolError(f"非法 protocol: {protocol!r}")
    normalized = protocol.strip().lower()
    if normalized not in PROTOCOLS:
        raise InvalidProtocolError(f"非法 protocol: {protocol!r}")
    return normalized


def normalize_port(port: object, *, field: str = "port") -> int:
    """校验端口：非 bool 整数且在 0～65535 之间。"""
    if isinstance(port, bool) or not isinstance(port, int):
        raise InvalidPortError(f"{field} 必须是 {PORT_MIN}～{PORT_MAX} 的整数: {port!r}")
    if not PORT_MIN <= port <= PORT_MAX:
        raise InvalidPortError(
            f"{field} 必须在 {PORT_MIN}～{PORT_MAX} 之间，实际 {port}"
        )
    return port


def normalize_session_timeout(timeout: object) -> int:
    """校验会话存活时间：非 bool 正整数且不超过 :data:`SESSION_TIMEOUT_MAX`。"""
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise ValueError(
            f"session_timeout 必须是 {SESSION_TIMEOUT_MIN}～"
            f"{SESSION_TIMEOUT_MAX} 的整数: {timeout!r}"
        )
    if not SESSION_TIMEOUT_MIN <= timeout <= SESSION_TIMEOUT_MAX:
        raise ValueError(
            f"session_timeout 必须在 {SESSION_TIMEOUT_MIN}～"
            f"{SESSION_TIMEOUT_MAX} 之间，实际 {timeout}"
        )
    return timeout


def validate_port_protocol(
    protocol: str,
    src_port: object,
    dst_port: object,
) -> tuple[int | None, int | None]:
    """按协议校验端口组合，返回 ``(src_port, dst_port)``。

    tcp / udp 必须同时给出 0～65535 的整数端口；icmp 不允许端口，
    二者必须均为 ``None``。
    """
    if protocol == ICMP:
        if src_port is not None or dst_port is not None:
            raise InvalidPortError("icmp 事件/规则不允许携带端口")
        return None, None
    return (
        normalize_port(src_port, field="src_port"),
        normalize_port(dst_port, field="dst_port"),
    )


def five_tuple_key(
    protocol: str,
    src_ip: int,
    src_port: int | None,
    dst_ip: int,
    dst_port: int | None,
) -> tuple:
    """构造有向五元组键：``(protocol, src_ip, src_port, dst_ip, dst_port)``。"""
    return (protocol, src_ip, src_port, dst_ip, dst_port)


def reverse_key(key: tuple) -> tuple:
    """交换源 / 目的（地址与端口），协议不变。"""
    protocol, src_ip, src_port, dst_ip, dst_port = key
    return (protocol, dst_ip, dst_port, src_ip, src_port)


def format_five_tuple(
    protocol: str,
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
) -> str:
    """把五元组格式化为稳定的人类可读字符串（icmp 省略端口）。"""
    if protocol == ICMP:
        return f"{protocol} {src_ip} -> {dst_ip}"
    return f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"


def _validate_time_order(times: Sequence[int]) -> None:
    """检查事件时间非严格递增，收集全部逆序位置后一次性抛出。"""
    violations = [
        {
            "index": index,
            "time": times[index],
            "previous_index": index - 1,
            "previous_time": times[index - 1],
        }
        for index in range(1, len(times))
        if times[index] < times[index - 1]
    ]
    if violations:
        raise FirewallTimeOrderError(violations)


def _parse_rules(rules: Sequence[tuple]) -> list[dict]:
    """校验并解析有序规则列表（保持输入顺序）。"""
    if not 0 <= len(rules) <= FIREWALL_RULES_MAX:
        raise ValueError(
            f"规则数必须在 0～{FIREWALL_RULES_MAX} 之间，实际 {len(rules)}"
        )
    parsed: list[dict] = []
    for index, (action, src_cidr, dst_cidr, protocol, port_min, port_max) in enumerate(
        rules
    ):
        action = normalize_action(action)
        protocol = normalize_protocol(protocol)
        src_start, src_end, src_text = parse_cidr_v4(src_cidr)
        dst_start, dst_end, dst_text = parse_cidr_v4(dst_cidr)
        if protocol == ICMP:
            if port_min is not None or port_max is not None:
                raise InvalidPortError("icmp 规则不允许携带端口范围")
            low: int | None = None
            high: int | None = None
        else:
            low = normalize_port(port_min, field="port_min")
            high = normalize_port(port_max, field="port_max")
            if low > high:
                raise InvalidPortError(
                    f"port_min 不能大于 port_max：{low} > {high}（规则 {index}）"
                )
        parsed.append(
            {
                "index": index,
                "action": action,
                "protocol": protocol,
                "src_start": src_start,
                "src_end": src_end,
                "src_cidr": src_text,
                "dst_start": dst_start,
                "dst_end": dst_end,
                "dst_cidr": dst_text,
                "port_min": low,
                "port_max": high,
            }
        )
    return parsed


def _parse_events(events: Sequence[tuple]) -> list[dict]:
    """校验并解析事件列表（保持输入顺序），并检查时间非严格递增。"""
    if not FIREWALL_EVENTS_MIN <= len(events) <= FIREWALL_EVENTS_MAX:
        raise ValueError(
            f"事件数必须在 {FIREWALL_EVENTS_MIN}～{FIREWALL_EVENTS_MAX} 之间，"
            f"实际 {len(events)}"
        )
    parsed: list[dict] = []
    times: list[int] = []
    for index, (time, src_ip, src_port, dst_ip, dst_port, protocol) in enumerate(
        events
    ):
        if isinstance(time, bool) or not isinstance(time, int):
            raise ValueError(f"事件 time 必须是非负整数: {time!r}（事件 {index}）")
        if time < 0:
            raise ValueError(f"事件 time 不能为负数: {time}（事件 {index}）")
        protocol = normalize_protocol(protocol)
        src_value, src_text = parse_address_v4(src_ip)
        dst_value, dst_text = parse_address_v4(dst_ip)
        src_port, dst_port = validate_port_protocol(protocol, src_port, dst_port)
        parsed.append(
            {
                "index": index,
                "time": time,
                "protocol": protocol,
                "src_value": src_value,
                "src_text": src_text,
                "src_port": src_port,
                "dst_value": dst_value,
                "dst_text": dst_text,
                "dst_port": dst_port,
            }
        )
        times.append(time)
    _validate_time_order(times)
    return parsed


def _match_rule(parsed_rules: Sequence[dict], event: dict) -> dict | None:
    """按顺序返回首条命中事件的规则（五元组；端口仅匹配目的端口）。"""
    for rule in parsed_rules:
        if rule["protocol"] != event["protocol"]:
            continue
        if not (
            rule["src_start"] <= event["src_value"] <= rule["src_end"]
            and rule["dst_start"] <= event["dst_value"] <= rule["dst_end"]
        ):
            continue
        if rule["protocol"] != ICMP and not (
            rule["port_min"] <= event["dst_port"] <= rule["port_max"]
        ):
            continue
        return rule
    return None


def _stale_summary(session: dict) -> dict:
    """已清除的过期会话摘要（挂到触发清除的事件结果上）。"""
    return {
        "key": session["key_text"],
        "rule_index": session["rule_index"],
        "created_at": session["created_at"],
        "last_seen_at": session["last_seen_at"],
        "expires_at": session["expires_at"],
        "established_by_event": session["established_by_event"],
    }


def _session_descriptor(session: dict, now: int) -> dict:
    """事件命中 / 新建会话的会话描述。"""
    return {
        "key": session["key_text"],
        "rule_index": session["rule_index"],
        "created_at": session["created_at"],
        "last_seen_at": session["last_seen_at"],
        "expires_at": session["expires_at"],
        "age": now - session["created_at"],
        "established_by_event": session["established_by_event"],
    }


def simulate_firewall(
    rules: Sequence[tuple],
    default_action: str,
    events: Sequence[tuple],
    session_timeout: int = DEFAULT_SESSION_TIMEOUT,
) -> dict:
    """模拟有序规则 + 有状态会话对一串数据包事件的逐条裁决。

    ``rules`` 每项为
    ``(action, src_cidr, dst_cidr, protocol, port_min, port_max)``，
    允许为空（此时全部走默认动作）；tcp/udp 的 ``port_min`` / ``port_max``
    为目的端口闭区间，icmp 二者传 ``None``。``events`` 每项为
    ``(time, src_ip, src_port, dst_ip, dst_port, protocol)``，time 必须
    非严格递增（相等时间戳合法），icmp 的两个端口传 ``None``。

    返回可直接 JSON 序列化的字典：``results`` 严格保持事件输入顺序，每项
    给出裁决来源（``rule`` / ``default`` / ``stateful``）、命中规则索引、
    最终动作、包方向（``forward`` / ``reverse``）、会话状态
    （``new`` / ``established`` / ``expired`` / ``none``）、会话描述与本事件
    清除的过期会话；``summary`` 汇总放行 / 拒绝 / 新建 / 过期数量以及请求
    结束时仍存活的会话数。

    时间逆序抛出 :class:`FirewallTimeOrderError`（一次性列出全部逆序位置）；
    存活五元组重复建会话抛出 :class:`DuplicateSessionKeyError`；非法 CIDR /
    地址 / 端口 / 协议抛出对应 ValueError 子类。
    """
    default_action = normalize_action(default_action)
    session_timeout = normalize_session_timeout(session_timeout)
    parsed_rules = _parse_rules(rules)
    parsed_events = _parse_events(events)

    # 以“正向有向五元组”为键的会话表（dict 同时承担存活顺序记录）
    sessions: dict[tuple, dict] = {}

    counts = {
        ALLOW: 0,
        DENY: 0,
        "sessions_new": 0,
        "sessions_expired": 0,
    }
    results: list[dict] = []

    for event in parsed_events:
        fwd_key = five_tuple_key(
            event["protocol"],
            event["src_value"],
            event["src_port"],
            event["dst_value"],
            event["dst_port"],
        )
        now = event["time"]
        expired_this_event: list[dict] = []

        # 1) 反向会话命中：存活则 stateful 放行；过期则清除并重新走规则
        reverse_session = sessions.get(reverse_key(fwd_key))
        if reverse_session is not None and now <= reverse_session["expires_at"]:
            reverse_session["last_seen_at"] = now
            counts[ALLOW] += 1
            results.append(
                {
                    **_event_common(event),
                    "decision": FROM_STATEFUL,
                    "rule_index": reverse_session["rule_index"],
                    "action": ALLOW,
                    "direction": REVERSE,
                    "session_state": SESSION_ESTABLISHED,
                    "session": _session_descriptor(reverse_session, now),
                    "expired_sessions": [],
                }
            )
            continue

        if reverse_session is not None:
            # 反向键上的会话已超时：清除后重新走规则匹配
            del sessions[reverse_key(fwd_key)]
            expired_this_event.append(_stale_summary(reverse_session))
            counts["sessions_expired"] += 1

        # 2) 正向包：严格按有序规则首条匹配
        rule = _match_rule(parsed_rules, event)
        if rule is not None:
            decision = FROM_RULE
            rule_index = rule["index"]
            action = rule["action"]
        else:
            decision = FROM_DEFAULT
            rule_index = None
            action = default_action

        session_state = SESSION_EXPIRED if expired_this_event else SESSION_NONE
        session_descriptor = None

        if action == ALLOW and decision == FROM_RULE:
            # 3) 正向 allow：同方向旧会话存活 => 重叠会话键（422）；
            #    已过期则惰性清除并允许以新规则重建
            existing = sessions.get(fwd_key)
            if existing is not None:
                if now <= existing["expires_at"]:
                    raise DuplicateSessionKeyError(
                        [
                            {
                                "index": event["index"],
                                "key": existing["key_text"],
                                "rule_index": rule_index,
                                "existing": {
                                    "rule_index": existing["rule_index"],
                                    "created_at": existing["created_at"],
                                    "last_seen_at": existing["last_seen_at"],
                                    "established_by_event": existing[
                                        "established_by_event"
                                    ],
                                },
                            }
                        ]
                    )
                del sessions[fwd_key]
                expired_this_event.append(_stale_summary(existing))
                counts["sessions_expired"] += 1

            new_session = {
                "key": fwd_key,
                "key_text": format_five_tuple(
                    event["protocol"],
                    event["src_text"],
                    event["src_port"],
                    event["dst_text"],
                    event["dst_port"],
                ),
                "rule_index": rule_index,
                "created_at": now,
                "last_seen_at": now,
                "expires_at": now + session_timeout,
                "established_by_event": event["index"],
            }
            sessions[fwd_key] = new_session
            counts["sessions_new"] += 1
            session_state = SESSION_NEW
            session_descriptor = _session_descriptor(new_session, now)

        counts[action] += 1
        results.append(
            {
                **_event_common(event),
                "decision": decision,
                "rule_index": rule_index,
                "action": action,
                "direction": FORWARD,
                "session_state": session_state,
                "session": session_descriptor,
                "expired_sessions": expired_this_event,
            }
        )

    active_sessions = sum(
        1
        for session in sessions.values()
        if session["expires_at"] >= parsed_events[-1]["time"]
    )

    return {
        "rule_count": len(parsed_rules),
        "event_count": len(parsed_events),
        "session_timeout": session_timeout,
        "default_action": default_action,
        "results": results,
        "summary": {
            ALLOW: counts[ALLOW],
            DENY: counts[DENY],
            "sessions_new": counts["sessions_new"],
            "sessions_expired": counts["sessions_expired"],
            "active_sessions": active_sessions,
        },
    }


def _event_common(event: dict) -> dict:
    """事件结果中回显输入的公共字段（地址规范化，保持输入顺序）。"""
    return {
        "index": event["index"],
        "time": event["time"],
        "src_ip": event["src_text"],
        "src_port": event["src_port"],
        "dst_ip": event["dst_text"],
        "dst_port": event["dst_port"],
        "protocol": event["protocol"],
    }
