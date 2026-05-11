from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .validation import ForwardRuleInput


class IptablesError(RuntimeError):
    pass


@dataclass(frozen=True)
class ParsedRule:
    key: str
    table: str
    chain: str
    protocol: str | None
    source_ip: str | None
    destination_ip: str | None
    source_port: str | None
    destination_port: str | None
    target: str | None
    forwarded_ip: str | None
    forwarded_port: str | None
    packets: int
    bytes: int
    raw: str
    rule_type: str
    direction: str
    managed: bool
    status: str
    bytes_per_second: float = 0.0
    packets_per_second: float = 0.0


class Iptables:
    def __init__(self, iptables: str, save: str, restore: str) -> None:
        self.iptables = iptables
        self.save = save
        self.restore = restore

    def _run(self, argv: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                argv,
                input=input_text,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise IptablesError(str(exc)) from exc

    def save_rules(self) -> str:
        proc = self._run([self.save, "-c"])
        if proc.returncode != 0:
            raise IptablesError(proc.stderr.strip() or "iptables-save failed")
        return proc.stdout

    def validate_restore(self, content: str) -> None:
        proc = self._run([self.restore, "--test"], content)
        if proc.returncode != 0:
            raise IptablesError(proc.stderr.strip() or "iptables-restore validation failed")

    def apply_restore(self, content: str) -> None:
        proc = self._run([self.restore], content)
        if proc.returncode != 0:
            raise IptablesError(proc.stderr.strip() or "iptables-restore apply failed")

    def current_with_managed_rule(self, rule: ForwardRuleInput) -> str:
        current = self.save_rules()
        lines = current.splitlines()
        nat_commit = _find_commit(lines, "nat")
        filter_commit = _find_commit(lines, "filter")
        if nat_commit is None or filter_commit is None:
            raise IptablesError("iptables-save output is missing nat or filter table")

        marker = _managed_marker(rule)
        dnat = _dnat_line(rule, marker)
        forward = _forward_line(rule, marker)
        if dnat in lines or forward in lines:
            raise IptablesError("an identical managed rule already exists")

        lines.insert(nat_commit, dnat)
        if filter_commit > nat_commit:
            filter_commit += 1
        lines.insert(filter_commit, forward)
        return "\n".join(lines) + "\n"


def parse_rules(save_output: str, managed_rules: list[dict]) -> list[ParsedRule]:
    managed_targets = {
        (m["protocol"], str(m["external_port"]), m["source_cidr"] or None): m for m in managed_rules
    }
    table = "filter"
    parsed: list[ParsedRule] = []
    for line in save_output.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            continue
        if not line.startswith("[") and " -A " not in line and not line.startswith("-A "):
            continue
        rule = _parse_rule_line(table, line, managed_targets)
        if rule:
            parsed.append(rule)
    return parsed


def enrich_rates(db, rules: list[ParsedRule]) -> list[ParsedRule]:
    now = time.time()
    enriched: list[ParsedRule] = []
    with db.connect() as conn:
        for rule in rules:
            row = conn.execute(
                "SELECT packets, bytes, seen_at FROM counter_snapshots WHERE rule_key = ?",
                (rule.key,),
            ).fetchone()
            bps = pps = 0.0
            if row:
                elapsed = max(now - float(row["seen_at"]), 0.001)
                bps = max(rule.bytes - int(row["bytes"]), 0) / elapsed
                pps = max(rule.packets - int(row["packets"]), 0) / elapsed
            conn.execute(
                """
                INSERT INTO counter_snapshots(rule_key, packets, bytes, bytes_per_second, packets_per_second, seen_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(rule_key) DO UPDATE SET
                    packets = excluded.packets,
                    bytes = excluded.bytes,
                    bytes_per_second = excluded.bytes_per_second,
                    packets_per_second = excluded.packets_per_second,
                    seen_at = excluded.seen_at
                """,
                (rule.key, rule.packets, rule.bytes, bps, pps, now),
            )
            enriched.append(
                ParsedRule(
                    **{**rule.__dict__, "bytes_per_second": bps, "packets_per_second": pps}
                )
            )
    return enriched


def _find_commit(lines: list[str], table: str) -> int | None:
    in_table = False
    for idx, line in enumerate(lines):
        if line == f"*{table}":
            in_table = True
        elif in_table and line == "COMMIT":
            return idx
    return None


def _managed_marker(rule: ForwardRuleInput) -> str:
    digest = hashlib.sha256(
        json.dumps(rule.__dict__, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return f"iptfw:{digest}"


def _dnat_line(rule: ForwardRuleInput, marker: str) -> str:
    parts = ["-A", "PREROUTING", "-p", rule.protocol]
    if rule.source_cidr:
        parts.extend(["-s", rule.source_cidr])
    parts.extend([
        "--dport",
        str(rule.external_port),
        "-m",
        "comment",
        "--comment",
        marker,
        "-j",
        "DNAT",
        "--to-destination",
        f"{rule.internal_ip}:{rule.internal_port}",
    ])
    return shlex.join(parts)


def _forward_line(rule: ForwardRuleInput, marker: str) -> str:
    parts = [
        "-A",
        "FORWARD",
        "-p",
        rule.protocol,
        "-d",
        rule.internal_ip,
        "--dport",
        str(rule.internal_port),
    ]
    if rule.source_cidr:
        parts.extend(["-s", rule.source_cidr])
    parts.extend(["-m", "comment", "--comment", marker, "-j", "ACCEPT"])
    return shlex.join(parts)


def _parse_rule_line(table: str, line: str, managed_targets: dict) -> ParsedRule | None:
    packets = bytes_count = 0
    body = line
    if line.startswith("["):
        counters, _, rest = line.partition(" ")
        p, b = counters.strip("[]").split(":")
        packets, bytes_count = int(p), int(b)
        body = rest
    if not body.startswith("-A "):
        return None

    tokens = shlex.split(body)
    chain = tokens[1]
    values = _scan_tokens(tokens)
    target = values.get("jump")
    forwarded_ip, forwarded_port = _split_host_port(values.get("to_destination"))
    if target in {"SNAT"} and not forwarded_ip:
        forwarded_ip, forwarded_port = _split_host_port(values.get("to_source"))

    rule_type = _classify(table, chain, target)
    managed = bool(values.get("comment", "").startswith("iptfw:"))
    if not managed and table == "nat" and target == "DNAT":
        key = (values.get("protocol"), values.get("destination_port"), values.get("source_ip"))
        managed = key in managed_targets

    direction = chain if chain in {"INPUT", "OUTPUT", "FORWARD"} else table
    key = hashlib.sha256(f"{table}\0{body}".encode("utf-8")).hexdigest()
    return ParsedRule(
        key=key,
        table=table,
        chain=chain,
        protocol=values.get("protocol"),
        source_ip=values.get("source_ip"),
        destination_ip=values.get("destination_ip"),
        source_port=values.get("source_port"),
        destination_port=values.get("destination_port"),
        target=target,
        forwarded_ip=forwarded_ip,
        forwarded_port=forwarded_port,
        packets=packets,
        bytes=bytes_count,
        raw=body,
        rule_type=rule_type,
        direction=direction,
        managed=managed,
        status="active",
    )


def _scan_tokens(tokens: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if token == "-p" and nxt:
            out["protocol"] = nxt
            i += 2
        elif token == "-s" and nxt:
            out["source_ip"] = nxt
            i += 2
        elif token == "-d" and nxt:
            out["destination_ip"] = nxt
            i += 2
        elif token in {"--sport", "--source-port", "--sports"} and nxt:
            out["source_port"] = nxt
            i += 2
        elif token in {"--dport", "--destination-port", "--dports"} and nxt:
            out["destination_port"] = nxt
            i += 2
        elif token == "-j" and nxt:
            out["jump"] = nxt
            i += 2
        elif token == "--to-destination" and nxt:
            out["to_destination"] = nxt
            i += 2
        elif token == "--to-source" and nxt:
            out["to_source"] = nxt
            i += 2
        elif token == "--comment" and nxt:
            out["comment"] = nxt
            i += 2
        else:
            i += 1
    return out


def _split_host_port(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    if ":" in value and not value.startswith("["):
        host, port = value.rsplit(":", 1)
        return host, port
    return value, None


def _classify(table: str, chain: str, target: str | None) -> str:
    if target == "DNAT":
        return "DNAT / port forwarding"
    if target in {"SNAT", "MASQUERADE"}:
        return target
    if target in {"ACCEPT", "DROP", "REJECT"}:
        return target
    if chain in {"INPUT", "OUTPUT", "FORWARD"}:
        return f"{chain} rule"
    return f"{table} rule"
