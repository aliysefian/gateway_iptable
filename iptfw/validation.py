from __future__ import annotations

import ipaddress
from dataclasses import dataclass


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ForwardRuleInput:
    name: str | None
    protocol: str
    external_port: int
    internal_ip: str
    internal_port: int
    source_cidr: str | None


def parse_port(value: str, field: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValidationError(f"{field} must be a number") from exc
    if not 1 <= port <= 65535:
        raise ValidationError(f"{field} must be between 1 and 65535")
    return port


def parse_forward_rule(form: dict[str, str]) -> ForwardRuleInput:
    protocol = form.get("protocol", "").strip().lower()
    if protocol not in {"tcp", "udp"}:
        raise ValidationError("protocol must be tcp or udp")

    internal_ip = form.get("internal_ip", "").strip()
    try:
        ipaddress.ip_address(internal_ip)
    except ValueError as exc:
        raise ValidationError("internal destination IP is invalid") from exc

    source_raw = form.get("source_cidr", "").strip()
    source_cidr = None
    if source_raw:
        try:
            source_cidr = str(ipaddress.ip_network(source_raw, strict=False))
        except ValueError as exc:
            raise ValidationError("source allowlist must be a valid IP or CIDR") from exc

    name = form.get("name", "").strip() or None
    if name and len(name) > 80:
        raise ValidationError("description/name must be 80 characters or less")

    return ForwardRuleInput(
        name=name,
        protocol=protocol,
        external_port=parse_port(form.get("external_port", ""), "external port"),
        internal_ip=str(ipaddress.ip_address(internal_ip)),
        internal_port=parse_port(form.get("internal_port", ""), "internal port"),
        source_cidr=source_cidr,
    )
