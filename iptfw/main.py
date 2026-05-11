from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .auth import Auth
from .backup import BackupManager
from .config import settings
from .db import Database
from .iptables import Iptables, IptablesError, enrich_rates, parse_rules
from .validation import ValidationError, parse_forward_rule


logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("iptfw")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

db: Database
auth: Auth
iptables: Iptables
backups: BackupManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, auth, iptables, backups
    if settings.bind_host != "127.0.0.1":
        raise RuntimeError("Refusing to start: IPTFW_BIND_HOST must be 127.0.0.1")
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.db_path)
    auth = Auth(settings.secret_path, settings.admin_password, settings.dev_mode)
    iptables = Iptables(settings.iptables_bin, settings.iptables_save_bin, settings.iptables_restore_bin)
    backups = BackupManager(settings.backup_dir, db, iptables)
    log.info("started", extra={"bind_host": settings.bind_host, "bind_port": settings.bind_port})
    yield
    log.info("stopped")


app = FastAPI(title="iptfw", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str | None = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def login(request: Request):
    form = await _form(request)
    if auth.verify_password(form.get("password", "")):
        _audit("login", "admin", "local login", True)
        return auth.redirect_with_cookie("/", auth.issue_cookie())
    _audit("login", "anonymous", "failed login", False)
    return RedirectResponse("/login?error=invalid", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    actor = auth.actor(request) or "anonymous"
    _audit("logout", actor, "logout", True)
    return auth.logout_response()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    auth.require(request)
    state = _state()
    return templates.TemplateResponse("dashboard.html", {"request": request, **state})


@app.post("/rules")
async def add_rule(request: Request):
    actor = auth.require(request)
    try:
        form = await _form(request)
        rule = parse_forward_rule(form)
        _ensure_no_conflict(rule)
        backup_id = backups.create("before add forwarding rule")
        candidate = iptables.current_with_managed_rule(rule)
        iptables.validate_restore(candidate)
        rollback = iptables.save_rules()
        try:
            iptables.apply_restore(candidate)
        except IptablesError:
            iptables.apply_restore(rollback)
            raise
        with db.connect() as conn:
            conn.execute(
                """
                INSERT INTO managed_rules(name, protocol, external_port, internal_ip, internal_port, source_cidr)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (rule.name, rule.protocol, rule.external_port, rule.internal_ip, rule.internal_port, rule.source_cidr),
            )
        _audit("add_rule", actor, json.dumps({**rule.__dict__, "backup_id": backup_id}), True)
        return RedirectResponse("/?notice=rule-added", status_code=303)
    except (ValidationError, IptablesError, ValueError) as exc:
        _audit("add_rule", actor, str(exc), False)
        state = _state(error=str(exc))
        return templates.TemplateResponse("dashboard.html", {"request": request, **state}, status_code=400)


@app.post("/backups")
async def create_backup(request: Request):
    actor = auth.require(request)
    try:
        backup_id = backups.create("manual backup")
        _audit("backup_create", actor, f"backup_id={backup_id}", True)
        return RedirectResponse("/?notice=backup-created", status_code=303)
    except IptablesError as exc:
        _audit("backup_create", actor, str(exc), False)
        state = _state(error=str(exc))
        return templates.TemplateResponse("dashboard.html", {"request": request, **state}, status_code=500)


@app.get("/backups/{backup_id}", response_class=PlainTextResponse)
async def view_backup(request: Request, backup_id: int):
    auth.require(request)
    try:
        return backups.content(backup_id)
    except (FileNotFoundError, ValueError) as exc:
        return PlainTextResponse(str(exc), status_code=404)


@app.post("/backups/{backup_id}/restore")
async def restore_backup(request: Request, backup_id: int):
    actor = auth.require(request)
    try:
        backups.create("before restore")
        backups.restore(backup_id)
        _audit("backup_restore", actor, f"backup_id={backup_id}", True)
        return RedirectResponse("/?notice=backup-restored", status_code=303)
    except (FileNotFoundError, ValueError, IptablesError) as exc:
        _audit("backup_restore", actor, str(exc), False)
        state = _state(error=str(exc))
        return templates.TemplateResponse("dashboard.html", {"request": request, **state}, status_code=400)


def _state(error: str | None = None) -> dict:
    managed = _managed_rules()
    rules = []
    inspect_error = None
    try:
        rules = enrich_rates(db, parse_rules(iptables.save_rules(), managed))
    except IptablesError as exc:
        inspect_error = str(exc)
    return {
        "error": error or inspect_error,
        "managed_rules": managed,
        "nat_rules": [r for r in rules if r.table == "nat"],
        "filter_rules": [r for r in rules if r.table == "filter"],
        "metrics": _metrics(rules, managed),
        "top_traffic": _top_traffic(rules),
        "flow_rules": _flow_rules(managed),
        "backups": backups.list(),
        "audit": _audit_rows(),
        "polling_interval": settings.polling_interval_seconds,
    }


def _metrics(rules: list, managed: list[dict]) -> dict:
    nat_rules = [r for r in rules if r.table == "nat"]
    filter_rules = [r for r in rules if r.table == "filter"]
    dnat_rules = [r for r in rules if r.target == "DNAT"]
    blocked_rules = [r for r in rules if r.target in {"DROP", "REJECT"}]
    total_bps = sum(r.bytes_per_second for r in rules)
    total_packets = sum(r.packets for r in rules)
    return {
        "managed_count": len(managed),
        "unmanaged_count": len([r for r in rules if not r.managed]),
        "nat_count": len(nat_rules),
        "filter_count": len(filter_rules),
        "dnat_count": len(dnat_rules),
        "blocked_count": len(blocked_rules),
        "total_packets": total_packets,
        "total_bandwidth": _format_rate(total_bps),
    }


def _top_traffic(rules: list) -> list[dict]:
    candidates = sorted(rules, key=lambda r: (r.bytes_per_second, r.bytes), reverse=True)[:8]
    max_bps = max([r.bytes_per_second for r in candidates] or [0.0])
    rows = []
    for rule in candidates:
        label = f"{rule.table}/{rule.chain}"
        if rule.destination_port:
            label = f"{label}:{rule.destination_port}"
        rows.append(
            {
                "label": label,
                "type": rule.rule_type,
                "managed": rule.managed,
                "rate": _format_rate(rule.bytes_per_second),
                "bytes": rule.bytes,
                "width": int((rule.bytes_per_second / max_bps) * 100) if max_bps else 4,
            }
        )
    return rows


def _flow_rules(managed: list[dict]) -> list[dict]:
    return [
        {
            "name": rule["name"] or f"{rule['protocol'].upper()} {rule['external_port']}",
            "protocol": rule["protocol"].upper(),
            "external": rule["external_port"],
            "internal": f"{rule['internal_ip']}:{rule['internal_port']}",
            "source": rule["source_cidr"] or "any source",
        }
        for rule in managed[:6]
    ]


def _format_rate(bytes_per_second: float) -> str:
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    value = float(bytes_per_second)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024


async def _form(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8")
    parsed = parse_qs(body, keep_blank_values=True)
    return {k: v[-1] if v else "" for k, v in parsed.items()}


def _managed_rules() -> list[dict]:
    with db.connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM managed_rules ORDER BY id DESC")]


def _audit_rows() -> list[dict]:
    with db.connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100")]


def _audit(action: str, actor: str, details: str, success: bool) -> None:
    try:
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log(action, actor, details, success) VALUES (?, ?, ?, ?)",
                (action, actor, details[:4000], 1 if success else 0),
            )
    except Exception:
        log.exception("failed to write audit log")


def _ensure_no_conflict(rule) -> None:
    with db.connect() as conn:
        row = conn.execute(
            """
            SELECT id FROM managed_rules
            WHERE protocol = ? AND external_port = ? AND COALESCE(source_cidr, '') = COALESCE(?, '')
            """,
            (rule.protocol, rule.external_port, rule.source_cidr),
        ).fetchone()
        if row:
            raise ValidationError("a managed rule already uses this protocol/source/external port")

    current = parse_rules(iptables.save_rules(), _managed_rules())
    for existing in current:
        if (
            existing.table == "nat"
            and existing.target == "DNAT"
            and existing.protocol == rule.protocol
            and existing.destination_port == str(rule.external_port)
            and (existing.source_ip or None) == rule.source_cidr
        ):
            raise ValidationError("an existing DNAT rule already uses this protocol/source/external port")
