# iptfw

`iptfw` is a small localhost-only web dashboard for inspecting and managing iptables forwarding/NAT rules on Debian/Ubuntu gateway servers.

## Architecture

- Backend: Python FastAPI, server-rendered Jinja HTML, no frontend build step.
- Database: SQLite in `/var/lib/iptfw/iptfw.sqlite3`.
- Rule inspection: `iptables-save -c` for raw rules and packet/byte counters.
- Rule application: generate a complete candidate ruleset, validate with `iptables-restore --test`, apply with `iptables-restore`.
- Safety path: backup before every change, validate before apply, restore previous live rules if apply fails.
- Binding: service refuses to start unless `IPTFW_BIND_HOST=127.0.0.1`.

Go would use less memory at runtime, but FastAPI keeps this implementation shorter, easier to audit, and still light enough for a localhost admin service. The privileged surface is isolated in `iptfw/iptables.py` and all subprocess calls use argument arrays with `shell=False`.

Future nftables support should be added behind a separate firewall provider interface, for example `FirewallProvider.inspect()`, `validate()`, and `apply()`, with an nft parser using `nft -j list ruleset`. This project intentionally implements iptables first.

## Project Structure

```text
iptfw/
  auth.py          signed local session cookie auth
  backup.py        iptables-save backup and restore handling
  config.py        environment based settings
  db.py            SQLite schema and connection helper
  iptables.py      parser, classifier, counter rates, apply helpers
  main.py          FastAPI routes
  templates/       server-rendered UI
  static/          CSS
systemd/
  iptfw.service
tests/
  test_iptables_parser.py
```

## Database Schema

- `managed_rules`: protocol, external port, internal IP/port, optional source CIDR, name, enabled flag.
- `backups`: backup filename, SHA-256, size, reason, created time.
- `audit_log`: action, actor, details, success flag, created time.
- `counter_snapshots`: last packet/byte counters per parsed rule key and calculated packet/byte rates.

## Rule Detection

The parser reads `iptables-save -c`, tracks the current table, extracts each `-A` rule, and classifies:

- `DNAT` as port forwarding.
- `SNAT` and `MASQUERADE` as source NAT.
- `ACCEPT`, `DROP`, and `REJECT` verdict rules.
- `INPUT`, `OUTPUT`, and `FORWARD` filter chains.
- TCP/UDP protocol, source/destination IP, source/destination ports, forwarded target IP/port, packet count, byte count, and raw rule text.

Rules created by this app include an `iptables` comment marker (`iptfw:<hash>`) and are shown as managed. Other detected rules remain visible and are marked unmanaged.

## Bandwidth Calculation

iptables counters are cumulative. On each dashboard refresh, `iptfw` stores the latest packet and byte count for each stable rule key. Estimated rates are:

```text
bytes_per_second = max(current_bytes - previous_bytes, 0) / elapsed_seconds
packets_per_second = max(current_packets - previous_packets, 0) / elapsed_seconds
```

Counter resets therefore show `0` for that interval instead of negative values.

## Install

```bash
sudo apt-get update
sudo apt-get install -y python3-venv iptables
sudo mkdir -p /opt/iptfw /etc/iptfw /var/lib/iptfw
sudo cp -a . /opt/iptfw/
cd /opt/iptfw
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo install -m 0644 systemd/iptfw.service /etc/systemd/system/iptfw.service
```

Create `/etc/iptfw/iptfw.env`:

```text
IPTFW_ADMIN_PASSWORD=replace-with-a-long-local-admin-password
IPTFW_BIND_HOST=127.0.0.1
IPTFW_BIND_PORT=8088
IPTFW_POLLING_INTERVAL=10
```

Start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now iptfw
```

Open `http://127.0.0.1:8088` from the gateway host, or use SSH port forwarding:

```bash
ssh -L 8088:127.0.0.1:8088 admin@gateway
```

## Development Run

For non-root parser/UI development without touching the real firewall:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
IPTFW_DEV_MODE=1 IPTFW_DATA_DIR=/tmp/iptfw-dev python -m iptfw
```

Real rule inspection and application require root or sufficient `CAP_NET_ADMIN`.

## Add Rule Workflow

1. Validate protocol, external port, internal IP, internal port, source CIDR, and name length.
2. Reject duplicate managed rules.
3. Inspect current iptables rules and reject conflicting DNAT rules for the same protocol/source/external port.
4. Create an `iptables-save` backup.
5. Build a full candidate ruleset by adding DNAT in `nat/PREROUTING` and ACCEPT in `filter/FORWARD`.
6. Validate with `iptables-restore --test`.
7. Apply with `iptables-restore`.
8. Roll back to the previous live ruleset if apply fails.
9. Store the managed rule metadata and audit event.

## Backup and Restore

- Manual backups are available from the UI.
- Every change creates a backup first.
- Restore validates content shape and runs `iptables-restore --test` before applying.
- Restore also creates a fresh rollback backup before applying the selected backup.

## Security Notes

- The service refuses non-local bind addresses.
- Use a strong `IPTFW_ADMIN_PASSWORD`; production startup fails without it.
- Keep the service behind localhost or SSH tunneling only.
- All privileged command execution is centralized in `iptfw/iptables.py`.
- User input is never interpolated into shell strings.
- The systemd unit limits filesystem writes to `/var/lib/iptfw` and bounds capabilities to firewall administration.
- Audit logs record login, backup, restore, and rule changes.
- Managed rule deletion is intentionally not implemented yet, so unmanaged/manual rules are never removed by accident.

## Tests

```bash
pytest
```
