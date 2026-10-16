# SentinelBoard

A lightweight SIEM built from scratch and running in production on a single
Linux host. It collects logs from `auth.log`, nginx and syslog/UFW, normalizes
them into one event schema, correlates them with Sigma-format rules, and runs a
second detection layer based on statistical and ML anomaly scoring.

Live at **siem.ysnemre.com** (behind HTTP Basic Auth — not publicly browsable).

~6,800 lines of Python · 103 automated tests · 6 detection rules · deployed as
five independent systemd services.

---

## Why it looks the way it does

This was not built to a specification. It was built against one real,
internet-facing host and changed whenever that host proved a design wrong. Most
of what follows exists because something failed first — the
[engineering decisions](#engineering-decisions-from-production) section records
those failures rather than hiding them, because they are the part worth reading.

---

## Architecture

```
/var/log/auth.log        /var/log/nginx/access.log        /var/log/syslog
        │                          │                            │
        └──────────────┬───────────┴────────────────────────────┘
                       ▼
              ┌──────────────────┐
              │    collector     │  inode-based tailing, survives logrotate
              └────────┬─────────┘  per-source ignore patterns
                       ▼
              ┌──────────────────┐
              │  Redis Streams   │  decouples collection from processing
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │      parser      │  raw line → common event schema
              └────────┬─────────┘
                       ▼
              ┌──────────────────┐
              │  SQLite (Django) │
              └───┬───────────┬──┘
                  │           │
        ┌─────────▼──┐   ┌────▼───────────┐
        │   engine   │   │       ml       │
        │ Sigma rules│   │ Z-score +      │
        │ MITRE tags │   │ Isolation For. │
        └─────────┬──┘   └────┬───────────┘
                  │           │
                  └─────┬─────┘
                        ▼
        ┌───────────────────────────────┐
        │  Django + DRF + React panel   │
        │  Telegram alerts · LLM layer  │
        └───────────────────────────────┘
```

Each box is a separate systemd service. They share only the database and the
Redis stream, so one of them crashing does not take the others down.

---

## Detection layers

### Rule-based (Sigma format)

Rules are YAML, loaded at runtime, and mapped to MITRE ATT&CK techniques.

| ID | Rule | Level | Technique |
|---|---|---|---|
| sentinel-001 | SSH Brute Force Detection | high | T1110 |
| sentinel-002 | Web Application Scanning Detected | high | T1595 |
| sentinel-003 | Firewall Block Flood (Possible Port Scan) | medium | T1046 |
| sentinel-004 | Suspicious Sudo Activity | high | T1548 |
| sentinel-005 | New User Account Created | critical | T1136.001 |
| sentinel-006 | Failed Sudo Attempt | high | T1548.003 |

```yaml
title: Failed Sudo Attempt
id: sentinel-006
level: high
detection:
  selection:
    event_type: sudo_failure
  condition: selection | count(user) > 0
  timeframe: 1h
response:
  alert: true
  cooldown: 1h
```

### Anomaly-based

An 11-dimensional feature vector is built over 10-minute windows: total events,
unique source IPs and destination ports, auth successes and failures and their
ratio, suspicious requests, HTTP 4xx count, firewall blocks, event-type
diversity, and sudo volume. Two methods score each window:

* **Z-score** against a rolling baseline
* **Isolation Forest** (scikit-learn)

A window is only reported when **both** methods agree *and* the absolute
deviation clears a floor. Rationale and measurements are below.

---

## LLM layer

Alert analysis, single-event explanation, and a RAG-style natural-language
query interface over the stored events.

The provider is configurable: any OpenAI-compatible `/chat/completions`
endpoint works. Groq is the default; pointing `LLM_BASE_URL` at a local Ollama
instance needs no code change and no API key.

```bash
LLM_BASE_URL=http://127.0.0.1:11434/v1   # local model
LLM_MODEL=qwen2.5:7b
```

**Data sent to the provider is minimized first.** Raw log lines are never sent.
IP addresses and usernames are replaced with consistent pseudonyms (`IP_1`,
`USER_1`), command arguments and file paths are stripped, and system accounts
(`root`, `www-data`) are kept as-is because they carry analytic meaning and
identify nobody. What leaves the host is effectively a rule name, a count and a
MITRE tag.

The one honest gap: a question typed into the chatbot is not sanitized, because
the user wrote it. That limit is marked in the code rather than papered over.

---

## Engineering decisions from production

**The system fed on its own logs.** Every alert written to syslog came back in
through the collector as a new event — write, log, read, write. The fix is a
per-source ignore list in `config/settings.yaml`, which also filters a CasaOS
health check that was posting once per second and inflating the ML baseline.

**A rule was designed, measured, and thrown away.** A slow-brute-force rule
(low request rate, high persistence) looked obviously correct. Measured against
31 days of real traffic it was not: 3,549 distinct source IPs, 972 of them
appearing on three or more days, 46 on 25 or more. Every threshold that caught
the slow scanner produced 171+ alerts per day. Failed SSH logins are background
radiation on an internet-facing host. The rule was dropped and the effort moved
to post-access detection instead — `sentinel-005` and `sentinel-006` exist
because of that measurement.

**Cooldown was keyed on the wrong column.** It queried `src_ip` while
user-grouped alerts store `src_ip = NULL`, so cooldown never fired for them and
the engine re-sent the same alert every 10 seconds. Nine copies reached
Telegram. Alerts now carry an explicit `group_value`, and a test locks the
behaviour. SQLite hid the type mismatch; PostgreSQL would have raised.

**A rule queried a field that did not exist.** `extra__status_code` instead of
`extra__http_status` — a filter that silently matched nothing for months and
failed no test, because a query returning zero rows is not an error. There is
now a contract test that parses the source with `ast` and verifies that every
field a rule references is one the parser actually emits.

**The ML layer was tuned by measurement, not intuition.** Raising the Z-score
threshold was tried first and measured useless: 37 of 74 alerts survived at
z > 5. Isolation Forest agreed with Z-score on only 24 of 74. Simulating
candidate policies over the stored alerts gave: agreement required → 20,
agreement plus an absolute-deviation floor → 13. The second policy shipped.

**A failing request burned API quota and returned nothing.** Gunicorn's worker
timeout was shorter than the LLM call, so the worker was killed mid-response —
the user saw a 502, retried, and each silent failure had already consumed
output tokens. Three retries exhausted a 1,000 token/minute budget. The fix is
ordering: the HTTP client's timeout must be strictly shorter than the server's,
so the application's own error handling runs instead of being killed. That rule
is written down in `alerts/llm_client.py` next to the code it governs.

**Generated analyses are stored.** Before that, reopening an alert produced the
same text again at full cost. The panel now marks which alerts already have an
analysis, and regeneration is a separate, explicit action.

---

## Testing

103 tests, run with `pytest`. Three kinds:

* **Behaviour** — correlation, cooldown, retention, ML scoring
* **Contract** — "this data never crosses this boundary": no raw log line
  reaches the LLM, no rule references a field the parser does not emit
* **Lint-style invariants** — e.g. a rule's `cooldown` must not be shorter than
  its `timeframe`, which is how a second, pre-existing instance of that bug was
  found right after the first one was fixed

Every fix in this repository was validated by **falsification**: revert the
fix, confirm the test fails, restore it. A test that has never been seen red
proves nothing.

---

## Running it

Requires Python 3.12+ and Redis.

```bash
git clone https://github.com/EmreYsn/sentinelboard.git
cd sentinelboard

python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # fill in Telegram token and LLM key
docker compose up -d          # Redis only; the database is SQLite

cd dashboard && python manage.py migrate && cd ..
```

Then start the four workers and the web app. Each is its own process, and in
production each is its own systemd unit:

```bash
python -m collector.worker     # tail log files → Redis
python -m parser.worker        # Redis → normalized events → DB
python -m engine.worker        # Sigma rules → alerts
python -m ml.worker            # anomaly detection
python dashboard/manage.py runserver
```

Reading `/var/log/auth.log` requires the running user to be in the `adm` group
(or root). Without it the collector starts normally and silently sees nothing.

### Operating it

```bash
# retention — deletes alerts first, then only events that no alert
# references, so evidence attached to an alert is never orphaned
python dashboard/manage.py prune_events --days 30 --vacuum --dry-run
```

In production: nginx + Gunicorn over a Unix socket, Let's Encrypt, HTTP Basic
Auth in front of the panel, a systemd timer for retention, and a nightly
`sqlite3.Connection.backup()` of both databases.

---

## Project layout

```
collector/   log tailing, per-source parsers, ignore filters
parser/      Redis consumer → common event schema
engine/      Sigma rule loader, correlation, cooldown
  rules/     YAML detection rules
ml/          feature extraction, Z-score + Isolation Forest
alerts/      Telegram, LLM client, data minimization, RAG chat
dashboard/   Django + DRF + React panel
config/      settings.yaml — sources, ignore patterns, thresholds
tests/       103 tests
docs/        architecture notes
```

---

## Known limits

* **SQLite.** Correct for one host, and its single-writer model has not been a
  constraint at this volume. Multi-host collection would need PostgreSQL.
* **Single-host collection.** There is no remote agent or forwarder yet.
* **ML severity is always `high`**, because the agreement rule makes the score
  saturate at 1.0. The score needs rescaling before it means anything.
* **`web_scan` is noisy** on an internet-facing host. The cooldown bounds it,
  but alerts still accumulate.
* **The dashboard polls**; there is no WebSocket stream.
* **Timestamp handling assumes modern rsyslog.** BSD-format timestamps are now
  parsed as local time (RFC 3164) rather than UTC, but that path is exercised
  only by tests — this host writes ISO timestamps with offsets.

---

## License

MIT — see `LICENSE`.

## Author

Yasin Emre Karabacak — cybersecurity and digital forensics
[ysnemre.com](https://ysnemre.com) · [@EmreYsn](https://github.com/EmreYsn)