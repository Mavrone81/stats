# bevoraSG netmap

Inventory, reachability and incident board for the **non-RMA** fleet.

One long-lived process that serves a single static page, probes a curated target
list every 30 seconds in a background thread, records every cycle to SQLite, and
exposes a small read-only JSON API the page polls.

Published as **https://status.bevorasg.com**.

---

## ⚠️ Read this before you debug anything

**The source does not tell you what is being probed.**

Targets are data, in three layers, most specific wins:

| Layer | Where | Role |
|---|---|---|
| 1 | `BUILTIN_TARGETS` in `server.py` | fallback seed only |
| 2 | `/app/targets.json` | deployed seed (optional) |
| 3 | **`/data/targets.json`** | **live store — this wins** |

Layer 3 is written by the **Targets** tab in the UI. Adding a host is a
two-minute edit by whoever is on shift — no code change, no rebuild, no deploy.

The cost of that convenience is a trap, so it is spelled out here: you can grep
`server.py` for a hostname, get zero hits, and the box will be probing it
happily the whole time. **To find out what is actually probed, ask the API:**

```bash
curl -s https://status.bevorasg.com/api/targets   # (authenticated)
```

Never conclude anything about coverage from reading the source.

---

## Scope — non-RMA only

This board covers three hosts and nothing else:

| Segment | Host | What it is |
|---|---|---|
| `edge-165` | `165.22.246.45` | 31 public name-based vhosts behind one nginx |
| `host-165` | `165.22.246.45` | the box itself + two ports that must stay closed |
| `gadonghr` | `157.230.38.96` | HR platform, one hostname, path-routed via Traefik |
| `bevora-ops` | `157.245.152.227` | the host this tool runs on |

**RMA hosts, target lists and credentials never appear here and must never be
added.** The two estates do not share a box, an account or a credential, and
this board is exactly the kind of file that quietly merges them if nobody says
otherwise.

---

## Why no framework

Python **stdlib only** — `http.server`, `socket`, `ssl`, `sqlite3`,
`concurrent.futures`. One HTML file, no build step, no framework. It runs in a
stock `python:3.12-slim` with the source bind-mounted read-only.

This class of tool has to keep working on the day everything else is broken.
Zero dependencies means zero dependency rot and no supply chain, and it means
the whole thing survives being handed to somebody else. ~1,100 lines of Python
and one HTML file do inventory, topology, live status, incidents, latency
history and a NOC overview.

---

## Layout

```
server.py             the whole backend
index.html            the whole frontend
test_server.py        stdlib unittest, zero deps, 94 tests
agent/push-agent.py   optional remote prober for unroutable devices
deploy/               nginx vhost, drift check, post-deploy verification
docker-compose.yml    source read-only at /app, state on the /data volume
```

---

## Probe modes

Dispatched off `opts["m"]`:

- **`tcp`** — plain connect. `{"invert": true}` flips it: UP means the port is
  *closed*. Used to guard ports that must stay shut.
- **`http` / `https`** — GET, judged on the status line. Sends SNI +
  `Host:` + a path.
- **`push`** — no probe; reads the last value a remote agent submitted.

Status judgement is `code in opts["expect"]` when the target declares expected
codes, else `code < 500`. Each target decides, because a 302 is healthy for a
login redirect and a fault for a static site.

### Three things that were got wrong first

**A bare TCP probe of a shared address is worse than no monitoring.** 31 vhosts
share `165.22.246.45:443`. A TCP check there is one check reported 31 times —
all green together, all red together, and *still green* when a single app dies,
because nginx keeps answering. Hence SNI + Host + status code per vhost.

**…and probing that shared IP with a Host header still hides a dead name.**
nginx answers its catch-all for any unknown host, so the row stays green even
when the hostname resolves for nobody. Measured here: `med.awakenfs.store` has
no DNS record at all, and by-IP probing reported it **up with a healthy 200 and
a valid certificate**. Public vhosts are therefore probed **by hostname** —
resolving the name is part of what users depend on, so it is part of the check.

**GET, never HEAD.** An app was found answering HEAD with a redirect
byte-identical to the proxy's "not served here" catch-all while answering GET
correctly. Only the status line is read, so GET costs nothing extra.

### TLS

Connections are made with `check_hostname=False` / `CERT_NONE`. That is not
laziness: we are measuring **reachability, not trust** — a self-signed but
in-date cert still means the vhost is serving, and we want a status code either
way. Expiry is then read off the presented certificate **separately** and
reported as its own field.

`notAfter` is parsed straight out of the DER, because with verification off the
stdlib returns no parsed certificate at all. The parser was diffed against
`openssl x509 -noout -enddate` on six live hosts before it was trusted;
`NETMAP_LIVE=1 python3 -m unittest test_server` re-runs that comparison.

An **already-expired** certificate is reported **DOWN**, whatever the status
code — it is a total outage for every browser however cheerfully the server
returns 200. Warning threshold is 21 days.

---

## The flap gate

A host must fail **two consecutive cycles** to be called down.

```python
DOWN_CONFIRM_CYCLES = 2
```

The counter is **persistent across cycles**. It is emphatically *not* a retry
inside one probe: a retry a second later lands inside the same 4–6s graceful
restart, fails twice, and confirms the wrong answer with more confidence. The
two probes must be a full `REFRESH` apart.

The counter is clamped with `min()` — a permanently-down host fails every cycle
forever, and an unclamped counter grows without bound.

The gate lives **inside the cycle function**, so the board, the sample history
and the incident log all get the same answer. `/api/probe` ("probe now") returns
its result raw, because the caller asked what the host is doing *right now* —
but it never moves stored state, so one click during a blip cannot turn the
board red behind the loop's back.

Cost: at most one `REFRESH` of extra detection delay on a real outage. Worth it.
Without this, an incident log is noise.

---

## History

SQLite, WAL, `synchronous=NORMAL`. **One** write connection owned by the probe
thread; short-lived read connections per request. That invariant is the only
reason there is no lock anywhere in the codebase.

**It fails safe.** If the database cannot be opened — no writable volume, disk
full — `HISTORY_OK` goes false and the live map keeps serving. Reachability is
the product; history is a nice-to-have. Storage failure must never take the
board down.

Raw samples are pruned on a 7-day window.

### Stranded incidents — the subtle one

An incident only closes when a later cycle sees that host **up**. So the moment
a target is *removed from the list*, nothing probes it, no up sample ever
arrives, and its open incident can **never** close. It reads as an ongoing
outage for as long as the database lives and permanently skews the open-incident
count and every MTTR figure.

Fixed at the source, in the cycle:

```python
live = {(h["ip"], h["port"]) for h in hosts}
if live:                                  # never act on an empty snapshot
    for key in [k for k in open_ev if k not in live]:
        close_event(...); fail_counts.pop(key, None)
```

Three details that each matter:

- **In the cycle, not the target editor.** The probe thread already knows which
  targets exist, so this needs no new API, no lock, and no second writer on the
  probe thread's connection.
- **The `if live:` guard.** Without it, a momentarily empty target list closes
  every open incident at once.
- **Drop the flap counter too**, or state is retained for a host that will never
  be probed again.

---

## Acknowledgements

`POST /api/ack` stores `ip:port -> {note, since, until}`.

- `until: null` → **permanent** (down by design).
- `until: <epoch>` → a time-boxed maintenance window.

Both render **amber**. **Red is reserved for genuine, unaccounted faults.** Red
stops carrying information the moment most red rows are states somebody chose on
purpose — if everything is red, nothing is.

Acked hosts are excluded from the open-incident KPI, or it never reaches zero
and people stop reading it.

---

## The discriminating check

On the Overview tab:

> **open-incident count must equal the number of down rows on the board**

The two numbers are computed from completely different sources — the `event`
table versus the live snapshot — and must agree. It is cheap to eyeball and it
breaks loudly. This exact mismatch is what exposes stranded incidents.

---

## Hosts with no route — push, don't open a firewall

Some devices the prober cannot reach. The fix is **not** a new firewall policy:
that widens the blast radius of the monitoring system itself to make a dashboard
tidier.

Instead, `agent/push-agent.py` runs by cron on a host that *already* has the
access and POSTs to `/api/probe-push`. Targets marked `{"m": "push"}` read the
last submitted value.

- Results carry a **300s TTL**. Past it the row reads **STALE and DOWN**, never
  green — a dead agent must not look like perfect uptime forever. That is the
  whole safety property.
- Ingest requires `NETMAP_PUSH_TOKEN`. Unset ⇒ `503`. An open ingest endpoint
  lets anyone paint the board green, which is strictly worse than no monitoring.
- `--dry-run` prints the payload and needs no credential. **Run it FROM the
  candidate host before adopting that host.** Do not assume that because one
  machine on a segment reaches a device, any machine on it does — access is
  frequently per-address.
- **Decide where the agent permanently lives before shipping it.** An agent that
  is "proven end to end" but homeless means those rows are stale by design.

### In use: 26 loopback services on gadonghr-prod

That host ran **43 containers while this board watched 9 endpoints on it** — a
board that looks complete and is not, which is the failure this project keeps
finding elsewhere and had itself. 26 services bind `127.0.0.1` only, so no
external prober could ever see them.

Opening a firewall so the central prober could reach them was the wrong fix.
`agent/netmap-agent.{service,timer}` runs the agent on the host that already
has the access, every 60s — comfortably inside the 300s TTL, because a healthy
agent must never look like a dead one just because its interval drifted past
the staleness window.

Three details that matter:

- **The agent reads the status line**, not just the socket. These backends
  answer `/health` with 200 and `/` with **404**, so the path decides whether
  24 services read up or down. Paths were measured across all 26 before being
  written down — 24 × `/health`, the Next.js frontend on `/`, postgres `tcp`.
- **Rows are keyed by the host's VPC address** (`10.104.0.4`), not `127.0.0.1`.
  The agent probes loopback and reports under `--report-ip`, because otherwise
  every agent on every host collides on the same keys.
- **`--token-file`, never `--token`.** argv is world-readable via `/proc`.

---

## Auth

Session cookie, `HttpOnly`, `SameSite=Strict`, `Secure`, 12h TTL.

**It fails closed.** Nothing is served without a live session except `/login`
and `/api/health` (which deliberately reports only that the process is alive,
never what it monitors). Only an explicit path allow-list is routed — never a
directory, or the `.bak` files, the database and the source would be
downloadable. This page is an inventory of everything we own and where it is
weak; treat it as sensitive.

**Bootstrap credential.** Set in an **untracked `.env`** beside
`docker-compose.yml` on the box — never committed:

```bash
printf 'NETMAP_USER=%s\nNETMAP_PASS=%s\n' "youruser" "$(openssl rand -base64 18)" > /opt/netmap/.env
chmod 600 /opt/netmap/.env
```

It was a committed literal (`Mavrone` / `P@55w0rd`) until it was noticed that
this repository is public. A published default alongside a known URL is a race
between the owner's first login and anyone reading the repo — and because the
first person in gets to set the password, the forced-change flow would lock the
*owner* out rather than the attacker. A bootstrap credential is only safe while
it is unpublished. `docker compose` now refuses to start if either value is
unset, rather than falling back to a guessable default.

The credential ships with `must_change` Until it is replaced, **every authenticated route redirects to `/change`** —
the board and the API are unreachable. A default that is merely "documented as
temporary" stays live for years; one the server refuses to work around does not.

Credentials are stored on the `/data` volume as PBKDF2-SHA256 (200k rounds),
never in the image and never in plaintext. Changing them **signs out every
session**, including the one that made the change — otherwise a stolen cookie
outlives the password change made to revoke it. Failed logins are throttled per
IP (8 per 5 minutes).

`/api/probe` refuses hosts that are not already on the target list: an
authenticated arbitrary-connect endpoint is a port scanner with our source
address on it.

---

## Testing

```bash
python3 -m unittest -v test_server        # 94 tests, no network, no real DB
NETMAP_LIVE=1 python3 -m unittest test_server   # + the openssl cross-check
```

Run it **inside the same image as prod**:

```bash
docker run --rm -v "$PWD:/app:ro" -w /app -e NETMAP_DATA=/tmp \
  python:3.12-slim python3 -m unittest test_server
```

### Proving the guards are actually in force

**A test that passes against code where the feature is unwired is not a test.**
The recurring defect worth guarding against is not a wrong check — it is a check
that was never in force: configured, healthy-looking, exit 0, testing nothing.

So each guard was verified by physically deleting its wiring and confirming the
suite fails:

| Guard removed | Result |
|---|---|
| flap gate in `run_cycle` | **5 failures** (2 wiring + 3 incident-lifecycle) |
| `reconcile_stranded` call in `run_cycle` | **2 failures** |
| forced-credential-change branch in `_gate` | **1 failure** |

Repeat this whenever you touch those paths. A steady-looking board is *not*
evidence the gate is live — unwired code produces an identical board. What
proves it is (a) the wiring test failing against unwired code, and (b) the
deployed file being byte-identical to the file those tests pass against.

Ask constantly: *what would this check look like if the thing it checks were
broken?* If the answer is "exactly the same", it is not a check.

---

## CI

`.github/workflows/ci.yml`, on every push and PR. Runs in the **same
`python:3.12-slim` image as production** — for a zero-dependency stdlib tool,
"works in CI" and "works on the box" should be the same claim, and running the
suite on a runner's own Python quietly weakens it to "works on some Python".

| Step | What it defends |
|---|---|
| Unit tests | the 94-test suite, no network, no database |
| **Estate boundary** | `scripts/assert-non-rma-only.py` — every seeded target is inside the approved non-RMA estate |
| **Guards must be able to fail** | `scripts/assert-guards-can-fail.sh` — breaks each guard and requires the suite to FAIL |
| Working tree unchanged | the guard check restores what it broke (or CI would ship a sabotaged file) |
| Frontend sanity | balanced tags, API calls present, mobile rules still inside a `max-width` query |
| Deploy scripts parse | `bash -n` on everything in `deploy/` and `scripts/` |
| No swallowed exit status | `verify.sh` never runs the suite through a pipe again (see below) |

### `assert-guards-can-fail.sh`

The step that matters most. It deletes each safety guard in turn, runs the
suite, and **requires it to fail**:

```
OK    flap gate: suite fails when the guard is removed
OK    stranded-incident reconciliation: suite fails when the guard is removed
OK    forced credential change: suite fails when the guard is removed
OK    expired cert forces DOWN: suite fails when the guard is removed
OK    inverted target (port must stay closed): suite fails when the guard is removed
```

If a guard is ever unwired, its test stops being evidence of anything, and this
is what notices. The script also fails if its own anchor lines have drifted —
a guard-checker that silently matches nothing is the same failure it exists to
catch. It restores `server.py` through a trap, and CI separately asserts the
working tree came back clean.

### The estate guard is an allowlist

`assert-non-rma-only.py` checks every host in the seed against an approved
list. Deliberately **not** a denylist: a denylist would have to name RMA hosts
*in this repo*, which is the leak it claims to prevent, and it would silently
pass anything nobody thought of. The allowlist fails closed — a new host is
rejected until a human adds it here, which is the moment the boundary question
actually gets asked.

---

## CD — pull, not push

`deploy/auto-deploy-netmap.sh`, driven by `deploy/netmap-deploy.timer` every
five minutes on the box.

**Why pull.** The host's cloud firewall permits inbound tcp/22 from *one*
address. GitHub-hosted runners have no stable egress address, so a push deploy
would mean either allowing a very large published IP range to SSH in, or
holding a long-lived deploy key in CI. A pull needs neither — the box reaches
out to a public git remote and nothing needs to reach in. CI therefore holds no
deploy credential at all (`permissions: contents: read`).

It also closes the drift hole this README has flagged from the start: without a
puller, a hand-edit on the box survives indefinitely and nothing resets it.

**Order of operations, and none of it is optional:**

1. **Refuse if the box's working tree is dirty.** A hand-edit here exists
   nowhere else; the script stops and tells you to reconcile with
   `pull-drift.sh` rather than destroying it.
2. Fetch; exit quietly if there is nothing new.
3. **Run the full suite in the prod image, on the new code.** Exit status is
   checked directly — never through a pipe.
4. Restart only then, with `docker restart` (not recreate, which would drop
   run-time flags). `index.html`-only changes skip the restart entirely.
5. **Verify it came back**, and roll back if it did not. Then assert `GET /`
   returns **401** — a board answering the public unauthenticated is the
   failure that would be worst to find late.

Verified locally against a throwaway repo, because a deploy script that has
never failed on purpose is a deploy script nobody knows the failure behaviour of:

| Case | Result |
|---|---|
| nothing new | quiet, exit 0 |
| dirty working tree | refuses, **exit 1**, hand-edit survives untouched |
| new commit whose tests fail | **rolls back**, exit 1, box stays on the old commit |

**Is the box running what you pushed?** `/api/health` reports the deployed
commit, unauthenticated, so you can check without SSH:

```bash
curl -s https://status.bevorasg.com/api/health
# {"ok": true, "history_ok": true, "cycles": 1835, "version": "9df87fc3"}
```

Compare it against `git rev-parse --short=8 origin/main`. This project has had
to answer that question the hard way more than once — a fix live in production
while existing only on a laptop, and a deploy assumed rather than verified.

Deploy history is `journalctl -u netmap-deploy`. Logs go to the journal and
deliberately *not* to a file inside `/opt/netmap` — deploy logs living in the
deploy target is how a working tree ends up dirty, which is how this script
then refuses to run.

### Access: a read-only deploy key

The box pulls with a **dedicated deploy key**, not a personal account and not
an unauthenticated HTTPS clone:

```bash
ssh-keygen -t ed25519 -N "" -C "netmap-deploy@<host> (read-only)" \
  -f /root/.ssh/netmap_deploy
cat /root/.ssh/netmap_deploy.pub     # add at Settings -> Deploy keys
```

Two things about it are deliberate:

- **Read access only.** Never tick "Allow write access". CD only ever reads,
  and a writable key sitting on a monitoring box is a path back into the source
  that nothing needs.
- **`IdentitiesOnly yes`** in `/root/.ssh/config`, pinning `github.com` to that
  key alone. Otherwise ssh offers every identity on the box and the pull may
  quietly succeed on someone else's credential — which works right up until
  that credential is rotated, and then fails for a reason nobody can see.

A deploy key is per-repository, so it also cannot reach anything else in the
account. That matters more than usual here: this repo is the inventory of the
estate, and the machine holding the key is reachable from the internet.

### Installing it on the box

```bash
git clone git@github.com:Mavrone81/stats.git /opt/netmap
cp /opt/netmap/deploy/netmap-deploy.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now netmap-deploy.timer
systemctl list-timers netmap-deploy      # confirm it is actually scheduled
```

The unit files were validated with `systemd-analyze verify`. Worth doing on the
box too: a sibling project in this estate shipped an agent unit whose own
comments record that it was never checked on a real systemd host.

---

## Deploy (first time / manual)

```bash
./deploy/pull-drift.sh <ssh-host>     # ALWAYS first
rsync -av --exclude .git --exclude __pycache__ ./ <ssh-host>:/opt/netmap/
ssh <ssh-host> 'cd /opt/netmap && docker compose up -d'
./deploy/verify.sh <ssh-host>
```

- `index.html` is served fresh on the next request — no restart.
- `server.py` changes need `docker restart netmap`. Use **`docker restart`, not
  recreate**, if the container was ever started with run-time flags a recreate
  would drop.
- **Verify with checksums on both sides.** "I copied it" is not "it's there" —
  `deploy/verify.sh` does this and also asserts that `/` returns **401**, because
  a board that answers 200 to the public is a serious finding.
- **There is no auto-deploy puller, so the box drifts and nothing resets it.** A
  server-side edit survives indefinitely and an rsync would silently destroy it.
  `deploy/pull-drift.sh` pulls the box's copy down and diffs it before you push
  anything over it — commit drift first.
- **Check `git log origin/main` after deploying, not just the box.** With no
  puller, nothing catches a fix that is live in production while existing only
  on a laptop and the box.

### nginx

`deploy/nginx-status.conf` proxies `status.bevorasg.com` → `127.0.0.1:8080`.
Point the DNS A record at the host **before** running
`certbot --nginx -d status.bevorasg.com`, or HTTP-01 validation cannot reach it.

The container binds `127.0.0.1` only. nginx is the sole way in, which is what
lets the app trust the last `X-Forwarded-For` hop — the *first* entry is always
client-controlled and is never read.

---

## Findings from the first inventory sweep

Recorded here because a monitoring board is also an audit:

1. ~~`med.awakenfs.store`~~ — **retired 2026-09-03.** The app (`medusa-web`) was
   healthy on `127.0.0.1:20021` and the cert was valid, but no DNS record
   existed, so nobody could reach it — and the cert could never renew, because
   HTTP-01 needs the name to resolve. Removed on Samuel's instruction: nginx
   vhost deleted, certificate deleted via `certbot delete`, container, image and
   `/root/medusa` compose project removed. Everything was backed up first to
   `/root/retired-med.awakenfs.store-<timestamp>/` on the 165 host. The apex
   `awakenfs.store` is a *different* application (ports 9010/8010) and was
   verified still serving 307 afterwards.

   Note also that `www.awakenfs.store` points at a Namecheap parking page rather
   than this server, despite nginx still having a `server_name awakenfs.store
   www.awakenfs.store` block. It is deliberately not monitored: a parking page
   answers `200` and would show green. Reachability monitoring cannot tell "our
   app" from "somebody's parking page" without a content check.

1b. ~~`crm.bevorasg.com`~~ — **retired 2026-09-04.** Its backend on `:3013` had
   been gone; only a static brochure page was answering, which is what made it
   read green until the probe was repointed at `/login`. Removed on Samuel's
   instruction (a replacement CRM is planned): nginx vhost, certificate and
   `/var/www/crm.bevorasg.com` deleted, backed up first to
   `/root/retired-crm.bevorasg.com-<timestamp>/`. Neighbouring vhosts verified
   unaffected afterwards.

   Note the DNS record still points here, so the name now falls through to
   nginx's catch-all: `http://` returns the default 200 and `https://` fails
   the handshake, because no certificate covers that name any more. Harmless
   for a retired service; the replacement will need its own cert.

2. ~~`track.urbanfleetsg.com` — 404~~ — **this was a monitoring defect, not an
   outage.** The app (CDMS `web-tracking`) has exactly one route,
   `app/track/[trackingId]`, and no root page, so `/` returning 404 is correct
   behaviour for a public parcel-tracking page you reach with an ID.
   `/track/<anything>` returns 200. The target now probes the route the app
   actually serves. Recorded rather than quietly deleted, because "the board
   says red" and "the service is broken" are not the same claim, and a board
   that cries wolf gets ignored exactly like one that stays green.
3. **`165` postgres (5432) and redis (6379) bind `0.0.0.0`.** They are *not*
   internet-reachable, but not for the reason `docker ps` suggests. There is
   **no cloud firewall attached to this droplet at all.** What closes them is
   the host's own `ufw` (default-deny INPUT; only OpenSSH, Nginx Full and
   wireguard allowed) together with a `DOCKER-USER` rule dropping new inbound
   connections on `eth0` — the rule that stops Docker's published ports from
   punching straight through ufw, which is otherwise exactly what they do.
   Both are probed **inverted**, so the board goes red if either protection is
   dropped. Publishing them to `127.0.0.1` in the compose files is still worth
   doing: it would make the guarantee a property of the service rather than of
   two firewall rules that a future `docker run -p` can quietly sidestep.
4. **`bevora-ops` (157.245.152.227) answers on no *public* port** — but it is
   **not unrouted**, and an earlier version of this file said it was. All three
   droplets share a DigitalOcean VPC (`165`=`10.104.0.2`, `bevora-ops`=
   `10.104.0.3`, `gadonghr`=`10.104.0.4`), and from 165 across that VPC port
   **4100 is open** while 22/80/443/3000 are filtered. The separation is a
   firewall *policy on a shared private network*, not an absence of route.

   Worth stating plainly because this file spends a section warning that "no L3
   route" and "air-gapped" are different claims, and then made the stronger
   claim itself off two probes of the **public** address only. The lesson is
   the one already written down: name the vantage point, and say whether the
   path was measured or merely not tried.

6. **`crm.bevorasg.com` — the application is DOWN, and this board said it was
   up.** The vhost serves a static brochure page from `/var/www` for `/`, and
   only proxies `^/(admin|login|api|_next)` to the app on `:3013`. Nothing has
   been listening on 3013. Measured at the same instant, from outside:
   `/` → **200**, `/login` → **502**.

   This is the same class of defect as probing a shared IP, and it is the more
   dangerous one: a reverse proxy that can answer *without its backend* will
   keep a row green through a total application outage. The target now probes
   `/login`. An audit of every vhost for this shape (static root + backend only
   on sub-paths) found exactly one other, `back-end.store`, which is currently
   healthy but was repointed to `/api/health` for the same reason.

   **The general rule: probe a path that cannot be served without the thing you
   are trying to monitor.** A 200 from nginx's filesystem is not evidence that
   an application is alive.

5. **Bevora Ops is already monitoring both hosts.** `bevora-agent.service` is
   active on `165` *and* `gadonghr-prod`, with an established connection to
   `10.104.0.3:4100`. See "Overlap with Bevora Ops" below — this board should
   not become a second, disagreeing opinion about the same hostnames.

---

## bevora-ops

This tool is intended to run **on `157.245.152.227`**, served at
`status.bevorasg.com`.

The droplet is **running** — `doctl compute droplet list --context bevora`
reports it `active`. What blocks access is its DigitalOcean cloud firewall
`bevora-ops-fw` (`b1892b4b-e5c3-43ed-9628-744b02180ee0`), whose *entire*
inbound ruleset is:

| Protocol | Ports | Source |
|---|---|---|
| tcp | 22 | `129.126.113.103/32` — one address only |
| tcp | 4100 | droplet `577712325` |
| tcp | 4100 | droplet `589252860` (gadonghr-prod) |

So SSH is reachable from exactly one address, and **80/443 are not open at
all** — meaning `status.bevorasg.com` cannot serve, and certbot's HTTP-01
challenge cannot reach the host either. Two changes are needed before deploy:

1. **Inbound tcp/22 from the deploying workstation** (or run the deploy from
   whatever host holds `129.126.113.103`).
2. **Inbound tcp/80 and tcp/443 from anywhere** — required both for certbot
   validation and for anyone to read the board.

Opening 80/443 creates a public listener, so it is a deliberate decision and
not one this repo makes on anyone's behalf. Note that it is also the *only*
firewall change this tool ever wants: nothing here asks for a policy opened so
the prober can reach some other device — avoiding exactly that is what
`agent/push-agent.py` is for.

Everything else is ready and tested; only the copy step is blocked.

### On the word "isolated"

**"No L3 route" and "air-gapped" are different claims**, and so are "no route"
and "a route with one port open". This board previously asserted the strongest
of those from the weakest evidence — two probes of the *public* address — and
was wrong. The three hosts share a VPC and `10.104.0.3:4100` answers from 165.

The corrected Simple View says what is actually true: one shared private
network, with a firewall deciding which doors are open, and that this is *a
setting, not a wall*. The retraction is left visible on the page rather than
edited out, because a page that silently revises what it claimed cannot be
audited by the people making decisions from it.

Untested segments are marked *unverified* rather than inheriting the appearance
of the tested ones. If this board asserts isolation, it must say which kind,
from which vantage point, and whether it was **measured or assumed**.

---

## Overlap with Bevora Ops

`bevora-agent.service` is **active on both monitored hosts** (`165` and
`gadonghr-prod`) with a live connection to `10.104.0.3:4100`. Bevora Ops
therefore already has app-level coverage of the same estate, and it derives
vhosts from nginx config, so it picks up a new stack the day it deploys —
something this board's hand-maintained seed list will never do.

The two are different products and both can exist:

| | Bevora Ops | netmap |
|---|---|---|
| Question | is the *app* answering, and where is the fault? | what exists, in what segments, reachable from where |
| Method | two probes never merged into one boolean — on-box container port vs public DNS/TLS; the **disagreement** is the product | one external probe per target, plus inverted and push modes |
| Discovery | derived from nginx, automatic | curated list, edited in the UI |
| Covers | the enrolled hosts' app stacks | topology, segments, host ports, cross-segment reachability, plain-English map |

**What must not happen is a third independent opinion about the same
hostnames.** Two probers disagreeing about one host is worse than one prober.
The 31 `edge-165` vhost rows here are exactly that duplication today.

### Decision (2026-09-04): netmap keeps its own probes

Not on preference — on evidence. Bevora Ops **cannot currently be consumed**:
`bevops-web` accepts TCP connections on `:3000` and then returns nothing. Up 20
hours, 0 restarts, log says `✓ Ready`, CPU 0.00%, socket in `LISTEN` — and no
bytes ever come back. Its `next-server` is bound to the container's bridge IP
rather than `0.0.0.0`, and even probing that address directly gets a connect
followed by silence.

That is the failure this board exists to catch, sitting inside the tool that
was supposed to be the authority: healthy by every cheap signal — container
status, log line, listening port, successful TCP connect — and serving nothing.
A `tcp` probe of `:3000` would report it UP. Only reading a status line finds
it.

So the duplication concern is currently theoretical: there is one working board
and it is this one. Revisit when `bevops-web` answers again; consuming it for
the liveness half is still the better end state, and its nginx-derived
discovery is still better than a curated list.

Not yet monitored here: `bevops-web` itself. netmap's container cannot reach
`172.18.0.2:3000` (separate docker bridge, verified from inside the container),
so putting it on the board means joining netmap to that stack's network — a
change to someone else's deployment, not one to make unasked.

The options remain, for when that changes:

1. **Consume Bevora Ops for the liveness half.** Drop the `edge-165` vhost
   probes; read app state from its API and keep netmap to topology, segments,
   host-level ports, inverted guards and the reachability map. Least
   duplication, and Bevora Ops' nginx-derived discovery is better than a
   curated list.
2. **Agree an explicit split.** Bevora Ops owns app liveness; netmap owns
   host/segment/route facts it does not model. Written down, or it erodes.
3. **Keep both probing**, accepting that two boards will sometimes disagree and
   that somebody must arbitrate. Hard to recommend.
