#!/usr/bin/env python3
"""
Tests for bevoraSG netmap. Stdlib unittest, zero deps, no network, no real DB.

Run inside the SAME image as prod:
    python3 -m unittest -v test_server

THE RULE THIS FILE IS BUILT AROUND: a test that passes against code where the
feature is UNWIRED is not a test. The three tests marked WIRING below were each
verified by physically deleting the wiring in server.py, watching them FAIL,
then restoring it -- see README "Proving the guards are in force". The recurring
defect worth guarding against is not a wrong check, it is a check that was
never in force: configured, healthy-looking, exit 0, and testing nothing.

Ask of every test here: "what would this look like if the thing it checks were
broken?" If the answer is "exactly the same", it is not a test.
"""
import base64
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import server


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def mkdb():
    conn = sqlite3.connect(":memory:")
    conn.executescript(server.SCHEMA)
    return conn


def target(ip="10.0.0.1", port=80, mode="tcp", **opts):
    o = {"m": mode}
    o.update(opts)
    return {"ip": ip, "port": port, "label": f"t-{ip}:{port}", "seg": "test", "opts": o}


def der_with_validity(not_before, not_after):
    """Minimal DER carrying a Validity SEQUENCE of two UTCTimes, wrapped in
    enough noise to prove the scanner finds the right pair."""
    def utctime(dt):
        body = dt.strftime("%y%m%d%H%M%SZ").encode()
        return bytes([0x17, len(body)]) + body
    validity = utctime(not_before) + utctime(not_after)
    seq = bytes([0x30, len(validity)]) + validity
    # leading noise that must not be mistaken for a time, plus a trailing
    # unrelated time (as extensions carry) that must not win
    tail = utctime(not_after + timedelta(days=900))
    return b"\x30\x82\x01\x00" + b"\x02\x01\x02" + seq + b"\x03\x02\x00\x00" + tail


# ---------------------------------------------------------------------------
# §6 The flap gate
# ---------------------------------------------------------------------------
class TestFlapGate(unittest.TestCase):
    def test_single_failure_is_not_an_outage(self):
        counts = {}
        self.assertTrue(server.confirmed_up("k", False, counts),
                        "one failed cycle must NOT be reported as down")

    def test_two_consecutive_failures_confirm_down(self):
        counts = {}
        server.confirmed_up("k", False, counts)
        self.assertFalse(server.confirmed_up("k", False, counts))

    def test_recovery_clears_the_counter(self):
        counts = {}
        server.confirmed_up("k", False, counts)
        server.confirmed_up("k", True, counts)
        self.assertNotIn("k", counts)
        # ...and the next single failure is again absorbed, not confirmed
        self.assertTrue(server.confirmed_up("k", False, counts))

    def test_counter_is_clamped(self):
        """A permanently-down host fails every cycle forever. Unclamped, this
        counter grows without bound for the life of the process."""
        counts = {}
        for _ in range(10000):
            server.confirmed_up("k", False, counts)
        self.assertEqual(counts["k"], server.DOWN_CONFIRM_CYCLES)

    def test_gate_is_per_key(self):
        counts = {}
        server.confirmed_up("a", False, counts)
        self.assertTrue(server.confirmed_up("b", False, counts),
                        "b's first failure must not inherit a's count")


class TestFlapGateWiring(unittest.TestCase):
    """WIRING: proves run_cycle actually ROUTES through the gate.

    TestFlapGate above passes fine against a run_cycle that ignores
    confirmed_up() entirely -- that is exactly the unwired-guard failure this
    file exists to catch."""

    def test_cycle_absorbs_a_single_failed_probe(self):
        state = {}
        t = [target(mode="push")]        # push with no store => always raw-down
        snap = server.run_cycle(t, None, state, now=1000, push_store={})
        self.assertFalse(snap[0]["raw_up"], "probe should have failed")
        self.assertTrue(snap[0]["up"],
                        "WIRING: first failure reached the board ungated")
        self.assertTrue(snap[0]["pending"])

    def test_cycle_confirms_on_the_second_cycle(self):
        state = {}
        t = [target(mode="push")]
        server.run_cycle(t, None, state, now=1000, push_store={})
        snap = server.run_cycle(t, None, state, now=1030, push_store={})
        self.assertFalse(snap[0]["up"])

    def test_no_event_opens_on_an_unconfirmed_failure(self):
        """The gate must apply to the incident log too, not just the board."""
        conn, state = mkdb(), {}
        server.run_cycle([target(mode="push")], conn, state, now=1000, push_store={})
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM event").fetchone()[0], 0,
            "WIRING: an incident was logged for a single blip")
        server.run_cycle([target(mode="push")], conn, state, now=1030, push_store={})
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM event").fetchone()[0], 1)


# ---------------------------------------------------------------------------
# §7 Incident lifecycle + stranded events
# ---------------------------------------------------------------------------
class TestIncidents(unittest.TestCase):
    def _down(self, conn, state, t, t0, cycles=2):
        for i in range(cycles):
            server.run_cycle([t], conn, state, now=t0 + i * 30, push_store={})

    def test_event_opens_and_closes(self):
        conn, state = mkdb(), {}
        t = target(mode="push")
        self._down(conn, state, t, 1000)
        self.assertEqual(len(server.load_open_events(conn)), 1)
        server.run_cycle([t], conn, state, now=1100,
                         push_store={"10.0.0.1:80": {"up": True, "ms": 5, "ts": 1100}})
        row = conn.execute("SELECT up_ts,duration FROM event").fetchone()
        self.assertEqual(row[0], 1100)
        self.assertEqual(row[1], 1100 - 1030)

    def test_removed_target_does_not_strand_its_incident(self):
        """THE BUG: an event only closes when a later cycle sees the host UP.
        Remove the target and no up sample ever arrives, so without
        reconciliation the incident stays open for the life of the database and
        permanently skews the open count and every MTTR figure."""
        conn, state = mkdb(), {}
        t = target(mode="push")
        self._down(conn, state, t, 1000)
        self.assertEqual(len(server.load_open_events(conn)), 1)
        # target removed from the list; a different target keeps the list live
        server.run_cycle([target(ip="10.0.0.9")], conn, state, now=1100, push_store={})
        self.assertEqual(len(server.load_open_events(conn)), 0,
                         "removed target left a stranded, uncloseable incident")

    def test_empty_target_list_does_not_close_everything(self):
        """A momentarily empty list (bad edit, unreadable store) must not be
        read as 'every host recovered at once'."""
        conn, state = mkdb(), {}
        self._down(conn, state, target(mode="push"), 1000)
        server.run_cycle([], conn, state, now=1100, push_store={})
        self.assertEqual(len(server.load_open_events(conn)), 1,
                         "empty snapshot wrongly closed an open incident")

    def test_reconcile_drops_the_flap_counter_too(self):
        """Otherwise state is retained forever for a host never probed again."""
        conn = mkdb()
        state = {"fail_counts": {("10.0.0.1", 80): 2}, "open_ev": {}}
        server.open_event(conn, state["open_ev"], target(), 1000)
        server.reconcile_stranded(conn, state["open_ev"], {("10.0.0.9", 80)},
                                  1100, state["fail_counts"])
        self.assertEqual(state["fail_counts"], {})

    def test_reopening_after_close_creates_a_second_event(self):
        conn, state = mkdb(), {}
        t = target(mode="push")
        self._down(conn, state, t, 1000)
        server.run_cycle([t], conn, state, now=1100,
                         push_store={"10.0.0.1:80": {"up": True, "ms": 1, "ts": 1100}})
        self._down(conn, state, t, 2000)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM event").fetchone()[0], 2)


class TestStrandedWiring(unittest.TestCase):
    """WIRING: proves run_cycle calls reconcile_stranded.

    TestIncidents.test_reconcile_drops_the_flap_counter_too passes against a
    run_cycle that never calls it."""

    def test_cycle_reconciles_without_being_asked(self):
        conn, state = mkdb(), {}
        t = target(mode="push")
        for i in range(2):
            server.run_cycle([t], conn, state, now=1000 + i * 30, push_store={})
        before = conn.execute(
            "SELECT COUNT(*) FROM event WHERE up_ts IS NULL").fetchone()[0]
        self.assertEqual(before, 1)
        server.run_cycle([target(ip="10.0.0.9")], conn, state, now=1200, push_store={})
        after = conn.execute(
            "SELECT COUNT(*) FROM event WHERE up_ts IS NULL").fetchone()[0]
        self.assertEqual(after, 0, "WIRING: run_cycle never reconciled")


# ---------------------------------------------------------------------------
# §5 Probe judgement and certs
# ---------------------------------------------------------------------------
class TestJudgement(unittest.TestCase):
    def test_default_is_below_500(self):
        self.assertTrue(server._judge(404, {}))
        self.assertFalse(server._judge(502, {}))

    def test_expect_list_overrides(self):
        """A 301/307 is healthy for some vhosts and a fault for others -- the
        target decides, not the prober."""
        self.assertTrue(server._judge(307, {"expect": [200, 307]}))
        self.assertFalse(server._judge(200, {"expect": [307]}))
        self.assertFalse(server._judge(404, {"expect": [200]}),
                         "expect must be able to make a sub-500 code DOWN")

    def test_empty_expect_falls_back(self):
        self.assertTrue(server._judge(200, {"expect": []}))


class TestCertParsing(unittest.TestCase):
    def test_reads_not_after_not_not_before(self):
        nb = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        na = datetime(2026, 11, 28, 10, 30, 20, tzinfo=timezone.utc)
        self.assertEqual(server.cert_not_after(der_with_validity(nb, na)), na)

    def test_days_left(self):
        now = datetime(2026, 9, 3, tzinfo=timezone.utc)
        der = der_with_validity(now - timedelta(days=30), now + timedelta(days=45))
        self.assertEqual(server.cert_days_left(der, now=now), 45)

    def test_expired_cert_reports_negative_days(self):
        now = datetime(2026, 9, 3, tzinfo=timezone.utc)
        der = der_with_validity(now - timedelta(days=500), now - timedelta(days=486))
        self.assertLess(server.cert_days_left(der, now=now), 0)

    def test_garbage_der_returns_none_rather_than_raising(self):
        self.assertIsNone(server.cert_not_after(b"\x00" * 64))

    @unittest.skipUnless(os.environ.get("NETMAP_LIVE"),
                         "live cross-check; set NETMAP_LIVE=1")
    def test_matches_openssl_on_a_live_host(self):
        """The parser is only trustworthy because it was diffed against
        `openssl x509 -noout -enddate` on real hosts. This keeps that honest."""
        import subprocess
        host = os.environ.get("NETMAP_LIVE_HOST", "vo.urbanwerkzsg.com")
        r = server.probe_https(host, 443, {"host": host, "path": "/"})
        out = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:443",
             "-servername", host],
            input=b"", capture_output=True, timeout=20).stdout
        end = subprocess.run(["openssl", "x509", "-noout", "-enddate"],
                             input=out, capture_output=True).stdout.decode()
        expect = datetime.strptime(end.strip().split("=", 1)[1],
                                   "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = int((expect - datetime.now(timezone.utc)).total_seconds() // 86400)
        self.assertEqual(r["cert_days"], days)


class TestExpiredCertIsDown(unittest.TestCase):
    """A server can return a cheerful 200 behind a cert that every browser
    rejects outright. Pure reachability monitoring misses this completely."""

    def test_expired_cert_overrides_a_healthy_200(self):
        opts = {"expect": [200]}
        self.assertTrue(server._judge(200, opts), "the status code alone says up")
        up, detail = server.judge_with_cert(200, opts, cert_days=-486)
        self.assertFalse(up, "expired cert must force DOWN despite HTTP 200")
        self.assertIn("EXPIRED", detail)

    def test_valid_cert_does_not_change_the_verdict(self):
        self.assertEqual(server.judge_with_cert(200, {"expect": [200]}, 45)[0], True)
        self.assertEqual(server.judge_with_cert(502, {}, 45)[0], False)

    def test_absent_cert_days_is_not_treated_as_expired(self):
        """tcp/http targets carry cert_days=None; None must not read as <0."""
        self.assertTrue(server.judge_with_cert(200, {"expect": [200]}, None)[0])

    def test_cert_expiring_today_is_still_up(self):
        self.assertTrue(server.judge_with_cert(200, {"expect": [200]}, 0)[0])


# ---------------------------------------------------------------------------
# §9 Push TTL
# ---------------------------------------------------------------------------
class TestPushTTL(unittest.TestCase):
    def test_fresh_push_is_up(self):
        r = server.probe_push("10.0.0.1", 80, {},
                              push_store={"10.0.0.1:80": {"up": True, "ms": 3, "ts": 1000}},
                              now=1100)
        self.assertTrue(r["up"])
        self.assertFalse(r["stale"])

    def test_stale_push_is_DOWN_not_green(self):
        """The whole safety property of push mode: a dead agent must not look
        like perfect uptime forever."""
        r = server.probe_push("10.0.0.1", 80, {},
                              push_store={"10.0.0.1:80": {"up": True, "ms": 3, "ts": 1000}},
                              now=1000 + server.PUSH_TTL + 1)
        self.assertFalse(r["up"])
        self.assertTrue(r["stale"])

    def test_never_reported_is_down(self):
        r = server.probe_push("10.0.0.1", 80, {}, push_store={}, now=1000)
        self.assertFalse(r["up"])
        self.assertTrue(r["stale"])

    def test_per_target_ttl_override(self):
        store = {"10.0.0.1:80": {"up": True, "ms": 3, "ts": 1000}}
        self.assertTrue(server.probe_push("10.0.0.1", 80, {"ttl": 600},
                                          push_store=store, now=1500)["up"])
        self.assertFalse(server.probe_push("10.0.0.1", 80, {"ttl": 100},
                                           push_store=store, now=1500)["up"])


# ---------------------------------------------------------------------------
# §4 Target store
# ---------------------------------------------------------------------------
class TestTargetValidation(unittest.TestCase):
    def test_accepts_a_good_target(self):
        ts, errs = server.validate_targets([{"ip": "10.0.0.1", "port": 443,
                                             "label": "x", "seg": "s",
                                             "opts": {"m": "https"}}])
        self.assertEqual(errs, [])
        self.assertEqual(len(ts), 1)

    def test_rejects_the_whole_payload_on_one_bad_entry(self):
        """A partially-applied target list is a silent coverage hole."""
        ts, errs = server.validate_targets(
            [{"ip": "10.0.0.1", "port": 443}, {"ip": "bad host!", "port": 1}])
        self.assertIsNone(ts)
        self.assertTrue(errs)

    def test_rejects_bad_port_mode_and_expect(self):
        for bad in ([{"ip": "a", "port": 0}],
                    [{"ip": "a", "port": 70000}],
                    [{"ip": "a", "port": 80, "opts": {"m": "icmp"}}],
                    [{"ip": "a", "port": 80, "opts": {"expect": ["200"]}}]):
            self.assertIsNone(server.validate_targets(bad)[0], bad)

    def test_caps_the_list(self):
        big = [{"ip": "10.0.0.1", "port": 80}] * (server.MAX_TARGETS + 1)
        self.assertIsNone(server.validate_targets(big)[0])

    def test_defaults_seg_so_aggregates_never_lose_a_host(self):
        ts, _ = server.validate_targets([{"ip": "10.0.0.1", "port": 80}])
        self.assertEqual(ts[0]["seg"], "unsegmented")

    def test_live_store_wins_over_seed_and_builtin(self):
        with tempfile.TemporaryDirectory() as d:
            live = os.path.join(d, "targets.json")
            with open(live, "w") as fh:
                json.dump([{"ip": "10.9.9.9", "port": 1234, "label": "live"}], fh)
            old = server.LIVE_TARGETS
            try:
                server.LIVE_TARGETS = live
                ts, src = server.load_targets()
                self.assertEqual(ts[0]["ip"], "10.9.9.9")
                self.assertEqual(src, live)
            finally:
                server.LIVE_TARGETS = old

    def test_invalid_live_store_falls_back_rather_than_probing_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            live = os.path.join(d, "targets.json")
            with open(live, "w") as fh:
                fh.write('[{"ip": "!!bad", "port": 1}]')
            old_l, old_s = server.LIVE_TARGETS, server.SEED_TARGETS
            try:
                server.LIVE_TARGETS = live
                server.SEED_TARGETS = os.path.join(d, "nope.json")
                ts, src = server.load_targets()
                self.assertEqual(src, "builtin")
                self.assertTrue(ts)
            finally:
                server.LIVE_TARGETS, server.SEED_TARGETS = old_l, old_s

    def test_atomic_write_keeps_a_backup(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "targets.json")
            server._write_json_atomic(p, [{"a": 1}])
            server._write_json_atomic(p, [{"a": 2}])
            self.assertEqual(json.load(open(p)), [{"a": 2}])
            self.assertTrue([f for f in os.listdir(d) if f.endswith(".bak")])


# ---------------------------------------------------------------------------
# §8 Acks
# ---------------------------------------------------------------------------
class TestAcks(unittest.TestCase):
    def test_null_until_is_permanent(self):
        self.assertEqual(
            server.ack_state({"1.2.3.4:80": {"until": None}}, "1.2.3.4:80", 9e9),
            "perm")

    def test_window_expires(self):
        acks = {"1.2.3.4:80": {"until": 1000}}
        self.assertEqual(server.ack_state(acks, "1.2.3.4:80", 999), "window")
        self.assertEqual(server.ack_state(acks, "1.2.3.4:80", 1001), "")

    def test_unacked_is_empty(self):
        self.assertEqual(server.ack_state({}, "1.2.3.4:80", 1000), "")


# ---------------------------------------------------------------------------
# §14 The discriminating check
# ---------------------------------------------------------------------------
class TestInvariant(unittest.TestCase):
    def test_invariant_holds_in_the_normal_case(self):
        conn, state = mkdb(), {}
        t = target(mode="push")
        for i in range(2):
            snap = server.run_cycle([t], conn, state, now=1000 + i * 30, push_store={})
        o = server.overview(snap, conn, {}, now=1100)
        self.assertTrue(o["invariant_ok"], o["invariant_detail"])
        self.assertEqual(o["open_incidents"], o["down_unacked"])

    def test_invariant_catches_a_stranded_incident(self):
        """Inject the exact defect §7 describes and prove the board SCREAMS.
        A check that cannot fail is not a check."""
        conn, state = mkdb(), {}
        t = target(mode="push")
        for i in range(2):
            server.run_cycle([t], conn, state, now=1000 + i * 30, push_store={})
        snap = server.run_cycle([t], conn, state, now=1060, push_store={})
        # A ghost incident for a host that is not on the board at all -- exactly
        # what a removed target used to leave behind. Injected AFTER the last
        # cycle: reconcile_stranded would (correctly) clean it up, and this test
        # is about the DETECTOR, not the fix.
        conn.execute("INSERT INTO event(ip,port,label,seg,down_ts) "
                     "VALUES('10.0.0.99',80,'ghost','test',900)")
        o = server.overview(snap, conn, {}, now=1060)
        self.assertFalse(o["invariant_ok"])
        self.assertIn("!=", o["invariant_detail"])

    def test_acked_hosts_are_excluded_from_the_kpi(self):
        """Otherwise the open-incident KPI never reaches zero and people stop
        reading it."""
        conn, state = mkdb(), {}
        t = target(mode="push")
        for i in range(2):
            snap = server.run_cycle([t], conn, state, now=1000 + i * 30, push_store={})
        acks = {"10.0.0.1:80": {"until": None, "note": "down by design"}}
        o = server.overview(snap, conn, acks, now=1100)
        self.assertEqual(o["down"], 1)
        self.assertEqual(o["down_unacked"], 0)
        self.assertEqual(o["open_incidents"], 0)
        self.assertTrue(o["invariant_ok"])


# ---------------------------------------------------------------------------
# §7 fail-safe history
# ---------------------------------------------------------------------------
class TestHistoryFailsSafe(unittest.TestCase):
    def test_cycle_still_returns_a_board_with_no_database(self):
        """Reachability is the product. Storage failure must never take the
        board down."""
        snap = server.run_cycle([target(mode="push")], None, {}, now=1000,
                                push_store={"10.0.0.1:80": {"up": True, "ms": 2, "ts": 1000}})
        self.assertEqual(len(snap), 1)
        self.assertTrue(snap[0]["up"])

    def test_overview_degrades_without_a_database(self):
        o = server.overview([], None, {}, now=1000)
        self.assertEqual(o["open_incidents"], 0)
        self.assertIn("history", o["invariant_detail"])

    def test_db_open_safe_sets_the_flag_instead_of_raising(self):
        old = server.HISTORY_OK
        try:
            conn = server.db_open_safe("/proc/definitely/not/writable/x.db")
            self.assertIsNone(conn)
            self.assertFalse(server.HISTORY_OK)
        finally:
            server.HISTORY_OK = old


# ---------------------------------------------------------------------------
# §11 Auth -- fails CLOSED, and the bootstrap credential must not survive
# ---------------------------------------------------------------------------
class TestPasswordHashing(unittest.TestCase):
    def test_roundtrip(self):
        salt, h = server.hash_pw("correct horse battery staple")
        self.assertTrue(server.verify_pw("correct horse battery staple", salt, h))

    def test_wrong_password_fails(self):
        salt, h = server.hash_pw("aaaaaaaaaaaa")
        self.assertFalse(server.verify_pw("aaaaaaaaaaab", salt, h))

    def test_salt_is_per_record(self):
        self.assertNotEqual(server.hash_pw("same")[0], server.hash_pw("same")[0])

    def test_password_is_never_stored_in_the_clear(self):
        salt, h = server.hash_pw("P@55w0rdP@55w0rd")
        self.assertNotIn("P@55w0rd", h)
        self.assertNotIn("P@55w0rd", salt)

    def test_verify_does_not_raise_on_a_corrupt_record(self):
        self.assertFalse(server.verify_pw("x", "not-hex", "deadbeef"))


class TestPasswordPolicy(unittest.TestCase):
    def test_rejects_short(self):
        self.assertIsNotNone(server.password_problem("short", "u"))

    def test_rejects_reusing_the_bootstrap_password(self):
        """The whole point of the forced change is to retire this exact string."""
        self.assertIsNotNone(server.password_problem(server.SEED_PASS, "u"))

    def test_rejects_password_equal_to_username(self):
        self.assertIsNotNone(server.password_problem("Mavrone12345", "mavrone12345"))

    def test_accepts_a_reasonable_password(self):
        self.assertIsNone(server.password_problem("a-long-enough-one", "Mavrone"))


class TestSessions(unittest.TestCase):
    def setUp(self):
        server._SESSIONS.clear()

    def test_unknown_token_has_no_user(self):
        self.assertIsNone(server.session_user("nope"))
        self.assertIsNone(server.session_user(""))
        self.assertIsNone(server.session_user(None))

    def test_session_roundtrip(self):
        self.assertEqual(server.session_user(server.new_session("Mavrone")), "Mavrone")

    def test_expired_session_is_rejected_and_dropped(self):
        tok = server.new_session("Mavrone")
        server._SESSIONS[tok]["ts"] -= server.SESSION_TTL + 1
        self.assertIsNone(server.session_user(tok))
        self.assertNotIn(tok, server._SESSIONS)

    def test_tokens_are_unguessable(self):
        toks = {server.new_session("u") for _ in range(200)}
        self.assertEqual(len(toks), 200)
        self.assertGreaterEqual(min(len(t) for t in toks), 32)

    def test_credential_change_evicts_every_session(self):
        """Otherwise a stolen cookie outlives the password change made to
        revoke it."""
        a, b = server.new_session("Mavrone"), server.new_session("Mavrone")
        server.drop_all_sessions()
        self.assertIsNone(server.session_user(a))
        self.assertIsNone(server.session_user(b))


class TestLoginThrottle(unittest.TestCase):
    def setUp(self):
        server._LOGIN_FAILS.clear()

    def test_not_throttled_initially(self):
        self.assertFalse(server.login_throttled("1.2.3.4", now=1000))

    def test_throttles_after_repeated_failures(self):
        for _ in range(server.LOGIN_MAX_FAILS):
            server.note_login_fail("1.2.3.4", now=1000)
        self.assertTrue(server.login_throttled("1.2.3.4", now=1000))

    def test_throttle_window_expires(self):
        for _ in range(server.LOGIN_MAX_FAILS):
            server.note_login_fail("1.2.3.4", now=1000)
        self.assertFalse(server.login_throttled("1.2.3.4",
                                                now=1000 + server.LOGIN_WINDOW + 1))

    def test_success_clears_the_counter(self):
        server.note_login_fail("1.2.3.4", now=1000)
        server.clear_login_fails("1.2.3.4")
        self.assertFalse(server.login_throttled("1.2.3.4", now=1000))

    def test_throttle_is_per_ip(self):
        for _ in range(server.LOGIN_MAX_FAILS):
            server.note_login_fail("1.2.3.4", now=1000)
        self.assertFalse(server.login_throttled("5.6.7.8", now=1000))


class TestPathAllowlist(unittest.TestCase):
    def test_source_backups_and_database_are_not_routable(self):
        """Serving a directory would expose .bak files, the SQLite database and
        this source -- and the target list names every host we own."""
        for p in ("/server.py", "/targets.json", "/targets.json.bak",
                  "/../etc/passwd", "/data/netmap.db", "/auth.json"):
            self.assertNotIn(p, server.STATIC)
            self.assertNotIn(p, server.API_GET)
            self.assertNotIn(p, server.API_POST)

    def test_only_login_and_health_are_open(self):
        self.assertEqual(set(server.OPEN_PATHS), {"/login", "/api/health"})

    def test_bad_path_regex_catches_crlf_and_whitespace(self):
        for p in ("/api/status\r\nX: 1", "/api/ status", "/api/status\n"):
            self.assertTrue(server._BADPATH.search(p), p)
        self.assertIsNone(server._BADPATH.search("/api/status?window=3600"))


class TestLiveAuthFlow(unittest.TestCase):
    """WIRING, end to end: boots the real server and drives it over HTTP.

    Every assertion below passes trivially against a server that simply never
    checks anything -- except that each one demands a SPECIFIC status code, so
    an unwired gate returns 200 where 401/403 is required and the test fails.
    This is the class that proves the lock is actually on the door."""

    @classmethod
    def setUpClass(cls):
        import http.server as hs
        import threading
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.tmp.name
        cls._saved = {k: getattr(server, k) for k in
                      ("DATA_DIR", "AUTH_PATH", "LIVE_TARGETS", "SEED_TARGETS",
                       "ACKS_PATH", "PUSH_PATH", "DB_PATH", "PUSH_TOKEN")}
        server.DATA_DIR = d
        server.AUTH_PATH = os.path.join(d, "auth.json")
        server.LIVE_TARGETS = os.path.join(d, "targets.json")
        server.SEED_TARGETS = os.path.join(d, "seed.json")
        server.ACKS_PATH = os.path.join(d, "acks.json")
        server.PUSH_PATH = os.path.join(d, "push.json")
        server.DB_PATH = os.path.join(d, "netmap.db")
        server.PUSH_TOKEN = "test-push-token"
        server._SESSIONS.clear()
        server._LOGIN_FAILS.clear()
        server.STATE["snapshot"] = []
        cls.srv = hs.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        for k, v in cls._saved.items():
            setattr(server, k, v)
        cls.tmp.cleanup()

    # -- tiny HTTP client (no redirect following, so we can assert on 303) ---
    def req(self, method, path, body=None, cookie=None, ctype=None, headers=None):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if cookie:
            h["Cookie"] = f"{server.COOKIE}={cookie}"
        if body is not None and ctype:
            h["Content-Type"] = ctype
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        out = (r.status, dict(r.getheaders()), data)
        c.close()
        return out

    def form(self, path, fields, cookie=None):
        import urllib.parse as up
        return self.req("POST", path, up.urlencode(fields), cookie,
                        "application/x-www-form-urlencoded")

    def cookie_from(self, headers):
        sc = headers.get("Set-Cookie", "")
        return sc.split(";")[0].split("=", 1)[1] if "=" in sc.split(";")[0] else ""

    def login(self, user, pw):
        st, hd, _ = self.form("/login", {"user": user, "pass": pw})
        return st, hd, self.cookie_from(hd)

    # -- the flow -----------------------------------------------------------
    def test_01_board_is_not_served_without_a_session(self):
        st, _, _ = self.req("GET", "/")
        self.assertEqual(st, 401)

    def test_02_api_is_not_served_without_a_session(self):
        for p in ("/api/status", "/api/targets", "/api/overview", "/api/events"):
            st, _, _ = self.req("GET", p, headers={"Accept": "application/json"})
            self.assertEqual(st, 401, p)

    def test_03_health_is_open_but_says_nothing_about_the_fleet(self):
        st, _, body = self.req("GET", "/api/health")
        self.assertEqual(st, 200)
        j = json.loads(body)
        self.assertNotIn("hosts", j)
        self.assertNotIn("targets", j)

    def test_04_wrong_password_is_rejected(self):
        st, _, _ = self.login("Mavrone", "wrong-password")
        self.assertEqual(st, 401)

    def test_05_unknown_user_is_rejected(self):
        st, _, _ = self.login("root", server.SEED_PASS)
        self.assertEqual(st, 401)

    def test_06_bootstrap_login_lands_on_the_change_form(self):
        st, hd, tok = self.login("Mavrone", server.SEED_PASS)
        self.assertEqual(st, 303)
        self.assertEqual(hd.get("Location"), "/change")
        self.assertTrue(tok)
        self.assertIn("HttpOnly", hd.get("Set-Cookie", ""))
        self.assertIn("SameSite=Strict", hd.get("Set-Cookie", ""))

    def test_07_bootstrap_session_cannot_reach_the_board(self):
        """A session holding the default credential is routed to /change and
        NOWHERE else -- that is what makes the change mandatory rather than
        merely suggested."""
        _, _, tok = self.login("Mavrone", server.SEED_PASS)
        st, hd, _ = self.req("GET", "/", cookie=tok)
        self.assertEqual(st, 303)
        self.assertEqual(hd.get("Location"), "/change")
        st, _, _ = self.req("GET", "/api/status", cookie=tok,
                            headers={"Accept": "application/json"})
        self.assertEqual(st, 403)

    def test_08_change_form_is_reachable_with_the_bootstrap_session(self):
        _, _, tok = self.login("Mavrone", server.SEED_PASS)
        st, _, body = self.req("GET", "/change", cookie=tok)
        self.assertEqual(st, 200)
        self.assertIn(b"Current password", body)

    def test_09_change_rejects_a_weak_or_reused_password(self):
        _, _, tok = self.login("Mavrone", server.SEED_PASS)
        for pw in ("short", server.SEED_PASS):
            st, _, _ = self.form("/api/credentials",
                                 {"user": "Mavrone", "current": server.SEED_PASS,
                                  "new": pw, "confirm": pw}, cookie=tok)
            self.assertEqual(st, 400, pw)

    def test_10_change_rejects_a_wrong_current_password(self):
        _, _, tok = self.login("Mavrone", server.SEED_PASS)
        st, _, _ = self.form("/api/credentials",
                             {"user": "Mavrone", "current": "not-it",
                              "new": "a-good-long-one", "confirm": "a-good-long-one"},
                             cookie=tok)
        self.assertEqual(st, 401)

    def test_11_change_rejects_mismatched_confirmation(self):
        _, _, tok = self.login("Mavrone", server.SEED_PASS)
        st, _, _ = self.form("/api/credentials",
                             {"user": "Mavrone", "current": server.SEED_PASS,
                              "new": "a-good-long-one", "confirm": "a-different-one"},
                             cookie=tok)
        self.assertEqual(st, 400)

    def test_12_successful_change_then_old_credentials_are_dead(self):
        _, _, tok = self.login("Mavrone", server.SEED_PASS)
        st, hd, _ = self.form("/api/credentials",
                              {"user": "samuel", "current": server.SEED_PASS,
                               "new": "a-properly-long-secret",
                               "confirm": "a-properly-long-secret"}, cookie=tok)
        self.assertEqual(st, 303)
        self.assertEqual(hd.get("Location"), "/login")
        # the session that made the change is evicted too
        st, _, _ = self.req("GET", "/api/status", cookie=tok,
                            headers={"Accept": "application/json"})
        self.assertEqual(st, 401)
        # old credential no longer works, under either username
        self.assertEqual(self.login("Mavrone", server.SEED_PASS)[0], 401)
        self.assertEqual(self.login("samuel", server.SEED_PASS)[0], 401)

    def test_13_new_credentials_reach_the_board(self):
        st, hd, tok = self.login("samuel", "a-properly-long-secret")
        self.assertEqual(st, 303)
        self.assertEqual(hd.get("Location"), "/",
                         "must_change should be cleared, so no /change redirect")
        st, _, body = self.req("GET", "/api/status", cookie=tok,
                               headers={"Accept": "application/json"})
        self.assertEqual(st, 200)
        self.assertIn("hosts", json.loads(body))

    def test_14_logout_invalidates_the_session(self):
        _, _, tok = self.login("samuel", "a-properly-long-secret")
        st, _, _ = self.req("POST", "/logout", cookie=tok)
        self.assertEqual(st, 303)
        st, _, _ = self.req("GET", "/api/status", cookie=tok,
                            headers={"Accept": "application/json"})
        self.assertEqual(st, 401)

    def test_15_push_ingest_requires_its_token(self):
        """An open ingest endpoint lets anyone paint the board green, which is
        strictly worse than no monitoring."""
        payload = json.dumps({"agent": "t", "results":
                              [{"ip": "10.0.0.1", "port": 80, "up": True}]})
        st, _, _ = self.req("POST", "/api/probe-push", payload, ctype="application/json")
        self.assertEqual(st, 401)
        st, _, _ = self.req("POST", "/api/probe-push", payload,
                            ctype="application/json",
                            headers={"X-Push-Token": "wrong"})
        self.assertEqual(st, 401)
        st, _, body = self.req("POST", "/api/probe-push", payload,
                               ctype="application/json",
                               headers={"X-Push-Token": "test-push-token"})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["accepted"], 1)

    def test_16_push_does_not_accept_a_user_session_instead_of_a_token(self):
        _, _, tok = self.login("samuel", "a-properly-long-secret")
        st, _, _ = self.req("POST", "/api/probe-push",
                            json.dumps({"results": []}), cookie=tok,
                            ctype="application/json")
        self.assertEqual(st, 401)

    def test_17_unknown_paths_404_rather_than_leaking_files(self):
        _, _, tok = self.login("samuel", "a-properly-long-secret")
        for p in ("/server.py", "/auth.json", "/targets.json", "/data/netmap.db"):
            st, _, _ = self.req("GET", p, cookie=tok)
            self.assertEqual(st, 404, p)

    def test_18_crlf_in_path_is_rejected(self):
        st, _, _ = self.req("GET", "/api/status%0d%0aX-Injected:%201")
        self.assertIn(st, (400, 401, 404))

    def test_19_oversized_body_is_refused(self):
        """Either a 413 or a dropped connection counts -- both are a refusal.

        The server rejects an oversized body WITHOUT draining it and then closes
        the connection, because leftover bytes would be parsed as the next
        request line on a keep-alive connection. That means the client can lose
        the socket while it is still writing, and never get to read a status.
        Asserting only on the status code made this test fail intermittently
        under load -- it was racing the server's own correct behaviour.

        What must never happen is the payload being ACCEPTED, so that is what
        is actually asserted."""
        _, _, tok = self.login("samuel", "a-properly-long-secret")
        big = json.dumps([{"ip": "10.0.0.1", "port": 80}] * 60000)
        self.assertGreater(len(big), server.MAX_POST, "payload must exceed the cap")
        try:
            st, _, _ = self.req("POST", "/api/targets", big, cookie=tok,
                                ctype="application/json")
        except (BrokenPipeError, ConnectionResetError, OSError):
            return                      # connection dropped mid-send = refused
        self.assertIn(st, (400, 413))
        self.assertNotEqual(st, 200, "an oversized target list was accepted")

    def test_20_probe_endpoint_refuses_hosts_not_on_the_target_list(self):
        """An authenticated arbitrary-connect endpoint is a port scanner with
        our source address on it."""
        _, _, tok = self.login("samuel", "a-properly-long-secret")
        st, _, _ = self.req("GET", "/api/probe?ip=192.0.2.1&port=22", cookie=tok,
                            headers={"Accept": "application/json"})
        self.assertEqual(st, 404)

    def test_21_target_editor_round_trips_and_rejects_bad_input(self):
        _, _, tok = self.login("samuel", "a-properly-long-secret")
        good = json.dumps([{"ip": "10.0.0.7", "port": 443, "label": "x",
                            "seg": "s", "opts": {"m": "tcp"}}])
        st, _, _ = self.req("POST", "/api/targets", good, cookie=tok,
                            ctype="application/json")
        self.assertEqual(st, 200)
        st, _, body = self.req("GET", "/api/targets", cookie=tok,
                               headers={"Accept": "application/json"})
        self.assertEqual(json.loads(body)["targets"][0]["ip"], "10.0.0.7")
        bad = json.dumps([{"ip": "!!bad", "port": 1}])
        st, _, _ = self.req("POST", "/api/targets", bad, cookie=tok,
                            ctype="application/json")
        self.assertEqual(st, 400)


# ---------------------------------------------------------------------------
# §5 order stability
# ---------------------------------------------------------------------------
class TestSnapshotOrder(unittest.TestCase):
    def test_snapshot_preserves_target_order(self):
        """ex.map preserves input order so rows do not jump around between
        cycles. This asserts the contract run_cycle relies on."""
        ts = [target(ip=f"10.0.0.{i}") for i in range(1, 12)]
        snap = server.run_cycle(ts, None, {}, now=1000, push_store={})
        self.assertEqual([r["ip"] for r in snap], [t["ip"] for t in ts])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestInvertedTargets(unittest.TestCase):
    """A port that must STAY closed. Without this, "closed" and "nobody
    checked" look identical on the board."""

    def test_refused_port_reads_up_when_inverted(self):
        # port 1 on localhost: nothing listens, connection refused
        r = server.probe_tcp("127.0.0.1", 1, {"invert": True})
        self.assertTrue(r["up"])
        self.assertIn("closed", r["detail"])

    def test_open_port_reads_down_when_inverted(self):
        import socket as _s
        srv = _s.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            r = server.probe_tcp("127.0.0.1", srv.getsockname()[1], {"invert": True})
            self.assertFalse(r["up"], "an open port must be a FAULT when inverted")
            self.assertIn("must be closed", r["detail"])
        finally:
            srv.close()

    def test_normal_mode_is_unaffected(self):
        self.assertFalse(server.probe_tcp("127.0.0.1", 1, {})["up"])


class TestGroupingFields(unittest.TestCase):
    """`srv` and `co` drive the card board's server/company grouping. They were
    being silently STRIPPED by validate_targets, which builds its output dict
    field by field -- so a target could carry them, pass validation, and arrive
    at the UI without them. Nothing would error; the board would just quietly
    lump everything under one heading."""

    def test_srv_and_co_survive_validation(self):
        ts, errs = server.validate_targets([{
            "ip": "10.0.0.1", "port": 443, "label": "x", "seg": "s",
            "srv": "app-165 (165.22.246.45)", "co": "Bevora",
            "opts": {"m": "https"}}])
        self.assertEqual(errs, [])
        self.assertEqual(ts[0]["srv"], "app-165 (165.22.246.45)")
        self.assertEqual(ts[0]["co"], "Bevora")

    def test_absent_grouping_fields_are_simply_absent(self):
        """The UI derives a fallback, so validation must not invent one here --
        two different defaults in two places is how they drift apart."""
        ts, _ = server.validate_targets([{"ip": "10.0.0.1", "port": 80}])
        self.assertNotIn("srv", ts[0])
        self.assertNotIn("co", ts[0])

    def test_grouping_fields_are_length_capped(self):
        ts, _ = server.validate_targets([{"ip": "10.0.0.1", "port": 80,
                                          "srv": "s" * 500, "co": "c" * 500}])
        self.assertLessEqual(len(ts[0]["srv"]), 60)
        self.assertLessEqual(len(ts[0]["co"]), 60)

    def test_every_seeded_target_declares_both(self):
        """A target without them lands in an 'unassigned' bucket on the board,
        which is exactly the flat list the cards replaced."""
        missing = [t["label"] for t in server.BUILTIN_TARGETS
                   if not t.get("srv") or not t.get("co")]
        self.assertEqual(missing, [])

    def test_seed_covers_exactly_the_three_servers(self):
        self.assertEqual(
            len({t["srv"] for t in server.BUILTIN_TARGETS}), 3,
            "the fleet is three machines; a fourth grouping means a typo")


class TestBrandingOnAuthPages(unittest.TestCase):
    """/login and /change are rendered from a Python template, not index.html,
    so they missed the favicon and logo entirely -- and they are the first (and
    for anyone without an account, only) page the tool ever shows."""

    def test_login_page_carries_favicon_and_mark(self):
        pg = server.login_page().decode()
        self.assertIn('rel="icon"', pg)
        self.assertIn('class="mark"', pg)

    def test_change_page_carries_favicon_and_mark(self):
        pg = server.change_page("someone").decode()
        self.assertIn('rel="icon"', pg)
        self.assertIn('class="mark"', pg)

    def test_no_template_escaping_artifacts_leak(self):
        """The template is %-formatted, so every literal % in the inlined SVG
        and CSS must be doubled. A single missed one raises at render time; a
        doubled one that should not be renders as a stray '%%' on the page."""
        for pg in (server.login_page().decode(),
                   server.change_page("x", err="bad", forced=True).decode()):
            self.assertNotIn("%%", pg)
            self.assertNotIn("%(", pg)

    def test_error_text_is_escaped_not_injected(self):
        pg = server.change_page("x", err="<script>alert(1)</script>").decode()
        self.assertNotIn("<script>alert(1)</script>", pg)
        self.assertIn("&lt;script&gt;", pg)

    def test_username_is_escaped_in_the_change_form(self):
        pg = server.change_page('" onload="x').decode()
        self.assertNotIn('" onload="x', pg)


class TestDeployedVersion(unittest.TestCase):
    """`/api/health` reports the commit being served, so "is the box running
    what I pushed?" is answerable without SSH. This project has had to answer
    that question the hard way more than once."""

    def test_reads_a_sha_from_a_loose_ref(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".git", "refs", "heads"))
            with open(os.path.join(d, ".git", "HEAD"), "w") as fh:
                fh.write("ref: refs/heads/main\n")
            with open(os.path.join(d, ".git", "refs", "heads", "main"), "w") as fh:
                fh.write("abcdef1234567890abcdef1234567890abcdef12\n")
            old = server.APP_DIR
            try:
                server.APP_DIR = d
                self.assertEqual(server.deployed_version(), "abcdef12")
            finally:
                server.APP_DIR = old

    def test_reads_a_detached_head(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".git"))
            with open(os.path.join(d, ".git", "HEAD"), "w") as fh:
                fh.write("0123456789abcdef0123456789abcdef01234567\n")
            old = server.APP_DIR
            try:
                server.APP_DIR = d
                self.assertEqual(server.deployed_version(), "01234567")
            finally:
                server.APP_DIR = old

    def test_missing_git_returns_unknown_rather_than_raising(self):
        """A tarball deploy has no .git. That is not a reason to fail a health
        check -- health is about the process being alive."""
        with tempfile.TemporaryDirectory() as d:
            old = server.APP_DIR
            try:
                server.APP_DIR = d
                self.assertEqual(server.deployed_version(), "unknown")
            finally:
                server.APP_DIR = old

    def test_health_still_leaks_nothing_about_the_fleet(self):
        """This endpoint is unauthenticated. Adding `version` must not have
        turned it into an inventory disclosure."""
        import inspect
        src = inspect.getsource(server.Handler._api_get) + \
              inspect.getsource(server.Handler.do_GET)
        i = src.index('path == "/api/health"')
        block = src[i:i + 400]
        for leaky in ("hosts", "targets", "snapshot", "BUILTIN"):
            self.assertNotIn(leaky, block, f"/api/health exposes {leaky}")


class TestVersionIsSnapshotted(unittest.TestCase):
    """`/api/health` must report the RUNNING code, not the checked-out code.

    The deploy does `git reset --hard` and only then restarts the container, so
    a per-request read of .git returns the new SHA from a process still running
    the old one. The window is seconds long and falls exactly when somebody is
    watching a deploy -- the only time this field is ever read."""

    def test_version_is_captured_at_import(self):
        self.assertTrue(server.VERSION)
        self.assertIsInstance(server.VERSION, str)

    def test_snapshot_does_not_follow_a_later_checkout(self):
        before = server.VERSION
        old = server.APP_DIR
        try:
            with tempfile.TemporaryDirectory() as d:
                server.APP_DIR = d          # simulate .git changing under us
                self.assertEqual(server.deployed_version(), "unknown",
                                 "a live read should follow the change")
                self.assertEqual(server.VERSION, before,
                                 "the snapshot must NOT follow it")
        finally:
            server.APP_DIR = old

    def test_health_serves_the_snapshot_not_a_live_read(self):
        """Guards the wiring: reverting `VERSION` to `deployed_version()` in the
        handler would pass every other test in this class."""
        import inspect
        src = inspect.getsource(server.Handler.do_GET)
        # Match the expression itself rather than slicing N characters after a
        # marker: the first version of this test took a 300-char window that the
        # surrounding comments filled entirely, so it asserted against comment
        # text and failed identically whether the code was right or sabotaged.
        # A test that fails for the wrong reason proves nothing -- it just looks
        # like it is working.
        self.assertIn('"version": VERSION', src,
                      "health must serve the import-time snapshot")
        self.assertNotIn('"version": deployed_version()', src,
                         "health must not re-read .git per request")


def _load_agent():
    import importlib.util
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent", "push-agent.py")
    spec = importlib.util.spec_from_file_location("push_agent", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestPushAgentProbe(unittest.TestCase):
    """The agent is the ONLY thing watching 26 loopback services on gadonghr,
    so its probe has to be as strict as the server's. An agent that reported
    bare TCP reachability would reproduce, on the pushed half of the board,
    exactly the weakness the central prober exists to avoid."""

    @classmethod
    def setUpClass(cls):
        cls.agent = _load_agent()

    def _serve(self, response, requests):
        """Minimal one-shot HTTP server; records the request line it received."""
        import socket as s, threading
        srv = s.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        def run():
            try:
                c, _ = srv.accept()
                requests.append(c.recv(512))
                if response is not None:
                    c.sendall(response)
                c.close()
            except Exception:
                pass
            finally:
                srv.close()
        threading.Thread(target=run, daemon=True).start()
        return srv.getsockname()[1]

    def test_http_mode_reads_the_status_line(self):
        reqs = []
        port = self._serve(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", reqs)
        r = self.agent.probe({"ip": "127.0.0.1", "port": port, "m": "http",
                              "path": "/health", "expect": [200]})
        self.assertTrue(r["up"])
        self.assertEqual(r["code"], 200)

    def test_it_requests_the_configured_path(self):
        """These backends answer /health with 200 and / with 404 -- probing the
        wrong path would mark every one of them down."""
        reqs = []
        port = self._serve(b"HTTP/1.1 200 OK\r\n\r\n", reqs)
        self.agent.probe({"ip": "127.0.0.1", "port": port, "m": "http",
                          "path": "/health", "expect": [200]})
        self.assertIn(b"GET /health ", reqs[0])

    def test_a_listening_socket_that_never_answers_is_DOWN(self):
        """The bevops-web failure, exactly: accepts the connection, returns no
        bytes. A tcp probe calls that UP."""
        reqs = []
        port = self._serve(None, reqs)          # accepts, sends nothing
        r = self.agent.probe({"ip": "127.0.0.1", "port": port, "m": "http",
                              "path": "/health", "expect": [200]}, timeout=2)
        self.assertFalse(r["up"], "a silent socket must not be reported up")

    def test_unexpected_status_is_DOWN(self):
        reqs = []
        port = self._serve(b"HTTP/1.1 503 Service Unavailable\r\n\r\n", reqs)
        r = self.agent.probe({"ip": "127.0.0.1", "port": port, "m": "http",
                              "path": "/health", "expect": [200]})
        self.assertFalse(r["up"])

    def test_refused_connection_is_DOWN(self):
        r = self.agent.probe({"ip": "127.0.0.1", "port": 1, "m": "http"}, timeout=2)
        self.assertFalse(r["up"])

    def test_tcp_mode_still_available_for_databases(self):
        reqs = []
        port = self._serve(None, reqs)
        r = self.agent.probe({"ip": "127.0.0.1", "port": port, "m": "tcp"})
        self.assertTrue(r["up"], "postgres speaks no HTTP; tcp is correct there")

    def test_targets_are_data_not_code(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "t.json")
            with open(f, "w") as fh:
                json.dump([{"ip": "10.0.0.1", "port": 80, "m": "tcp"}], fh)
            self.assertEqual(self.agent.load_targets(f)[0]["ip"], "10.0.0.1")


class TestPushedRowsGoStale(unittest.TestCase):
    """The whole safety property of push mode, now that 26 real services depend
    on it: if the agent dies, its rows must go STALE, not stay green."""

    def test_fresh_then_stale(self):
        store = {"10.104.0.4:4100": {"up": True, "ms": 3, "ts": 1000}}
        fresh = server.probe_push("10.104.0.4", 4100, {}, push_store=store, now=1100)
        self.assertTrue(fresh["up"])
        dead = server.probe_push("10.104.0.4", 4100, {}, push_store=store,
                                 now=1000 + server.PUSH_TTL + 1)
        self.assertFalse(dead["up"], "a dead agent must not look like uptime")
        self.assertTrue(dead["stale"])

    def test_every_seeded_push_target_is_in_the_internal_segment(self):
        push = [t for t in server.BUILTIN_TARGETS
                if (t.get("opts") or {}).get("m") == "push"]
        self.assertTrue(push, "the push targets went missing from the seed")
        for t in push:
            self.assertEqual(t["seg"], "gadonghr-internal")
            self.assertTrue(t["ip"].startswith("10.104."),
                            "pushed rows must carry the HOST identity, not loopback")


class TestNoUnscopedElementLayoutRules(unittest.TestCase):
    """A bare `svg{min-width:660px}` — written for the topology diagram — also
    matched the 26px header logo and blew it up to 660px square on the live
    board. Element selectors carrying layout constraints find every other
    element of that type on the page."""

    def _css(self):
        s = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "index.html"), encoding="utf-8").read()
        return s[s.index("<style>"):s.index("</style>")]

    def test_no_bare_media_element_selector_sets_a_size(self):
        import re
        css = self._css()
        for m in re.finditer(r"(?m)^(svg|img|canvas|video|iframe|figure)\s*\{([^}]*)\}", css):
            tag, body = m.group(1), m.group(2)
            for prop in ("min-width", "min-height", "width:", "height:"):
                if prop in body and "auto" not in body.split(prop)[1][:12]:
                    self.fail(f"bare `{tag}{{}}` sets {prop} — scope it to an id/class")

    def test_the_topology_rule_is_scoped(self):
        css = self._css()
        self.assertIn("#topo svg{", css)
        self.assertNotIn("\nsvg{", css, "the unscoped svg rule is back")

    def test_header_logo_declares_its_own_size(self):
        s = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "index.html"), encoding="utf-8").read()
        i = s.index('class="logo"')
        self.assertRegex(s[i:i + 200], r'width="\d+"\s+height="\d+"')
