#!/usr/bin/env python3
"""Tests for the thread-safety / rotation bookkeeping of macstalker.Rotator.

These tests run without touching the network or the real ``nordvpn`` CLI:
``rotate_nordvpn`` and ``current_ip`` are patched out. Run with:

    python3 -m unittest test_macstalker -v
    # or
    python3 test_macstalker.py
"""

import threading
import time
import unittest
from unittest import mock

import macstalker
from macstalker import Rotator


def wait_until(cond, timeout=5):
    """Block until ``cond()`` is true (polling), for asserting on background
    threads."""
    deadline = time.time() + timeout
    while not cond():
        if time.time() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.01)


def make_rotator(countries=("DE", "NL", "FR"), requests_per_ip=None,
                 prefetch=True):
    """Build a Rotator without touching the real nordvpn country list.

    ``country`` is left as None so the (patched) country list is used whole,
    giving us more than one country to round-robin over. Tests that rely on
    the exact legacy slot/rotation math pass ``prefetch=False`` so rotations
    happen inline and deterministically.
    """
    with mock.patch.object(macstalker, "nordvpn_countries", return_value=list(countries)):
        r = Rotator(country=None, requests_per_ip=requests_per_ip,
                    prefetch=prefetch)
    return r


class BeginRequestTests(unittest.TestCase):
    """``begin_request`` is a *barrier* for a single NordVPN tunnel.

    It blocks until the current source IP's budget has a free slot, then takes
    that slot and returns ``None`` (workers ignore the value). The observable
    effects are the per-IP counter and, once ``requests_per_ip`` requests have
    been taken, a rotation to a fresh IP on the next call. That guarantees we
    never fire past the WAF ceiling onto an already-burning IP.
    """

    def test_rotates_once_budget_exhausted(self):
        r = make_rotator(requests_per_ip=3, prefetch=False)
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            r.begin_request()          # 1/3
            r.begin_request()          # 2/3
            r.begin_request()          # 3/3 -> budget now full
            self.assertEqual(r.rotations, 0)
            r.begin_request()          # budget full -> rotate, take fresh slot
            self.assertEqual(r.rotations, 1)
        self.assertEqual(r.current, "ip1")

    def test_counter_resets_after_rotation(self):
        r = make_rotator(requests_per_ip=2, prefetch=False)
        with mock.patch.object(macstalker, "rotate_nordvpn",
                               side_effect=["ipA", "ipB"]):
            r.begin_request()          # 1/2
            r.begin_request()          # 2/2 -> budget full
            r.begin_request()          # full -> rotate ipA, counter reset -> 1/2
            self.assertEqual(r.rotations, 1)
            r.begin_request()          # 2/2 -> budget full
            r.begin_request()          # full -> rotate ipB, counter reset -> 1/2
        self.assertEqual(r.rotations, 2)
        self.assertEqual(r.current, "ipB")

    def test_no_counter_when_requests_per_ip_is_none(self):
        r = make_rotator(requests_per_ip=None)
        with mock.patch.object(macstalker, "rotate_nordvpn"):
            # Without a budget, begin_request never proactively rotates.
            for _ in range(50):
                r.begin_request()
        self.assertEqual(r.rotations, 0)


class ReportBlockedTests(unittest.TestCase):
    def test_report_blocked_rotates_to_fresh_ip(self):
        r = make_rotator()
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            r.report_blocked()
        self.assertEqual(r.rotations, 1)
        self.assertEqual(r.current, "ip1")

    def test_report_blocked_sequential_calls_each_rotate(self):
        """Sequential report_blocked calls each rotate: ``_rotate`` clears
        ``_dirty``, so burst-suppression only kicks in under real concurrency
        (multiple reporters reading the flag before the first rotation lands)."""
        r = make_rotator()
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            r.report_blocked()
            r.report_blocked()
            r.report_blocked()
        self.assertEqual(r.rotations, 3)
        self.assertFalse(r._dirty)

    def test_begin_request_after_block_rotates_and_clears_dirty(self):
        r = make_rotator()
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            r.report_blocked()              # dirty -> rotate
            self.assertFalse(r._dirty)
            self.assertFalse(r.begin_request())  # nothing pending now
        self.assertEqual(r.rotations, 1)


class BarrierConcurrencyTests(unittest.TestCase):
    """Workers parked on the rotation barrier wake the instant a rotation
    bumps the generation (no busy-polling, no lost wakeups)."""

    def test_parked_workers_wake_on_rotation(self):
        r = make_rotator(requests_per_ip=1)
        gate = threading.Event()

        def fake_rotate(country, avoid_ip=None):
            gate.wait(timeout=10)        # hold the rotation open
            return "ip1"

        with mock.patch.object(macstalker, "rotate_nordvpn",
                               side_effect=fake_rotate):
            r.begin_request()            # take the only slot; prefetch spawns
            wait_until(lambda: r._dirty)  # a background rotation (in flight)
            results = []
            worker = lambda: results.append(r.begin_request())
            threads = [threading.Thread(target=worker) for _ in range(4)]
            for t in threads:
                t.start()
            time.sleep(0.1)              # let them all park on the barrier
            self.assertEqual(results, [])
            gate.set()                   # rotation lands -> generation bump
            for t in threads:
                t.join(timeout=10)
            # Drain every background rotation the rerequests triggered, so
            # none of them outlives the mock context below.
            wait_until(lambda: r.rotations >= 5)
        self.assertEqual(len(results), 4)

    def test_concurrent_callers_never_overshoot_budget(self):
        """No more than requests_per_ip slots are ever handed out per
        generation, no matter how the threads interleave.

        Prefetch is disabled: with it on, a background rotation can reset the
        counter mid-generation, so the exact slot math below no longer holds
        (see BarrierConcurrencyTests.test_concurrent_with_prefetch)."""
        r = make_rotator(requests_per_ip=3, prefetch=False)
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            errors = []

            def worker():
                try:
                    for _ in range(5):
                        r.begin_request()
                except Exception as e:  # noqa: BLE001
                    errors.append(e)

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
        self.assertEqual(errors, [])
        # A generation yields exactly `requests_per_ip` slots, and a rotation
        # is only ever triggered by an exhausted budget, so the slot math is
        # exact: 20 calls = 6 rotations + 3 + 3 + 3 + 3 + 3 + 2.
        self.assertEqual(r.rotations, 6)
        self.assertEqual(r._used_this_ip, 2)


class PrefetchRotationTests(unittest.TestCase):
    """Rotation is prefetched in the BACKGROUND while the current IP still
    has budget left, so the barrier stall is hidden behind the scan."""

    def test_prefetch_kicks_off_rotation_early(self):
        r = make_rotator(requests_per_ip=3)
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            r.begin_request()          # 1/3
            r.begin_request()          # 2/3 -> prefetch spawns bg rotation
            self.assertTrue(r._dirty)  # a rotation is claimed
            wait_until(lambda: r.rotations == 1)   # bg rotation lands
            self.assertEqual(r._generation, 1)
            self.assertFalse(r._dirty)
            self.assertEqual(r._used_this_ip, 0)   # budget reset
        self.assertEqual(r.current, "ip1")

    def test_prefetch_barrier_hides_the_stall(self):
        """Once the prefetch rotation is in flight, a blocked worker returns
        as soon as it lands -- no inline rotation on the calling thread."""
        r = make_rotator(requests_per_ip=1)
        gate = threading.Event()

        def fake_rotate(country, avoid_ip=None):
            gate.wait(timeout=10)
            return "ip1"

        with mock.patch.object(macstalker, "rotate_nordvpn",
                               side_effect=fake_rotate):
            r.begin_request()          # slot 1/1 + bg rotation (held by gate)
            wait_until(lambda: r._dirty)
            gate.set()                 # let the bg rotation finish
            wait_until(lambda: r._generation == 1)
            t0 = time.time()
            r.begin_request()          # must NOT wait for any nordvpn call
            self.assertLess(time.time() - t0, 1.0)
            wait_until(lambda: r.rotations == 2)  # drain the bg rotation
        self.assertEqual(r.rotations, 2)

    def test_prefetch_disabled(self):
        r = make_rotator(requests_per_ip=3, prefetch=False)
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            r.begin_request()
            r.begin_request()
            time.sleep(0.05)
            self.assertFalse(r._dirty)
            self.assertEqual(r.rotations, 0)

    def test_concurrent_with_prefetch(self):
        """With prefetch on the exact slot math becomes timing-dependent
        (a background rotation can reset the counter mid-generation), so we
        only assert the invariants: no errors, no hang, and the rotation
        count stays within the bounds implied by the budget."""
        r = make_rotator(requests_per_ip=3)
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            errors = []

            def worker():
                for _ in range(5):
                    try:
                        r.begin_request()
                    except Exception as e:  # noqa: BLE001
                        errors.append(e)

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)
            # Drain the background rotation thread outliving the workers so
            # it doesn't outlive the mock context below.
            wait_until(lambda: r._rot_thread is None or
                       not r._rot_thread.is_alive(), timeout=10)
        self.assertEqual(errors, [])
        # 20 calls: each generation hands out at most 3 slots (prefetch can
        # only make generations shorter), so rotations is in [ceil(20/3), 10].
        self.assertGreaterEqual(r.rotations, 6)
        self.assertLessEqual(r.rotations, 10)
        self.assertLessEqual(r._used_this_ip, 2)


class PortalGatingTests(unittest.TestCase):
    """Every portal request consumes exactly one per-IP budget slot."""

    def test_action_consumes_budget(self):
        r = make_rotator(requests_per_ip=3, prefetch=False)
        p = macstalker.Portal("http://x", rotator=r)
        ok = mock.Mock(status_code=200, text="{}")
        with mock.patch.object(p, "_get", return_value=ok):
            for _ in range(3):
                p.action("00:1A:79:AA:00:01", "get_all_channels")
        self.assertEqual(r._used_this_ip, 3)

    def test_no_rotator_no_gating(self):
        p = macstalker.Portal("http://x", rotator=None)
        ok = mock.Mock(status_code=200, text="{}")
        with mock.patch.object(p, "_get", return_value=ok):
            p.action("00:1A:79:AA:00:01", "get_all_channels")


class RoundRobinTests(unittest.TestCase):
    def test_next_country_cycles(self):
        r = make_rotator(countries=("DE", "NL", "FR"))
        self.assertEqual(r._next_country(), "DE")
        self.assertEqual(r._next_country(), "NL")
        self.assertEqual(r._next_country(), "FR")
        self.assertEqual(r._next_country(), "DE")  # wraps around


class SerializationTests(unittest.TestCase):
    def test_rotations_are_serialized(self):
        """Only one blocking rotation may run at a time (the core fix)."""
        r = make_rotator()
        active = 0
        max_active = 0
        lock = threading.Lock()

        def fake_rotate(country, avoid_ip=None):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            threading.Event().wait(0.05)  # simulate a slow reconnect
            with lock:
                active -= 1
            return "ip"

        with mock.patch.object(macstalker, "rotate_nordvpn", side_effect=fake_rotate):
            threads = [threading.Thread(target=r.rotate) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(max_active, 1)      # never two rotations at once
        self.assertEqual(r.rotations, 8)     # all of them happened


if __name__ == "__main__":
    unittest.main(verbosity=2)
