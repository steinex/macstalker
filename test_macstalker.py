#!/usr/bin/env python3
"""Tests for the thread-safety / rotation bookkeeping of macstalker.Rotator.

These tests run without touching the network or the real ``nordvpn`` CLI:
``rotate_nordvpn`` and ``current_ip`` are patched out. Run with:

    python3 -m unittest test_macstalker -v
    # or
    python3 test_macstalker.py
"""

import threading
import unittest
from unittest import mock

import macstalker
from macstalker import Rotator


def make_rotator(countries=("DE", "NL", "FR"), requests_per_ip=None):
    """Build a Rotator without touching the real nordvpn country list.

    ``country`` is left as None so the (patched) country list is used whole,
    giving us more than one country to round-robin over.
    """
    with mock.patch.object(macstalker, "nordvpn_countries", return_value=list(countries)):
        r = Rotator(country=None, requests_per_ip=requests_per_ip)
    return r


class BeginRequestTests(unittest.TestCase):
    def test_returns_false_until_threshold(self):
        r = make_rotator(requests_per_ip=3)
        with mock.patch.object(macstalker, "rotate_nordvpn", return_value="ip1"):
            self.assertFalse(r.begin_request())  # 1/3
            self.assertFalse(r.begin_request())  # 2/3
            self.assertTrue(r.begin_request())   # 3/3 -> rotates
        self.assertEqual(r.rotations, 1)
        self.assertEqual(r.current, "ip1")

    def test_counter_resets_after_rotation(self):
        r = make_rotator(requests_per_ip=2)
        with mock.patch.object(macstalker, "rotate_nordvpn",
                               side_effect=["ipA", "ipB"]):
            r.begin_request()          # 1/2
            self.assertTrue(r.begin_request())   # 2/2 -> rotate -> ipA
            self.assertFalse(r.begin_request())  # counter reset, 1/2
            self.assertTrue(r.begin_request())   # 2/2 -> rotate -> ipB
        self.assertEqual(r.rotations, 2)
        self.assertEqual(r.current, "ipB")

    def test_no_counter_when_requests_per_ip_is_none(self):
        r = make_rotator(requests_per_ip=None)
        with mock.patch.object(macstalker, "rotate_nordvpn"):
            # Without a budget, begin_request never proactively rotates.
            for _ in range(50):
                self.assertFalse(r.begin_request())
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
