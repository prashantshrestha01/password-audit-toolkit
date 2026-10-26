"""Tests for password_audit. The breach list used here is built from
hashes of well-known weak passwords, computed at test time -- nothing
is fetched online."""

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from password_audit import analyze, is_breached, load_hash_list, audit_file


def sha1(text):
    return hashlib.sha1(text.encode()).hexdigest()


class TestPasswordAudit(unittest.TestCase):
    def test_strong_long_random_beats_short_weak(self):
        strong = analyze("K7$mQ2!vX9#pL4&wR8")
        weak = analyze("password123")
        self.assertGreater(strong["score"], weak["score"])
        self.assertEqual(strong["verdict"], "Strong")
        self.assertEqual(weak["verdict"], "Weak")

    def test_keyboard_walk_penalty(self):
        result = analyze("qwertyuiop99!")
        self.assertTrue(any("keyboard walk" in p for p in result["penalties"]))

    def test_repeat_and_sequence_penalties(self):
        self.assertTrue(any("repeated" in p for p in analyze("aaabbbCCC11")["penalties"]))
        self.assertTrue(any("sequential" in p for p in analyze("abcXYZ99!")["penalties"]))

    def test_year_penalty(self):
        self.assertTrue(any("year" in p for p in analyze("Summer2020!")["penalties"]))

    def test_breach_check_local_only(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(sha1("password") + "\n" + sha1("123456") + "\n")
            path = fh.name
        try:
            hashes = load_hash_list(path)
            self.assertTrue(is_breached("password", hashes))
            self.assertFalse(is_breached("K7$mQ2!vX9#pL4&wR8", hashes))
        finally:
            os.unlink(path)

    def test_audit_file_uses_bundled_sample_list(self):
        sample = os.path.join(os.path.dirname(__file__), "..", "sample_hashes.txt")
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("password\nK7$mQ2!vX9#pL4&wR8\n")
            lst = fh.name
        try:
            results = audit_file(lst, sample)
        finally:
            os.unlink(lst)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0]["breached"])
        self.assertFalse(results[1]["breached"])


if __name__ == "__main__":
    unittest.main()
