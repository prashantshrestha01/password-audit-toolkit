"""Defensive password auditing, stdlib only.

Scores a password's entropy with pattern penalties, and checks it
against a local hash list of known-breached passwords. Nothing is ever
sent online: the breach check is a local set lookup on SHA-1 hashes.

This tool is for auditing passwords you own or are authorized to test
(e.g. your own accounts, a lab list). It never cracks, guesses, or
exfiltrates anything.
"""

import argparse
import hashlib
import math
import re
import sys

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
COMMON_YEARS = re.compile(r"(19\d\d|20[0-2]\d)")


def charset_size(password):
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 32
    return size or 1


def _has_keyboard_walk(password):
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 2):
            if row[i:i + 3] in lowered or row[i:i + 3][::-1] in lowered:
                return True
    return False


def _has_repeat(password):
    return re.search(r"(.)\1{2,}", password) is not None


def _has_sequence(password):
    lowered = password.lower()
    for i in range(len(lowered) - 2):
        a, b, c = lowered[i:i + 3]
        if ord(b) == ord(a) + 1 and ord(c) == ord(b) + 1:
            return True
        if ord(b) == ord(a) - 1 and ord(c) == ord(b) - 1:
            return True
    return False


def analyze(password):
    """Return a dict: entropy_bits, penalties, score (0-100), verdict."""
    entropy = len(password) * math.log2(charset_size(password)) if password else 0.0
    penalties = []
    if len(password) < 12:
        penalties.append("short (< 12 characters)")
    if _has_keyboard_walk(password):
        penalties.append("keyboard walk (e.g. qwerty/asdf)")
    if _has_repeat(password):
        penalties.append("repeated character run")
    if _has_sequence(password):
        penalties.append("sequential characters (e.g. abc/123)")
    if COMMON_YEARS.search(password):
        penalties.append("contains a year (common in weak passwords)")
    if password.lower() in ("password", "letmein", "admin", "welcome"):
        penalties.append("well-known weak password")
    # Score: entropy scaled to 100, minus 12 per penalty, clamped.
    score = max(0, min(100, int(entropy * 1.25) - 12 * len(penalties)))
    if score >= 70:
        verdict = "Strong"
    elif score >= 40:
        verdict = "Fair"
    else:
        verdict = "Weak"
    return {
        "length": len(password),
        "entropy_bits": round(entropy, 1),
        "penalties": penalties,
        "score": score,
        "verdict": verdict,
    }


def load_hash_list(path):
    """Load a file of one hex hash per line (SHA-1, lowercase)."""
    hashes = set()
    with open(path) as fh:
        for line in fh:
            line = line.strip().lower()
            if line:
                hashes.add(line)
    return hashes


def is_breached(password, hash_set):
    """True if the password's SHA-1 appears in the local hash list."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest()
    return digest in hash_set


def audit_file(list_path, hash_path=None):
    """Audit one password per line. Returns list of result dicts."""
    hash_set = load_hash_list(hash_path) if hash_path else set()
    results = []
    with open(list_path) as fh:
        for line in fh:
            password = line.rstrip("\n")
            if not password:
                continue
            result = analyze(password)
            result["breached"] = is_breached(password, hash_set) if hash_set else False
            results.append(result)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit passwords locally: entropy score + breach check.")
    parser.add_argument("--password", help="audit a single password")
    parser.add_argument("--list", dest="list_path",
                        help="file with one password per line")
    parser.add_argument("--hash-file",
                        help="local breached-password SHA-1 list")
    args = parser.parse_args(argv)
    if args.password is not None:
        result = analyze(args.password)
        if args.hash_file:
            result["breached"] = is_breached(args.password, load_hash_list(args.hash_file))
        print(f"score {result['score']}/100 ({result['verdict']}), "
              f"entropy {result['entropy_bits']} bits, "
              f"penalties: {', '.join(result['penalties']) or 'none'}, "
              f"breached: {result.get('breached', 'not checked')}")
        return 0
    if args.list_path:
        try:
            results = audit_file(args.list_path, args.hash_file)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for result in results:
            print(f"{result['verdict']}: score {result['score']}/100, "
                  f"breached={result['breached']}, "
                  f"penalties={', '.join(result['penalties']) or 'none'}")
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
