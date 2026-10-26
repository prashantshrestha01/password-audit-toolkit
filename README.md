# password-audit-toolkit

Defensive password auditing: entropy scoring and breached-password checks for local password lists.

## What it does

`password_audit.py` audits passwords you own or are authorized to test:

- **Entropy/strength scoring** — charset-based entropy (bits) mapped to a 0–100 score and a Weak/Fair/Strong verdict
- **Pattern penalties** — keyboard walks (`qwerty`, `asdf`), repeated character runs, sequential characters (`abc`, `123`), and years (`1990`, `2020`), each explained in the output
- **Breached-password checking** — the password's SHA-1 is looked up in a local hash list only; nothing is ever sent online

## Quick start

```bash
python3 password_audit.py --password 'Summer2020!'
python3 password_audit.py --list passwords.txt --hash-file sample_hashes.txt
```

No third-party packages are needed. Python 3.8+ only.

## Usage

```
python3 password_audit.py --password <password>
python3 password_audit.py --list <file> [--hash-file <hashes.txt>]
```

The hash file is one SHA-1 hex digest per line. `sample_hashes.txt` ships a small list of well-known weak-password hashes for testing.

## Layout

```
password_audit.py   # scoring + penalties + local breach check (stdlib only)
sample_hashes.txt   # sample weak-password SHA-1 list
tests/
  test_password_audit.py
```

## Design notes (custom mods)

- **Never sends anything online.** Breach checking is a local set lookup, by design: a tool that audits passwords must not leak the passwords it audits, so there is no API call, no k-anonymity round-trip, nothing leaving the machine.
- **Penalties are named, not just numeric.** The output says *why* a password scored low (keyboard walk, year, repeat), which is what makes the score actionable for the password's owner.
- **Sample list is testable.** The bundled hash list covers well-known weak passwords only, and the tests verify both a hit and a miss against it.

Run the tests with:

```bash
python3 -m unittest discover -s tests -v
```

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
