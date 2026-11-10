# SEAX Intelligence – Threat Model (DRAFT v0.1)

Owner: the security lead · Drafted 10 Nov 2026 (Europe/London, GMT) · Status: draft, untested. Nothing here is "secure" until the linked test passes.

Scope: SEAX v1 web desk (GitHub Pages preview, installable PWA, offline), encrypted sync and backup between the owner's Mac and iPhone, this repository and its CI. Later: native Swift app.
Out of scope: third-party systems (GitHub, Apple, browsers) except how SEAX uses them.

## Assets
- A1 Case data (people, locations, vehicles, organisations, cases, notes)
- A2 Media (photos, video, documents)
- A3 Special-category custom fields (extra encryption layer)
- A4 Admin passphrase and the derived keys
- A5 Printed recovery key
- A6 Audit log (integrity, used as evidence)
- A7 Encrypted backups and sync files
- A8 Source repo, CI and Pages deployment (integrity of what the owner runs)
- A9 The owner's identity metadata (e.g. commit author email)

## Threats, controls and tests

| ID | Threat | Asset | Control (expected) | Test to prove it | Status |
|---|---|---|---|---|---|
| T1 | Phone or Mac stolen or seized while locked | A1–A3 | All data encrypted at rest with AES-GCM via WebCrypto; key derived from the passphrase (PBKDF2 ≥600k or Argon2id), never stored | Read IndexedDB/OPFS raw: no plaintext names or values; key material is absent | Untested |
| T2 | Device taken while unlocked | A1–A3 | Auto-lock on idle or backgrounding; key wiped from memory on lock | Idle past timer, confirm lock, confirm decrypt fails until the passphrase is entered again | Untested |
| T3 | Passphrase guessed online | A4 | 12+ chars; lockout after 5 tries for 15 min (configurable); lockout state can't be reset by reloading or clearing one store | Script 6 wrong tries, reload, clear localStorage: still locked | Untested |
| T4 | Passphrase brute-forced offline from copied data | A4, A1 | Slow KDF with unique salt; no passphrase hint or verifier stored in plaintext | Measure KDF cost; inspect stored verifier | Untested |
| T5 | Recovery key lost, or found by someone else | A5 | High-entropy key (≥128 bits) that wraps the data key; can be rotated; never stored on the device in plaintext or in the repo | Restore with the key; rotate, then confirm the old key fails | Untested |
| T6 | Backup or sync file tampered with or swapped | A7, A1 | Authenticated encryption plus a checksum; restore check refuses altered files; replay of old versions detected | Flip one byte, restore: rejected. Restore an older file: warned | Untested |
| T7 | Audit log edited or truncated | A6 | Hash-chained, append-only entries, encrypted; tamper check on open | Edit, delete or reorder an entry: tamper check fails | Untested |
| T8 | Special-category data leaks across cases | A3 | Extra key layer; excluded from search, filters, bulk export and cross-case lists; every view and edit logged | Seed made-up data; query Search all, filters and export: absent; audit entries present | Untested |
| T9 | Anyone opens the public Pages link | A8, A1 | Site ships code only, no data; no secrets, keys or real names in the repo; CSP headers via meta tag | A secret scan; fetch the site fresh: blank desk, nothing in its storage | Partly checked (scan: 3 commits clean) |
| T10 | Malicious code pushed (compromised GitHub account or dependency) | A8 | 2FA on GitHub; protected main branch; required checks; pinned dependencies; Subresource Integrity on any CDN script, or none at all | Check branch protection settings; run a dependency audit; grep for unpinned external scripts | Untested |
| T11 | XSS through custom fields or imported text exfiltrates decrypted data | A1–A3 | All rendering escaped; no innerHTML with user data; strict CSP with no inline script | Enter `<img src=x onerror=alert(1)>` in every field and import path | Untested |
| T12 | Plaintext leaks through exports, print, clipboard, OS previews or caches | A1–A3 | Exports encrypted by default; service worker never caches decrypted data; app switcher blurs the screen | Inspect the Cache Storage and service-worker caches; export without encryption shows a warning | Untested |
| T13 | Personal metadata exposed in the public repo | A9 | GitHub private-email setting; scrub history only on the owner's yes | `git log --format=%ae` shows only the no-reply address on new commits | Open (author email exposed in commit history; see the security review) |
| T14 | Real subject data ends up in test builds or fixtures | A1 | Made-up fixtures only; CI scan for known real-data patterns | CI check plus manual review of fixtures | Untested |

## Review method
Checked against OWASP ASVS 4.0 (web) and OWASP MASVS 2.x (mobile/PWA). Each finding is reported with a severity (Critical/High/Medium/Low), evidence, a reproducible test and a fix, then handed on and re-tested.
