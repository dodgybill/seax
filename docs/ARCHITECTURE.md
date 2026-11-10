# Architecture

VIGIL is a static site published by SEAX Intelligence. `index.html` loads `js/app.js` as a module. There is no bundler. GitHub Pages serves the repository root. The Pages path stays `/seax/`. `.nojekyll` stops Jekyll.

The browser holds the only plaintext. IndexedDB store `kv` in database `seax-intelligence` keeps the wrapped vault, lockout timestamps, one encrypted state blob, and encrypted media chunks. `js/app.js` renders the desk after unlock and drops the data key on lock.

## Modules

| Module | Role |
|---|---|
| `js/config.js` | `APP_NAME`, `FIRM_NAME`, `BYLINE`, `APP_LISTING`, `ICONS`, `ACTIVE_MODE` |
| `js/crypto.js` | PBKDF2, AES-GCM, recovery-key text, audit hash |
| `js/special.js` | HKDF sub-key for special-category values |
| `js/lockout.js` | Rolling lockout window |
| `js/settings.js` | Owner settings, including compliance switches |
| `js/schema.js` | Built-in shape and key denylist |
| `js/fields.js` | Custom fields and special-category labels |
| `js/search.js` | In-memory search that omits special-category values |
| `js/db.js` | IndexedDB |
| `js/media.js` | Chunked file encryption and thumbnails |
| `js/exif.js` | Evidence metadata copy |
| `js/sync.js` | Bundle pack, verify, merge, `SyncAdapter` |
| `js/time.js` | Europe/London display times |
| `js/icons.js` | Inlined Lucide icons |
| `sw.js` | App-shell cache only |

`ACTIVE_MODE` changes setup (no username, owner name SEAX ALPHA, ACTIVE badge, audit line `ACTIVE MODE active`). Compliance behaviour is the Settings switches, all off until SEAX ALPHA turns one on.

## Names

The platform is VIGIL. SEAX Intelligence is the maker. `BYLINE` is `by ${FIRM_NAME}` and `APP_LISTING` is `${APP_NAME} by ${FIRM_NAME}`, both derived in `js/config.js`. The lock screen and About show VIGIL as the large title and the byline beneath. The document title and the Apple web-app title are VIGIL. The manifest name is the listing and `short_name` is VIGIL.

IndexedDB stays `seax-intelligence`. Storage keys, backup file names (`seax-sync.seax`, `seax-backup.seax`), the shell cache prefix and `/seax/` are unchanged, so an existing desk and any published URL keep working. Icon files are unchanged until the VIGIL mark arrives. Their paths are the `ICONS` object. `index.html` and `manifest.json` repeat those paths because the browser reads them before the module. `sw.js` imports `ICONS`. `tests/unit.mjs` checks the static copies still match the object.

## Security controls

Threat identifiers are from `docs/THREAT-MODEL.md`. A control is listed only where this desk implements it.

| Control | T-ID | Implementation | Test |
|---|---|---|---|
| PBKDF2-SHA256, 600,000 iterations, 16-byte salt, no passphrase stored | T1, T4 | `deriveKek` in `js/crypto.js`; vault written in `confirmSetup` in `js/app.js` | `tests/unit.mjs` passphrase wrap round-trip; Playwright reads vault iterations and salt length |
| Data key AES-256-GCM, wrapped (not stored raw) by the passphrase key | T1, T4 | `generateDataKey`, `wrapDataKey`, `unwrapDataKey`, `sealJson` in `js/crypto.js` | `tests/unit.mjs` round-trip and wrong-passphrase failure; Playwright IndexedDB dump has no plaintext label |
| Special-category sub-key, HKDF-SHA256 from the data key, separate AES-GCM | T8 | `deriveFieldKey`, `sealSpecialValue`, `openSpecialValue` in `js/special.js`; `storedCustomValue` in `js/app.js` | `tests/unit.mjs` sealed blob omits the value; Playwright search and SAR file omit `TEMPLE-NOTE` |
| Lockout after 5 failures in 15 minutes, kept in IndexedDB, owner can change the count | T3 | `nextLockout` in `js/lockout.js`; `registerFailure` in `js/app.js` | `tests/unit.mjs` lockout window; Playwright “five failures lock the desk” |
| Auto-lock on idle and when the tab has been hidden | T2 | `armIdle`, `lock` in `js/app.js`; idle minutes on the vault and in `state.settings` | Playwright “idle lock” |
| Recovery key: 256 bits, 13 groups of 4 Crockford characters, wraps the data key, not stored as plaintext | T5 | `encodeKey`, `decodeKey`, `importRawKey` in `js/crypto.js`; `confirmSetup`, `recoveryUnlock` in `js/app.js` | `tests/unit.mjs` recovery unwrap; Playwright types groups back and later unlocks with the key |
| Audit hash chain over prev, time, who, action, detail | T7 | `auditHash`, `verifyChain` in `js/crypto.js`; `audit` in `js/app.js` | `tests/unit.mjs` edited entry fails the chain; Playwright “CHAIN INTACT” |
| Sync and backup bundle: AES-GCM plus SHA-256 of the ciphertext, kind check, verify does not write | T6 | `packBundle`, `BundleSyncAdapter.verifyBundle` in `js/sync.js` | Playwright flips one byte and expects “This file failed the integrity check.”; a backup is refused as a sync import |
| Special-category values stay out of search, filters, cross-record lists and unencrypted print | T8 | `publicText` in `js/search.js`; `printSheet` in `js/app.js` | `tests/unit.mjs` search and `publicText`; Playwright “No matches” for the special value |
| Rendering escapes text; no third-party script | T9, T10, T11 | `esc` in `js/app.js`; CSP meta in `index.html`; Lucide paths are inlined | Playwright asserts no third-party host and no console error |
| Service worker caches the shell only | T12 | `sw.js` asset list; comment and cache name `seax-shell-v4` | Playwright offline shell still shows setup, with no desk data in that cache |
| Fixtures are made-up tokens | T14 | `tests/v1.spec.js`, `tests/exif-fixture.js`, `tests/unit.mjs` | Those files; no real subject names |

Not implemented in this version, and not claimed above: recovery-key rotation (T5; a new passphrase keeps the same recovery key), a warning when an older backup is restored (T6), GitHub branch protection (T10), and blurring the app switcher (T12). `docs/THREAT-MODEL.md` is the Security Lead’s draft and is stored unchanged.
