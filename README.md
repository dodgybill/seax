# VIGIL

VIGIL is the case desk. SEAX Intelligence is the maker. On screen it reads VIGIL, with "by SEAX Intelligence" under the name on the lock screen and on About. The page title is VIGIL. The installed name is "VIGIL by SEAX Intelligence".

The desk runs entirely in the browser. This repository is a static site: `index.html`, the `js/` modules, a manifest and a service worker. There is no build step. GitHub Pages can serve the repository root, which stays `/seax/`. The `.nojekyll` file stops Pages from running Jekyll. The IndexedDB name, storage keys and file names stay as they are, so a desk already on a device keeps opening.

`APP_NAME`, `FIRM_NAME`, `BYLINE` and `APP_LISTING` live in `js/config.js`. Icon paths live in `ICONS` in that same file. The header mark, favicon and home-screen icons are still the current artwork. When the VIGIL mark arrives, change `ICONS` and the matching paths in `index.html` and `manifest.json`. The service worker imports `ICONS`, so the shell cache follows that list.

The header uses the small mark (`ICONS.mark`, today `assets/icons/seax-small-mark-64.png`), drawn at 64 pixels on a wide window and 32 on a phone. The favicon is the small-mark `favicon.ico`. The Apple touch icon and the manifest icons are the full badge. In-app icons are inlined Lucide drawings.

## Run it

WebCrypto, IndexedDB and the service worker need a real site. Do not open the folder with `file://`.

```bash
python3 -m http.server 4173 --bind 127.0.0.1
```

Open `http://127.0.0.1:4173`. On an iPhone, use Share and then Add to Home Screen. After one successful load the shell works offline. The desk itself stays in IndexedDB on that device.

## What this version does

- Setup creates a SEAX ALPHA desk from a passphrase and a recovery key. The key is 256 bits, shown once as grouped characters, with a printable page. You type three groups back before the desk is stored. It is not shown again.
- Unlock with the recovery key sets a new passphrase. The recovery key itself does not change.
- Every desk record is encrypted at rest in IndexedDB with AES-256-GCM. A random data key is wrapped twice: once by PBKDF2-SHA256 (600,000 iterations and a random salt) from the passphrase, and once by the recovery key.
- Five failed passphrase or recovery attempts in 15 minutes lock the desk for 15 minutes. The desk also locks after 15 minutes with no activity, and if the tab stays hidden for that long.
- Cases, people, locations, vehicles, organisations and other records, a link graph, provenance, a hash-chained audit log, and subject-rights actions: export, objection, and freeze/erase.
- Custom fields on a case, person, location, vehicle, organisation or other record. Types are text, long text, number, date, yes/no, dropdown and URL. A field can be required and has a display order. You can rename it. If it already holds a value you archive it; delete is only offered when nothing is stored.
- Photos and video attached to a case or a record. Each file is encrypted in 1 MiB chunks before it is stored, with the SHA-256 of the original, who attached it, when, and the source you type. EXIF, comments and similar evidence metadata are copied into their own encrypted record and shown only after Reveal. The original file is kept. Nothing is stripped. Thumbnails and previews are decrypted in memory only. The desk does not do face matching or biometric processing.
- Home, after unlock: a search control, recent records, open cases and quick-add buttons. Search opens a full view with a Search all bar and chips for All, People, Locations, Vehicles, Organisations, Cases and Media. Results update as you type, grouped by type, with a thumbnail where a picture exists. `/` and Ctrl-K or Cmd-K open search. The query never leaves the browser. It runs over the desk already decrypted in memory. Special-category values are not included.
- An encrypted, integrity-checked sync bundle, and an encrypted backup of the whole desk. Verify decrypts and checks the integrity hash and the audit chain, and does not write. Import onto a new device adopts the desk. Import onto a device that already has a desk merges record by record: the later `updatedAt` wins, and the other copy is kept as a conflict.
- A web app manifest and a service worker so the shell can be installed and opened offline.

## ACTIVE mode

`js/config.js` is the switch:

```js
export const ACTIVE_MODE = true;
```

This build ships with the flag on. While it is on:

- The header shows a small ACTIVE badge and nothing else about the mode.
- Setup asks for a passphrase only. The operator name stored on the desk is SEAX ALPHA.

Compliance behaviour is not the flag. Settings, under Compliance, has a switch for each of these, and each one starts off: the unlock gate, consent and legitimate interests on people, the Article 9 condition picker, paperwork prompts, retention reminders, data-protection notices, and the not-official disclaimer. While a switch is off, that control is not shown. Encryption, the passphrase, lockout, the recovery key, the audit log and backups stay on and are not switches.

Set `ACTIVE_MODE` to `false` before a real matter if you want a username at setup. Turn on the compliance switches you want in Settings. The built-in schema does not gain ethnicity, religion or political-view fields in either position of the flag.

When the flag is on, setup writes an audit entry whose action is `ACTIVE_MODE` and whose detail is `ACTIVE MODE active`.

## Custom fields and special categories

A label about ethnicity, race, religion, faith or political views is allowed. Matching labels, and any field with the special-category tick, are tagged special. The value is encrypted again under a sub-key derived from the data key, and the record blob is still encrypted. Those values are not searchable, not shown on Home or in cross-record lists, and not printed. Opening a record that has such a field, and every edit of the value, is written to the audit log. The detail names the field and the record, not the value. A subject-access file may include the sealed object. It does not include the plaintext.

The screen shows a SPECIAL tag. Warning text appears only when the notices switch is on. The Article 9 condition picker appears only when that switch is on. Special-category fields belong on a record inside a case, not on the case itself.

## Security model, in plain English

The browser is the only place that can read the desk. IndexedDB holds ciphertext, the wrapped data key, the salt, the iteration count, and the times of recent failed attempts. The passphrase and the recovery key are not written down by the app. Locking drops the data key and the decrypted desk from memory.

The audit log is a hash chain. Anyone who can open the desk can recompute it, so it shows whether that log was edited. It is not a signature from anyone else. A failed sign-in cannot append to the chain, because the chain is inside the encrypted desk. A successful sign-in records how many failures came before it.

A sync bundle or a backup is encrypted with the passphrase typed at export, and the file includes a SHA-256 of the ciphertext. `js/sync.js` exposes `SyncAdapter`. `BundleSyncAdapter` is the one that writes a file. `CloudSyncAdapter` is the seam for a later store: it does not send anything. A server in that design would hold the same ciphertext and would not receive the passphrase or the data key.

Search does not call a network. There is no third-party script, font or tracker.

## Limits

- iOS can delete IndexedDB for a site that has not been opened for a while. Keep a backup, and keep the recovery key offline.
- Sync is a file you carry between devices. It is not a live link. If both sides change one record, the later edit is kept and the earlier one is stored as a conflict.
- If the passphrase and the recovery key are both lost, the desk cannot be opened.
- Someone who knows the passphrase can rewrite the audit log and rebuild the chain.
- The size of the ciphertext, and how many media chunks exist, can be seen by someone with access to the browser profile.
- There is one operator, SEAX ALPHA.
- Previewing a large video decrypts it in memory.
- The service worker stores the app shell only, and only after one online load. Desk data is never placed in that cache.
- Turning GitHub Pages off, or deleting this repository, closes the public site. It does not wipe a phone or computer that already opened it. On each device use Erase this device, and destroy printed recovery keys and every `.seax` file.
- A holder of the data key, including a sync bundle, can still open special-category values. The sub-key stops those values sitting in plaintext inside the state or in an unencrypted export.
- The threat model is `docs/THREAT-MODEL.md`. `docs/ARCHITECTURE.md` names the control, the function and the test for each one this desk implements.
- 600,000 rounds of PBKDF2 slow guessing. They are not a hardware security module.
- A backup opens with the passphrase that was used when that file was exported.
- If two copies of a record carry the same timestamp, the imported copy is kept and a conflict is recorded.
- Merging into a device that already has a desk does not replace that device's operator name.

## Tests

```bash
npm install
npm test
```

`npm test` runs `pretest` first, which installs Chromium (`playwright install chromium`, the same step as `npx playwright install chromium`). A CI job only needs those two commands. `npm run test:setup` installs the browser on its own. The browser suite covers the flag on and off. The off run answers `js/config.js` with `ACTIVE_MODE = false` for that browser only. The file in the repository is left on.

## Close the site

Disable GitHub Pages for this repository, or delete the repository. Then erase the desk on every device that has opened it, and destroy the recovery key and any backup or sync files.
