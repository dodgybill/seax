# Changelog

## 1.0.0

- The desk is presented as VIGIL by SEAX Intelligence. `APP_NAME`, `FIRM_NAME` and the derived byline live in `js/config.js`. IndexedDB (`seax-intelligence`), storage keys, file names and the `/seax/` path are unchanged.
- Encrypted desk in IndexedDB: passphrase, recovery key, lockout, idle lock, audit hash chain, media with evidence metadata, sync bundle and backup.
- `ACTIVE_MODE` build flag. Compliance controls are Settings switches, off until turned on.
- Custom fields. Special-category values use a separate sub-key and stay out of search, lists, print and plaintext export. A subject-access file may carry the sealed value.
- Design tokens, small-mark favicon and header badge, full badge for the home-screen icon and manifest.
- Lucide icons, inlined. Dark desk, 44px targets, large titles, sheet preview.
