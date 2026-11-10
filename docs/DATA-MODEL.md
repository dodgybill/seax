# Data model

Database `seax-intelligence`, object store `kv`. Only the vault and the lockout record are unencrypted. Everything else is AES-GCM under the data key, or under the special-category sub-key and then the data key.

## Unencrypted keys

| Key | Contents |
|---|---|
| `vault` | `iterations`, `salt`, `passWrap`, `recoveryWrap`, `idleMin`, `lockoutMax`, `createdAt` |
| `lockout` | `{ fails: [timestamps] }` inside the rolling window |

`idleMin` and `lockoutMax` are desk policy, not personal data. They have to be readable before sign-in. They are also copied into the encrypted state so a sync carries them.

## Encrypted state (`s`)

`normalise` in `js/schema.js` fills missing arrays. Shape:

- `owner.name` — `SEAX ALPHA` when `ACTIVE_MODE` is on
- `settings.idleMin`, `settings.lockoutMax`, `settings.retentionDate`
- `settings.compliance` — `gate`, `personBasis`, `art9`, `paperwork`, `retention`, `notices`, `disclaimer`, each boolean, default false
- `attest` — desk paperwork, only meaningful when those switches are on
- `cases[]` — `id`, `client`, `lia`, `unlocks`, `art9` (condition per special field, only when that switch is on), `custom`, `updatedAt`
- `ents[]` — person, location, vehicle, organisation and the other entry types. `custom` holds field values. Built-in `sp` is only Health, Criminal record or Biometrics
- `fieldDefs[]` — label, type, record type, required, options, order, `explicitSpecial`, `archived`
- `links`, `tasks`, `media` (metadata), `conflicts`, `tombstones`, `audit`, `retainedAudits`, `curCase`

A special-category custom value is `{ seaxSpecial: 1, iv, ct }`. The plaintext is not a property of the record. Other custom values are stored in the state blob as JSON, still inside the state ciphertext.

Built-in property keys cannot contain ethnicity, religion or political-view names. `assertClean` checks keys only. A custom-field label is a value and is allowed.

## Media

`b:<id>:<chunk>` ciphertext, 1 MiB of the original file per chunk. `x:<id>` evidence metadata. `t:<id>` thumbnail. The original bytes are not rewritten.

## Bundles

Magic `SEAXBND1`, a JSON header (kind `sync` or `backup`, salt, iv, SHA-256 of the ciphertext), then AES-GCM payload: data key, recovery wrap, state, media. Verify checks the hash, the authentication tag, the schema and the audit chain, and does not write.
