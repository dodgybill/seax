import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ITERATIONS,
  auditHash,
  decodeKey,
  deriveKek,
  encodeKey,
  generateDataKey,
  importRawKey,
  sealJson,
  openJson,
  unwrapDataKey,
  verifyChain,
  wrapDataKey,
} from '../js/crypto.js';
import { extractMetadata } from '../js/exif.js';
import { isSpecialLabel, resolveSpecial } from '../js/fields.js';
import { nextLockout } from '../js/lockout.js';
import { assertClean } from '../js/schema.js';
import { groupResults, publicText, searchDesk } from '../js/search.js';
import { deriveFieldKey, isSealedSpecial, openSpecialValue, sealSpecialValue } from '../js/special.js';
import { mergeStates } from '../js/sync.js';
import { buildMarkedJpeg } from './exif-fixture.js';

test('special labels are tagged and ordinary words are not', () => {
  for (const label of ['Religion', 'Ethnicity', 'Racial origin', 'Political views', 'Party affiliation', 'Faith', 'Race']) {
    assert.equal(isSpecialLabel(label), true, label);
  }
  for (const label of ['Grace', 'Terrace', 'faithful', 'sacrilegious', 'Call sign', 'Favourite colour']) {
    assert.equal(isSpecialLabel(label), false, label);
  }
  assert.equal(resolveSpecial({ label: 'Squad colour', explicitSpecial: true }), true);
  assert.equal(resolveSpecial({ label: 'Squad colour' }), false);
  assert.equal(resolveSpecial({ label: 'Religion' }), true);
});

test('built-in keys stay rejected and custom labels do not', () => {
  assert.throws(() => assertClean({ ethnicity: 'x' }));
  assert.throws(() => assertClean({ nested: { faith: 'x' } }));
  assert.doesNotThrow(() => assertClean({
    label: 'Religion',
    fieldDefs: [{ id: 'FLD-1', label: 'Political views' }],
    custom: { 'FLD-1': 'TEMPLE-NOTE' },
  }));
});

test('exif marker is copied out of a synthetic jpeg', () => {
  const meta = extractMetadata(buildMarkedJpeg(), 'image/jpeg');
  assert.equal(meta.fields.Make, 'TestCamSEAX');
  assert.equal(meta.fields.Model, 'Synthetic');
  assert.equal(meta.fields.DateTime, '2026:01:01 00:00:00');
  assert.match(meta.comments.join(' '), /UNIQUEPLAINTEXTMARKER/);
  assert.equal(meta.retained, true);
});

test('search stays in memory and skips special-category values', () => {
  const state = {
    cases: [{ id: 'CASE-ALPHA', client: 'CLIENT-A' }],
    ents: [
      { id: 'P1', type: 'Person', label: 'SIGNAL-77', case: 'CASE-ALPHA', desc: '', source: '', custom: { a: 'TEMPLE-NOTE', b: 'CS-77' } },
      { id: 'L1', type: 'Location', label: 'SITE-NORTH', case: 'CASE-ALPHA', desc: '', source: '' },
    ],
    fieldDefs: [
      { id: 'a', recordType: 'person', label: 'Religion' },
      { id: 'b', recordType: 'person', label: 'Call sign' },
    ],
    media: [{ id: 'M1', name: 'plate.jpg', provenance: 'camera roll', mime: 'image/jpeg', sha256: 'abc', by: 'SEAX ALPHA' }],
  };
  assert.equal(searchDesk(state, 'temple-note', 'all').length, 0);
  assert.equal(searchDesk(state, 'cs-77', 'people')[0].title, 'SIGNAL-77');
  assert.equal(publicText(state, state.ents[0], 'person').includes('TEMPLE-NOTE'), false);
  assert.equal(publicText(state, state.ents[0], 'person').includes('CS-77'), true);
  const listed = JSON.stringify(state.ents.map((e) => publicText(state, e, 'person')));
  assert.equal(listed.includes('TEMPLE-NOTE'), false);
  assert.equal(searchDesk(state, 'temple-note', 'locations').length, 0);
  assert.equal(searchDesk(state, 'site-north', 'locations')[0].title, 'SITE-NORTH');
  assert.equal(searchDesk(state, 'plate', 'media')[0].kind, 'media');
  const groups = groupResults(searchDesk(state, 'case-alpha', 'all')).map((g) => g.label);
  assert.deepEqual(groups, ['People', 'Locations', 'Cases']);
});

test('later edit wins and the other copy is kept as a conflict', () => {
  const local = baseState('2026-11-10T12:00:00.000Z', 'NOTE-A2');
  const remote = baseState('2026-11-10T11:00:00.000Z', 'NOTE-B');
  remote.audit = [{ hash: 'remote' }];
  const kept = mergeStates(local, remote);
  assert.equal(kept.state.ents[0].desc, 'NOTE-A2');
  assert.equal(kept.conflicts.length, 1);
  assert.equal(kept.conflicts[0].kept, 'local');

  const older = baseState('2026-11-10T10:00:00.000Z', 'NOTE-A');
  const newer = baseState('2026-11-10T11:00:00.000Z', 'NOTE-B');
  newer.audit = [{ hash: 'remote' }];
  const imported = mergeStates(older, newer);
  assert.equal(imported.state.ents[0].desc, 'NOTE-B');
  assert.equal(imported.conflicts[0].kept, 'imported');
});

function baseState(updatedAt, desc) {
  return {
    cases: [],
    ents: [{ id: 'P', updatedAt, desc, label: 'SIGNAL-77' }],
    tasks: [],
    media: [],
    links: [],
    tombstones: [],
    fieldDefs: [],
    audit: [{ hash: 'local' }],
    conflicts: [],
    retainedAudits: [],
    attest: {},
    owner: { name: 'SEAX ALPHA' },
    curCase: null,
  };
}

test('passphrase wrap round-trip fails closed on the wrong passphrase', async () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const dataKey = await generateDataKey();
  const box = await wrapDataKey(dataKey, await deriveKek('strand-harbour-lantern', salt, ITERATIONS));
  const opened = await unwrapDataKey(box, await deriveKek('strand-harbour-lantern', salt, ITERATIONS));
  const sealed = await sealJson(opened, { label: 'SIGNAL-77' });
  assert.equal((await openJson(opened, sealed)).label, 'SIGNAL-77');
  await assert.rejects(async () => unwrapDataKey(box, await deriveKek('strand-harbour-lantern-2', salt, ITERATIONS)));
});

test('recovery key unwraps the data key and is 256 bits', async () => {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const groups = encodeKey(raw);
  assert.equal(groups.length, 13);
  const dataKey = await generateDataKey();
  const box = await wrapDataKey(dataKey, await importRawKey(raw));
  const opened = await unwrapDataKey(box, await importRawKey(decodeKey(groups.join('-'))));
  assert.equal((await openJson(opened, await sealJson(opened, { ok: 1 }))).ok, 1);
});

test('lockout window keeps five failures and drops an old one', () => {
  const windowMs = 15 * 60 * 1000;
  let fails = [];
  let locked = false;
  for (let i = 0; i < 5; i++) ({ fails, locked } = nextLockout(fails, 1_000 + i, windowMs, 5));
  assert.equal(locked, true);
  const later = nextLockout(fails, fails[fails.length - 1] + windowMs + 1, windowMs, 5);
  assert.equal(later.locked, false);
  assert.equal(later.count, 1);
});

test('audit chain fails when an entry is edited', async () => {
  const first = { prev: 'GENESIS', t: '10 Nov 2026, 20:28:01 GMT', who: 'SEAX ALPHA', action: 'OWNER_CREATED', detail: 'SEAX ALPHA' };
  first.hash = await auditHash(first);
  const second = { prev: first.hash, t: '10 Nov 2026, 20:28:02 GMT', who: 'SEAX ALPHA', action: 'CASE_CREATED', detail: 'CASE-ALPHA' };
  second.hash = await auditHash(second);
  assert.equal(await verifyChain([first, second]), true);
  second.detail = 'CASE-BETA';
  assert.equal(await verifyChain([first, second]), false);
  second.detail = 'CASE-ALPHA';
  assert.equal(await verifyChain([second, first]), false);
});

test('special-category sub-key hides the value from a stringified record', async () => {
  const dataKey = await generateDataKey();
  const fieldKey = await deriveFieldKey(dataKey);
  const sealed = await sealSpecialValue(fieldKey, 'TEMPLE-NOTE');
  assert.equal(isSealedSpecial(sealed), true);
  assert.equal(JSON.stringify(sealed).includes('TEMPLE-NOTE'), false);
  assert.equal(await openSpecialValue(fieldKey, sealed), 'TEMPLE-NOTE');
  const other = await deriveFieldKey(await generateDataKey());
  await assert.rejects(async () => openSpecialValue(other, sealed));
});
