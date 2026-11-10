import { devices, expect, test } from '@playwright/test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { insertExif } from './exif-fixture.js';

const PASS = 'strand-harbour-lantern';
const PASS2 = 'strand-harbour-lantern-2';
const BANNED = [
  'DEMO BUILD',
  'v1 PREVIEW',
  'TEST DATA ONLY',
  'NOT FOR REAL PERSONAL DATA',
  'UK GDPR',
  'Article 9',
  'lawful basis',
  'ICO registration',
  'ethnicity',
  'police',
  'DEMO',
];
const SHOTS = path.join(process.cwd(), 'test-results', 'screenshots');

function track(page, bucket) {
  page.on('console', (msg) => {
    if (msg.type() === 'error') bucket.errors.push(msg.text());
  });
  page.on('pageerror', (err) => bucket.errors.push(String(err)));
  page.on('request', (req) => {
    try {
      const hostname = new URL(req.url()).hostname;
      if (hostname && hostname !== '127.0.0.1' && hostname !== 'localhost') bucket.hosts.push(req.url());
    } catch { /* ignore */ }
  });
}

async function shot(page, name) {
  fs.mkdirSync(SHOTS, { recursive: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: path.join(SHOTS, name) });
}

async function hasVault(page) {
  return page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('seax-intelligence');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const value = await new Promise((resolve, reject) => {
      const tx = db.transaction('kv', 'readonly');
      const req = tx.objectStore('kv').get('vault');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return !!value;
  });
}

async function latin1Dump(page) {
  return page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('seax-intelligence');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const rows = await new Promise((resolve, reject) => {
      const tx = db.transaction('kv', 'readonly');
      const req = tx.objectStore('kv').getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    const chunks = [];
    const walk = (value) => {
      if (value instanceof Uint8Array) chunks.push(new TextDecoder('latin1').decode(value));
      else if (value instanceof ArrayBuffer) chunks.push(new TextDecoder('latin1').decode(new Uint8Array(value)));
      else if (ArrayBuffer.isView(value)) chunks.push(new TextDecoder('latin1').decode(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)));
      else if (value && typeof value === 'object') Object.values(value).forEach(walk);
      else if (typeof value === 'string') chunks.push(value);
    };
    walk(rows);
    return chunks.join('\n');
  });
}

async function vaultInfo(page) {
  return page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('seax-intelligence');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const vault = await new Promise((resolve, reject) => {
      const req = db.transaction('kv', 'readonly').objectStore('kv').get('vault');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    const len = (b) => {
      if (!b) return 0;
      if (b instanceof ArrayBuffer) return b.byteLength;
      if (ArrayBuffer.isView(b)) return b.byteLength;
      if (typeof b === 'object') return Object.keys(b).length;
      return 0;
    };
    const hex = (b) => {
      const u = b instanceof Uint8Array ? b : new Uint8Array(b.buffer || b);
      return [...u].map((n) => n.toString(16).padStart(2, '0')).join('');
    };
    return {
      iterations: vault.iterations,
      saltLen: len(vault.salt),
      wrapsDiffer: hex(vault.passWrap.ct) !== hex(vault.recoveryWrap.ct),
    };
  });
}

function twist(group) {
  const alph = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const i = Math.max(0, alph.indexOf(group[3]));
  return group.slice(0, 3) + alph[(i + 1) % alph.length];
}

async function confirmRecovery(page, { succeed }) {
  await expect(page.locator('#recovery-sheet')).toBeVisible();
  const groups = await page.locator('#key-grid .rk').evaluateAll((els) => els.map((el) => el.dataset.group));
  const ask = await page.locator('[id^=ch]').evaluateAll((els) => els.map((el) => Number(el.dataset.idx)));
  if (!succeed) {
    await page.getByRole('button', { name: 'CONFIRM AND CONTINUE' }).click();
    await expect(page.locator('#e')).toContainText('Tick the box');
    for (let i = 0; i < 3; i++) await page.fill(`#ch${i}`, twist(groups[ask[i]]));
    await page.check('#stored');
    await page.getByRole('button', { name: 'CONFIRM AND CONTINUE' }).click();
    await expect(page.locator('#e')).toContainText('do not match');
    expect(await hasVault(page)).toBe(false);
  }
  for (let i = 0; i < 3; i++) await page.fill(`#ch${i}`, groups[ask[i]]);
  await page.check('#stored');
  await page.getByRole('button', { name: 'CONFIRM AND CONTINUE' }).click();
  return groups.join('-');
}

async function createDesk(page, { name } = {}) {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'CREATE SEAX ALPHA' })).toBeVisible();
  if (name) await page.fill('#n', name);
  await page.fill('#p', PASS);
  await page.fill('#p2', PASS);
  await page.getByRole('button', { name: 'CREATE SEAX ALPHA' }).click();
  const key = await confirmRecovery(page, { succeed: false });
  await expect(page.locator('#home, .band')).toBeVisible();
  return key;
}

async function saveCase(page) {
  await page.locator('.qadd', { hasText: 'Case' }).click();
  await page.fill('#case-name', 'CASE-ALPHA');
  await page.fill('#case-client', 'CLIENT-A');
  await page.getByRole('button', { name: 'SAVE CASE' }).click();
  await expect(page.locator('#home')).toContainText('CASE-ALPHA');
}

async function openDesk(page) {
  await page.locator('#home .card', { hasText: 'CASE-ALPHA' }).click();
  await expect(page.locator('[data-tab="add"]')).toBeVisible();
}

async function addEntry(page, type, label, extra) {
  await page.locator('[data-tab="add"]').click();
  await page.selectOption('#ty', type);
  await expect(page.locator('#lb')).toBeVisible();
  await page.fill('#lb', label);
  await page.fill('#src', 'SRC-1');
  await page.fill('#sd', '2026-11-01');
  await page.fill('#od', '2026-11-01');
  if (extra) await extra();
  await page.getByRole('button', { name: 'SAVE ENTRY' }).click();
  await expect(page.locator('#insp')).toContainText(label.toUpperCase());
}

async function openFields(page) {
  await page.locator('.rail [data-screen="settings"]').click();
  await page.getByRole('button', { name: 'Custom fields' }).click();
  await expect(page.locator('#fields-view')).toBeVisible();
}

async function addField(page, { label, kind = 'text', required = false, special = false, options = '', record = 'person' }) {
  await page.selectOption('#fd-record', record);
  await page.fill('#fd-label', label);
  await page.selectOption('#fd-kind', kind);
  if (options) await page.fill('#fd-options', options);
  if (required) await page.check('#fd-required');
  else await page.uncheck('#fd-required');
  if (special) await page.check('#fd-special');
  else await page.uncheck('#fd-special');
  await page.getByRole('button', { name: 'ADD FIELD' }).click();
  await expect(page.locator('#fields-view .box .cn', { hasText: label }).first()).toBeVisible();
}

function fieldControl(page, label) {
  return page.locator('#custom-fields label', { hasText: label }).locator('xpath=following-sibling::*[1]');
}

async function markedPhoto(page) {
  const raw = await page.evaluate(async () => {
    const canvas = document.createElement('canvas');
    canvas.width = 16;
    canvas.height = 16;
    const g = canvas.getContext('2d');
    g.fillStyle = '#1b3a4b';
    g.fillRect(0, 0, 16, 16);
    g.fillStyle = '#3fd28c';
    g.fillRect(4, 4, 8, 8);
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.92));
    return Array.from(new Uint8Array(await blob.arrayBuffer()));
  });
  return insertExif(Buffer.from(raw));
}

async function downloadBytes(page, buttonName) {
  const pending = page.waitForEvent('download');
  await page.getByRole('button', { name: buttonName }).click();
  const download = await pending;
  const file = path.join(os.tmpdir(), `seax-${Date.now()}-${download.suggestedFilename()}`);
  await download.saveAs(file);
  return file;
}

async function assertCleanCopy(page) {
  const text = (await page.locator('body').innerText()).toLowerCase();
  for (const phrase of BANNED) {
    expect(text, phrase).not.toContain(phrase.toLowerCase());
  }
}

test.describe.serial('ACTIVE mode', () => {
  let context;
  let page;
  const bucket = { errors: [], hosts: [] };
  let recoveryKey = '';

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    page = await context.newPage();
    track(page, bucket);
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test('setup, recovery confirm, and home', async () => {
    await page.addInitScript(() => localStorage.setItem('seax_launch_v1', 'plain'));
    await page.goto('/');
    await expect(page).toHaveTitle('VIGIL');
    await expect(page.locator('h1.title')).toHaveText('VIGIL');
    await expect(page.locator('.firm')).toHaveText('by SEAX Intelligence');
    await expect(page.locator('#n')).toHaveCount(0);
    await expect(page.locator('.h', { hasText: 'CREATE SEAX ALPHA' })).toBeVisible();
    expect(await page.evaluate(() => localStorage.getItem('seax_launch_v1'))).toBeNull();
    const manifest = JSON.parse(await page.evaluate(async () => (await fetch('./manifest.json')).text()));
    expect(JSON.stringify(manifest)).not.toMatch(/DEMO|v1 PREVIEW|TEST DATA|NOT FOR REAL/i);
    expect(manifest.name).toBe('VIGIL by SEAX Intelligence');
    expect(manifest.short_name).toBe('VIGIL');
    await page.fill('#p', PASS);
    await page.fill('#p2', PASS);
    await page.getByRole('button', { name: 'CREATE SEAX ALPHA' }).click();
    await expect(page.getByRole('button', { name: 'PRINT RECOVERY KEY' })).toBeVisible();
    recoveryKey = await confirmRecovery(page, { succeed: false });
    await expect(page.locator('#home')).toBeVisible();
    await expect(page.locator('#mode-badge')).toHaveText('ACTIVE');
    await expect(page.locator('.brand')).toContainText('VIGIL');
    await page.locator('.rail [data-screen="settings"]').click();
    await page.getByRole('button', { name: 'About' }).click();
    await expect(page.locator('#about-view h1.title')).toHaveText('VIGIL');
    await expect(page.locator('#about-view .firm')).toHaveText('by SEAX Intelligence');
    await page.locator('.rail [data-screen="home"]').click();
    await expect(page.locator('#home')).toBeVisible();
    await expect(page.getByText('COMPLIANCE UNLOCK')).toHaveCount(0);
    await expect(page.getByText('Review desk documents', { exact: false })).toHaveCount(0);
    await assertCleanCopy(page);
    const body = await page.evaluate(() => document.body.textContent);
    expect(body).not.toContain(recoveryKey);
  });

  test('lock and unlock', async () => {
    await page.locator('[data-act="lock"]').click();
    await expect(page.locator('h1.title')).toHaveText('VIGIL');
    await expect(page.locator('.firm')).toHaveText('by SEAX Intelligence');
    await expect(page.getByRole('button', { name: 'SIGN IN' })).toBeVisible();
    await page.fill('#p', 'not-the-passphrase');
    await page.getByRole('button', { name: 'SIGN IN' }).click();
    await expect(page.locator('#e')).toContainText('Wrong passphrase');
    await page.fill('#p', PASS);
    await page.getByRole('button', { name: 'SIGN IN' }).click();
    await expect(page.locator('#home')).toBeVisible();
  });

  test('custom fields, records, and special tag', async () => {
    await openFields(page);
    await expect(page.locator('#fields-view')).toBeVisible();
    await addField(page, { label: 'Religion' });
    await expect(page.locator('#fields-view .box', { hasText: 'Religion' }).locator('.tag', { hasText: 'SPECIAL' })).toBeVisible();

    await addField(page, { label: 'Squad colour', special: true });
    await expect(page.locator('#fields-view .box', { hasText: 'Squad colour' }).locator('.tag', { hasText: 'SPECIAL' })).toBeVisible();

    await addField(page, { label: 'Call sign', required: true });
    await expect(page.locator('#fields-view')).toContainText('Call sign');

    await addField(page, { label: 'Shift', kind: 'dropdown', options: 'Day\nNight' });
    await expect(page.locator('#fields-view .box', { hasText: 'Shift' })).toContainText('dropdown');

    await addField(page, { label: 'Marker code' });
    await expect(page.locator('#fields-view .box', { hasText: 'Marker code' }).getByRole('button', { name: 'DELETE' })).toBeVisible();
    await assertCleanCopy(page);

    await page.locator('.rail [data-screen="home"]').click();
    await saveCase(page);
    await openDesk(page);
    await page.locator('[data-tab="add"]').click();
    await expect(fieldControl(page, 'Call sign')).toBeVisible();
    await page.fill('#lb', 'SIGNAL-77');
    await page.fill('#src', 'SRC-1');
    await page.fill('#sd', '2026-11-01');
    await page.fill('#od', '2026-11-01');
    await page.getByRole('button', { name: 'SAVE ENTRY' }).click();
    await expect(page.locator('.pane #e')).toContainText('Call sign is required');

    await addEntry(page, 'Person', 'SIGNAL-77', async () => {
      await page.fill('#ds', 'NOTE-A');
      await fieldControl(page, 'Call sign').fill('CS-77');
      await fieldControl(page, 'Religion').fill('TEMPLE-NOTE');
      await fieldControl(page, 'Shift').selectOption('Night');
    });
    await expect(page.locator('[data-cat="Health"]')).toBeVisible();
    await expect(page.locator('[data-cat="Criminal record"]')).toBeVisible();
    await expect(page.locator('[data-cat="Biometrics"]')).toBeVisible();
    await expect(page.getByRole('button', { name: 'UNLOCK FOR THIS CASE' })).toHaveCount(0);
    await page.locator('[data-cat="Health"]').fill('HX-NONE');
    await page.locator('[data-cat="Criminal record"]').fill('CR-NONE');
    await page.locator('[data-cat="Biometrics"]').fill('BIO-NONE');
    await expect(page.locator('#insp label', { hasText: 'Religion' }).locator('xpath=following-sibling::input[1]')).toHaveValue('TEMPLE-NOTE');
    await expect(page.locator('#pane > svg.graph')).toBeVisible();
    await expect(page.locator('.graph-fold')).toHaveCount(0);

    await addEntry(page, 'Location', 'SITE-NORTH');
    await addEntry(page, 'Vehicle', 'PLATE-4');
    await addEntry(page, 'Organisation', 'ORG-NORTH');

    await openFields(page);
    const religion = page.locator('#fields-view .box', { hasText: 'Religion' });
    await religion.getByRole('button', { name: 'ARCHIVE' }).click();
    await expect(religion).toContainText('ARCHIVED');
    await expect(religion.getByRole('button', { name: 'DELETE' })).toHaveCount(0);
    const marker = page.locator('#fields-view .box', { hasText: 'Marker code' });
    await marker.getByRole('button', { name: 'Delete', exact: true }).click();
    await marker.getByRole('button', { name: 'Delete field' }).click();
    await expect(page.getByText('Marker code')).toHaveCount(0);
    await assertCleanCopy(page);
  });

  test('home, search, keyboard and screenshots', async () => {
    await page.locator('.rail [data-screen="home"]').click();
    await expect(page.locator('#home')).toContainText('CASE-ALPHA');
    await expect(page.locator('#home')).toContainText('SIGNAL-77');
    await expect(page.locator('.hero-search')).toContainText('Search the desk');
    await shot(page, 'home-desktop.png');

    await page.locator('.hero-search').click();
    await expect(page.locator('#q')).toBeFocused();
    await expect(page.locator('#chips')).toContainText('Organisations');
    await page.fill('#q', 'CASE-ALPHA');
    for (const label of ['People', 'Locations', 'Vehicles', 'Organisations', 'Cases']) {
      await expect(page.locator('.group h3', { hasText: label })).toBeVisible();
    }
    await shot(page, 'search-desktop.png');

    await page.fill('#q', 'TEMPLE-NOTE');
    await expect(page.locator('#results')).toContainText('No matches');
    await page.locator('[data-scope="locations"]').click();
    await expect(page.locator('#results')).toContainText('No matches');
    await page.locator('[data-scope="people"]').click();
    await expect(page.locator('#results')).toContainText('No matches');
    await page.fill('#q', 'SIGNAL-77');
    await expect(page.locator('.result .cn')).toHaveText('SIGNAL-77');
    await expect(page.locator('.result .cm')).not.toContainText('TEMPLE-NOTE');

    await page.locator('.rail [data-screen="home"]').click();
    await page.keyboard.press('/');
    await expect(page.locator('#search-view')).toBeVisible();
    await page.locator('.rail [data-screen="home"]').click();
    await page.keyboard.press('Control+k');
    await expect(page.locator('#q')).toBeVisible();
    await page.locator('.rail [data-screen="home"]').click();
    await page.keyboard.press('Meta+k');
    await expect(page.locator('#q')).toBeVisible();
  });

  test('media stays encrypted and evidence metadata can be revealed', async () => {
    await page.locator('.rail [data-screen="home"]').click();
    await openDesk(page);
    await page.locator('[data-tab="entries"]').click();
    await page.locator('tr', { hasText: 'SIGNAL-77' }).click();
    await expect(page.locator('#insp')).toContainText('SIGNAL-77');
    const photo = await markedPhoto(page);
    await page.fill('#msrc', 'camera roll');
    await page.locator('#mfile').setInputFiles({ name: 'plate.jpg', mimeType: 'image/jpeg', buffer: photo });
    await page.getByRole('button', { name: 'ATTACH' }).click();
    await expect(page.locator('#insp')).toContainText('plate.jpg');
    await expect.poll(async () => page.locator('#insp img.thumb').getAttribute('src')).toMatch(/^blob:/);

    const stored = await latin1Dump(page);
    for (const secret of [PASS, recoveryKey, 'SIGNAL-77', 'TEMPLE-NOTE', 'TestCamSEAX', 'UNIQUEPLAINTEXTMARKER', 'HX-NONE']) {
      expect(stored.includes(secret), secret).toBe(false);
    }
    const info = await vaultInfo(page);
    expect(info.iterations).toBeGreaterThanOrEqual(600000);
    expect(info.saltLen).toBe(16);
    expect(info.wrapsDiffer).toBe(true);

    await page.getByRole('button', { name: 'REVEAL EVIDENCE METADATA' }).click();
    await expect(page.locator('#insp')).toContainText('TestCamSEAX');
    await expect(page.locator('#insp')).toContainText('UNIQUEPLAINTEXTMARKER');

    await page.locator('.rail [data-screen="search"]').click();
    await page.fill('#q', 'plate');
    await page.locator('[data-scope="media"]').click();
    await expect(page.locator('.result')).toContainText('plate.jpg');
    await expect.poll(async () => page.locator('.result img.thumb').getAttribute('src')).toMatch(/^blob:/);
  });

  test('audit, subject export, sync, backup and recovery', async () => {
    await page.locator('.rail [data-screen="home"]').click();
    await openDesk(page);
    await page.locator('[data-tab="entries"]').click();
    await page.locator('tr', { hasText: 'SIGNAL-77' }).click();
    const [sar] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: 'EXPORT ALL (SAR)' }).click(),
    ]);
    const sarPath = path.join(os.tmpdir(), sar.suggestedFilename());
    await sar.saveAs(sarPath);
    const sarJson = JSON.parse(fs.readFileSync(sarPath, 'utf8'));
    const religion = sarJson.custom.find((f) => f.label === 'Religion');
    const squad = sarJson.custom.find((f) => f.label === 'Squad colour');
    const call = sarJson.custom.find((f) => f.label === 'Call sign');
    expect(religion.specialCategory).toBe(true);
    expect(religion.value.seaxSpecial).toBe(1);
    expect(religion.value.iv).toBeTruthy();
    expect(religion.value.ct).toBeTruthy();
    expect(fs.readFileSync(sarPath, 'utf8')).not.toContain('TEMPLE-NOTE');
    expect(squad.specialCategory).toBe(true);
    expect(call.specialCategory).toBe(false);
    expect(call.value).toBe('CS-77');

    await page.locator('[data-tab="audit"]').click();
    const table = page.locator('.pane table');
    await expect(table).toContainText('ACTIVE MODE active');
    await expect(table).toContainText('FIELD_DEFINE');
    await expect(table).toContainText('FIELD_VIEW');
    await expect(table).toContainText('FIELD_VALUE');
    await expect(table).toContainText('MEDIA_ADD');
    await expect(table).not.toContainText('TEMPLE-NOTE');
    await expect(table).not.toContainText('HX-NONE');
    await page.getByRole('button', { name: 'VERIFY HASH CHAIN' }).click();
    await expect(page.locator('#vr')).toContainText('CHAIN INTACT');

    await page.locator('[data-tab="sync"]').click();
    await page.fill('#sync-pass', PASS);
    const syncA = await downloadBytes(page, 'EXPORT SYNC BUNDLE');
    await expect(page.locator('#sync-msg')).toContainText('Sync bundle downloaded');

    const other = await context.browser().newContext();
    const pageB = await other.newPage();
    const bucketB = { errors: [], hosts: [] };
    track(pageB, bucketB);
    await pageB.goto('/');
    await pageB.locator('#bundle-file').setInputFiles(syncA);
    await pageB.fill('#bundle-pass', PASS);
    await pageB.getByRole('button', { name: 'IMPORT SYNC BUNDLE' }).click();
    await expect(pageB.locator('body')).toContainText('IMPORTED');
    await pageB.locator('#home .card', { hasText: 'CASE-ALPHA' }).click();
    await pageB.locator('[data-tab="entries"]').click();
    await pageB.locator('tr', { hasText: 'SIGNAL-77' }).click();
    await expect(pageB.locator('#insp')).toContainText('SIGNAL-77');
    await expect(pageB.locator('#insp label', { hasText: 'Religion' }).locator('xpath=following-sibling::input[1]')).toHaveValue('TEMPLE-NOTE');
    await pageB.getByRole('button', { name: 'REVEAL EVIDENCE METADATA' }).click();
    await expect(pageB.locator('#insp')).toContainText('TestCamSEAX');
    await pageB.fill('#notes', 'NOTE-B');
    await pageB.getByRole('button', { name: 'SAVE NOTES' }).click();
    await expect(pageB.locator('#notes')).toHaveValue('NOTE-B');
    await pageB.locator('[data-tab="sync"]').click();
    await pageB.fill('#sync-pass', PASS);
    const syncB = await downloadBytes(pageB, 'EXPORT SYNC BUNDLE');
    expect(bucketB.errors).toEqual([]);
    expect(bucketB.hosts).toEqual([]);
    await other.close();

    await page.locator('[data-tab="entries"]').click();
    await page.locator('tr', { hasText: 'SIGNAL-77' }).click();
    await expect(page.locator('#notes')).toHaveValue('NOTE-A');
    await page.fill('#notes', 'NOTE-A2');
    await page.getByRole('button', { name: 'SAVE NOTES' }).click();
    await expect(page.locator('#notes')).toHaveValue('NOTE-A2');
    await page.locator('[data-tab="sync"]').click();
    await page.fill('#sync-pass', PASS);
    await page.locator('#bundle-file').setInputFiles(syncB);
    await page.getByRole('button', { name: 'IMPORT AND MERGE' }).click();
    await expect(page.locator('body')).toContainText('MERGED');
    await expect(page.locator('body')).toContainText('conflicts');
    await openDesk(page);
    await page.locator('[data-tab="entries"]').click();
    await page.locator('tr', { hasText: 'SIGNAL-77' }).click();
    await expect(page.locator('#notes')).toHaveValue('NOTE-A2');
    await page.locator('[data-tab="audit"]').click();
    await expect(page.locator('.pane table')).toContainText('SYNC_CONFLICT');

    await page.locator('[data-tab="sync"]').click();
    await page.fill('#sync-pass', PASS);
    const backup = await downloadBytes(page, 'EXPORT ENCRYPTED BACKUP');
    await expect(page.locator('#sync-msg')).toContainText('Backup downloaded.');
    await page.locator('[data-act="lock"]').click();
    await expect(page.getByRole('button', { name: 'SIGN IN' })).toBeVisible();
    await expect(page.locator('body')).not.toContainText('Backup downloaded');
    await page.fill('#p', PASS);
    await page.getByRole('button', { name: 'SIGN IN' }).click();
    await openDesk(page);
    await page.locator('[data-tab="sync"]').click();
    await page.locator('#bundle-file').setInputFiles(backup);
    await page.fill('#sync-pass', PASS);
    await page.getByRole('button', { name: 'VERIFY BACKUP' }).click();
    await expect(page.locator('#sync-msg')).toContainText('BACKUP OK');
    await expect(page.locator('#sync-msg')).toContainText('chain intact');

    const tampered = path.join(os.tmpdir(), `seax-tampered-${Date.now()}.seax`);
    const bytes = fs.readFileSync(backup);
    bytes[bytes.length - 1] ^= 0xff;
    fs.writeFileSync(tampered, bytes);
    await page.locator('#bundle-file').setInputFiles(tampered);
    await page.fill('#sync-pass', PASS);
    await page.getByRole('button', { name: 'VERIFY BACKUP' }).click();
    await expect(page.locator('body')).toContainText('This file failed the integrity check.');

    await page.fill('#sync-pass', 'wrong-passphrase-value');
    await page.locator('#bundle-file').setInputFiles(backup);
    await page.getByRole('button', { name: 'VERIFY BACKUP' }).click();
    await expect(page.locator('body')).toContainText('Could not open this file');

    await page.fill('#sync-pass', PASS);
    await page.locator('#bundle-file').setInputFiles(backup);
    await page.getByRole('button', { name: 'IMPORT AND MERGE' }).click();
    await expect(page.locator('body')).toContainText('This file is a backup, not a sync bundle.');

    await page.locator('[data-tab="entries"]').click();
    await page.locator('tr', { hasText: 'SIGNAL-77' }).click();
    await expect(page.locator('#notes')).toHaveValue('NOTE-A2');
    await page.fill('#notes', 'NOTE-WIP');
    await page.getByRole('button', { name: 'SAVE NOTES' }).click();
    await page.locator('[data-tab="sync"]').click();
    await page.fill('#sync-pass', PASS);
    await page.locator('#bundle-file').setInputFiles(backup);
    await page.getByRole('button', { name: 'RESTORE BACKUP' }).click();
    await expect(page.getByRole('button', { name: 'CONFIRM RESTORE' })).toBeVisible();
    await page.getByRole('button', { name: 'CONFIRM RESTORE' }).click();
    await expect(page.locator('body')).toContainText('RESTORED');
    await openDesk(page);
    await page.locator('[data-tab="entries"]').click();
    await page.locator('tr', { hasText: 'SIGNAL-77' }).click();
    await expect(page.locator('#notes')).toHaveValue('NOTE-A2');

    await page.locator('[data-act="lock"]').click();
    await page.getByRole('button', { name: 'UNLOCK WITH RECOVERY KEY' }).click();
    await page.fill('#rec-key', recoveryKey);
    await page.fill('#new-p', PASS2);
    await page.fill('#new-p2', PASS2);
    await page.getByRole('button', { name: 'SET NEW PASSPHRASE AND OPEN' }).click();
    await expect(page.locator('#home')).toBeVisible();
    await page.locator('[data-act="lock"]').click();
    await page.fill('#p', PASS);
    await page.getByRole('button', { name: 'SIGN IN' }).click();
    await expect(page.locator('#e')).toContainText('Wrong passphrase');
    await page.fill('#p', PASS2);
    await page.getByRole('button', { name: 'SIGN IN' }).click();
    await expect(page.locator('#home')).toBeVisible();
  });

  test('no console errors and no third-party requests', async () => {
    expect(bucket.errors).toEqual([]);
    expect(bucket.hosts).toEqual([]);
  });
});

test('five failures lock the desk', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const bucket = { errors: [], hosts: [] };
  track(page, bucket);
  await createDesk(page);
  await page.locator('[data-act="lock"]').click();
  for (let i = 0; i < 4; i++) {
    await page.fill('#p', 'wrong-passphrase-value');
    await page.getByRole('button', { name: 'SIGN IN' }).click();
    await expect(page.locator('#e')).toContainText('Wrong passphrase');
  }
  await page.fill('#p', 'wrong-passphrase-value');
  await page.getByRole('button', { name: 'SIGN IN' }).click();
  await expect(page.locator('#e')).toContainText('Locked for 15 minutes after 5 failed attempts');
  await page.fill('#p', PASS);
  await page.getByRole('button', { name: 'SIGN IN' }).click();
  await expect(page.locator('#e')).toContainText('Locked for 15 minutes');
  expect(bucket.errors).toEqual([]);
  await context.close();
});

test('idle lock', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.clock.install();
  await createDesk(page);
  await expect(page.locator('#home')).toBeVisible();
  await page.clock.fastForward(16 * 60 * 1000);
  await expect(page.getByRole('button', { name: 'SIGN IN' })).toBeVisible();
  await context.close();
});

test('offline shell', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors = [];
  page.on('pageerror', (err) => pageErrors.push(String(err)));
  await page.goto('/');
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.reload();
  await page.waitForFunction(() => navigator.serviceWorker.controller);
  await context.setOffline(true);
  await page.reload();
  await expect(page.getByRole('button', { name: 'CREATE SEAX ALPHA' })).toBeVisible();
  await context.setOffline(false);
  expect(pageErrors).toEqual([]);
  await context.close();
});

test('compliance gate returns when ACTIVE mode is off', async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, serviceWorkers: 'block' });
  const page = await context.newPage();
  const bucket = { errors: [], hosts: [] };
  track(page, bucket);
  const configBody = fs.readFileSync(new URL('../js/config.js', import.meta.url), 'utf8')
    .replace('export const ACTIVE_MODE = true;', 'export const ACTIVE_MODE = false;');
  await context.route('**/js/config.js', (route) => route.fulfill({
    status: 200,
    contentType: 'text/javascript',
    body: configBody,
  }));
  await page.goto('/');
  await expect(page.locator('#mode-badge')).toHaveCount(0);
  await expect(page.locator('#n')).toBeVisible();
  await expect(page.locator('.h', { hasText: 'CREATE SEAX ALPHA' })).toBeVisible();
  await createDesk(page, { name: 'desk-owner' });
  await expect(page.locator('#home')).toBeVisible();
  await expect(page.locator('body')).not.toContainText('ethnicity');
  await page.locator('.rail [data-screen="settings"]').click();
  for (const key of ['gate', 'paperwork', 'notices', 'personBasis']) await page.check(`#cmp-${key}`);
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.locator('body')).toContainText('ethnicity');
  await expect(page.locator('body')).toContainText('UK GDPR Article 9');
  await expect(page.locator('#home')).toHaveCount(0);
  await page.fill('#ico', 'ZB000000');
  await page.fill('#dt', 'Desk assessment');
  await page.fill('#dv', '1');
  await page.fill('#dsg', '2026-11-01');
  await page.fill('#drv', '2027-01-15');
  await page.check('#notice');
  await page.check('#ropa');
  await page.check('#retention');
  await page.check('#apd');
  await page.getByRole('button', { name: 'CONFIRM DESK DOCUMENTS' }).click();
  await expect(page.locator('#home')).toBeVisible();
  await expect(page.locator('#mode-badge')).toHaveCount(0);

  await saveCase(page);
  await openDesk(page);
  await page.locator('[data-tab="add"]').click();
  await page.selectOption('#ty', 'Location');
  await page.fill('#lb', 'SITE-NORTH');
  await page.fill('#src', 'SRC-1');
  await page.fill('#sd', '2026-11-01');
  await page.fill('#od', '2026-11-01');
  await page.getByRole('button', { name: 'SAVE ENTRY' }).click();
  await expect(page.locator('#insp')).toContainText('SITE-NORTH');
  const photo = await markedPhoto(page);
  await page.fill('#msrc', 'camera roll');
  await page.check('#ident');
  await page.locator('#mfile').setInputFiles({ name: 'plate.jpg', mimeType: 'image/jpeg', buffer: photo });
  await page.getByRole('button', { name: 'ATTACH' }).click();
    await expect(page.locator('#insp #e, #e').first()).toContainText('lawful-basis');

  await page.locator('[data-tab="add"]').click();
  await page.selectOption('#ty', 'Person');
  await expect(page.locator('#bs')).toBeVisible();
  await page.fill('#lb', 'SIGNAL-77');
  await page.fill('#src', 'SRC-1');
  await page.fill('#sd', '2026-11-01');
  await page.fill('#od', '2026-11-01');
  await page.getByRole('button', { name: 'SAVE ENTRY' }).click();
  await expect(page.locator('.pane #e')).toContainText('Consent needs a proof reference');
  await page.fill('#cp', 'PROOF-1');
  await page.getByRole('button', { name: 'SAVE ENTRY' }).click();
  await expect(page.locator('#insp')).toContainText('SIGNAL-77');
  await expect(page.locator('[data-cat="Health"]')).toHaveCount(0);
  await expect(page.locator('#insp')).toContainText('HEALTH');

  await page.locator('[data-tab="compliance"]').click();
  await expect(page.getByRole('button', { name: 'REVIEW DESK DOCUMENTS' })).toBeVisible();
  await page.fill('#ev_Health', 'EV-REF-1');
  await page.locator('[data-act="do-unlock"][data-cat="Health"]').click();
  await expect(page.locator('body')).toContainText('HEALTH · UNLOCKED');
  await page.locator('[data-tab="entries"]').click();
  await page.locator('tr', { hasText: 'SIGNAL-77' }).click();
  await expect(page.locator('[data-cat="Health"]')).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  expect(bucket.errors).toEqual([]);
  expect(bucket.hosts).toEqual([]);
  await context.close();
});

test('iPhone home and search', async ({ browser }) => {
  const iphone = { ...devices['iPhone 13'] };
  delete iphone.defaultBrowserType;
  const context = await browser.newContext(iphone);
  const page = await context.newPage();
  const bucket = { errors: [], hosts: [] };
  track(page, bucket);
  await createDesk(page);
  await assertCleanCopy(page);
  await expect(page.locator('#mode-badge')).toHaveText('ACTIVE');
  await saveCase(page);
  await openDesk(page);
  await addEntry(page, 'Person', 'SIGNAL-77');
  await addEntry(page, 'Location', 'SITE-NORTH');
  const record = await page.evaluate(() => {
    const insp = document.querySelector('#insp').getBoundingClientRect();
    const fold = document.querySelector('.graph-fold');
    return {
      inspTop: insp.top,
      foldTop: fold ? fold.getBoundingClientRect().top : null,
      open: fold ? fold.open : null,
      foldHeight: fold ? fold.getBoundingClientRect().height : null,
    };
  });
  expect(record.open).toBe(false);
  expect(record.inspTop).toBeLessThan(280);
  expect(record.inspTop).toBeLessThan(record.foldTop);
  expect(record.foldHeight).toBeLessThan(80);
  await page.locator('.rail [data-screen="home"]').click();
  await expect(page.locator('.hero-search')).toBeVisible();
  const homeTargets = await page.locator('#home button, .rail button, header button').evaluateAll((els) => (
    els.filter((el) => el.getBoundingClientRect().height < 44).map((el) => el.innerText.slice(0, 40))
  ));
  expect(homeTargets).toEqual([]);
  let overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await shot(page, 'home-iphone.png');

  await page.keyboard.press('/');
  await expect(page.locator('#q')).toBeVisible();
  await page.fill('#q', 'CASE-ALPHA');
  await expect(page.locator('.group h3', { hasText: 'People' })).toBeVisible();
  await expect(page.locator('.group h3', { hasText: 'Locations' })).toBeVisible();
  const searchTargets = await page.locator('#search-view button, .chip').evaluateAll((els) => (
    els.filter((el) => el.getBoundingClientRect().height < 44).map((el) => el.innerText.slice(0, 40))
  ));
  expect(searchTargets).toEqual([]);
  overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await shot(page, 'search-iphone.png');
  expect(bucket.errors).toEqual([]);
  expect(bucket.hosts).toEqual([]);
  await context.close();
});
