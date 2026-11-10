import { ACTIVE_MODE } from './config.js';
import { lockoutView, nextLockout } from './lockout.js';
import { COMPLIANCE_KEYS } from './settings.js';
import { deriveFieldKey, isSealedSpecial, openSpecialValue, sealSpecialValue } from './special.js';
import {
  ITERATIONS,
  LOCKOUT_MS,
  asBytes,
  auditHash,
  decodeKey,
  deriveKek,
  encodeKey,
  generateDataKey,
  importRawKey,
  normaliseBox,
  openBytes,
  openJson,
  sealBytes,
  sealJson,
  sha256Hex,
  toB64,
  unwrapDataKey,
  verifyChain,
  wrapDataKey,
} from './crypto.js';
import {
  LOCKOUT_KEY,
  STATE_KEY,
  VAULT_KEY,
  exifKey,
  idbAll,
  idbDel,
  idbDeleteDb,
  idbGet,
  idbSet,
  mediaKey,
  thumbKey,
} from './db.js';
import { extractMetadata } from './exif.js';
import { icon } from './icons.js';
import {
  FIELD_RECORD_TYPES,
  FIELD_TYPES,
  coerceField,
  defsFor,
  fieldHasData,
  fieldRecordTypeForEntry,
  fieldText,
  isSpecialLabel,
  resolveSpecial,
} from './fields.js';
import { decryptMedia, deleteMediaBlobs, encryptMedia, makeThumbBytes, sniffMime } from './media.js';
import { ENTRY_TYPES, SPECIAL_CATEGORIES, assertClean, assertSpecial, normalise, uid } from './schema.js';
import { groupResults, searchDesk } from './search.js';
import { BundleSyncAdapter } from './sync.js';
import { nowLondon, todayLondon } from './time.js';

const NOTICE = {
  excluded: 'Built-in fields do not include ethnicity, religion or political views. A custom field whose label matches those topics is tagged as a special category, and each view and edit is written to the audit log.',
  notes: 'Notes (no ethnic or racial labels; observable features only)',
  lawful: 'Lawful basis (required)',
  consent: 'Consent proof / privacy-notice status',
  identifiable: 'Images of identifiable people need the lawful-basis check already on this case (consent on the person, or a case LIA).',
  specialLead: 'Special-category data stays locked until it is unlocked for this case. UK GDPR Article 9 and the Data Protection Act 2018 still apply.',
  gateLead: 'You confirm each document exists and where it is kept. The desk stores only the details below, never the document.',
  fieldHelp: 'Labels about ethnicity, race, religion, faith or political views are stored as a special category: views and edits are audit-logged and flagged on a subject access export.',
};

const ABBR = {
  Person: 'P',
  Location: 'LOC',
  Vehicle: 'VEH',
  Organisation: 'ORG',
  'Telecom/Email': 'TEL',
  Intelligence: 'INT',
  Financial: '\u00a3',
  Other: 'OTH',
};

const ui = {
  screen: 'home',
  tab: 'graph',
  sel: null,
  error: '',
  notice: '',
  busy: '',
  vault: false,
  showRecovery: false,
  showErase: false,
  showCase: false,
  query: '',
  scope: 'all',
  confirmRemove: null,
  confirmWithdraw: null,
  pendingRestore: null,
  editField: null,
  confirmDelete: null,
  printRecord: null,
  preview: null,
  addType: 'Person',
};
const revealed = new Set();
const seenThumb = new Set();
let setupPending = null;
let dataKey = null;
let state = null;
let renderGen = 0;
let thumbUrls = [];
let idleTimer = 0;
let hiddenAt = 0;
let chain = Promise.resolve();
let fieldKey = null;
let devicePolicy = { idleMin: 15, lockoutMax: 5 };
const DISCLAIMER = 'SEAX Intelligence is a private case-management desk. It is not a police, government or official body.';

const api = {
  getDataKey: () => dataKey,
  setDataKey: (k) => { dataKey = k; },
  getState: () => state,
  setState: (s) => { state = normalise(s); },
  hasVault: async () => !!(await idbGet(VAULT_KEY)),
  getVault: () => idbGet(VAULT_KEY),
  putVault: (v) => idbSet(VAULT_KEY, v),
  getRecord: (k) => idbGet(k),
  putRecord: (k, v) => idbSet(k, v),
  delRecord: (k) => idbDel(k),
  listKeys: async () => (await idbAll()).map(([k]) => k),
  wipeRecords: async () => {
    for (const [k] of await idbAll()) {
      if (k !== VAULT_KEY && k !== LOCKOUT_KEY) await idbDel(k);
    }
  },
  deleteMediaBlobs: (id) => deleteMediaBlobsByPrefix(id),
  audit: (action, detail) => audit(action, detail),
  saveState: () => saveState(),
  assertPassphrase: (pass) => assertPassphrase(pass),
};
const bundles = new BundleSyncAdapter(api);

function flag(name) {
  return !!(state && state.settings && state.settings.compliance && state.settings.compliance[name]);
}
function note(key) {
  if (!flag('notices')) return '';
  return NOTICE[key] || '';
}
function idleMs() {
  return devicePolicy.idleMin * 60 * 1000;
}
async function ensureFieldKey() {
  if (!dataKey) throw new Error('The desk is locked. Sign in and try again.');
  if (!fieldKey) fieldKey = await deriveFieldKey(dataKey);
  return fieldKey;
}
function applyDevicePolicy(src) {
  if (!src) return;
  if (src.idleMin) devicePolicy.idleMin = src.idleMin;
  if (src.lockoutMax) devicePolicy.lockoutMax = src.lockoutMax;
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
function v(id) {
  return document.getElementById(id)?.value?.trim() ?? '';
}
function secret(id) {
  return document.getElementById(id)?.value ?? '';
}
function touch(o) {
  o.updatedAt = new Date().toISOString();
  return o;
}
function cur() {
  return state.cases.find((c) => c.id === state.curCase) || state.cases[0] || null;
}
function deskOpen() {
  if (!flag('gate')) return true;
  const a = state.attest || {};
  if (!flag('paperwork')) return !!a.opened;
  return !!(a.ico && a.dpia && a.notice && a.ropa && a.retention && a.dpia.review >= todayLondon());
}
function categoryOpen(c, cat) {
  if (!flag('gate')) return true;
  if (!c) return false;
  return !!(c.unlocks || []).find((u) => u.cat === cat && !u.revoked);
}
function serial(fn) {
  const job = chain.then(() => fn());
  chain = job.then(() => {}, () => {});
  return job;
}
function typeIcon(type) {
  return { Person: 'person', Location: 'pin', Vehicle: 'vehicle', Organisation: 'org', case: 'case', media: 'media' }[type] || 'other';
}

function emptyState(name) {
  return normalise({
    owner: { name, updatedAt: new Date().toISOString() },
    attest: {},
    cases: [],
    ents: [],
    links: [],
    tasks: [],
    audit: [],
    media: [],
    conflicts: [],
    tombstones: [],
    retainedAudits: [],
    fieldDefs: [],
    curCase: null,
  });
}
async function saveState() {
  assertClean(state);
  for (const e of state.ents) assertSpecial(e.sp);
  await idbSet(STATE_KEY, await sealJson(dataKey, state));
}
async function audit(action, detail) {
  const prev = state.audit.length ? state.audit[state.audit.length - 1].hash : 'GENESIS';
  const entry = { t: nowLondon(), who: state.owner?.name || 'system', action, detail: String(detail ?? ''), prev };
  entry.hash = await auditHash(entry);
  state.audit.push(entry);
}
function addTombstone(collection, targetId) {
  const id = `${collection}:${targetId}`;
  const rec = { id, collection, target: targetId, updatedAt: new Date().toISOString() };
  const existing = state.tombstones.find((t) => t.id === id);
  if (existing) Object.assign(existing, rec);
  else state.tombstones.push(rec);
}
async function deleteMediaBlobsByPrefix(id) {
  for (const [k] of await idbAll()) {
    if (k === exifKey(id) || k === thumbKey(id) || String(k).startsWith(`b:${id}:`)) await idbDel(k);
  }
}
async function lockoutStatus() {
  const now = Date.now();
  const curLock = (await idbGet(LOCKOUT_KEY)) || { fails: [] };
  const view = lockoutView(curLock.fails, now, LOCKOUT_MS, devicePolicy.lockoutMax);
  if (view.fails.length !== (curLock.fails || []).length) await idbSet(LOCKOUT_KEY, { fails: view.fails });
  return { locked: view.locked, until: view.until, fails: view.fails };
}
async function registerFailure() {
  const now = Date.now();
  const curLock = (await idbGet(LOCKOUT_KEY)) || { fails: [] };
  const view = nextLockout(curLock.fails, now, LOCKOUT_MS, devicePolicy.lockoutMax);
  await idbSet(LOCKOUT_KEY, { fails: view.fails });
  return view.count;
}
async function clearLockout() {
  await idbSet(LOCKOUT_KEY, { fails: [] });
}
function lockText(status) {
  const mins = Math.max(1, Math.ceil((status.until - Date.now()) / 60000));
  return `Locked for 15 minutes after ${devicePolicy.lockoutMax} failed attempts. Try again in ${mins} min.`;
}
async function assertNotLocked() {
  const status = await lockoutStatus();
  if (status.locked) throw new Error(lockText(status));
  return status;
}
async function assertPassphrase(pass) {
  if (!pass) throw new Error('Passphrase is required.');
  const vault = await idbGet(VAULT_KEY);
  try {
    const kek = await deriveKek(pass, asBytes(vault.salt), vault.iterations);
    await unwrapDataKey(normaliseBox(vault.passWrap), kek);
  } catch (err) {
    if (String(err.message || '').includes('minimum') || String(err.message || '').includes('too weak')) throw err;
    throw new Error('Passphrase does not match this device.');
  }
}
function armIdle() {
  clearTimeout(idleTimer);
  if (!dataKey) return;
  idleTimer = setTimeout(() => lock(), idleMs());
}
function lock() {
  clearTimeout(idleTimer);
  dataKey = null;
  fieldKey = null;
  state = null;
  setupPending = null;
  if (ui.preview?.url) URL.revokeObjectURL(ui.preview.url);
  ui.preview = null;
  ui.sel = null;
  ui.error = '';
  ui.showRecovery = false;
  revealed.clear();
  seenThumb.clear();
  clearThumbs();
  render();
}
function clearThumbs() {
  thumbUrls.forEach((u) => URL.revokeObjectURL(u));
  thumbUrls = [];
}
function pick3() {
  const s = new Set();
  while (s.size < 3) s.add(crypto.getRandomValues(new Uint8Array(1))[0] % 13);
  return [...s].sort((a, b) => a - b);
}

function render() {
  const gen = ++renderGen;
  clearThumbs();
  document.body.dataset.screen = screenName();
  document.body.classList.toggle('print-key', !!setupPending);
  document.body.classList.toggle('print-record', !!ui.printRecord && !setupPending);
  document.getElementById('app').innerHTML = shell();
  document.getElementById('print-root').innerHTML = printSheet();
  if (dataKey && state && deskOpen() && cur() && ui.screen === 'desk' && ui.tab === 'graph') {
    const pane = document.getElementById('pane');
    if (pane) pane.innerHTML = graphHtml();
  }
  const q = document.getElementById('q');
  if (q) q.focus();
  queueMicrotask(() => {
    fillAddExtras();
    fillSpecialInputs(gen);
    hydrate(gen);
  });
}
function screenName() {
  if (!ui.vault && !setupPending) return 'setup';
  if (setupPending) return 'recovery';
  if (!dataKey) return ui.showRecovery ? 'recover' : 'signin';
  if (!deskOpen()) return 'gate';
  return ui.screen || 'home';
}
function shell() {
  if (setupPending) return recoveryScreen();
  if (!ui.vault) return setupScreen();
  if (!dataKey) return ui.showRecovery ? recoverScreen() : signScreen();
  if (!deskOpen()) return gateScreen();
  return `${frameStart()}${bodyScreen()}${footer()}</div></div>${previewHtml()}`;
}
function frameStart() {
  return `<div class="shell"><nav class="rail">${rail()}</nav><div class="stage">${header()}${banners()}`;
}
function rail() {
  const item = (screen, name, label) =>
    `<button class="${ui.screen === screen ? 'on' : ''}" data-act="go" data-screen="${screen}">${icon(name)}<span>${label}</span></button>`;
  return `${item('home', 'home', 'Home')}${item('desk', 'case', 'Cases')}${item('search', 'search', 'Search')}${item('settings', 'settings', 'Settings')}`;
}
function header() {
  const name = state.owner.name === 'SEAX ALPHA' ? 'SEAX ALPHA' : `${state.owner.name} · SEAX ALPHA`;
  return `<header>
    <div class="brand"><img class="mark" src="assets/icons/seax-small-mark-64.png" width="64" height="64" alt="">SEAX${ACTIVE_MODE ? '<span class="badge" id="mode-badge">ACTIVE</span>' : ''}</div>
    <button class="search-jump" data-act="go" data-screen="search" aria-label="Search">${icon('search')}<span>Search</span><span class="shortcut">/</span></button>
    <div class="st">
      <span class="ok">${esc(name)}</span>
      <span>Sync bundle</span>
      ${flag('gate') ? `<span>Desk gate ${deskOpen() ? '<span class="ok">open</span>' : '<span class="amb">shut</span>'}</span>` : ''}
      <span>Lock after ${devicePolicy.idleMin} min</span>
      <span id="clock">${esc(nowLondon())}</span>
      <a href="#" data-act="lock">Lock</a>
    </div>
  </header>`;
}
function banners() {
  const mark = '<div class="seax-banner seax-banner--internal">SEAX desk-internal</div>';
  return `${mark}${ui.busy ? `<div class="band">${esc(ui.busy)}</div>` : ''}${ui.notice ? `<div class="band">${esc(ui.notice)}</div>` : ''}${ui.error ? `<div class="errband">${esc(ui.error)}</div>` : ''}`;
}
function footer() {
  const disclaimer = flag('disclaimer') ? `<span class="seax-disclaimer">${esc(DISCLAIMER)}</span>` : '<span>Private case desk</span>';
  return `<footer>${disclaimer}<span id="chain">Audit ${state.audit.length} entries</span></footer>`;
}
function bodyScreen() {
  if (ui.screen === 'search') return searchScreen();
  if (ui.screen === 'fields') return fieldsScreen();
  if (ui.screen === 'settings') return settingsScreen();
  if (ui.screen === 'desk') return cur() ? deskScreen() : emptyCases();
  ui.screen = 'home';
  return homeScreen();
}
function emptyCases() {
  return `<div class="home" id="cases-empty"><div class="h">Cases</div><p class="note">No cases yet.</p><button class="g" data-act="show-case">New case</button>${ui.showCase ? caseForm() : ''}</div>`;
}
function settingsScreen() {
  const s = state.settings;
  const switches = [
    ['gate', 'Compliance unlock gate'],
    ['personBasis', 'Consent and legitimate interests on people'],
    ['art9', 'Article 9 condition on special-category fields'],
    ['paperwork', 'Paperwork and document prompts'],
    ['retention', 'Retention reminders'],
    ['notices', 'Data-protection notices'],
    ['disclaimer', 'Not-official disclaimer'],
  ];
  const due = flag('retention') && s.retentionDate && s.retentionDate <= todayLondon()
    ? '<p class="note">Retention review is due.</p>'
    : '';
  return `<div class="settings" id="settings-view">
    <h1 class="title">Settings</h1>
    <div class="box">
      <label>Lock after idle minutes</label><input id="set-idle" type="number" min="1" max="240" value="${esc(s.idleMin)}">
      <label>Failed attempts before lockout</label><input id="set-lock" type="number" min="3" max="20" value="${esc(s.lockoutMax)}">
      ${flag('retention') ? `<label>Retention review date</label><input id="set-ret" type="date" value="${esc(s.retentionDate || '')}">${due}` : ''}
      <button class="g" data-act="save-settings">Save settings</button>
    </div>
    <div class="box">
      <div class="h" style="margin-top:0">Compliance</div>
      <p class="note">Each control stays off until you turn it on. Encryption, the passphrase, lockout, the recovery key, the audit log and backups stay on.</p>
      ${switches.map(([key, label]) => `<label class="switch"><input type="checkbox" id="cmp-${key}" ${s.compliance[key] ? 'checked' : ''}> ${label}</label>`).join('')}
    </div>
    <button data-act="go" data-screen="fields">Custom fields</button>
  </div>`;
}

function setupScreen() {
  const name = ACTIVE_MODE
    ? ''
    : '<label>SEAX ALPHA username</label><input id="n" autocomplete="username" autocapitalize="off">';
  return `<div class="center"><div class="brand"><img class="mark" src="assets/icons/seax-small-mark-64.png" width="64" height="64" alt="">SEAX</div>
    <div class="h">${ACTIVE_MODE ? 'Create SEAX ALPHA' : 'Create SEAX ALPHA'}</div>
    ${name}
    <label>Passphrase (12+ characters)</label><input id="p" type="password" autocomplete="new-password">
    <label>Confirm passphrase</label><input id="p2" type="password" autocomplete="new-password">
    <button class="g" data-act="create-admin">CREATE SEAX ALPHA</button>
    <p class="note">The desk is encrypted on this device. The recovery key is shown once, on the next screen.</p>
    <div id="e" class="red">${esc(ui.error)}</div>
    <div class="box"><div class="h" style="margin-top:0">ALREADY HAVE A BUNDLE?</div>
      <label>Bundle or backup file</label><input id="bundle-file" type="file">
      <label>Passphrase for that file</label><input id="bundle-pass" type="password" autocomplete="current-password">
      <button data-act="import-bundle">IMPORT SYNC BUNDLE</button>
      <button data-act="restore-backup">RESTORE BACKUP</button>
      <button data-act="verify-backup">VERIFY BACKUP</button>
      <div id="sync-msg" class="note">${esc(ui.notice)}</div>
    </div></div>`;
}
function recoveryScreen() {
  const groups = setupPending.groups;
  const ask = setupPending.ask;
  const grid = groups.map((g, i) => `<div class="rk" data-group="${g}"><span class="k">${String(i + 1).padStart(2, '0')}</span> ${g}</div>`).join('');
  const inputs = ask.map((idx, n) => `<label for="ch${n}">Group ${String(idx + 1).padStart(2, '0')}</label><input id="ch${n}" data-idx="${idx}" autocomplete="off" autocapitalize="characters" spellcheck="false">`).join('');
  return `<div class="center" id="recovery-sheet" style="max-width:640px"><div class="brand"><img class="mark" src="assets/icons/seax-small-mark-64.png" width="64" height="64" alt="">SEAX</div>
    <div class="h">RECOVERY KEY · SHOWN ONCE</div>
    <p class="note">Print this page or write the key down, then store it offline. It will not be shown again. Anyone with this key can set a new passphrase.</p>
    <div class="rkgrid" id="key-grid">${grid}</div>
    <p class="m" id="key-line">${groups.join('-')}</p>
    <button class="g" data-act="print-key">PRINT RECOVERY KEY</button>
    <div class="box"><div class="h" style="margin-top:0">CONFIRM YOU HAVE THE KEY</div>
      <p class="note">Type group ${ask.map((i) => String(i + 1).padStart(2, '0')).join(', group ')}.</p>
      ${inputs}
      <label><input id="stored" type="checkbox" style="width:auto"> I have printed or written this key. I understand it will not be shown again.</label>
      <button class="g" data-act="confirm-recovery">CONFIRM AND CONTINUE</button>
      <div id="e" class="red">${esc(ui.error)}</div>
    </div></div>`;
}
function printSheet() {
  if (setupPending) {
    const groups = setupPending.groups;
    return `<h1>SEAX Intelligence</h1><h2>Recovery key</h2>
      <p>Shown once. Store this page offline. Anyone with this key can set a new passphrase.</p>
      ${groups.map((g, i) => `<div class="rk">${String(i + 1).padStart(2, '0')} &nbsp; ${g}</div>`).join('')}
      <p class="m">${groups.join('-')}</p><p>SEAX ALPHA: ${esc(setupPending.name)}</p>`;
  }
  if (!ui.printRecord || !state) return '';
  const e = state.ents.find((x) => x.id === ui.printRecord);
  if (!e) return '';
  const recordType = fieldRecordTypeForEntry(e.type);
  const fields = recordType
    ? (state.fieldDefs || []).filter((d) => d.recordType === recordType && !resolveSpecial(d))
    : [];
  const lines = fields.map((d) => {
    const value = e.custom ? e.custom[d.id] : '';
    if (value && typeof value === 'object') return '';
    return `<li>${esc(d.label)}: ${esc(fieldText(value))}</li>`;
  }).filter(Boolean);
  return `<div class="seax-banner seax-banner--internal">SEAX desk-internal</div>
    <h1>${esc(e.label)}</h1>
    <p>${esc(e.type)} · ${esc(e.id)} · ${esc(e.case)}</p>
    <h2>Record</h2>
    <p>Source ${esc(e.source || '')} · observed ${esc(e.obs || '')}</p>
    <p>${esc(e.desc || '')}</p>
    ${lines.length ? `<h2>Fields</h2><ul>${lines.join('')}</ul>` : ''}
    <p>Printed ${esc(nowLondon())}. Special-category values are omitted from this page.</p>`;
}
function signScreen() {
  return `<div class="center"><div class="brand"><img class="mark" src="assets/icons/seax-small-mark-64.png" width="64" height="64" alt="">SEAX</div>
    <div class="h">SIGN IN · SEAX ALPHA</div>
    <label>Passphrase</label><input id="p" type="password" autocomplete="current-password">
    <button class="g" data-act="sign-in">SIGN IN</button>
    <button data-act="show-recovery">UNLOCK WITH RECOVERY KEY</button>
    <button class="r" data-act="show-erase">ERASE THIS DEVICE</button>
    <div id="e" class="red">${esc(ui.error)}</div>
    ${ui.showErase ? '<div class="box"><label>Type ERASE to delete the encrypted desk on this device</label><input id="erase-word" autocomplete="off"><button class="r" data-act="erase-yes">CONFIRM ERASE</button></div>' : ''}
    <div class="box"><label>Backup file</label><input id="bundle-file" type="file">
      <label>Passphrase for that file</label><input id="bundle-pass" type="password">
      <button data-act="verify-backup">VERIFY BACKUP</button>
      <div id="sync-msg" class="note">${esc(ui.notice)}</div>
    </div></div>`;
}
function recoverScreen() {
  return `<div class="center"><div class="brand"><img class="mark" src="assets/icons/seax-small-mark-64.png" width="64" height="64" alt="">SEAX</div>
    <div class="h">UNLOCK WITH RECOVERY KEY</div>
    <p class="note">Enter the printed key, then choose a new passphrase. The recovery key itself stays the same.</p>
    <label>Recovery key</label><textarea id="rec-key" rows="3" autocomplete="off" autocapitalize="characters" spellcheck="false"></textarea>
    <label>New passphrase (12+ characters)</label><input id="new-p" type="password" autocomplete="new-password">
    <label>Confirm new passphrase</label><input id="new-p2" type="password" autocomplete="new-password">
    <button class="g" data-act="recovery-unlock">SET NEW PASSPHRASE AND OPEN</button>
    <button data-act="show-sign-in">BACK</button>
    <div id="e" class="red">${esc(ui.error)}</div></div>`;
}

function homeScreen() {
  const cases = state.cases.map((c) => `<button class="card" data-act="open-case" data-id="${esc(c.id)}"><div class="cn">${esc(c.id)}</div><div class="cm">${esc(c.client)} · ${state.ents.filter((e) => e.case === c.id).length} entries</div></button>`).join('') || '<div class="note">No open cases.</div>';
  const recent = recentRows().map((r) => `<button class="result" data-act="${r.kind === 'case' ? 'open-case' : 'open-entry'}" data-id="${esc(r.id)}" data-case="${esc(r.caseId || '')}">${icon(typeIcon(r.kind === 'case' ? 'case' : r.entryType))}<span><div class="cn">${esc(r.title)}</div><div class="cm">${esc(r.sub)}</div></span></button>`).join('') || '<div class="note">Nothing recorded yet.</div>';
  return `<div class="home" id="home">
    <h1 class="title">Home</h1>
    <button class="hero-search" data-act="go" data-screen="search">${icon('search')}<span>Search the desk</span><span class="shortcut">&#8984;K</span></button>
    <div class="h">QUICK ADD</div>
    <div class="qrow">
      ${['case', 'Person', 'Location', 'Vehicle', 'Organisation', 'Other'].map((t) => `<button class="qadd" data-act="quick-add" data-type="${t}">${icon(t === 'case' ? 'plus' : typeIcon(t))}<span>${t === 'case' ? 'Case' : t}</span></button>`).join('')}
    </div>
    ${ui.showCase ? caseForm() : ''}
    <div class="cols">
      <section class="panel"><div class="h" style="margin-top:0">OPEN CASES</div>${cases}</section>
      <section class="panel"><div class="h" style="margin-top:0">RECENT</div>${recent}</section>
    </div>
  </div>`;
}
function recentRows() {
  const rows = [];
  for (const c of state.cases) rows.push({ kind: 'case', id: c.id, title: c.id, sub: c.client || 'Case', at: c.updatedAt || '', entryType: 'case' });
  for (const e of state.ents) rows.push({ kind: 'entry', id: e.id, title: e.label, sub: `${e.type} · ${e.case}`, at: e.updatedAt || '', caseId: e.case, entryType: e.type });
  return rows.sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 8);
}
function searchScreen() {
  const chips = [
    ['all', 'All'], ['people', 'People'], ['locations', 'Locations'], ['vehicles', 'Vehicles'],
    ['organisations', 'Organisations'], ['cases', 'Cases'], ['media', 'Media'],
  ];
  return `<div class="search" id="search-view">
    <h1 class="title">Search</h1>
    <div class="search-bar">${icon('search')}<input id="q" placeholder="Search all" value="${esc(ui.query)}" autocomplete="off" enterkeyhint="search"></div>
    <div class="chips" id="chips">${chips.map(([id, label]) => `<button class="chip ${ui.scope === id ? 'on' : ''}" data-act="scope" data-scope="${id}">${label}</button>`).join('')}</div>
    <div id="results">${resultsHtml()}</div>
  </div>`;
}
function resultsHtml() {
  const q = ui.query.trim();
  if (!q) return '<p class="note">Type to search cases, people, places, vehicles, organisations, media and custom fields.</p>';
  const groups = groupResults(searchDesk(state, q, ui.scope));
  if (!groups.length) return '<p class="note">No matches.</p>';
  return groups.map((g) => `<section class="group"><h3>${icon(typeIcon(g.scope === 'people' ? 'Person' : g.scope === 'locations' ? 'Location' : g.scope === 'vehicles' ? 'Vehicle' : g.scope === 'organisations' ? 'Organisation' : g.scope === 'cases' ? 'case' : 'media'))} ${esc(g.label)}</h3>
    ${g.rows.map((r) => `<button class="result" data-act="open-result" data-kind="${esc(r.kind)}" data-id="${esc(r.id)}" data-case="${esc(r.caseId || '')}" data-parent-kind="${esc(r.parentKind || r.thumbParent?.kind || '')}" data-parent-id="${esc(r.parentId || r.thumbParent?.id || '')}">
      ${r.thumbId || r.kind === 'media' ? `<img class="thumb" alt="" data-thumb="${esc(r.thumbId || r.id)}">` : `<span class="ph">${icon(typeIcon(r.entryType || (r.kind === 'case' ? 'case' : 'other')))}</span>`}
      <span><div class="cn">${esc(r.title)}</div><div class="cm">${esc(r.subtitle)}</div></span>
    </button>`).join('')}
  </section>`).join('');
}
function fieldsScreen() {
  const editing = ui.editField ? state.fieldDefs.find((d) => d.id === ui.editField) : null;
  const help = note('fieldHelp');
  const list = FIELD_RECORD_TYPES.map(([id, label]) => {
    const defs = (state.fieldDefs || []).filter((d) => d.recordType === id).slice().sort((a, b) => a.order - b.order || a.label.localeCompare(b.label, 'en-GB'));
    if (!defs.length) return '';
    return `<div class="h">${esc(label).toUpperCase()}</div>${defs.map((d) => fieldRow(d)).join('')}`;
  }).join('');
  return `<div class="fields" id="fields-view">
    <h1 class="title">Custom fields</h1>
    ${help ? `<p class="note">${esc(help)}</p>` : ''}
    <div class="box" id="field-form">
      <label>Record type</label>
      <select id="fd-record">${FIELD_RECORD_TYPES.map(([id, label]) => `<option value="${id}" ${editing && editing.recordType === id ? 'selected' : ''}>${label}</option>`).join('')}</select>
      <label>Label</label><input id="fd-label" value="${esc(editing?.label || '')}">
      <label>Type</label>
      <select id="fd-kind">${FIELD_TYPES.map((t) => `<option ${editing && editing.type === t ? 'selected' : ''}>${t}</option>`).join('')}</select>
      <label>Display order</label><input id="fd-order" type="number" value="${esc(editing?.order ?? nextOrder())}">
      <label>Dropdown options (one per line)</label><textarea id="fd-options" rows="3">${esc((editing?.options || []).join('\n'))}</textarea>
      <label><input id="fd-required" type="checkbox" style="width:auto" ${editing?.required ? 'checked' : ''}> Required</label>
      <label><input id="fd-special" type="checkbox" style="width:auto" ${editing && (editing.explicitSpecial || resolveSpecial(editing)) ? 'checked' : ''}> Special category</label>
      <button class="g" data-act="save-field">${editing ? 'SAVE FIELD' : 'ADD FIELD'}</button>
      ${editing ? '<button data-act="cancel-field">CANCEL</button>' : ''}
      <div id="e" class="red"></div>
    </div>
    ${list || '<p class="note">No custom fields yet.</p>'}
    ${note('excluded') ? `<p class="note">${esc(note('excluded'))}</p>` : ''}
  </div>`;
}
function fieldRow(d) {
  const special = resolveSpecial(d);
  const data = fieldHasData(state, d.id);
  return `<div class="box"><div class="cn">${esc(d.label)}${special ? ' <span class="tag">SPECIAL</span>' : ''}${d.archived ? ' <span class="tag">ARCHIVED</span>' : ''}</div>
    <div class="cm">${esc(d.type)} · order ${esc(d.order)}${d.required ? ' · required' : ''}</div>
    <button data-act="edit-field" data-id="${esc(d.id)}">EDIT</button>
    ${d.archived ? `<button data-act="restore-field" data-id="${esc(d.id)}">RESTORE</button>` : `<button data-act="archive-field" data-id="${esc(d.id)}">ARCHIVE</button>`}
    ${data ? '' : `<button class="r" data-act="delete-field" data-id="${esc(d.id)}">${ui.confirmDelete === d.id ? 'Delete field' : 'Delete'}</button>`}
  </div>`;
}
function nextOrder() {
  const n = (state.fieldDefs || []).reduce((m, d) => Math.max(m, Number(d.order) || 0), 0);
  return n + 1;
}
function caseForm() {
  return `<div class="box"><label>Case codename</label><input id="case-name" autocomplete="off"><label>Client</label><input id="case-client" autocomplete="off">${customFieldsHtml('case', null, 'case')}<button class="g" data-act="save-case">SAVE CASE</button></div>`;
}

function gateScreen() {
  return `${header()}${banners()}<div class="band">Compliance</div><div class="pane" id="pane">${complianceHtml(null)}</div>${footer()}`;
}
function deskScreen() {
  const c = cur();
  const tabs = [['graph', 'Link graph'], ['entries', 'Entries'], ['add', 'Add entry'], ['audit', 'Audit log'], ['sync', 'Sync and backup']];
  if (flag('gate') || flag('paperwork') || flag('personBasis')) tabs.splice(3, 0, ['compliance', 'Compliance']);
  return `<div class="wrap"><div class="left"><div class="h">ACTIVE CASES</div>
      ${state.cases.map((k) => `<div class="card ${k.id === c.id ? 'on' : ''}" data-act="open-case" data-id="${esc(k.id)}"><div class="cn">${esc(k.id)}</div><div class="cm">${esc(k.client)}</div><div class="cm">${flag('personBasis') ? (k.lia ? 'LIA on file' : '<span class="amb">No LIA</span>') + ' · ' : ''}${state.ents.filter((e) => e.case === k.id).length} entries</div></div>`).join('')}
      ${ui.showCase ? caseForm() : ''}
      <button data-act="show-case">+ NEW CASE</button>
      <div class="h">TASK QUEUE</div>
      ${state.tasks.filter((t) => !t.done).map((t) => `<div class="card"><div class="cn red" style="font-size:11px">${esc(t.title)}</div><div class="cm">Due ${esc(t.due)}</div><button data-act="done-task" data-id="${esc(t.id)}">MARK DONE</button></div>`).join('') || '<div class="cm">Nothing due.</div>'}
    </div>
    <div class="main"><div class="band">${esc(c.id)}</div>
      <div class="tabs">${tabs.map(([id, label]) => `<div class="tab ${ui.tab === id ? 'on' : ''}" data-act="tab" data-tab="${id}">${label}</div>`).join('')}</div>
      <div class="pane" id="pane">${ui.tab === 'graph' ? '' : paneHtml(c)}</div>
    </div>
    <div class="right" id="insp">${inspectorHtml(c)}</div>
  </div>`;
}
function paneHtml(c) {
  if (ui.tab === 'entries') return entriesHtml(c);
  if (ui.tab === 'add') return addHtml();
  if (ui.tab === 'compliance') return complianceHtml(c);
  if (ui.tab === 'audit') return auditHtml();
  if (ui.tab === 'sync') return syncHtml();
  return '';
}
function entriesHtml(c) {
  const ents = state.ents.filter((e) => e.case === c.id);
  return `<div class="scroll"><table><tr><th>ID</th><th>Type</th><th>Label</th><th>Basis / grade</th><th>Source</th><th>Observed</th></tr>
    ${ents.map((e) => `<tr data-act="open-entry" data-id="${esc(e.id)}" data-case="${esc(c.id)}" style="cursor:pointer"><td>${esc(e.id)}</td><td>${esc(e.type)}</td><td>${e.locked ? 'Locked · ' : ''}${esc(e.label)}</td><td>${esc((flag('personBasis') ? e.basis : '') || e.grade || '')}</td><td>${esc(e.source)}</td><td>${esc(e.obs)}</td></tr>`).join('')}
  </table></div>`;
}
function addHtml() {
  if (!deskOpen()) return `<div class="box"><div class="cn amb">Desk gate shut</div><p class="note">${esc(note('gateLead') || 'The desk gate is shut.')}</p></div>`;
  return `<div style="max-width:560px"><label>Type</label><select id="ty">${ENTRY_TYPES.map((t) => `<option ${ui.addType === t ? 'selected' : ''}>${t}</option>`).join('')}</select>
    <label>Label</label><input id="lb"><div id="ex"></div>
    <label>Source (required)</label><input id="src"><label>Source date (required)</label><input id="sd" type="date"><label>Observation date (required)</label><input id="od" type="date" value="${todayLondon()}">
    <label>${esc(flag('notices') ? NOTICE.notes : 'Notes')}</label><textarea id="ds" rows="3"></textarea>
    <div id="custom-fields" data-prefix="new"></div>
    <button class="g" data-act="save-entry">SAVE ENTRY</button><div id="e" class="red"></div></div>`;
}
function extrasHtml() {
  const t = document.getElementById('ty')?.value || ui.addType;
  const c = cur();
  let html = '';
  if (t === 'Person' && flag('personBasis')) {
    const lawful = note('lawful') || 'Lawful basis';
    const consent = note('consent') || 'Consent proof';
    html += `<label>${esc(lawful)}</label><select id="bs"><option>Consent</option><option ${c && c.lia ? '' : 'disabled'}>Legitimate interests${c && c.lia ? '' : ' (needs case LIA)'}</option></select>
      <label>${esc(consent)}</label><input id="cp">`;
  }
  if (t === 'Intelligence') {
    html += `<label>Item type</label><select id="gr"><option>Fact</option><option>Attributed allegation</option><option>Analyst assessment</option></select>
      <label>Confidence grade</label><select id="cf">${['A1', 'A2', 'B2', 'B3', 'C3', 'D4', 'E5'].map((x) => `<option>${x}</option>`).join('')}</select>`;
  }
  if (t === 'Financial') html += '<p class="note">Financial source must be manual entry, Companies House, court judgment or client invoice.</p>';
  return html;
}
function customFieldsHtml(recordType, rec, prefix) {
  const defs = defsFor(state, recordType, { includeArchived: false }).concat(
    defsFor(state, recordType, { includeArchived: true }).filter((d) => d.archived && rec && fieldText(rec.custom && rec.custom[d.id])),
  );
  if (!defs.length) return '';
  return defs.map((d) => fieldInput(d, rec, prefix)).join('');
}
function fieldInput(d, rec, prefix) {
  const raw = rec && rec.custom ? rec.custom[d.id] : '';
  const sealed = isSealedSpecial(raw);
  const value = sealed || (raw && typeof raw === 'object') ? '' : raw;
  const id = `${prefix}-${d.id}`;
  const tag = resolveSpecial(d) ? ' <span class="tag">SPECIAL</span>' : '';
  const req = d.required ? ' *' : '';
  const seal = sealed ? ` data-sealed-field="${esc(d.id)}"` : '';
  const common = `id="${id}" data-field="${esc(d.id)}"${seal}`;
  let control = '';
  if (d.type === 'longtext') control = `<textarea ${common} rows="3">${esc(value ?? '')}</textarea>`;
  else if (d.type === 'bool') {
    const curV = value === true ? 'yes' : value === false ? 'no' : '';
    control = `<select ${common}><option value=""></option><option value="yes" ${curV === 'yes' ? 'selected' : ''}>Yes</option><option value="no" ${curV === 'no' ? 'selected' : ''}>No</option></select>`;
  } else if (d.type === 'dropdown') {
    control = `<select ${common}><option value=""></option>${(d.options || []).map((o) => `<option ${String(value) === o ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  } else if (d.type === 'number') control = `<input ${common} type="number" value="${esc(value ?? '')}">`;
  else if (d.type === 'date') control = `<input ${common} type="date" value="${esc(value ?? '')}">`;
  else if (d.type === 'url') control = `<input ${common} type="url" value="${esc(value ?? '')}">`;
  else control = `<input ${common} value="${esc(value ?? '')}">`;
  return `<label>${esc(d.label)}${req}${tag}${d.archived ? ' <span class="tag">ARCHIVED</span>' : ''}</label>${control}${art9Block(d)}`;
}
function art9Block(def) {
  if (!flag('art9') || !resolveSpecial(def)) return '';
  const c = cur();
  const saved = c && c.art9 ? c.art9[def.id] : null;
  const condition = saved?.condition || '';
  return `<label>Condition</label><select id="art9-${esc(def.id)}"><option value="">Choose</option><option ${condition === 'explicit consent' ? 'selected' : ''}>explicit consent</option><option ${condition === 'legal claims' ? 'selected' : ''}>legal claims</option></select>
    <label>Short note</label><input id="art9n-${esc(def.id)}" value="${esc(saved?.note || '')}">
    <label>Date</label><input id="art9d-${esc(def.id)}" type="date" value="${esc(saved?.date || '')}">`;
}
function graphHtml() {
  const c = cur();
  const ents = state.ents.filter((e) => e.case === c.id);
  const pane = document.getElementById('pane');
  const W = Math.min(900, Math.max(320, (pane?.clientWidth || 640) - 10));
  const H = 520;
  const cx = W / 2;
  const cy = H / 2;
  const r = Math.min(W, H) / 2 - 70;
  const pos = {};
  ents.forEach((e, i) => {
    const a = ents.length ? (i / ents.length) * Math.PI * 2 - Math.PI / 2 : 0;
    pos[e.id] = [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  });
  const links = state.links.filter((l) => pos[l.a] && pos[l.b]);
  if (!ents.length) return '<div class="note">No entries in this case yet.</div>';
  let s = `<svg width="${W}" height="${H}">`;
  links.forEach((l) => { s += `<line x1="${pos[l.a][0]}" y1="${pos[l.a][1]}" x2="${pos[l.b][0]}" y2="${pos[l.b][1]}" stroke="var(--seax-border-strong)" stroke-width="1.5"/>`; });
  ents.forEach((e) => {
    const [x, y] = pos[e.id];
    const col = e.locked ? 'var(--seax-red-text)' : 'var(--seax-text)';
    s += `<g data-act="open-entry" data-id="${esc(e.id)}" data-case="${esc(c.id)}" style="cursor:pointer"><circle cx="${x}" cy="${y}" r="${ui.sel === e.id ? 26 : 22}" fill="var(--seax-surface-1)" stroke="${col}" stroke-width="2" ${e.locked ? 'stroke-dasharray="4 3"' : ''}/><text x="${x}" y="${y + 4}" text-anchor="middle" fill="${col}" font-weight="700">${e.locked ? '!' : esc(ABBR[e.type] || '?')}</text><text x="${x}" y="${y + 40}" text-anchor="middle">${esc(e.label)}</text></g>`;
  });
  s += '</svg>';
  return s;
}
function auditHtml() {
  return `<button data-act="verify-chain">VERIFY HASH CHAIN</button> <span id="vr" class="m"></span>
    <div class="scroll"><table><tr><th>Time</th><th>Who</th><th>Action</th><th>Detail</th><th>Hash</th></tr>
    ${state.audit.slice().reverse().map((e) => `<tr><td>${esc(e.t)}</td><td>${esc(e.who)}</td><td>${esc(e.action)}</td><td>${esc(e.detail)}</td><td>${esc(e.hash.slice(0, 12))}…</td></tr>`).join('')}
    </table></div>`;
}
function syncHtml() {
  const conflicts = (state.conflicts || []).length;
  return `<div style="max-width:640px"><p class="note">Sync copies an encrypted bundle by hand. There is no account and no server. A later store can keep that same ciphertext only.</p>
    <label>Passphrase</label><input id="sync-pass" type="password" autocomplete="current-password">
    <button class="g" data-act="export-sync">EXPORT SYNC BUNDLE</button>
    <button data-act="export-backup">EXPORT ENCRYPTED BACKUP</button>
    <label>File to import, restore or verify</label><input id="bundle-file" type="file">
    <button data-act="import-bundle">IMPORT AND MERGE</button>
    <button class="a" data-act="restore-backup">${ui.pendingRestore ? 'CONFIRM RESTORE' : 'RESTORE BACKUP'}</button>
    <button data-act="verify-backup">VERIFY BACKUP</button>
    <div id="sync-msg" class="note">${esc(ui.notice)}</div>
    <div class="h">CONFLICTS KEPT</div><div class="note">${conflicts}</div></div>`;
}
function complianceHtml(c) {
  const showDesk = flag('gate') || flag('paperwork');
  const showPeople = flag('personBasis');
  if (!showDesk && !showPeople && !flag('notices')) return '';
  const a = state.attest || {};
  const d = a.dpia || {};
  const lead = note('gateLead');
  const special = note('specialLead');
  const excluded = note('excluded');
  const paperwork = flag('paperwork') ? `<label>ICO registration number</label><input id="ico" value="${esc(a.ico || '')}">
    <label>DPIA title</label><input id="dt" value="${esc(d.title || '')}"><label>DPIA version</label><input id="dv" value="${esc(d.version || '')}">
    <label>DPIA signed off</label><input id="dsg" type="date" value="${esc(d.signed || '')}"><label>DPIA review date</label><input id="drv" type="date" value="${esc(d.review || '')}">
    ${[['notice', 'Privacy notice in place'], ['ropa', 'Record of processing in place'], ['retention', 'Retention schedule in place'], ['apd', 'Appropriate Policy Document on file']].map(([k, label]) => `<label><input type="checkbox" id="${k}" style="width:auto" ${a[k] ? 'checked' : ''}> ${label}</label>`).join('')}
    <button class="g" data-act="save-attest">Confirm desk documents</button>` : (flag('gate') && !a.opened ? '<button class="g" data-act="open-desk">Open the desk</button>' : '');
  const deskBox = showDesk ? `<div class="box"><div class="cn">Desk</div>
    ${lead ? `<p class="note">${esc(lead)}</p>` : ''}
    ${special ? `<p class="note">${esc(special)}</p>` : ''}
    ${paperwork}
    <span class="${deskOpen() ? 'ok' : 'amb'} m">${deskOpen() ? 'Desk gate open' : 'Desk gate shut'}</span>
    ${deskOpen() && flag('paperwork') ? '<button data-act="review-desk">Review desk documents</button>' : ''}
  </div>` : `${special ? `<p class="note">${esc(special)}</p>` : ''}`;
  const people = showPeople && c ? `<div class="box"><div class="cn">Case ${esc(c.id)}</div>
    <label>Legitimate interests assessment</label>
    ${c.lia ? `<div class="m ok">${esc(c.lia.title)} v${esc(c.lia.version)} · ${esc(c.lia.date)}</div><button class="r" data-act="rev-lia">Withdraw LIA</button>` : `<input id="lt" placeholder="LIA title"><input id="lv" placeholder="Version"><button class="g" ${deskOpen() ? '' : 'disabled'} data-act="add-lia">Attest LIA</button>`}
  </div>` : '';
  const unlocks = flag('gate') && c ? `<div class="box"><div class="h" style="margin-top:0">Special category unlocks</div>
    ${special ? `<p class="note">${esc(special)}</p>` : ''}
    ${unlockUI(c, 'Health', ['Explicit consent covering health (Art 9(2)(a))', 'Legal claims (Art 9(2)(f))'], deskOpen())}
    ${unlockUI(c, 'Criminal record', ['Consent (DPA 2018 Sch 1 para 29)', 'Legal claims (DPA 2018 Sch 1 para 33)'], deskOpen() && (!flag('paperwork') || a.apd))}
    ${unlockUI(c, 'Biometrics', ['Explicit consent (Art 9(2)(a))'], deskOpen())}
  </div>` : '';
  return `${deskBox}${people}${unlocks}${excluded ? `<p class="note">${esc(excluded)}</p>` : ''}`;
}
function unlockUI(c, cat, conds, ok) {
  const u = (c.unlocks || []).find((x) => x.cat === cat && !x.revoked);
  const key = cat.replace(/ /g, '');
  if (u) return `<div class="box"><b class="ok m">${esc(cat.toUpperCase())} · UNLOCKED</b><div class="note">${esc(u.cond)} · evidence ${esc(u.ev)} · by ${esc(u.by)} ${esc(u.t)}</div><button class="r" data-act="revoke" data-cat="${esc(cat)}">REVOKE</button></div>`;
  return `<div class="box"><b class="m lock">${esc(cat.toUpperCase())}</b><select id="c_${key}">${conds.map((x) => `<option>${esc(x)}</option>`).join('')}</select>
    <input id="ev_${key}" placeholder="Evidence reference (required)"><button class="a" data-act="do-unlock" data-cat="${esc(cat)}" ${ok ? '' : 'disabled'}>UNLOCK FOR THIS CASE</button>
    ${ok ? '' : `<div class="note">Needs the desk gate open${cat === 'Criminal record' ? ' and an Appropriate Policy Document on file' : ''}.</div>`}</div>`;
}
function inspectorHtml(c) {
  const e = state.ents.find((x) => x.id === ui.sel && x.case === c.id);
  if (!e) return `<div class="h">CASE</div><div class="cn">${esc(c.id)}</div><div class="cm">${esc(c.client)}</div>${customBlock('case', c)}${mediaBlock('case', c.id)}`;
  const rows = [['Type', e.type], ['Case', e.case], ['Lawful basis', flag('personBasis') ? e.basis : ''], ['Consent', flag('personBasis') && e.consent && `${e.consent.method} · ${e.consent.date} · ${e.consent.proof}`], ['Item type', e.grade], ['Confidence', e.conf], ['Source', e.source], ['Source date', e.sdate], ['Observed', e.obs], ['Entered by', e.by]].filter((r) => r[1]);
  return `<div class="h">INSPECTOR</div><div class="cn">${esc(e.label)} · ${esc(e.id)}</div>
    ${rows.map(([k, val]) => `<div class="row"><span class="k">${esc(k)}</span><span class="v">${esc(val)}</span></div>`).join('')}
    <div class="box"><div class="h" style="margin-top:0">NOTES</div>
      ${e.locked ? '<span class="lock">Hidden: record locked</span>' : `<textarea id="notes">${esc(e.desc || '')}</textarea><button data-act="save-notes" data-id="${esc(e.id)}">Save notes</button>`}
    </div>
    <button data-act="print-record" data-id="${esc(e.id)}">Print record</button>
    ${customBlock(fieldRecordTypeForEntry(e.type), e)}
    ${builtinSpecial(c, e)}
    ${e.type === 'Person' ? `<div class="box"><div class="h" style="margin-top:0">Subject rights</div>
      <button data-act="sar" data-id="${esc(e.id)}">EXPORT ALL (SAR)</button>
      <button class="a" data-act="objection" data-id="${esc(e.id)}" ${e.objection || e.locked ? 'disabled' : ''}>OBJECTION RECEIVED</button>
      <button class="r" data-act="withdraw" data-id="${esc(e.id)}" ${e.locked ? 'disabled' : ''}>${ui.confirmWithdraw === e.id ? 'Confirm freeze' : e.basis === 'Consent' && flag('personBasis') ? 'Consent withdrawn' : 'Freeze / erase'}</button>
    </div>` : ''}
    ${linksHtml(c, e)}
    ${mediaBlock('entry', e.id, e)}`;
}
function customBlock(recordType, rec) {
  if (!recordType || !rec) return '';
  const html = customFieldsHtml(recordType, rec, 'cf');
  if (!html) return '';
  return `<div class="box" data-custom-for="${esc(rec.id)}" data-record-type="${esc(recordType)}"><div class="h" style="margin-top:0">FIELDS</div>${html}<button data-act="save-custom" data-id="${esc(rec.id)}" data-record-type="${esc(recordType)}">SAVE FIELDS</button></div>`;
}
function builtinSpecial(c, e) {
  if (e.type !== 'Person') return '';
  const cats = SPECIAL_CATEGORIES.map((cat) => {
    if (!categoryOpen(c, cat) || e.locked) return `<div class="lock">${esc(cat.toUpperCase())}</div>`;
    const tag = '<span class="tag">SPECIAL</span>';
    return `<label>${esc(cat)} ${tag}</label><input data-act="set-sp" data-id="${esc(e.id)}" data-cat="${esc(cat)}" value="${esc((e.sp || {})[cat] || '')}">`;
  }).join('');
  const lead = note('specialLead');
  return `<div class="box"><div class="h" style="margin-top:0">HEALTH / RECORD / BIOMETRICS</div>${lead ? `<p class="note">${esc(lead)}</p>` : ''}${cats}</div>`;
}
function linksHtml(c, e) {
  const linked = state.links.filter((l) => l.a === e.id || l.b === e.id);
  const ids = new Set(linked.map((l) => (l.a === e.id ? l.b : l.a)));
  const others = state.ents.filter((x) => x.case === c.id && x.id !== e.id && !ids.has(x.id));
  return `<div class="box"><div class="h" style="margin-top:0">LINKS (${linked.length})</div>
    ${linked.map((l) => { const id = l.a === e.id ? l.b : l.a; return `<div class="m">↔ ${esc(id)} ${esc(state.ents.find((x) => x.id === id)?.label || '')}</div>`; }).join('') || '<div class="note">None</div>'}
    ${e.locked ? '' : `<select id="lk">${others.map((o) => `<option value="${esc(o.id)}">${esc(o.id)} ${esc(o.label)}</option>`).join('')}</select><button data-act="add-link" data-id="${esc(e.id)}" ${others.length ? '' : 'disabled'}>+ LINK</button>`}
  </div>`;
}
function mediaBlock(kind, id, entry) {
  const items = state.media.filter((m) => m.parentKind === kind && m.parentId === id);
  const identNote = note('identifiable');
  return `<div class="box"><div class="h" style="margin-top:0">MEDIA</div>
    <p class="note">Photos and video are encrypted on this device. This desk does not do face matching or biometric processing.</p>
    ${items.map((m) => `<div class="box"><div class="cn">${esc(m.name)}</div>
      ${m.mime.startsWith('image/') ? `<img class="thumb" alt="" data-thumb="${esc(m.id)}" style="width:96px;height:72px">` : ''}
      <div class="cm">${esc(m.mime)} · ${esc(m.sha256.slice(0, 12))}… · ${esc(m.by)} · ${esc(m.at)}</div>
      <div class="cm">Source / provenance: ${esc(m.provenance)}</div>
      <button data-act="preview" data-id="${esc(m.id)}">OPEN PREVIEW</button>
      <button data-act="reveal" data-id="${esc(m.id)}">REVEAL EVIDENCE METADATA</button>
      <div data-exif-slot="${esc(m.id)}">${revealed.has(m.id) ? `<div data-exif="${esc(m.id)}">Opening…</div>` : ''}</div>
      <button class="r" data-act="remove-media" data-id="${esc(m.id)}">${ui.confirmRemove === m.id ? 'CONFIRM REMOVE' : 'REMOVE'}</button>
    </div>`).join('')}
    <label>Source / provenance</label><input id="msrc" autocomplete="off">
    <label><input id="ident" type="checkbox" style="width:auto" ${entry && entry.type === 'Person' ? 'checked' : ''}> Identifiable person</label>
    ${identNote ? `<p class="note">${esc(identNote)}</p>` : ''}
    <input id="mfile" type="file" accept="image/*,video/*">
    <button class="g" data-act="attach-media" data-kind="${esc(kind)}" data-id="${esc(id)}">ATTACH</button>
    <div id="e" class="red"></div>
  </div>`;
}
function previewHtml() {
  if (!ui.preview) return '';
  const p = ui.preview;
  const inner = p.mime.startsWith('video/')
    ? `<video src="${esc(p.url)}" controls playsinline></video>`
    : `<img src="${esc(p.url)}" alt="">`;
  return `<div class="overlay"><div class="sheet" role="dialog" aria-modal="true" aria-label="Preview"><button data-act="close-preview">Close</button><div class="cn">${esc(p.name)}</div>${inner}</div></div>`;
}

function basisProblem(c, entry, identifiable, mime) {
  if (!flag('personBasis')) return '';
  const visual = mime.startsWith('image/') || mime.startsWith('video/');
  if (!visual || !identifiable) return '';
  if (entry && entry.type === 'Person') {
    if (entry.locked) return 'This person record is locked.';
    if (!entry.basis) return 'This person has no lawful basis recorded.';
    return '';
  }
  if (c && c.lia) return '';
  if (state.ents.some((e) => e.case === c.id && e.type === 'Person' && e.basis && !e.locked)) return '';
  return NOTICE.identifiable;
}
async function auditCustomValues(custom, recordId) {
  for (const id of Object.keys(custom || {})) await audit('FIELD_VALUE', `${id} ${recordId}`);
}
function readCustomInputs(recordType, prefix) {
  const out = {};
  for (const def of defsFor(state, recordType)) {
    const el = document.getElementById(`${prefix}-${def.id}`);
    if (!el) {
      if (def.required) throw new Error(`${def.label} is required.`);
      continue;
    }
    const value = coerceField(def, el.value);
    if (def.required && (value == null || value === '')) throw new Error(`${def.label} is required.`);
    if (def.type === 'url' && value && !/^https?:\/\//i.test(value)) throw new Error(`${def.label} needs an http or https URL.`);
    out[def.id] = value;
  }
  return out;
}
async function storedCustomValue(def, value) {
  if (!resolveSpecial(def)) return value;
  if (value == null || value === '') return null;
  await captureArt9(def, value);
  return sealSpecialValue(await ensureFieldKey(), value);
}
async function sealCustomMap(recordType, custom) {
  const out = {};
  for (const [id, value] of Object.entries(custom || {})) {
    const def = (state.fieldDefs || []).find((d) => d.id === id && d.recordType === recordType);
    out[id] = def ? await storedCustomValue(def, value) : value;
  }
  return out;
}
async function captureArt9(def, value) {
  if (!flag('art9') || !resolveSpecial(def) || value == null || value === '') return;
  const c = cur();
  if (!c) throw new Error('Open a case before saving this special-category field.');
  const picked = document.getElementById(`art9-${def.id}`)?.value || '';
  const condition = picked || (c.art9 && c.art9[def.id] && c.art9[def.id].condition) || '';
  if (condition !== 'explicit consent' && condition !== 'legal claims') {
    throw new Error('Choose explicit consent or legal claims before saving this special-category field.');
  }
  c.art9 = c.art9 || {};
  c.art9[def.id] = {
    condition,
    note: document.getElementById(`art9n-${def.id}`)?.value || c.art9[def.id]?.note || '',
    date: document.getElementById(`art9d-${def.id}`)?.value || c.art9[def.id]?.date || todayLondon(),
  };
  touch(c);
}
async function fillSpecialInputs(gen) {
  if (!dataKey || !state) return;
  const nodes = [...document.querySelectorAll('[data-sealed-field]')];
  if (!nodes.length) return;
  let key;
  try { key = await ensureFieldKey(); } catch { return; }
  for (const el of nodes) {
    if (gen !== renderGen) return;
    const box = el.closest('[data-custom-for]');
    if (!box) continue;
    const rec = box.dataset.recordType === 'case'
      ? state.cases.find((c) => c.id === box.dataset.customFor)
      : state.ents.find((e) => e.id === box.dataset.customFor);
    const sealed = rec && rec.custom && rec.custom[el.dataset.sealedField];
    if (!isSealedSpecial(sealed)) continue;
    try {
      const plain = await openSpecialValue(key, sealed);
      if (gen !== renderGen || document.activeElement === el) continue;
      el.value = plain == null ? '' : String(plain);
    } catch { /* ciphertext stays off the page */ }
  }
}
async function saveSettings() {
  const idle = Math.min(240, Math.max(1, Math.round(Number(v('set-idle')) || 15)));
  const lockMax = Math.min(20, Math.max(3, Math.round(Number(v('set-lock')) || 5)));
  state.settings.idleMin = idle;
  state.settings.lockoutMax = lockMax;
  if (flag('retention')) state.settings.retentionDate = document.getElementById('set-ret')?.value || '';
  for (const key of COMPLIANCE_KEYS) state.settings.compliance[key] = !!document.getElementById(`cmp-${key}`)?.checked;
  devicePolicy = { idleMin: idle, lockoutMax: lockMax };
  const vault = await idbGet(VAULT_KEY);
  if (vault) {
    vault.idleMin = idle;
    vault.lockoutMax = lockMax;
    await idbSet(VAULT_KEY, vault);
  }
  await audit('SETTINGS', `idle ${idle}; lockout ${lockMax}`);
  await saveState();
  ui.notice = 'Settings saved.';
  if (!deskOpen()) ui.screen = 'gate';
  armIdle();
  render();
}
async function openDeskGate() {
  state.attest = state.attest || {};
  state.attest.opened = true;
  state.attest.updatedAt = new Date().toISOString();
  await audit('DESK_OPENED', state.owner.name);
  await saveState();
  ui.screen = deskOpen() ? 'home' : 'gate';
  render();
}
async function logSpecialViews(recordType, recordId) {
  if (!recordType) return;
  for (const def of defsFor(state, recordType, { includeArchived: true })) {
    if (!resolveSpecial(def)) continue;
    await audit('FIELD_VIEW', `${def.id} ${recordId}`);
  }
}
function saveFile(name, bytes) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const a = document.createElement('a');
  const url = URL.createObjectURL(blob);
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
async function readInputFile(id) {
  const input = document.getElementById(id);
  const file = input?.files?.[0];
  if (!file) throw new Error('Choose a file first.');
  return { name: file.name, type: file.type || 'application/octet-stream', file, bytes: new Uint8Array(await file.arrayBuffer()) };
}
function bundlePass() {
  return secret('sync-pass') || secret('bundle-pass') || secret('verify-pass');
}
async function openSession(key, priorFails) {
  dataKey = key;
  fieldKey = null;
  const box = await idbGet(STATE_KEY);
  if (!box) throw new Error('The encrypted desk is missing. Restore a backup.');
  try {
    state = normalise(await openJson(dataKey, normaliseBox(box)));
    applyDevicePolicy(state.settings);
  } catch {
    dataKey = null;
    throw new Error('The encrypted desk could not be opened.');
  }
  await clearLockout();
  await audit('SIGN_IN', priorFails ? `ok; prior failures in window: ${priorFails}` : 'ok');
  await saveState();
  ui.screen = deskOpen() ? 'home' : 'gate';
  ui.error = '';
  armIdle();
}

async function act(name, el) {
  ui.error = '';
  if (name === 'print-key') { window.print(); return; }
  if (name === 'show-recovery') { ui.showRecovery = true; render(); return; }
  if (name === 'show-sign-in') { ui.showRecovery = false; render(); return; }
  if (name === 'show-erase') { ui.showErase = !ui.showErase; render(); return; }
  if (name === 'show-case') { ui.showCase = !ui.showCase; render(); return; }
  if (name === 'go') {
    ui.screen = el.dataset.screen;
    if (ui.screen !== 'desk') ui.sel = null;
    render();
    return;
  }
  if (name === 'scope') {
    ui.scope = el.dataset.scope;
    const box = document.getElementById('results');
    document.querySelectorAll('.chip').forEach((c) => c.classList.toggle('on', c.dataset.scope === ui.scope));
    if (box) box.innerHTML = resultsHtml();
    hydrate(renderGen);
    return;
  }
  if (name === 'tab') { ui.tab = el.dataset.tab; render(); return; }
  if (name === 'lock') { lock(); return; }
  if (name === 'cancel-field') { ui.editField = null; render(); return; }
  if (name === 'close-preview') {
    if (ui.preview?.url) URL.revokeObjectURL(ui.preview.url);
    ui.preview = null;
    render();
    return;
  }
  if (name === 'create-admin') return createAdmin();
  if (name === 'confirm-recovery') return confirmSetup();
  if (name === 'sign-in') return signIn();
  if (name === 'recovery-unlock') return recoveryUnlock();
  if (name === 'erase-yes') return eraseDevice();
  if (name === 'quick-add') return quickAdd(el.dataset.type);
  if (name === 'save-case') return saveCase();
  if (name === 'open-case') return openCase(el.dataset.id);
  if (name === 'open-entry') return openEntry(el.dataset.id, el.dataset.case);
  if (name === 'open-result') return openResult(el);
  if (name === 'save-entry') return saveEntry();
  if (name === 'save-field') return saveField();
  if (name === 'edit-field') { ui.editField = el.dataset.id; ui.screen = 'fields'; render(); return; }
  if (name === 'archive-field') return archiveField(el.dataset.id, true);
  if (name === 'restore-field') return archiveField(el.dataset.id, false);
  if (name === 'delete-field') return deleteField(el.dataset.id);
  if (name === 'save-custom') return saveCustom(el.dataset.recordType, el.dataset.id);
  if (name === 'save-notes') return saveNotes(el.dataset.id);
  if (name === 'save-attest') return saveAttest();
  if (name === 'open-desk') return openDeskGate();
  if (name === 'save-settings') return saveSettings();
  if (name === 'print-record') {
    ui.printRecord = el.dataset.id;
    render();
    window.print();
    return;
  }
  if (name === 'review-desk') return reviewDesk();
  if (name === 'add-lia') return addLia();
  if (name === 'rev-lia') return revLia();
  if (name === 'do-unlock') return doUnlock(el.dataset.cat);
  if (name === 'revoke') return revoke(el.dataset.cat);
  if (name === 'add-link') return addLink(el.dataset.id);
  if (name === 'objection') return objection(el.dataset.id);
  if (name === 'withdraw') return withdraw(el.dataset.id);
  if (name === 'done-task') return doneTask(el.dataset.id);
  if (name === 'sar') return sar(el.dataset.id);
  if (name === 'verify-chain') return verifyChainUi();
  if (name === 'attach-media') return attachMedia(el.dataset.kind, el.dataset.id);
  if (name === 'preview') return previewMedia(el.dataset.id);
  if (name === 'reveal') return revealMeta(el.dataset.id);
  if (name === 'remove-media') return removeMedia(el.dataset.id);
  if (name === 'export-sync') return exportBundle('sync');
  if (name === 'export-backup') return exportBundle('backup');
  if (name === 'import-bundle') return importBundle('merge');
  if (name === 'restore-backup') return restoreBackup();
  if (name === 'verify-backup') return verifyBackup();
}

async function createAdmin() {
  const name = ACTIVE_MODE ? 'SEAX ALPHA' : v('n');
  const pass = secret('p');
  const pass2 = secret('p2');
  if (pass.length < 12 || pass !== pass2 || (!ACTIVE_MODE && !name)) {
    throw new Error(ACTIVE_MODE
      ? 'Passphrase must be 12 characters or more, and both entries must match.'
      : 'Name required. Passphrase must be 12 characters or more, and both entries must match.');
  }
  const recovery = crypto.getRandomValues(new Uint8Array(32));
  setupPending = { name, pass, recovery, groups: encodeKey(recovery), ask: pick3() };
  ui.error = '';
  render();
}
async function confirmSetup() {
  if (!setupPending) throw new Error('Start again.');
  if (!document.getElementById('stored')?.checked) throw new Error('Tick the box to confirm you have stored the recovery key.');
  const ask = setupPending.ask;
  for (let i = 0; i < ask.length; i++) {
    const got = secret(`ch${i}`).toUpperCase().replace(/[^0-9A-Z]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1').replace(/U/g, 'V');
    if (got !== setupPending.groups[ask[i]]) throw new Error('Those groups do not match. Check the key and try again.');
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await generateDataKey();
  const passWrap = await wrapDataKey(key, await deriveKek(setupPending.pass, salt));
  const recoveryWrap = await wrapDataKey(key, await importRawKey(setupPending.recovery));
  setupPending.recovery.fill(0);
  const name = setupPending.name;
  setupPending = null;
  await idbSet(VAULT_KEY, { v: 1, iterations: ITERATIONS, salt, passWrap, recoveryWrap, idleMin: 15, lockoutMax: 5, createdAt: new Date().toISOString() });
  dataKey = key;
  state = emptyState(name);
  ui.vault = true;
  await audit('OWNER_CREATED', name);
  if (ACTIVE_MODE) await audit('ACTIVE_MODE', 'ACTIVE MODE active');
  await saveState();
  ui.screen = 'home';
  ui.error = '';
  armIdle();
  render();
}
async function signIn() {
  const pass = secret('p');
  const status = await assertNotLocked();
  const vault = await idbGet(VAULT_KEY);
  if (!vault) throw new Error('This device has no desk yet.');
  let key;
  try {
    key = await unwrapDataKey(normaliseBox(vault.passWrap), await deriveKek(pass, asBytes(vault.salt), vault.iterations));
  } catch (err) {
    if (String(err.message || '').includes('minimum') || String(err.message || '').includes('too weak')) throw err;
    await registerFailure();
    const again = await lockoutStatus();
    throw new Error(again.locked ? lockText(again) : 'Wrong passphrase.');
  }
  await openSession(key, status.fails);
  render();
}
async function recoveryUnlock() {
  const pass = secret('new-p');
  const pass2 = secret('new-p2');
  if (pass.length < 12 || pass !== pass2) throw new Error('New passphrase must be 12 characters or more, and both entries must match.');
  await assertNotLocked();
  const vault = await idbGet(VAULT_KEY);
  let raw;
  try { raw = decodeKey(secret('rec-key')); } catch (err) { throw new Error(err.message || 'Recovery key is not valid.'); }
  let key;
  try {
    key = await unwrapDataKey(normaliseBox(vault.recoveryWrap), await importRawKey(raw));
  } catch {
    raw.fill(0);
    await registerFailure();
    const again = await lockoutStatus();
    throw new Error(again.locked ? lockText(again) : 'Recovery key did not match.');
  }
  raw.fill(0);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  vault.salt = salt;
  vault.iterations = ITERATIONS;
  vault.passWrap = await wrapDataKey(key, await deriveKek(pass, salt));
  await idbSet(VAULT_KEY, vault);
  await openSession(key, 0);
  await audit('RECOVERY_UNLOCK', 'passphrase replaced');
  await saveState();
  ui.showRecovery = false;
  render();
}
async function eraseDevice() {
  if (v('erase-word') !== 'ERASE') throw new Error('Type ERASE to confirm.');
  dataKey = null;
  state = null;
  await idbDeleteDb();
  ui.vault = false;
  ui.showErase = false;
  ui.notice = 'This device has been erased.';
  render();
}
function quickAdd(type) {
  if (type === 'case') { ui.screen = 'home'; ui.showCase = true; render(); return; }
  if (!deskOpen()) throw new Error('Desk gate is shut.');
  if (!cur()) throw new Error('Open a case first.');
  ui.addType = type;
  ui.screen = 'desk';
  ui.tab = 'add';
  render();
}
async function saveCase() {
  if (!deskOpen()) throw new Error('Desk gate is shut.');
  const codename = v('case-name').toUpperCase();
  const client = v('case-client');
  if (!codename || !client) throw new Error('Case codename and client are required.');
  if (state.cases.some((c) => c.id === codename)) throw new Error('That case already exists.');
  const rec = touch({ id: codename, client, lia: null, unlocks: [], art9: {}, custom: await sealCustomMap('case', readCustomInputs('case', 'case')) });
  state.cases.push(rec);
  state.curCase = codename;
  await audit('CASE_CREATED', codename);
  await auditCustomValues(rec.custom, codename);
  await logSpecialViews('case', codename);
  await saveState();
  ui.showCase = false;
  ui.screen = 'home';
  ui.notice = '';
  render();
}
async function openCase(id) {
  const c = state.cases.find((x) => x.id === id);
  if (!c) return;
  state.curCase = id;
  ui.sel = null;
  ui.screen = 'desk';
  ui.tab = 'graph';
  render();
  await logSpecialViews('case', id);
  await saveState();
}
async function openEntry(id, caseId) {
  const e = state.ents.find((x) => x.id === id);
  if (!e) return;
  state.curCase = caseId || e.case;
  ui.sel = id;
  ui.screen = 'desk';
  render();
  await logSpecialViews(fieldRecordTypeForEntry(e.type), id);
  await saveState();
}
async function openResult(el) {
  const kind = el.dataset.kind;
  if (kind === 'case') return openCase(el.dataset.id);
  if (kind === 'entry') return openEntry(el.dataset.id, el.dataset.case);
  const parentKind = el.dataset.parentKind;
  const parentId = el.dataset.parentId;
  if (parentKind === 'entry') {
    const e = state.ents.find((x) => x.id === parentId);
    if (e) await openEntry(e.id, e.case);
  } else if (parentId) await openCase(parentId);
  await previewMedia(el.dataset.id);
}
async function saveEntry() {
  if (!deskOpen()) throw new Error('Desk gate is shut.');
  const c = cur();
  const t = v('ty');
  if (!v('lb') || !v('src') || !v('sd') || !v('od')) throw new Error('Label, source, source date and observation date are all required.');
  const recordType = fieldRecordTypeForEntry(t);
  const custom = recordType ? await sealCustomMap(recordType, readCustomInputs(recordType, 'new')) : {};
  const e = touch({
    id: uid(ABBR[t] === '\u00a3' ? 'F' : (ABBR[t] || 'X')[0]),
    type: t,
    label: v('lb').toUpperCase(),
    case: c.id,
    source: v('src'),
    sdate: v('sd'),
    obs: v('od'),
    by: state.owner.name,
    desc: v('ds'),
    custom,
  });
  if (t === 'Person' && flag('personBasis')) {
    e.basis = v('bs');
    if (e.basis === 'Consent') {
      if (!v('cp')) throw new Error('Consent needs a proof reference.');
      e.consent = { scope: 'Case enquiries', date: todayLondon(), method: 'Recorded', proof: v('cp') };
    } else e.notice = v('cp') || 'Notice status not yet recorded';
  }
  if (t === 'Intelligence') { e.grade = v('gr'); e.conf = v('cf'); }
  state.ents.push(e);
  await audit('CREATE', `${e.id} ${e.type} in ${c.id}`);
  await auditCustomValues(custom, e.id);
  await logSpecialViews(recordType, e.id);
  await saveState();
  ui.sel = e.id;
  ui.tab = 'graph';
  render();
}
async function saveField() {
  const recordType = v('fd-record');
  const label = v('fd-label');
  const type = v('fd-kind');
  if (!label) throw new Error('Label is required.');
  if (!FIELD_TYPES.includes(type)) throw new Error('Choose a field type.');
  if (!FIELD_RECORD_TYPES.some(([id]) => id === recordType)) throw new Error('Choose a record type.');
  const options = (document.getElementById('fd-options')?.value || '').split(/\n|,/).map((s) => s.trim()).filter(Boolean);
  if (type === 'dropdown' && options.length < 1) throw new Error('A dropdown needs at least one option.');
  const dup = state.fieldDefs.find((d) => d.recordType === recordType && d.label.toLowerCase() === label.toLowerCase() && !d.archived && d.id !== ui.editField);
  if (dup) throw new Error('That label is already in use for this record type.');
  const explicitSpecial = !!document.getElementById('fd-special')?.checked;
  if (recordType === 'case' && (explicitSpecial || isSpecialLabel(label))) {
    throw new Error('Special-category fields belong on a record inside a case, not on the case itself.');
  }
  const order = Number(v('fd-order'));
  if (ui.editField) {
    const def = state.fieldDefs.find((d) => d.id === ui.editField);
    const renamed = def.label !== label;
    def.recordType = recordType;
    def.label = label;
    def.type = type;
    def.required = !!document.getElementById('fd-required')?.checked;
    def.options = type === 'dropdown' ? options : [];
    def.order = Number.isFinite(order) ? order : def.order;
    def.explicitSpecial = explicitSpecial;
    touch(def);
    await audit(renamed ? 'FIELD_RENAME' : 'FIELD_EDIT', `${def.id} ${label}`);
  } else {
    const def = touch({
      id: uid('FLD'),
      recordType,
      label,
      type,
      required: !!document.getElementById('fd-required')?.checked,
      options: type === 'dropdown' ? options : [],
      order: Number.isFinite(order) ? order : nextOrder(),
      explicitSpecial,
      archived: false,
      createdAt: new Date().toISOString(),
    });
    state.fieldDefs.push(def);
    await audit('FIELD_DEFINE', `${def.id} ${label}`);
  }
  ui.editField = null;
  await saveState();
  ui.notice = resolveSpecial({ label, explicitSpecial }) ? '' : '';
  render();
}
async function archiveField(id, archived) {
  const def = state.fieldDefs.find((d) => d.id === id);
  if (!def) return;
  def.archived = archived;
  touch(def);
  await audit(archived ? 'FIELD_ARCHIVE' : 'FIELD_RESTORE', `${def.id} ${def.label}`);
  await saveState();
  render();
}
async function deleteField(id) {
  if (fieldHasData(state, id)) throw new Error('This field has values, so it can only be archived.');
  const def = state.fieldDefs.find((d) => d.id === id);
  if (ui.confirmDelete !== id) {
    ui.confirmDelete = id;
    ui.notice = def ? `Delete ${def.label}? This cannot be undone.` : 'Delete this field?';
    render();
    return;
  }
  ui.confirmDelete = null;
  ui.notice = '';
  state.fieldDefs = state.fieldDefs.filter((d) => d.id !== id);
  addTombstone('fieldDefs', id);
  await audit('FIELD_DELETE', id);
  await saveState();
  render();
}
async function saveCustom(recordType, id) {
  const rec = recordType === 'case' ? state.cases.find((c) => c.id === id) : state.ents.find((e) => e.id === id);
  if (!rec) return;
  rec.custom = rec.custom || {};
  for (const def of defsFor(state, recordType, { includeArchived: true })) {
    const el = document.getElementById(`cf-${def.id}`);
    if (!el) continue;
    const value = coerceField(def, el.value);
    if (!def.archived && def.required && (value == null || value === '')) throw new Error(`${def.label} is required.`);
    rec.custom[def.id] = await storedCustomValue(def, value);
    await audit('FIELD_VALUE', `${def.id} ${id}`);
  }
  touch(rec);
  await saveState();
  ui.notice = 'Fields saved.';
  render();
}
async function saveNotes(id) {
  const e = state.ents.find((x) => x.id === id);
  e.desc = document.getElementById('notes')?.value ?? '';
  touch(e);
  await audit('EDIT', `${id} notes`);
  await saveState();
  render();
}
async function saveAttest() {
  if (!flag('paperwork') && !flag('gate')) return;
  const a = state.attest;
  a.ico = v('ico');
  a.dpia = v('dt') && v('dv') && v('dsg') && v('drv') ? { title: v('dt'), version: v('dv'), signed: v('dsg'), review: v('drv') } : null;
  ['notice', 'ropa', 'retention', 'apd'].forEach((k) => { a[k] = !!document.getElementById(k)?.checked; });
  a.updatedAt = new Date().toISOString();
  await audit('ATTEST_DESK', `ICO ${a.ico || '-'}; DPIA ${a.dpia ? `${a.dpia.title} v${a.dpia.version} review ${a.dpia.review}` : 'missing'}`);
  ui.screen = deskOpen() ? 'home' : 'gate';
  render();
}
async function reviewDesk() {
  if (!flag('paperwork') && !flag('gate')) return;
  state.attest = {};
  await audit('DESK_GATE_RESET', state.owner.name);
  await saveState();
  ui.screen = 'gate';
  render();
}
async function addLia() {
  const c = cur();
  if (!v('lt') || !v('lv')) throw new Error('LIA title and version are required.');
  c.lia = { title: v('lt'), version: v('lv'), date: todayLondon() };
  touch(c);
  await audit('ATTEST_LIA', `${c.id} ${c.lia.title}`);
  await saveState();
  render();
}
async function revLia() {
  const c = cur();
  c.lia = null;
  touch(c);
  await audit('WITHDRAW_LIA', c.id);
  await saveState();
  render();
}
async function doUnlock(cat) {
  const c = cur();
  const key = cat.replace(/ /g, '');
  const ev = v(`ev_${key}`);
  if (!ev) throw new Error('Evidence reference required.');
  c.unlocks = c.unlocks || [];
  c.unlocks.push({ cat, cond: v(`c_${key}`), ev, by: state.owner.name, t: nowLondon() });
  touch(c);
  await audit('UNLOCK', `${c.id} ${cat} · ${v(`c_${key}`)} · ${ev}`);
  await saveState();
  render();
}
async function revoke(cat) {
  const c = cur();
  const u = (c.unlocks || []).find((x) => x.cat === cat && !x.revoked);
  if (u) u.revoked = nowLondon();
  touch(c);
  await audit('REVOKE', `${c.id} ${cat}`);
  await saveState();
  render();
}
async function setSp(id, cat, value) {
  if (!SPECIAL_CATEGORIES.includes(cat)) return;
  const e = state.ents.find((x) => x.id === id);
  if (!e || !categoryOpen(cur(), cat)) return;
  e.sp = e.sp || {};
  e.sp[cat] = value;
  touch(e);
  await audit('EDIT_SPECIAL', `${id} ${cat}`);
  await saveState();
}
async function addLink(id) {
  const other = v('lk');
  if (!other) return;
  state.links.push(touch({ id: uid('L'), a: id, b: other }));
  await audit('LINK', `${id}↔${other}`);
  await saveState();
  render();
}
async function objection(id) {
  const e = state.ents.find((x) => x.id === id);
  e.objection = true;
  touch(e);
  await audit('OBJECTION', id);
  await saveState();
  render();
}
async function withdraw(id) {
  if (ui.confirmWithdraw !== id) { ui.confirmWithdraw = id; render(); return; }
  const e = state.ents.find((x) => x.id === id);
  e.locked = true;
  touch(e);
  const due = todayLondon(new Date(Date.now() + 30 * 864e5));
  state.tasks.push(touch({ id: uid('T'), title: `DELETE ${id} (${e.case})`, due, target: id, case: e.case, done: false }));
  await audit('LOCK_AND_DELETION_TASK', `${id} due ${due}`);
  await saveState();
  ui.confirmWithdraw = null;
  render();
}
async function doneTask(tid) {
  const t = state.tasks.find((x) => x.id === tid);
  t.done = true;
  touch(t);
  const id = t.target;
  const caseId = t.case;
  state.ents = state.ents.filter((e) => e.id !== id);
  addTombstone('ents', id);
  for (const l of state.links.filter((l) => l.a === id || l.b === id)) addTombstone('links', l.id);
  state.links = state.links.filter((l) => l.a !== id && l.b !== id);
  state.ents.push(touch({
    id: `DNP-${id}`, type: 'Person', label: 'DO NOT PROCESS', case: caseId, locked: true,
    source: 'Deletion record', sdate: todayLondon(), obs: todayLondon(), by: state.owner.name, desc: '', custom: {},
  }));
  await audit('DELETED', `${id}; do-not-process marker kept`);
  await saveState();
  ui.sel = null;
  render();
}
async function sar(id) {
  const e = state.ents.find((x) => x.id === id);
  const recordType = fieldRecordTypeForEntry(e.type);
  const defs = recordType ? defsFor(state, recordType, { includeArchived: true }) : [];
  const custom = [];
  const record = JSON.parse(JSON.stringify(e));
  record.custom = record.custom || {};
  for (const d of defs) {
    let value = record.custom[d.id] ?? null;
    if (resolveSpecial(d)) {
      if (value != null && value !== '' && !isSealedSpecial(value)) value = await sealSpecialValue(await ensureFieldKey(), value);
      if (!isSealedSpecial(value)) value = null;
      record.custom[d.id] = value;
    }
    custom.push({ id: d.id, label: d.label, type: d.type, specialCategory: resolveSpecial(d), value });
  }
  const media = state.media.filter((m) => m.parentId === id || m.subjectId === id);
  const files = [];
  for (const m of media) {
    if (m.size > 8 * 1024 * 1024) {
      files.push({ id: m.id, name: m.name, sha256: m.sha256, omitted: 'over 8MB' });
      continue;
    }
    const bytes = await decryptMedia(dataKey, m.id, m.chunks);
    files.push({ id: m.id, name: m.name, mime: m.mime, sha256: m.sha256, provenance: m.provenance, at: m.at, by: m.by, specialCategory: false, bytes: toB64(bytes) });
  }
  const out = {
    exported: nowLondon(),
    record,
    custom,
    links: state.links.filter((l) => l.a === id || l.b === id),
    media: files,
    audit: state.audit.filter((a) => String(a.detail).includes(id)),
  };
  saveFile(`SAR-${id}.json`, new TextEncoder().encode(JSON.stringify(out, null, 2)));
  await audit('EXPORT_SAR', id);
  await saveState();
}
async function verifyChainUi() {
  const ok = await verifyChain(state.audit);
  const el = document.getElementById('vr');
  if (el) el.innerHTML = ok ? '<span class="ok">CHAIN INTACT</span>' : '<span class="red">CHAIN BROKEN</span>';
}
async function attachMedia(kind, id) {
  const chosen = await readInputFile('mfile');
  const provenance = v('msrc');
  if (!provenance) throw new Error('Source / provenance is required.');
  const identifiable = !!document.getElementById('ident')?.checked;
  const mime = sniffMime(chosen.bytes, chosen.type);
  const c = cur();
  const entry = kind === 'entry' ? state.ents.find((e) => e.id === id) : null;
  const problem = basisProblem(c, entry, identifiable, mime);
  if (problem) throw new Error(problem);
  ui.busy = 'Encrypting file…';
  render();
  const enc = await encryptMedia(dataKey, chosen.bytes);
  const mediaId = uid('M');
  for (let i = 0; i < enc.chunks.length; i++) await idbSet(mediaKey(mediaId, i), enc.chunks[i]);
  await idbSet(exifKey(mediaId), await sealJson(dataKey, extractMetadata(chosen.bytes, mime)));
  const thumb = await makeThumbBytes(chosen.file);
  if (thumb) await idbSet(thumbKey(mediaId), await sealBytes(dataKey, thumb));
  state.media.push(touch({
    id: mediaId,
    parentKind: kind,
    parentId: id,
    name: chosen.name || 'file',
    mime,
    size: chosen.bytes.length,
    sha256: enc.sha256,
    provenance,
    by: state.owner.name,
    at: nowLondon(),
    chunks: enc.chunks.length,
    identifiable: !!identifiable,
    subjectId: entry && entry.type === 'Person' ? entry.id : '',
  }));
  await audit('MEDIA_ADD', `${mediaId} ${mime} sha256 ${enc.sha256} parent ${kind}:${id}`);
  await saveState();
  ui.busy = '';
  ui.notice = 'File encrypted and attached.';
  render();
}
async function previewMedia(id) {
  const m = state.media.find((x) => x.id === id);
  if (!m) return;
  const bytes = await decryptMedia(dataKey, id, m.chunks);
  if (await sha256Hex(bytes) !== m.sha256) throw new Error('This file failed the integrity check.');
  const url = URL.createObjectURL(new Blob([bytes], { type: m.mime }));
  if (ui.preview?.url) URL.revokeObjectURL(ui.preview.url);
  ui.preview = { url, mime: m.mime, name: m.name };
  await audit('MEDIA_VIEW', `${id} preview`);
  await saveState();
  render();
}
async function revealMeta(id) {
  revealed.add(id);
  await audit('MEDIA_REVEAL', id);
  await saveState();
  render();
}
async function removeMedia(id) {
  if (ui.confirmRemove !== id) { ui.confirmRemove = id; render(); return; }
  const m = state.media.find((x) => x.id === id);
  state.media = state.media.filter((x) => x.id !== id);
  addTombstone('media', id);
  if (m) await deleteMediaBlobs(id, m.chunks);
  await deleteMediaBlobsByPrefix(id);
  await audit('MEDIA_REMOVE', id);
  await saveState();
  ui.confirmRemove = null;
  render();
}
async function exportBundle(kind) {
  const pass = bundlePass();
  ui.busy = 'Sealing bundle…';
  render();
  const bytes = await bundles.exportBundle(pass, kind);
  await audit(kind === 'sync' ? 'SYNC_EXPORT' : 'BACKUP_EXPORT', 'bundle');
  await saveState();
  saveFile(kind === 'sync' ? 'seax-sync.seax' : 'seax-backup.seax', bytes);
  ui.busy = '';
  ui.notice = kind === 'sync' ? 'Sync bundle downloaded.' : 'Backup downloaded.';
  render();
}
async function importBundle(mode) {
  const pass = bundlePass();
  const file = await readInputFile('bundle-file');
  ui.busy = 'Opening bundle…';
  render();
  const result = await bundles.importBundle(file.bytes, pass, mode);
  ui.vault = true;
  ui.busy = '';
  ui.pendingRestore = null;
  ui.screen = 'home';
  ui.notice = result.mode === 'merge'
    ? `MERGED · conflicts ${result.conflicts.length} · cases ${result.counts.cases} · entries ${result.counts.entries} · media ${result.counts.media}`
    : `IMPORTED · cases ${result.counts.cases} · entries ${result.counts.entries} · media ${result.counts.media}`;
  armIdle();
  render();
}
async function restoreBackup() {
  if (!ui.pendingRestore) {
    const pass = bundlePass();
    const file = await readInputFile('bundle-file');
    if (!pass) throw new Error('Passphrase is required.');
    ui.pendingRestore = { pass, bytes: file.bytes };
    ui.notice = 'Restore replaces the desk on this device. Confirm to continue.';
    ui.screen = dataKey ? 'desk' : ui.screen;
    ui.tab = 'sync';
    render();
    return;
  }
  const { pass, bytes } = ui.pendingRestore;
  ui.pendingRestore = null;
  ui.busy = 'Restoring…';
  render();
  const result = await bundles.importBundle(bytes, pass, 'replace');
  ui.vault = true;
  ui.busy = '';
  ui.screen = 'home';
  ui.notice = `RESTORED · cases ${result.counts.cases} · entries ${result.counts.entries} · media ${result.counts.media}`;
  armIdle();
  render();
}
async function verifyBackup() {
  const pass = bundlePass();
  const file = await readInputFile('bundle-file');
  ui.busy = 'Checking file…';
  render();
  const checked = await bundles.verifyBundle(file.bytes, pass);
  ui.busy = '';
  const word = checked.kind === 'backup' ? 'BACKUP OK' : 'BUNDLE OK';
  ui.notice = `${word} · chain intact · cases ${checked.cases} · entries ${checked.entries} · media ${checked.media}`;
  render();
}

async function hydrate(gen) {
  if (!dataKey) return;
  for (const img of document.querySelectorAll('img[data-thumb]')) {
    if (gen !== renderGen) return;
    const id = img.getAttribute('data-thumb');
    try {
      const box = await idbGet(thumbKey(id));
      if (!box || gen !== renderGen) continue;
      const bytes = await openBytes(dataKey, box);
      const url = URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' }));
      thumbUrls.push(url);
      if (gen !== renderGen) { URL.revokeObjectURL(url); return; }
      img.src = url;
      if (!seenThumb.has(id)) {
        seenThumb.add(id);
        serial(async () => {
          if (!dataKey || !state) return;
          await audit('MEDIA_VIEW', `${id} thumbnail`);
          await saveState();
          const chainEl = document.getElementById('chain');
          if (chainEl) chainEl.textContent = `AUDIT ${state.audit.length} entries`;
        });
      }
    } catch { /* thumbnail missing */ }
  }
  for (const el of document.querySelectorAll('[data-exif]')) {
    if (gen !== renderGen) return;
    try {
      const meta = await openJson(dataKey, await idbGet(exifKey(el.getAttribute('data-exif'))));
      if (gen !== renderGen) return;
      el.innerHTML = formatMeta(meta);
    } catch {
      el.textContent = 'Could not open evidence metadata.';
    }
  }
}
function formatMeta(meta) {
  const rows = [];
  for (const [k, val] of Object.entries(meta.fields || {})) {
    const text = Array.isArray(val) ? val.join(', ') : String(val);
    rows.push(`<div class="row"><span class="k">${esc(k)}</span><span class="v">${esc(text)}</span></div>`);
  }
  if (meta.comments?.length) rows.push(`<div class="row"><span class="k">Comment</span><span class="v">${esc(meta.comments.join(' | '))}</span></div>`);
  const noteLine = `<p class="note">${esc(meta.note || '')}</p>`;
  if (!rows.length) return `${noteLine}<div class="note">No parsed fields. The original file is still stored in full.</div>`;
  return noteLine + rows.join('');
}

function bind() {
  document.body.addEventListener('click', (ev) => {
    const el = ev.target.closest('[data-act]');
    if (!el || el.hasAttribute('disabled')) return;
    if (el.matches('input, textarea, select')) return;
    ev.preventDefault();
    const dataset = { ...el.dataset };
    serial(() => act(dataset.act, { dataset })).catch(onErr);
  });
  document.body.addEventListener('input', (ev) => {
    if (ev.target.id === 'q') {
      ui.query = ev.target.value;
      const box = document.getElementById('results');
      if (box) {
        box.innerHTML = resultsHtml();
        hydrate(renderGen);
      }
    }
  });
  document.body.addEventListener('change', (ev) => {
    if (ev.target.id === 'ty') {
      const ex = document.getElementById('ex');
      const custom = document.getElementById('custom-fields');
      if (ex) {
        ex.innerHTML = extrasHtml();
        ex.dataset.for = ev.target.value;
      }
      const recordType = fieldRecordTypeForEntry(ev.target.value);
      if (custom) {
        custom.innerHTML = recordType ? customFieldsHtml(recordType, null, 'new') : '';
        custom.dataset.for = recordType || '';
      }
      return;
    }
    if (ev.target.dataset.act === 'set-sp') {
      const target = ev.target;
      serial(() => setSp(target.dataset.id, target.dataset.cat, target.value)).catch(onErr);
    }
  });
  document.addEventListener('keydown', (ev) => {
    const typing = ev.target && (ev.target.matches?.('input, textarea, select'));
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      if (dataKey && deskOpen()) { ui.screen = 'search'; render(); }
      return;
    }
    if (ev.key === '/' && dataKey && deskOpen() && !typing) {
      ev.preventDefault();
      ui.screen = 'search';
      render();
    }
    if (ev.key === 'Escape') {
      if (ui.preview) { ui.preview = null; render(); }
      else if (ui.confirmDelete || ui.confirmWithdraw || ui.confirmRemove) {
        ui.confirmDelete = null;
        ui.confirmWithdraw = null;
        ui.confirmRemove = null;
        render();
      }
      return;
    }
    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'n' && dataKey && deskOpen()) {
      ev.preventDefault();
      ui.screen = 'desk';
      ui.tab = 'add';
      if (!cur()) ui.showCase = true;
      render();
      return;
    }
    if (ev.key === 'Enter' && ev.target?.id === 'p') {
      ev.preventDefault();
      document.querySelector('[data-act="sign-in"], [data-act="create-admin"]')?.click();
    }
  });
  document.addEventListener('pointerdown', () => { if (dataKey) armIdle(); }, { passive: true });
  document.addEventListener('keydown', () => { if (dataKey) armIdle(); });
  document.addEventListener('visibilitychange', () => {
    if (!dataKey) return;
    if (document.visibilityState === 'hidden') hiddenAt = Date.now();
    else if (hiddenAt && Date.now() - hiddenAt >= idleMs()) lock();
    else armIdle();
  });
  setInterval(() => {
    const el = document.getElementById('clock');
    if (el) el.textContent = nowLondon();
  }, 1000);
}
function onErr(err) {
  const msg = err?.message || 'Something went wrong.';
  ui.busy = '';
  const sync = document.getElementById('sync-msg');
  const entry = document.getElementById('e');
  const el = ui.tab === 'sync' && sync ? sync : (entry || sync);
  if (el) el.textContent = msg;
  else { ui.error = msg; render(); }
}
function fillAddExtras() {
  const ty = document.getElementById('ty');
  if (!ty) return;
  const ex = document.getElementById('ex');
  const custom = document.getElementById('custom-fields');
  if (ex && ex.dataset.for !== ty.value) {
    ex.innerHTML = extrasHtml();
    ex.dataset.for = ty.value;
  }
  const recordType = fieldRecordTypeForEntry(ty.value);
  const key = recordType || '';
  if (custom && custom.dataset.for !== key) {
    custom.innerHTML = recordType ? customFieldsHtml(recordType, null, 'new') : '';
    custom.dataset.for = key;
  }
}

async function boot() {
  try { localStorage.removeItem('seax_launch_v1'); } catch { /* ignore */ }
  bind();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
  const vault = await idbGet(VAULT_KEY);
  ui.vault = !!vault;
  applyDevicePolicy(vault);
  render();
  queueMicrotask(fillAddExtras);
}

boot().catch((err) => {
  document.getElementById('app').textContent = err.message || 'Could not start.';
});
