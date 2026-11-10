import { normaliseSettings } from './settings.js';

/**
 * Built-in desk shape.
 * There are no built-in ethnicity, religion or political-view fields.
 * assertClean rejects those names as property keys. Custom-field labels are
 * values, not keys: they are allowed and tagged in fields.js.
 * assertClean walks keys only. Free text values are not scanned.
 */

export const ENTRY_TYPES = [
  'Person',
  'Location',
  'Vehicle',
  'Organisation',
  'Telecom/Email',
  'Intelligence',
  'Financial',
  'Other',
];

export const SPECIAL_CATEGORIES = ['Health', 'Criminal record', 'Biometrics'];

const KEY_FORBIDDEN = [
  'ethnic',
  'religion',
  'religious',
  'politic',
  'racial',
  'creed',
];

function forbiddenKey(name) {
  const norm = String(name).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (norm === 'race' || norm === 'faith') return true;
  return KEY_FORBIDDEN.some((w) => norm.includes(w));
}

export function assertClean(value) {
  walk(value);
}

function walk(value) {
  if (!value || typeof value !== 'object') return;
  if (value instanceof Uint8Array || value instanceof ArrayBuffer) return;
  if (ArrayBuffer.isView(value)) return;
  if (Array.isArray(value)) {
    value.forEach(walk);
    return;
  }
  for (const [k, v] of Object.entries(value)) {
    if (forbiddenKey(k)) {
      throw new Error('That field is not part of this desk and cannot be stored.');
    }
    walk(v);
  }
}

export function assertSpecial(sp) {
  if (!sp) return;
  for (const k of Object.keys(sp)) {
    if (!SPECIAL_CATEGORIES.includes(k)) {
      throw new Error('That field is not part of this desk and cannot be stored.');
    }
  }
}

export function normalise(s) {
  const state = s && typeof s === 'object' ? s : {};
  state.v = 1;
  state.owner = state.owner && typeof state.owner === 'object' ? state.owner : { name: '' };
  state.attest = state.attest && typeof state.attest === 'object' ? state.attest : {};
  state.cases = Array.isArray(state.cases) ? state.cases : [];
  state.ents = Array.isArray(state.ents) ? state.ents : [];
  state.links = Array.isArray(state.links) ? state.links : [];
  state.tasks = Array.isArray(state.tasks) ? state.tasks : [];
  state.audit = Array.isArray(state.audit) ? state.audit : [];
  state.media = Array.isArray(state.media) ? state.media : [];
  state.conflicts = Array.isArray(state.conflicts) ? state.conflicts : [];
  state.tombstones = Array.isArray(state.tombstones) ? state.tombstones : [];
  state.retainedAudits = Array.isArray(state.retainedAudits) ? state.retainedAudits : [];
  state.fieldDefs = Array.isArray(state.fieldDefs) ? state.fieldDefs : [];
  state.settings = normaliseSettings(state.settings);
  state.curCase = state.curCase || null;
  return state;
}

export function uid(prefix) {
  const b = crypto.getRandomValues(new Uint8Array(3));
  const hex = [...b].map((x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `${prefix}-${hex}`;
}
