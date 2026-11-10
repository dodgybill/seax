/** Custom fields. Special-category tagging is by label or an explicit toggle. */

export const FIELD_TYPES = ['text', 'longtext', 'number', 'date', 'bool', 'dropdown', 'url'];

export const FIELD_RECORD_TYPES = [
  ['case', 'Case'],
  ['person', 'Person'],
  ['location', 'Location'],
  ['vehicle', 'Vehicle'],
  ['organisation', 'Organisation'],
  ['other', 'Other'],
];

const ENTRY_TO_FIELD = {
  Person: 'person',
  Location: 'location',
  Vehicle: 'vehicle',
  Organisation: 'organisation',
  Other: 'other',
};

export function fieldRecordTypeForEntry(entryType) {
  return ENTRY_TO_FIELD[entryType] || null;
}

/**
 * Label match for ethnicity/race, religion/faith, or political views/affiliation.
 * Does not reject the field. Callers tag it as a special category.
 */
export function isSpecialLabel(label) {
  const raw = String(label || '');
  const n = raw.toLowerCase();
  if (/\bethnic\w*/i.test(n)) return true;
  if (/\bracial\w*/i.test(n) || /\brace\b/i.test(n)) return true;
  if (/\breligio\w*/i.test(n)) return true;
  if (/\bfaith\b/i.test(n)) return true;
  if (/\bpolitic\w*/i.test(n)) return true;
  if (/\bparty\s+affiliation\b/i.test(n)) return true;
  return false;
}

export function resolveSpecial(def) {
  if (!def) return false;
  return !!(def.explicitSpecial || isSpecialLabel(def.label));
}

export function defsFor(state, recordType, { includeArchived = false } = {}) {
  return (state.fieldDefs || [])
    .filter((d) => d.recordType === recordType && (includeArchived || !d.archived))
    .slice()
    .sort((a, b) => (a.order - b.order) || a.label.localeCompare(b.label, 'en-GB'));
}

export function fieldHasData(state, fieldId) {
  const filled = (rec) => {
    const v = rec.custom && rec.custom[fieldId];
    return v !== undefined && v !== null && v !== '';
  };
  return (state.cases || []).some(filled) || (state.ents || []).some(filled);
}

export function coerceField(def, raw) {
  if (raw == null) return null;
  const s = typeof raw === 'string' ? raw.trim() : raw;
  if (def.type === 'bool') {
    if (s === '' || s == null) return null;
    if (s === true || s === 'yes' || s === 'true') return true;
    if (s === false || s === 'no' || s === 'false') return false;
    return null;
  }
  if (s === '') return null;
  if (def.type === 'number') {
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  }
  return String(s);
}

export function fieldText(value) {
  if (value == null || value === '') return '';
  if (value === true) return 'yes';
  if (value === false) return 'no';
  return String(value);
}
