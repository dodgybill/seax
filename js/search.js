/** Local search over an already-decrypted desk. No network. */

import { fieldText, resolveSpecial } from './fields.js';
import { isSealedSpecial } from './special.js';

const ENTRY_SCOPE = {
  Person: 'people',
  Location: 'locations',
  Vehicle: 'vehicles',
  Organisation: 'organisations',
};

export function searchDesk(state, query, scope = 'all') {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return [];
  const rows = [];
  const want = scope || 'all';

  if (want === 'all' || want === 'cases') {
    for (const c of state.cases || []) {
      const hay = [c.id, c.client, customHay(state, 'case', c)].join(' ').toLowerCase();
      if (hay.includes(q)) {
        rows.push({
          kind: 'case',
          scope: 'cases',
          id: c.id,
          title: c.id,
          subtitle: c.client || 'Case',
          thumbParent: { kind: 'case', id: c.id },
        });
      }
    }
  }

  for (const e of state.ents || []) {
    const sc = ENTRY_SCOPE[e.type] || 'other';
    if (want !== 'all' && want !== sc) continue;
    if (want === 'all' && sc === 'other') {
      /* still included in All */
    }
    const hay = [e.id, e.label, e.type, e.case, e.desc, e.source, e.basis, customHay(state, fieldTypeOf(e), e)]
      .join(' ')
      .toLowerCase();
    if (!hay.includes(q)) continue;
    rows.push({
      kind: 'entry',
      scope: sc,
      id: e.id,
      entryType: e.type,
      caseId: e.case,
      title: e.label || e.id,
      subtitle: `${e.type} · ${e.case}`,
      thumbParent: { kind: 'entry', id: e.id },
    });
  }

  if (want === 'all' || want === 'media') {
    for (const m of state.media || []) {
      const hay = [m.name, m.provenance, m.source, m.mime, m.sha256, m.by].join(' ').toLowerCase();
      if (!hay.includes(q)) continue;
      rows.push({
        kind: 'media',
        scope: 'media',
        id: m.id,
        title: m.name || m.id,
        subtitle: m.provenance || m.mime || 'Media',
        thumbId: m.id,
        parentKind: m.parentKind,
        parentId: m.parentId,
      });
    }
  }

  return rows;
}

function fieldTypeOf(entry) {
  const map = {
    Person: 'person',
    Location: 'location',
    Vehicle: 'vehicle',
    Organisation: 'organisation',
    Other: 'other',
  };
  return map[entry.type] || null;
}

function shownValue(value) {
  if (value == null || typeof value === 'object' || isSealedSpecial(value)) return '';
  return fieldText(value);
}

/** Text that may appear in search, filters and cross-record lists. Special-category values are omitted. */
export function publicText(state, rec, recordType) {
  if (!recordType || !rec) return '';
  return (state.fieldDefs || [])
    .filter((d) => d.recordType === recordType && !resolveSpecial(d))
    .map((d) => shownValue(rec.custom && rec.custom[d.id]))
    .filter(Boolean)
    .join(' ');
}

function customHay(state, recordType, rec) {
  return publicText(state, rec, recordType);
}

export function groupResults(rows) {
  const order = [
    ['people', 'People'],
    ['locations', 'Locations'],
    ['vehicles', 'Vehicles'],
    ['organisations', 'Organisations'],
    ['cases', 'Cases'],
    ['media', 'Media'],
    ['other', 'Other'],
  ];
  return order
    .map(([scope, label]) => ({ scope, label, rows: rows.filter((r) => r.scope === scope) }))
    .filter((g) => g.rows.length);
}
