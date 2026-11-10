/** Owner settings. Compliance switches are off until SEAX ALPHA turns one on. */

export const COMPLIANCE_KEYS = [
  'gate',
  'personBasis',
  'art9',
  'paperwork',
  'retention',
  'notices',
  'disclaimer',
];

export function defaultSettings() {
  return {
    idleMin: 15,
    lockoutMax: 5,
    retentionDate: '',
    compliance: Object.fromEntries(COMPLIANCE_KEYS.map((key) => [key, false])),
  };
}

export function normaliseSettings(raw) {
  const base = defaultSettings();
  const src = raw && typeof raw === 'object' ? raw : {};
  const idle = Number(src.idleMin);
  const lock = Number(src.lockoutMax);
  if (Number.isFinite(idle)) base.idleMin = Math.min(240, Math.max(1, Math.round(idle)));
  if (Number.isFinite(lock)) base.lockoutMax = Math.min(20, Math.max(3, Math.round(lock)));
  base.retentionDate = typeof src.retentionDate === 'string' ? src.retentionDate : '';
  for (const key of COMPLIANCE_KEYS) base.compliance[key] = !!(src.compliance && src.compliance[key]);
  return base;
}
