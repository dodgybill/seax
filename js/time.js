/** Europe/London display times. en-GB, 24-hour clock. */

export function londonParts(date = new Date()) {
  const fmt = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/London',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'short',
  });
  const out = {};
  for (const p of fmt.formatToParts(date)) {
    if (p.type !== 'literal') out[p.type] = p.value;
  }
  return out;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Display form stored on audit entries, e.g. "10 Nov 2026, 19:05:01 GMT". */
export function nowLondon(date = new Date()) {
  const p = londonParts(date);
  const month = MONTHS[Number(p.month) - 1] || p.month;
  return `${Number(p.day)} ${month} ${p.year}, ${p.hour}:${p.minute}:${p.second} ${p.timeZoneName || 'GMT'}`;
}

/** YYYY-MM-DD in London, for date comparisons and date inputs. */
export function todayLondon(date = new Date()) {
  const p = londonParts(date);
  return `${p.year}-${p.month}-${p.day}`;
}
