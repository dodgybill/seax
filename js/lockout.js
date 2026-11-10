/** Rolling lockout window. Pure: no storage and no timers. */

export function lockoutView(fails, now, windowMs, max) {
  const kept = (fails || []).filter((t) => now - Number(t) < windowMs);
  const locked = kept.length >= max;
  return { fails: kept, locked, until: locked ? kept[0] + windowMs : 0, count: kept.length };
}

export function nextLockout(fails, now, windowMs, max) {
  const view = lockoutView(fails, now, windowMs, max);
  if (view.locked) return view;
  const next = view.fails.concat(now);
  const locked = next.length >= max;
  return { fails: next, locked, until: locked ? next[0] + windowMs : 0, count: next.length };
}
