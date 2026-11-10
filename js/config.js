/** Platform name. SEAX Intelligence is the maker, not the product name. */
export const APP_NAME = 'VIGIL';

/** Maker. Not the name of the desk. */
export const FIRM_NAME = 'SEAX Intelligence';

/** Secondary line under the platform name. */
export const BYLINE = `by ${FIRM_NAME}`;

/** Installed-app listing: platform by maker. */
export const APP_LISTING = `${APP_NAME} by ${FIRM_NAME}`;

/**
 * Icon files. Change this object when the VIGIL mark arrives.
 * index.html and manifest.json repeat these paths because the browser
 * reads them before this module. tests/unit.mjs checks the copies match.
 * The service worker imports this object, so the shell cache follows it.
 */
export const ICONS = {
  mark: 'assets/icons/seax-small-mark-64.png',
  favicon: 'favicon.ico',
  faviconAsset: 'assets/icons/favicon.ico',
  png16: 'assets/icons/seax-small-mark-16.png',
  png32: 'assets/icons/seax-small-mark-32.png',
  png48: 'assets/icons/seax-small-mark-48.png',
  appleTouch: 'assets/icons/apple-touch-icon.png',
  badge192: 'assets/icons/seax-badge-192.png',
  badge512: 'assets/icons/seax-badge-512.png',
  badge1024: 'assets/icons/seax-badge-1024.png',
};

/** Build flag. Set to false to restore the username at setup. */
export const ACTIVE_MODE = true;
