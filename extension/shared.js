// Settings and storage helpers shared by the service worker, popup and options page.

export const DEFAULTS = {
  apiBase: '',
  pollSeconds: 30,
  notify: true,
  monitorBrowsing: false,
};

export async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULTS, ...(settings || {}) };
}

export async function saveSettings(settings) {
  await chrome.storage.local.set({ settings });
}

export function normalizeBase(url) {
  return (url || '').trim().replace(/\/+$/, '');
}

export function originPattern(apiBase) {
  const { protocol, host } = new URL(apiBase);
  return `${protocol}//${host}/*`;
}

export async function fetchJson(apiBase, path, init) {
  const res = await fetch(`${apiBase}${path}`, { cache: 'no-store', ...init });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${path}`);
  }
  return res.json();
}

export function describeIndicators(indicators = {}) {
  const parts = [];
  if (indicators.entropy_flag) parts.push('high entropy');
  if (indicators.query_length_flag) parts.push('long query');
  if (indicators.query_frequency_flag) parts.push('query burst');
  if (indicators.unique_subdomains_flag) parts.push('many unique subdomains');
  return parts;
}

export function getDashboardUrl(apiBase) {
  if (!apiBase) return 'http://localhost:3000/';
  const clean = normalizeBase(apiBase);
  // When running locally on port 8000, open the local React dashboard on port 3000
  if (clean.includes(':8000') || clean === 'http://127.0.0.1' || clean === 'http://localhost') {
    return 'http://localhost:3000/';
  }
  return `${clean}/`;
}
