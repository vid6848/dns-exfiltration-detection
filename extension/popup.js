import { describeIndicators, getDashboardUrl, getSettings } from './shared.js';

const $ = (id) => document.getElementById(id);

function timeAgo(ms) {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

function renderAlert(alert) {
  const el = document.createElement('div');
  el.className = 'alert';
  const top = document.createElement('div');
  top.className = 'top';
  const risk = document.createElement('span');
  risk.className = 'risk';
  risk.textContent = `${alert.risk_label} · ${(alert.attack_score * 100).toFixed(1)}%`;
  const when = document.createElement('span');
  when.textContent = `${alert.src_ip} · ${alert.timestamp}`;
  top.append(risk, when);
  const name = document.createElement('div');
  name.className = 'mono';
  name.textContent = alert.requested_server_name;
  el.append(top, name);
  const reasons = describeIndicators(alert.rule_indicators);
  if (reasons.length) {
    const why = document.createElement('div');
    why.className = 'muted';
    why.textContent = `Why: ${reasons.join(', ')}`;
    el.append(why);
  }
  return el;
}

async function render() {
  const settings = await getSettings();
  const { status, stats, recent = [] } = await chrome.storage.local.get(['status', 'stats', 'recent']);

  $('server').textContent = settings.apiBase || 'No server configured — open Settings';
  $('dot').className = `dot ${status?.ok ? 'ok' : status ? 'err' : ''}`;
  $('status').textContent = status
    ? status.ok ? `Connected · ${timeAgo(status.checkedAt)}` : status.error
    : 'Not checked yet';

  if (stats) {
    $('processed').textContent = stats.total_processed.toLocaleString();
    $('suspicious').textContent = stats.total_suspicious.toLocaleString();
    $('rate').textContent = `${(stats.suspicious_rate * 100).toFixed(1)}%`;
  }

  const list = $('list');
  list.replaceChildren();
  if (recent.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty muted';
    empty.textContent = 'No suspicious DNS activity since you connected.';
    list.append(empty);
  } else {
    recent.forEach((alert) => list.append(renderAlert(alert)));
  }
}

$('dashboard').addEventListener('click', async () => {
  const { apiBase } = await getSettings();
  chrome.tabs.create({ url: getDashboardUrl(apiBase) });
});
$('settings').addEventListener('click', () => chrome.runtime.openOptionsPage());
$('clearBtn')?.addEventListener('click', async () => {
  await chrome.storage.local.set({ recent: [], seenIds: [], unread: 0 });
  await render();
});
$('refresh').addEventListener('click', async () => {
  $('status').textContent = 'Checking…';
  await chrome.runtime.sendMessage({ type: 'poll-now' });
  render();
});

// Opening the popup counts as reading the alerts.
chrome.storage.local.set({ unread: 0 }).then(() => chrome.action.setBadgeText({ text: '' }));
chrome.storage.onChanged.addListener(render);
render();
