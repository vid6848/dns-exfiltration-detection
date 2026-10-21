// CyberTrace DNS Alerts service worker.
// Polls GET /alerts on the configured server and raises a desktop notification for
// each new suspicious event. Optionally forwards hostnames this browser contacts to
// POST /ingest so the server scores them (off by default, see options page).

import { describeIndicators, fetchJson, getSettings } from './shared.js';

const POLL_ALARM = 'cybertrace-poll';
const MAX_SEEN = 1000;
const MAX_RECENT = 25;
const BROWSER_DEDUPE_MS = 60_000; // approximates a resolver cache: one lookup per host per minute
const BROWSER_FLUSH_MS = 3_000;

// ---------------------------------------------------------------- alert polling

async function schedulePolling() {
  const { pollSeconds } = await getSettings();
  await chrome.alarms.clear(POLL_ALARM);
  await chrome.alarms.create(POLL_ALARM, {
    delayInMinutes: 0.05,
    periodInMinutes: Math.max(30, Number(pollSeconds) || 30) / 60,
  });
}

async function setBadge(unread, ok) {
  if (!ok) {
    await chrome.action.setBadgeBackgroundColor({ color: '#6b7280' });
    await chrome.action.setBadgeText({ text: '!' });
    return;
  }
  await chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
  await chrome.action.setBadgeText({ text: unread > 0 ? String(Math.min(unread, 999)) : '' });
}

function notifyAlerts(alerts) {
  if (alerts.length === 1) {
    const alert = alerts[0];
    const reasons = describeIndicators(alert.rule_indicators);
    chrome.notifications.create(alert.alert_id, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: `Suspicious DNS: ${alert.risk_label} (${(alert.attack_score * 100).toFixed(1)}%)`,
      message: alert.requested_server_name,
      contextMessage: `Host ${alert.src_ip}${reasons.length ? ` · ${reasons.join(', ')}` : ''}`,
      priority: 2,
    });
    return;
  }
  const domains = [...new Set(alerts.map((a) => a.requested_server_name.split('.').slice(-2).join('.')))];
  const hosts = [...new Set(alerts.map((a) => a.src_ip))];
  chrome.notifications.create(`batch-${alerts[0].alert_id}`, {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: `${alerts.length} new suspicious DNS events`,
    message: `Target domain${domains.length > 1 ? 's' : ''}: ${domains.slice(0, 3).join(', ')}`,
    contextMessage: `From host${hosts.length > 1 ? 's' : ''} ${hosts.slice(0, 3).join(', ')}`,
    priority: 2,
  });
}

// Polls triggered together (alarm, ingest flush, popup button) share one request so
// the same new alert is never notified twice.
let inFlightPoll = null;

function poll() {
  inFlightPoll ??= pollOnce().finally(() => {
    inFlightPoll = null;
  });
  return inFlightPoll;
}

async function pollOnce() {
  const settings = await getSettings();
  if (!settings.apiBase) {
    await chrome.storage.local.set({ status: { ok: false, error: 'Server not configured', checkedAt: Date.now() } });
    await setBadge(0, false);
    return;
  }

  const state = await chrome.storage.local.get(['seenIds', 'recent', 'unread', 'primed']);
  const seen = new Set(state.seenIds || []);
  let recent = state.recent || [];
  let unread = state.unread || 0;

  try {
    const [alertsData, stats] = await Promise.all([
      fetchJson(settings.apiBase, '/alerts?limit=200'),
      fetchJson(settings.apiBase, '/statistics'),
    ]);
    // Server returns newest first; notify oldest-first among the unseen ones.
    const fresh = alertsData.alerts.filter((a) => !seen.has(a.alert_id)).reverse();

    // First successful poll after (re)configuring only records what already exists,
    // so connecting to a busy server does not produce a flood of notifications.
    if (state.primed && fresh.length > 0) {
      unread += fresh.length;
      if (settings.notify) notifyAlerts(fresh);
    }
    fresh.forEach((a) => seen.add(a.alert_id));
    recent = [...fresh.reverse(), ...recent].slice(0, MAX_RECENT);

    await chrome.storage.local.set({
      seenIds: [...seen].slice(-MAX_SEEN),
      recent,
      unread,
      primed: true,
      stats,
      status: { ok: true, checkedAt: Date.now() },
    });
    await setBadge(unread, true);
  } catch (err) {
    await chrome.storage.local.set({ status: { ok: false, error: err.message, checkedAt: Date.now() } });
    await setBadge(0, false);
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === POLL_ALARM) poll();
});

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  await schedulePolling();
  if (reason === 'install') chrome.runtime.openOptionsPage();
});

chrome.runtime.onStartup.addListener(schedulePolling);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'settings-changed') {
    chrome.storage.local
      .set({ primed: false, seenIds: [], recent: [], unread: 0 })
      .then(schedulePolling)
      .then(() => sendResponse({ ok: true }));
    return true;
  }
  if (message?.type === 'poll-now') {
    poll().then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});

chrome.notifications.onClicked.addListener(async (notificationId) => {
  const { apiBase } = await getSettings();
  if (apiBase) chrome.tabs.create({ url: `${apiBase}/` });
  chrome.notifications.clear(notificationId);
});

// ------------------------------------------------------- optional browser sensor

const lastSeenHost = new Map();
let pending = [];
let flushTimer = null;

function isScorableHost(hostname) {
  if (!hostname || !hostname.includes('.')) return false;
  if (/^[\d.]+$/.test(hostname) || hostname.includes(':')) return false; // IP literals need no DNS
  return !hostname.endsWith('.local') && hostname !== 'localhost';
}

async function browserCaptureId() {
  const { captureId } = await chrome.storage.local.get('captureId');
  if (captureId) return captureId;
  const created = `browser-${crypto.randomUUID().slice(0, 8)}`;
  await chrome.storage.local.set({ captureId: created });
  return created;
}

async function flushBrowserQueries() {
  flushTimer = null;
  const batch = pending.splice(0, 1000);
  if (batch.length === 0) return;
  const settings = await getSettings();
  if (!settings.apiBase || !settings.monitorBrowsing) return;
  try {
    await fetchJson(settings.apiBase, '/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ capture_id: await browserCaptureId(), queries: batch }),
    });
    // Surface any resulting alert straight away instead of waiting for the next poll.
    poll();
  } catch {
    // Server unreachable: drop the batch; the popup shows the connection error from polling.
  }
}

async function onBrowserRequest(details) {
  let url;
  try {
    url = new URL(details.url);
  } catch {
    return;
  }
  const hostname = url.hostname.toLowerCase();
  if (!isScorableHost(hostname)) return;

  const settings = await getSettings();
  if (!settings.monitorBrowsing || !settings.apiBase) return;
  if (hostname === new URL(settings.apiBase).hostname) return;

  const now = Date.now();
  if (now - (lastSeenHost.get(hostname) || 0) < BROWSER_DEDUPE_MS) return;
  lastSeenHost.set(hostname, now);

  pending.push({
    timestamp: new Date(now).toISOString(),
    src_ip: '127.0.0.1',
    dst_ip: '0.0.0.0',
    requested_server_name: hostname,
    query_type: 'A',
    source: 'CyberTrace browser extension',
  });
  if (!flushTimer) flushTimer = setTimeout(flushBrowserQueries, BROWSER_FLUSH_MS);
}

function attachBrowserSensor() {
  if (chrome.webRequest && !chrome.webRequest.onBeforeRequest.hasListener(onBrowserRequest)) {
    chrome.webRequest.onBeforeRequest.addListener(onBrowserRequest, { urls: ['http://*/*', 'https://*/*'] });
  }
}

// Listeners must be attached synchronously at start-up to wake the worker in MV3.
attachBrowserSensor();
chrome.permissions.onAdded.addListener(attachBrowserSensor);
