import { fetchJson, getSettings, normalizeBase, originPattern, saveSettings } from './shared.js';

const $ = (id) => document.getElementById(id);

function show(message, ok) {
  $('result').className = ok ? 'ok' : 'err';
  $('result').textContent = message;
}

function readForm() {
  return {
    apiBase: normalizeBase($('apiBase').value),
    pollSeconds: Math.max(30, Number($('pollSeconds').value) || 30),
    notify: $('notify').checked,
    monitorBrowsing: $('monitorBrowsing').checked,
  };
}

// Permission prompts must come straight from the click, before any other await.
function requestPermissions(settings) {
  const request = { origins: [originPattern(settings.apiBase)] };
  if (settings.monitorBrowsing) {
    request.permissions = ['webRequest'];
    request.origins.push('http://*/*', 'https://*/*');
  }
  return chrome.permissions.request(request);
}

async function checkServer(apiBase) {
  const health = await fetchJson(apiBase, '/health');
  if (health.status !== 'healthy' || !health.model_loaded) {
    throw new Error(`Server answered but is not ready (model_loaded=${health.model_loaded})`);
  }
  const stats = await fetchJson(apiBase, '/statistics');
  return `Connected. Model loaded; ${stats.total_processed} queries scored so far, ${stats.total_suspicious} suspicious.`;
}

$('test').addEventListener('click', async () => {
  const settings = readForm();
  if (!settings.apiBase) return show('Enter the server URL first.', false);
  try {
    if (!(await chrome.permissions.request({ origins: [originPattern(settings.apiBase)] }))) {
      return show('Permission to contact the server was declined.', false);
    }
    show(await checkServer(settings.apiBase), true);
  } catch (err) {
    show(`Could not reach the server: ${err.message}`, false);
  }
});

$('save').addEventListener('click', async () => {
  const settings = readForm();
  if (!settings.apiBase) return show('Enter the server URL first.', false);
  let granted;
  try {
    granted = await requestPermissions(settings);
  } catch (err) {
    return show(`Invalid server URL: ${err.message}`, false);
  }
  if (!granted) return show('Permission declined; settings not saved.', false);

  if (!settings.monitorBrowsing && (await chrome.permissions.contains({ permissions: ['webRequest'] }))) {
    await chrome.permissions.remove({ permissions: ['webRequest'] });
  }
  await saveSettings(settings);
  await chrome.runtime.sendMessage({ type: 'settings-changed' });
  try {
    show(`Saved. ${await checkServer(settings.apiBase)} You will be notified of new alerts.`, true);
  } catch (err) {
    show(`Saved, but the server is not reachable yet: ${err.message}`, false);
  }
});

getSettings().then((settings) => {
  $('apiBase').value = settings.apiBase;
  $('pollSeconds').value = settings.pollSeconds;
  $('notify').checked = settings.notify;
  $('monitorBrowsing').checked = settings.monitorBrowsing;
});
