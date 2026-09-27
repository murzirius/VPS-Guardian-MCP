'use strict';
(() => {
  let token = location.hash.slice(1);
  // Keep the capability out of referrers, API URLs, disk storage and history.
  history.replaceState(null, '', '/');
  const $ = id => document.getElementById(id);
  let busy = false;
  let state = null;
  let loadedRevision = null, dirty = false, reloadPending = false;
  let updateTimer;
  const labels = {disconnected:'Disconnected', connecting:'Connecting…', connected:'Connected', disconnecting:'Disconnecting…', error:'Connection error'};
  function notice(message) { $('notice').textContent = message || ''; $('notice').hidden = !message; }
  async function api(path, body) {
    const response = await fetch('/api/' + path, {
      method: body === undefined ? 'GET' : 'POST', cache:'no-store', credentials:'omit',
      headers: {'Authorization':'Bearer ' + token, ...(body === undefined ? {} : {'Content-Type':'application/json'})},
      ...(body === undefined ? {} : {body:JSON.stringify(body)}), signal:AbortSignal.timeout(8000)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Request failed.');
    return data;
  }
  function metric(name, value, detail) {
    const percent = typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : null;
    const node = $(name + '-value'); node.replaceChildren(document.createTextNode(percent === null ? '—' : percent.toFixed(1)));
    const unit = document.createElement('span'); unit.textContent = '%'; node.append(unit);
    $(name + '-bar').style.width = (percent || 0) + '%';
    $(name + '-bar').style.backgroundColor = percent >= 90 ? '#e29b83' : '';
    $(name + '-detail').textContent = detail;
  }
  function showServices(services) {
    const box = $('services-content'); box.replaceChildren(); box.className = 'empty-state';
    $('services-count').textContent = services?.status === 'ok' ? 'Failed: ' + services.total_failed : 'systemd';
    if (!services || services.status !== 'ok' || !services.failed_units.length) {
      const healthy = services?.status === 'ok'; box.classList.toggle('healthy', healthy);
      const icon = document.createElement('span'); icon.className = 'empty-icon'; icon.textContent = healthy ? '✓' : '◎';
      const title = document.createElement('p'); title.textContent = healthy ? 'No failed units' : services ? 'systemd status unavailable' : 'Service status unavailable';
      const note = document.createElement('span'); note.className = 'muted small'; note.textContent = healthy ? 'This does not verify every application is healthy.' : services ? 'systemd is unavailable or access was denied.' : 'Connect with monitoring tools enabled to check systemd.';
      box.append(icon, title, note); return;
    }
    for (const unit of services.failed_units) {
      const row = document.createElement('div'); row.className = 'service-row';
      const description = document.createElement('div');
      const name = document.createElement('strong'); name.textContent = unit.unit || 'Unknown service';
      const detail = document.createElement('p'); detail.textContent = unit.description || '';
      const status = document.createElement('span'); status.className = 'status'; status.textContent = unit.active || 'failed';
      description.append(name, detail); row.append(description, status); box.append(row);
    }
    if (services.total_failed > services.shown) {
      const more = document.createElement('p'); more.className = 'muted small'; more.textContent = 'Showing ' + services.shown + ' of ' + services.total_failed; box.append(more);
    }
  }
  function dependencies() {
    $('project-roots').disabled = $('access-fields').disabled || $('inherit-roots').checked;
    for (const input of $('tool-list').querySelectorAll('input')) input.disabled = $('all-tools').checked || input.dataset.locked === 'true';
    const inputs = [...$('tool-list').querySelectorAll('input')];
    $('tool-count').textContent = inputs.filter(input => $('all-tools').checked || input.checked).length + ' / ' + inputs.length + ' allowed';
  }
  function filterTools() {
    const term = $('tool-search').value.toLowerCase().trim();
    for (const row of $('tool-list').children) row.hidden = !!term && !row.dataset.search?.includes(term);
    $('no-tool-match').hidden = !term || [...$('tool-list').children].some(row => !row.hidden);
  }
  function loadPolicy(access) {
    const policy = access.policy;
    $('enabled').checked = policy.enabled;
    $('mode-cap').value = policy.mode_cap;
    $('all-tools').checked = policy.allowed_tools === null;
    $('inherit-roots').checked = policy.project_roots === null;
    $('project-roots').value = (policy.project_roots || []).join('\n');
    $('tool-list').replaceChildren();
    for (const tool of access.catalog) {
      const row = document.createElement('label'); row.className = 'tool-row'; row.dataset.search = (tool.name + ' ' + tool.description).toLowerCase();
      const check = document.createElement('input'); check.type = 'checkbox'; check.value = tool.name; check.dataset.locked = String(tool.locked === true);
      check.checked = policy.allowed_tools === null || policy.allowed_tools.includes(tool.name) || tool.locked === true;
      const text = document.createElement('span');
      const name = document.createElement('strong'); name.textContent = tool.name;
      const description = document.createElement('small'); description.textContent = tool.locked ? 'Always available · recovery metadata' : tool.description;
      text.append(name, description); row.append(check, text); $('tool-list').append(row);
    }
    loadedRevision = access.revision; dirty = false; filterTools(); dependencies();
  }
  function render(data) {
    state = data;
    const connection = data.connection;
    $('connection-status').textContent = labels[connection] || 'Unknown';
    $('connection-status').className = 'status ' + connection;
    const locked = ['connecting','connected','disconnecting'].includes(connection);
    if (locked && data.target) {
      for (const name of ['host','user','port']) $(name).value = data.target[name];
    }
    for (const input of $('connection-form').querySelectorAll('input')) input.disabled = locked;
    $('connect').hidden = locked; $('disconnect').hidden = !locked;
    $('disconnect').disabled = connection === 'disconnecting';
    $('refresh').disabled = connection !== 'connected';
    const canManage = connection === 'connected' && data.access_supported && !!data.access && !data.policy_busy;
    $('access-fields').disabled = !canManage; $('apply-policy').disabled = !canManage;
    $('reload-policy').disabled = connection !== 'connected' || !data.access_supported || data.policy_busy;
    if (!data.access) loadedRevision = null;
    if (data.access && (loadedRevision !== data.access.revision || reloadPending && !data.policy_busy && !data.access_error)) {
      loadPolicy(data.access); reloadPending = false;
    }
    dependencies();
    $('access-badge').textContent = data.access ? data.access.policy.enabled ? 'Enabled' : 'Paused' : 'Not loaded';
    $('access-help').textContent = data.access ? 'Shared policy for this SSH user · Guardian ' + data.access.version : 'Connect to Guardian 0.30.0+ to manage agent permissions.';
    const policyError = data.access_error || data.access?.error;
    $('access-message').textContent = policyError || ''; $('access-message').hidden = !policyError;
    $('policy-save-state').textContent = data.policy_busy ? 'Working…' : dirty ? 'Unsaved changes. Apply to enforce on the VPS.' : data.access ? data.access.configured ? 'Server policy loaded. Changes affect subsequent MCP calls.' : 'Launch defaults active. Apply to save a server policy.' : 'No policy loaded.';
    $('server-name').textContent = data.snapshot?.system?.hostname || data.target?.host || 'No server connected';
    $('server-detail').textContent = data.target ? data.target.user + '@' + data.target.host + ' · SSH ' + data.target.port : 'Enter your connection details on the left';
    const snapshot = data.snapshot;
    metric('cpu', snapshot?.cpu?.usage_percent_total, snapshot?.cpu?.logical_cores ? snapshot.cpu.logical_cores + ' logical cores' : 'Processor usage');
    metric('ram', snapshot?.ram?.used_percent, snapshot?.ram?.total ? snapshot.ram.used + ' / ' + snapshot.ram.total : 'Memory usage');
    metric('disk', snapshot?.disk?.used_percent, snapshot?.disk?.total ? snapshot.disk.used + ' / ' + snapshot.disk.total : 'Root filesystem');
    showServices(snapshot?.services);
    $('uptime').textContent = snapshot?.uptime?.uptime_human || '—';
    $('swap').textContent = snapshot?.swap?.total ? snapshot.swap.used + ' / ' + snapshot.swap.total : '—';
    $('updated-at').textContent = data.updated_at ? new Date(data.updated_at).toLocaleTimeString() : '—';
    $('data-note').textContent = connection === 'error' && snapshot ? 'Connection lost. Displayed metrics are stale.' : 'Metrics refresh every 30 seconds. Monitoring never changes the server.';
    if (data.monitoring_blocked) $('data-note').textContent = 'Monitoring is disabled by the access policy. Operator controls remain available.';
    notice(data.error?.message);
  }
  $('connection-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return; busy = true; $('connect').disabled = true;
    const config = Object.fromEntries(new FormData(event.currentTarget));
    try { render(await api('connect', config)); } catch(error) { notice(error.message); }
    finally { busy = false; $('connect').disabled = false; }
  });
  $('disconnect').addEventListener('click', async () => { try { render(await api('disconnect', {})); } catch(error) { notice(error.message); } });
  $('access-form').addEventListener('change', event => {
    if (event.target.id === 'tool-search') return;
    dirty = true; dependencies(); $('policy-save-state').textContent = 'Unsaved changes. Apply to enforce on the VPS.';
  });
  $('project-roots').addEventListener('input', () => { dirty = true; $('policy-save-state').textContent = 'Unsaved changes. Apply to enforce on the VPS.'; });
  $('tool-search').addEventListener('input', filterTools);
  $('access-form').addEventListener('submit', async event => {
    event.preventDefault(); if (!state?.access || busy || state.policy_busy) return;
    const policy = {
      enabled:$('enabled').checked, mode_cap:$('mode-cap').value,
      allowed_tools:$('all-tools').checked ? null : [...$('tool-list').querySelectorAll('input:checked')].map(input => input.value),
      project_roots:$('inherit-roots').checked ? null : $('project-roots').value.split('\n').map(line => line.trim()).filter(Boolean)
    };
    busy = true;
    try { reloadPending = true; render(await api('policy', {policy, expected_revision:loadedRevision})); } catch(error) { reloadPending = false; notice(error.message); }
    finally { busy = false; }
  });
  $('reload-policy').addEventListener('click', async () => {
    if (dirty && !confirm('Discard unsaved permission changes and reload the VPS policy?')) return;
    try { reloadPending = true; render(await api('policy/reload', {})); } catch(error) { reloadPending = false; notice(error.message); }
  });
  $('refresh').addEventListener('click', async () => { try { render(await api('refresh', {})); } catch(error) { notice(error.message); } });
  async function update() {
    clearTimeout(updateTimer);
    if (!token) { notice('Open the full private link printed when the panel starts. After reloading, you will need that link again.'); $('connect').disabled = true; return; }
    try { render(await api('status')); }
    catch (error) { notice(error.name === 'TimeoutError' || error.name === 'TypeError' ? 'The local panel is not responding. Check that its process is still running.' : error.message); }
    updateTimer = setTimeout(update, state?.policy_busy || state?.connection === 'connecting' || state?.connection === 'disconnecting' ? 1000 : 3000);
  }
  window.addEventListener('hashchange', () => {
    if (!location.hash) return;
    token = location.hash.slice(1);
    history.replaceState(null, '', '/');
    $('connect').disabled = false;
    update();
  });
  update();
})();
