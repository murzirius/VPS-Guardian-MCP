'use strict';
(() => {
  let token = location.hash.slice(1);
  // Keep the capability out of referrers, API URLs, disk storage and history.
  history.replaceState(null, '', '/');
  const $ = id => document.getElementById(id);
  let busy = false;
  let state = null;
  const labels = {disconnected:'Не подключён', connecting:'Подключаемся…', connected:'Подключён', disconnecting:'Отключаемся…', error:'Ошибка связи'};
  function notice(message) { $('notice').textContent = message || ''; $('notice').hidden = !message; }
  async function api(path, body) {
    const response = await fetch('/api/' + path, {
      method: body === undefined ? 'GET' : 'POST', cache:'no-store', credentials:'omit',
      headers: {'Authorization':'Bearer ' + token, ...(body === undefined ? {} : {'Content-Type':'application/json'})},
      ...(body === undefined ? {} : {body:JSON.stringify(body)}), signal:AbortSignal.timeout(8000)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Не удалось выполнить запрос.');
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
    $('services-count').textContent = services?.status === 'ok' ? 'Проблем: ' + services.total_failed : 'systemd';
    if (!services || services.status !== 'ok' || !services.failed_units.length) {
      const healthy = services?.status === 'ok'; box.classList.toggle('healthy', healthy);
      const icon = document.createElement('span'); icon.className = 'empty-icon'; icon.textContent = healthy ? '✓' : '◎';
      const title = document.createElement('p'); title.textContent = healthy ? 'Failed units не обнаружены' : services ? 'Статус systemd недоступен' : 'Здесь появятся проблемные сервисы';
      const note = document.createElement('span'); note.className = 'muted small'; note.textContent = healthy ? 'Это не проверка работоспособности всех приложений' : services ? 'systemd отсутствует, не ответил или недостаточно прав' : 'После подключения проверим failed units в systemd';
      box.append(icon, title, note); return;
    }
    for (const unit of services.failed_units) {
      const row = document.createElement('div'); row.className = 'service-row';
      const description = document.createElement('div');
      const name = document.createElement('strong'); name.textContent = unit.unit || 'Неизвестный сервис';
      const detail = document.createElement('p'); detail.textContent = unit.description || '';
      const status = document.createElement('span'); status.className = 'status'; status.textContent = unit.active || 'failed';
      description.append(name, detail); row.append(description, status); box.append(row);
    }
    if (services.total_failed > services.shown) {
      const more = document.createElement('p'); more.className = 'muted small'; more.textContent = 'Показано ' + services.shown + ' из ' + services.total_failed; box.append(more);
    }
  }
  function render(data) {
    state = data;
    const connection = data.connection;
    $('connection-status').textContent = labels[connection] || 'Неизвестно';
    $('connection-status').className = 'status ' + connection;
    const locked = ['connecting','connected','disconnecting'].includes(connection);
    for (const input of $('connection-form').querySelectorAll('input')) input.disabled = locked;
    $('connect').hidden = locked; $('disconnect').hidden = !locked;
    $('disconnect').disabled = connection === 'disconnecting';
    $('refresh').disabled = connection !== 'connected';
    $('server-name').textContent = data.snapshot?.system?.hostname || data.target?.host || 'Сервер не подключён';
    $('server-detail').textContent = data.target ? data.target.user + '@' + data.target.host + ' · SSH ' + data.target.port : 'Заполните данные подключения слева';
    const snapshot = data.snapshot;
    metric('cpu', snapshot?.cpu?.usage_percent_total, snapshot?.cpu?.logical_cores ? snapshot.cpu.logical_cores + ' логических ядер' : 'Загрузка процессора');
    metric('ram', snapshot?.ram?.used_percent, snapshot?.ram?.total ? snapshot.ram.used + ' / ' + snapshot.ram.total : 'Использование памяти');
    metric('disk', snapshot?.disk?.used_percent, snapshot?.disk?.total ? snapshot.disk.used + ' / ' + snapshot.disk.total : 'Корневой раздел');
    showServices(snapshot?.services);
    $('uptime').textContent = snapshot?.uptime?.uptime_human || '—';
    $('swap').textContent = snapshot?.swap?.total ? snapshot.swap.used + ' / ' + snapshot.swap.total : '—';
    $('updated-at').textContent = data.updated_at ? new Date(data.updated_at).toLocaleTimeString() : '—';
    $('data-note').textContent = connection === 'error' && snapshot ? 'Связь потеряна. Показаны устаревшие данные — они больше не обновляются.' : 'Метрики обновляются раз в 30 секунд. Никаких изменений на сервере.';
    notice(data.error?.message);
  }
  $('connection-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return; busy = true; $('connect').disabled = true;
    const config = Object.fromEntries(new FormData(event.currentTarget));
    try { render(await api('connect', config)); } catch(error) { notice(error.message); }
    finally { busy = false; $('connect').disabled = false; }
  });
  $('disconnect').addEventListener('click', async () => { try { render(await api('disconnect', {})); } catch(error) { notice(error.message); } });
  $('refresh').addEventListener('click', async () => { try { render(await api('refresh', {})); } catch(error) { notice(error.message); } });
  async function update() {
    if (!token) { notice('Откройте полную ссылку из терминала запуска панели. После перезагрузки страницы потребуется эта ссылка снова.'); $('connect').disabled = true; return; }
    try { render(await api('status')); }
    catch (error) { notice(error.name === 'TimeoutError' || error.name === 'TypeError' ? 'Локальная панель не отвечает. Проверьте, что процесс запуска ещё работает.' : error.message); }
    setTimeout(update, state?.connection === 'connecting' || state?.connection === 'disconnecting' ? 1000 : 3000);
  }
  update();
})();
