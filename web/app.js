const $ = (s) => document.querySelector(s);

async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json();
}

function typeClass(t) { return t === 'gateway' ? 'gw' : (t === 'ap' ? 'ap' : (t === 'host' ? 'host' : 'subnet')); }

function renderTree(node, container) {
  const div = document.createElement('div');
  div.className = 'node';
  const t = node.type || 'unknown';
  let label = escapeHtml(node.label || node.ip || node.id);
  let extra = '';
  if (node.mac) extra += ' <span class="dim">' + escapeHtml(node.mac) + '</span>';
  if (node.vendor && node.vendor !== 'unknown') extra += ' <span class="dim">· ' + escapeHtml(node.vendor) + '</span>';
  div.innerHTML = '<span class="type">[' + escapeHtml(t) + ']</span><span class="' + typeClass(t) + '">' + label + '</span>' + extra;
  container.appendChild(div);
  if (node.children && node.children.length) {
    const kids = document.createElement('div');
    kids.className = 'children';
    node.children.forEach((c) => renderTree(c, kids));
    container.appendChild(kids);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

async function refreshTopology() {
  try {
    const t = await api('/api/topology');
    $('#tree').innerHTML = '';
    if (t && t.children) t.children.forEach((c) => renderTree(c, $('#tree')));
    $('#gw').textContent = t && t.children && t.children.length ? '' : '（扫描中…）';
  } catch (e) { $('#tree').textContent = '加载失败'; }
}

async function refreshStatus() {
  try {
    const s = await api('/api/status');
    $('#ver').textContent = s.version || '';
    const agent = s.agent_ready ? ('Agent: ' + (s.provider || '?') + ' ✓') : 'Agent: 未就绪';\n    $('#status').textContent = (s.ssh ? 'SSH ✓ ' : 'SSH ✗ ') + agent;
  } catch (e) {}
}

async function refreshProviders() {
  try {
    const p = await api('/api/providers');
    const list = $('#prov-list');
    list.innerHTML = '';
    (p.providers || []).forEach((pr) => {
      const active = p.active === pr.name;
      const div = document.createElement('div');
      div.className = 'node';
      const tag = active ? ' <span class="badge">当前</span>' : '';
      const keyTag = pr.has_key ? '<span class="dim" style="color:#9fe8a9"> Key ✓</span>' : '<span class="dim" style="color:#f0b429"> Key ✗</span>';
      div.innerHTML = '<span class="' + (active ? 'gw' : 'host') + '">' + escapeHtml(pr.name) + '</span>' + tag + keyTag +
        '<div class="dim" style="margin-left:12px;word-break:break-all">' + escapeHtml(pr.base_url) + escapeHtml(pr.endpoint) + ' · ' + escapeHtml(pr.model) + '</div>';
      const btns = document.createElement('div');
      btns.className = 'row';
      const bUse = document.createElement('button');
      bUse.textContent = '设为当前';
      bUse.onclick = () => api('/api/provider/active', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name: pr.name})}).then(refreshProviders).then(refreshStatus);
      const bDel = document.createElement('button');
      bDel.textContent = '删除';
      bDel.onclick = () => api('/api/provider/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name: pr.name})}).then(refreshProviders);
      btns.appendChild(bUse); btns.appendChild(bDel);
      div.appendChild(btns);
      list.appendChild(div);
    });
  } catch (e) {}
}

async function refreshCreds() {
  try {
    const list = await api('/api/credentials');
    const sel = $('#exec-cred');
    const cur = sel.value;
    sel.innerHTML = '<option value="">（选择凭据）</option>';
    const ul = $('#cred-list');
    ul.innerHTML = '';
    list.forEach((c) => {
      const o = document.createElement('option');
      o.value = c.id;
      o.textContent = c.label + ' (' + c.type + ')';
      sel.appendChild(o);
      const li = document.createElement('li');
      li.textContent = '[' + c.id + '] ' + c.label + ' · ' + c.type + ' · ' + (c.target || '—');
      ul.appendChild(li);
    });
    if (cur) sel.value = cur;
  } catch (e) {}
}

let currentConfirm = null;

async function refreshConfirmations() {
  try {
    const list = await api('/api/confirmations');
    if (list.length > 0 && !currentConfirm) {
      currentConfirm = list[0];
      showModal(currentConfirm);
    }
  } catch (e) {}
}

function showModal(c) {
  $('#modal-level').textContent = '等级：' + (c.level === 2 ? '高危' : (c.level === 1 ? '可写' : '只读'));
  $('#modal-summary').textContent = c.summary || '';
  $('#modal').classList.remove('hidden');
}
function hideModal() { $('#modal').classList.add('hidden'); currentConfirm = null; }

async function pollJob(id, sink) {
  for (;;) {
    try {
      const j = await api('/api/job/' + id);
      if (j.status === 'done' || j.status === 'failed') {
        sink.textContent = (j.status === 'failed' ? '[失败] ' + (j.error || '') + '\n' : '') + (j.result || '');
        return;
      }
    } catch (e) { sink.textContent = '轮询失败'; return; }
    await new Promise((r) => setTimeout(r, 800));
  }
}

async function decide(approve) {
  if (!currentConfirm) return;
  const id = currentConfirm.id;
  hideModal();
  const r = await api('/api/confirm', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id, approve}),
  });
  if (approve && r.job_id) {
    $('#exec-out').textContent = '执行中…';
    pollJob(r.job_id, $('#exec-out'));
  } else {
    $('#exec-out').textContent = '已拒绝';
  }
}

$('#btn-approve').addEventListener('click', () => decide(true));
$('#btn-deny').addEventListener('click', () => decide(false));

$('#btn-rescan').addEventListener('click', async () => {
  $('#tree').textContent = '扫描中…';
  await api('/api/discover', {method: 'POST'});
  setTimeout(refreshTopology, 2500);
});

$('#btn-exec').addEventListener('click', async () => {
  const mode = $('#exec-mode').value;
  const payload = {
    mode,
    command: $('#exec-cmd').value,
    escalate: $('#exec-sudo').checked,
  };
  if (mode === 'remote') {
    payload.ip = $('#exec-ip').value;
    payload.cred_id = $('#exec-cred').value;
    if (!payload.ip) { alert('请输入远程 IP'); return; }
  }
  const r = await api('/api/exec', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
  });
  $('#exec-out').textContent = '已提交，等待人工确认…';
});

$('#btn-agent').addEventListener('click', async () => {
  const req = $('#agent-req').value.trim();
  if (!req) return;
  $('#agent-out').textContent = 'Agent 思考中…';
  const r = await api('/api/agent', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({requirement: req}),
  });
  pollJob(r.job_id, $('#agent-out'));
});

$('#btn-prov').addEventListener('click', async () => {
  const payload = {
    name: $('#prov-name').value.trim(),
    base_url: $('#prov-base').value.trim(),
    endpoint: $('#prov-endpoint').value.trim(),
    model: $('#prov-model').value.trim(),
  };
  if (!payload.name || !payload.base_url || !payload.endpoint) { alert('请填写名称/调用地址/请求地址'); return; }
  await api('/api/providers', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  refreshProviders(); refreshStatus();
});

$('#btn-prov-key').addEventListener('click', async () => {
  const name = $('#prov-key-name').value.trim();
  const key = $('#prov-key').value.trim();
  if (!name || !key) { alert('请填写提供方名与 API Key'); return; }
  await api('/api/provider/key', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, api_key: key})});
  $('#prov-key').value = '';
  refreshProviders(); refreshStatus();
});

$('#btn-cred').addEventListener('click', async () => {
  const payload = {
    label: $('#cred-label').value,
    type: $('#cred-type').value,
    target: $('#cred-target').value,
    username: $('#cred-user').value,
    secret: $('#cred-secret').value,
  };
  if (!payload.secret) { alert('请输入密码/密钥'); return; }
  const r = await api('/api/credentials', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
  });
  $('#cred-secret').value = '';
  refreshCreds();
});

(async function init() {
  refreshStatus();
  refreshTopology();
  refreshCreds();
  refreshProviders();
  setInterval(refreshProviders, 8000);
  setInterval(refreshTopology, 5000);
  setInterval(refreshConfirmations, 2000);
})();
