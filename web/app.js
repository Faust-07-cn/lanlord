const $ = (s) => document.querySelector(s);

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || r.status); }
  return r.json();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

/* ================= Graph rendering ================= */

let gTopo = null;
let gCreds = [];

const NS = 'http://www.w3.org/2000/svg';
const NODE_W = 180, NODE_H = 34;
const LEVEL_GAP = 92;   /* vertical space between levels (top-down) */
const SLOT = 212;       /* horizontal column per leaf */
const ICONS = { root:'🏠', subnet:'🌐', gateway:'📡', upstream:'⬆️', switch:'🔀', ap:'📶', host:'💻', container:'📦', unknown:'·' };
const COLORS = { root:'#5a6478', subnet:'#3a6fb0', gateway:'#d99a2b', upstream:'#d99a2b', switch:'#cc6a3a', ap:'#3fa6d9', host:'#3fae6a', container:'#9a63c7', unknown:'#5a6478' };

function initExp(n) {
  if (n._expanded === undefined) n._expanded = true;
  (n.children || []).forEach(initExp);
}

function estTextWidth(s) {
  let w = 0;
  for (const ch of String(s || '')) w += (ch.charCodeAt(0) > 0xFF ? 12.2 : 6.8);
  return w;
}

/* 滚动字幕：仅当鼠标悬停在节点上时滚动，移开即停并复位 */
let marquee = null;
function startMarquee(t, TX, scroll) {
  stopMarquee();
  marquee = { t, TX, scroll, x: TX, dir: -1, timer: setInterval(() => {
    marquee.x += marquee.dir * 1.5;
    if (marquee.x <= TX - scroll) marquee.dir = 1;
    else if (marquee.x >= TX) marquee.dir = -1;
    marquee.t.setAttribute('x', marquee.x);
  }, 16) };
}
function stopMarquee() {
  if (marquee) { clearInterval(marquee.timer); marquee.t.setAttribute('x', marquee.TX); marquee = null; }
}

/* Top-down tidy tree: root at top, depth increases downward, leaves spread horizontally. */
function layoutTree(n, depth, leaf) {
  n._depth = depth;
  if (!n._expanded || !n.children || !n.children.length) { n._x = leaf.index++ * SLOT; return; }
  n.children.forEach((c) => layoutTree(c, depth + 1, leaf));
  n._x = (n.children[0]._x + n.children[n.children.length - 1]._x) / 2;
}

function renderGraph() {
  const box = $('#tree');
  box.innerHTML = '';
  if (!gTopo) { box.textContent = '扫描中…'; return; }
  initExp(gTopo);

  const leaf = { index: 0 };
  layoutTree(gTopo, 0, leaf);

  let maxDepth = 0, maxX = 0;
  (function walk(n) {
    if (n._depth > maxDepth) maxDepth = n._depth;
    if (n._x > maxX) maxX = n._x;
    (n.children || []).forEach(walk);
  })(gTopo);

  const w = Math.ceil(maxX) + SLOT + 40;
  const h = (maxDepth + 1) * LEVEL_GAP + 60;
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('width', w);
  svg.setAttribute('height', h);
  svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
  svg.style.display = 'block';

  const defs = document.createElementNS(NS, 'defs');
  svg.appendChild(defs);
  let clipSeq = 0;

  const centerX = (n) => n._x + SLOT / 2;
  const topY = (n) => n._depth * LEVEL_GAP;
  const bottomY = (n) => n._depth * LEVEL_GAP + NODE_H;

  function edges(n) {
    if (!n._expanded || !n.children) return;
    const px = centerX(n), py = bottomY(n) + 4;
    n.children.forEach((c) => {
      const qx = centerX(c), qy = topY(c);
      const my = (py + qy) / 2;
      const p = document.createElementNS(NS, 'path');
      p.setAttribute('d', 'M' + px + ' ' + py + ' C' + px + ' ' + my + ' ' + qx + ' ' + my + ' ' + qx + ' ' + qy);
      p.setAttribute('stroke', '#2a3550'); p.setAttribute('stroke-width', '1.5'); p.setAttribute('fill', 'none');
      svg.appendChild(p);
      edges(c);
    });
  }
  edges(gTopo);

  function nodes(n) {
    const x = centerX(n) - NODE_W / 2, y = topY(n) + 4;
    const g = document.createElementNS(NS, 'g');
    g.setAttribute('cursor', 'pointer');
    const r = document.createElementNS(NS, 'rect');
    r.setAttribute('x', x); r.setAttribute('y', y);
    r.setAttribute('width', NODE_W); r.setAttribute('height', NODE_H);
    r.setAttribute('rx', 8);
    r.setAttribute('fill', COLORS[n.type] || '#5a6478'); r.setAttribute('stroke', '#0b0e14');
    g.appendChild(r);
    const ic = document.createElementNS(NS, 'text');
    ic.setAttribute('x', x + 7); ic.setAttribute('y', y + 24);
    ic.setAttribute('font-size', '15'); ic.setAttribute('fill', '#0b0e14');
    ic.textContent = ICONS[n.type] || '·';
    g.appendChild(ic);
    const fullLabel = n.label || n.id || '';
    const TX = x + 31, TY = y + 24;
    const TEXT_W = NODE_W - 31 - 8;
    const t = document.createElementNS(NS, 'text');
    t.setAttribute('x', TX); t.setAttribute('y', TY);
    t.setAttribute('fill', '#0b0e14'); t.setAttribute('font-size', '12'); t.setAttribute('font-weight', '600');
    t.textContent = fullLabel;
    if (estTextWidth(fullLabel) > TEXT_W) {
      const cid = 'cl' + (clipSeq++);
      const cp = document.createElementNS(NS, 'clipPath');
      cp.setAttribute('id', cid);
      const cr = document.createElementNS(NS, 'rect');
      cr.setAttribute('x', TX - 3); cr.setAttribute('y', TY - 13);
      cr.setAttribute('width', TEXT_W + 6); cr.setAttribute('height', 18);
      cp.appendChild(cr);
      defs.appendChild(cp);
      t.setAttribute('clip-path', 'url(#' + cid + ')');
      const scroll = estTextWidth(fullLabel) - TEXT_W + 28;
      g.addEventListener('mouseenter', () => startMarquee(t, TX, scroll));
      g.addEventListener('mouseleave', stopMarquee);
    }
    g.appendChild(t);
    const title = document.createElementNS(NS, 'title');
    title.textContent = (n.type || '') + '\n' + [n.ip, n.mac, n.vendor, n.status].filter(Boolean).join('  ');
    g.appendChild(title);
    g.addEventListener('click', (e) => { e.stopPropagation(); onNodeClick(n); });
    svg.appendChild(g);
    if (n._expanded && n.children) n.children.forEach(nodes);
  }
  nodes(gTopo);
  box.appendChild(svg);
}

let dockerTarget = null;

function openDockerModal(n) {
  dockerTarget = n;
  $('#docker-ip').textContent = '目标设备：' + (n.ip || n.label || '');
  $('#docker-user').value = '';
  $('#docker-pass').value = '';
  $('#docker-modal').classList.remove('hidden');
}
function closeDockerModal() { $('#docker-modal').classList.add('hidden'); dockerTarget = null; }

/* 该设备是否已有持久化凭据（服务端 DPAPI vault），有则无需再次输入密码 */
function hasStoredCred(ip) {
  return !!ip && gCreds.some((c) => (c.target || '').trim() === ip);
}

function applyDockerNodes(n, list) {
  if (list && list.length) {
    n.children = list.map((c) => ({ type:'container', label: (c.names || c.id || '?') + '  ' + (c.image || ''), status: c.status, ip:'', vendor:'' }));
  } else {
    n.children = [{ type:'container', label:'（无运行中的容器）', ip:'', vendor:'' }];
  }
  n._fetched = true;
  n._expanded = true;
}

/* 拉取 Docker 容器。extra 可带 username/password（首次输入）或 cred_id。 */
async function loadDocker(n, extra) {
  n._loading = true;
  n._expanded = true;
  renderGraph();
  let failed = null;
  try {
    const body = Object.assign({ ip: n.ip }, extra || {});
    const list = await api('/api/device/docker', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    applyDockerNodes(n, list);
  } catch (e) {
    failed = String(e.message || '获取失败').split('\n')[0].slice(0, 120);
  }
  n._loading = false;
  if (failed) {
    /* 失败时清空并复位，允许重试；已保存凭据失效则回退到手动输入密码 */
    n.children = [];
    n._fetched = false;
    n._expanded = false;
    renderGraph();
    if (!extra) openDockerModal(n);
    else alert('获取容器失败：' + failed);
    return;
  }
  renderGraph();
}

function onNodeClick(n) {
  const isHost = n.type === 'host' || n.type === 'ap';
  if (isHost && (!n.children || !n.children.length)) {
    if (n._loading) return;
    if (hasStoredCred(n.ip)) { loadDocker(n); return; }  /* 已有持久化凭据，直接拉取 */
    openDockerModal(n);
    return;
  }
  n._expanded = !n._expanded;
  renderGraph();
}

/* 持久化前端状态：每 60s 的拓扑刷新会用最新数据替换 gTopo，
   若直接替换会丢失用户已展开/已拉取 Docker 容器的节点，迫使用户反复输入密码。
   这里把旧树上的展开/拉取状态按 ip（或 label+type）合并到新树上。 */
function mergeState(oldN, newN) {
  if (!newN) return newN;
  if (oldN) {
    if (oldN._expanded !== undefined) newN._expanded = oldN._expanded;
    if (oldN._loading) newN._loading = oldN._loading;
    if (oldN._fetched && oldN.children && oldN.children.length) {
      newN._fetched = true;
      newN._expanded = true;
      newN.children = oldN.children;
      return newN;
    }
  }
  if (newN.children) {
    const oldKids = (oldN && oldN.children) || [];
    newN.children.forEach((nc) => {
      const oc = oldKids.find((c) => (c.ip && nc.ip && c.ip === nc.ip) ||
                                     (c.label === nc.label && c.type === nc.type));
      if (oc) mergeState(oc, nc);
    });
  }
  return newN;
}

let topoRetry = 0;
async function refreshTopology() {
  try {
    const t = await api('/api/topology');
    const hasData = t && t.children && t.children.length;
    if (hasData) { gTopo = mergeState(gTopo, t); topoRetry = 0; renderGraph(); return; }
    /* 扫描尚未完成：显示扫描中，并短间隔重试（有界），直到拿到数据 */
    if (!gTopo) {
      $('#tree').textContent = '扫描中…';
      if (topoRetry < 30) { topoRetry++; setTimeout(refreshTopology, 2000); }
      else { $('#tree').textContent = '未发现设备'; }
    }
  } catch (e) { $('#tree').textContent = '加载失败'; }
}

/* ================= status / providers / creds ================= */

async function refreshStatus() {
  try {
    const s = await api('/api/status');
    $('#ver').textContent = s.version || '';
    const agent = s.agent_ready ? ('Agent: ' + (s.provider || '?') + ' ✓') : 'Agent: 未就绪';
    $('#status').textContent = (s.ssh ? 'SSH ✓ ' : 'SSH ✗ ') + agent;
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

async function refreshVendors() {
  try {
    const list = await api('/api/vendors');
    const sel = $('#prov-vendor');
    sel.innerHTML = '<option value="">— 选择供应商（预设）—</option>';
    (list || []).forEach((v) => {
      const o = document.createElement('option');
      o.value = v.name;
      o.textContent = v.label + ' (' + v.name + ')';
      o.dataset.base = v.base_url || '';
      o.dataset.endpoint = v.endpoint || '';
      o.dataset.model = v.default_model || '';
      sel.appendChild(o);
    });
  } catch (e) {}
}

async function refreshCreds() {
  try {
    const list = await api('/api/credentials');
    gCreds = list;
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

/* ================= confirmations / exec / agent ================= */

let currentConfirm = null;

async function refreshConfirmations() {
  try {
    const list = await api('/api/confirmations');
    if (list.length > 0 && !currentConfirm) { currentConfirm = list[0]; showModal(currentConfirm); }
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
  const r = await api('/api/confirm', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id, approve}) });
  if (approve && r.job_id) { $('#exec-out').textContent = '执行中…'; pollJob(r.job_id, $('#exec-out')); }
  else { $('#exec-out').textContent = '已拒绝'; }
}

/* ================= event wiring ================= */

$('#btn-approve').addEventListener('click', () => decide(true));
$('#btn-deny').addEventListener('click', () => decide(false));

$('#btn-rescan').addEventListener('click', async () => {
  $('#tree').textContent = '扫描中…';
  await api('/api/discover', {method: 'POST'});
  setTimeout(refreshTopology, 2500);
});

function openSettings() { $('#settings-drawer').classList.add('open'); $('#drawer-backdrop').classList.remove('hidden'); }
function closeSettings() { $('#settings-drawer').classList.remove('open'); $('#drawer-backdrop').classList.add('hidden'); }
$('#btn-settings').addEventListener('click', openSettings);
$('#btn-settings-close').addEventListener('click', closeSettings);
$('#drawer-backdrop').addEventListener('click', closeSettings);

$('#btn-docker-cancel').addEventListener('click', closeDockerModal);
$('#btn-docker-ok').addEventListener('click', async () => {
  const n = dockerTarget;
  if (!n) return;
  const username = $('#docker-user').value.trim();
  const password = $('#docker-pass').value.trim();
  if (!username || !password) { alert('请输入用户名与密码'); return; }
  closeDockerModal();
  await loadDocker(n, { username, password });
  refreshCreds();  /* 服务端已把本次凭据 DPAPI 持久化，刷新凭据列表 */
});

$('#prov-vendor').addEventListener('change', () => {
  const o = $('#prov-vendor').selectedOptions[0];
  if (!o || !o.value) return;
  $('#prov-name').value = o.value;
  $('#prov-base').value = o.dataset.base || '';
  $('#prov-endpoint').value = o.dataset.endpoint || '';
  $('#prov-model').value = o.dataset.model || '';
});

$('#btn-prov-models').addEventListener('click', async () => {
  const key = $('#prov-key').value.trim();
  if (!key) { alert('请先填写 API Key'); return; }
  const payload = { api_key: key, base_url: $('#prov-base').value.trim() };
  const name = $('#prov-name').value.trim();
  if (name) payload.name = name;
  $('#btn-prov-models').textContent = '获取中…';
  try {
    const models = await api('/api/provider/models', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    const dl = $('#model-list'); dl.innerHTML = '';
    (models || []).forEach((m) => { const o = document.createElement('option'); o.value = m; dl.appendChild(o); });
    if (models && models.length) $('#prov-model').value = models[0];
    alert('已获取 ' + (models ? models.length : 0) + ' 个模型');
  } catch (e) { alert('获取模型失败（检查 API Key 与地址）'); }
  $('#btn-prov-models').textContent = '一键获取模型';
});

$('#btn-prov').addEventListener('click', async () => {
  const name = $('#prov-name').value.trim();
  const base = $('#prov-base').value.trim();
  const ep = $('#prov-endpoint').value.trim();
  const model = $('#prov-model').value.trim();
  const key = $('#prov-key').value.trim();
  if (!name || !base || !ep) { alert('请填写名称/调用地址/请求地址'); return; }
  await api('/api/providers', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, base_url: base, endpoint: ep, model})});
  if (key) await api('/api/provider/key', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, api_key: key})});
  $('#prov-key').value = '';
  refreshProviders(); refreshStatus();
  alert('已保存并自动填充配置');
});

$('#btn-exec').addEventListener('click', async () => {
  const mode = $('#exec-mode').value;
  const payload = { mode, command: $('#exec-cmd').value, escalate: $('#exec-sudo').checked };
  if (mode === 'remote') {
    payload.ip = $('#exec-ip').value;
    payload.cred_id = $('#exec-cred').value;
    if (!payload.ip) { alert('请输入远程 IP'); return; }
  }
  const r = await api('/api/exec', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  $('#exec-out').textContent = '已提交，等待人工确认…';
});

$('#btn-agent').addEventListener('click', async () => {
  const req = $('#agent-req').value.trim();
  if (!req) return;
  $('#agent-out').textContent = 'Agent 思考中…';
  const r = await api('/api/agent', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({requirement: req}) });
  pollJob(r.job_id, $('#agent-out'));
});

$('#btn-cred').addEventListener('click', async () => {
  const payload = {
    label: $('#cred-label').value, type: $('#cred-type').value, target: $('#cred-target').value,
    username: $('#cred-user').value, secret: $('#cred-secret').value,
  };
  if (!payload.secret) { alert('请输入密码/密钥'); return; }
  await api('/api/credentials', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  $('#cred-secret').value = '';
  refreshCreds();
});

(async function init() {
  refreshStatus();
  refreshTopology();
  refreshCreds();
  refreshProviders();
  refreshVendors();
  setInterval(refreshProviders, 8000);
  setInterval(refreshTopology, 60000);
  setInterval(refreshConfirmations, 2000);
})();
