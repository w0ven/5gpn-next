'use strict';

// 5gpn-NEXT 管理面板前端。零依赖、无框架，避免给网关引入额外供应链。

const $ = (id) => document.getElementById(id);
let currentStatus = null;

// ---------- 通用 ----------

function toast(msg, isErr) {
  const node = $('toast');
  node.textContent = msg;
  node.className = 'toast' + (isErr ? ' toast-err' : '');
  node.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { node.hidden = true; }, isErr ? 5000 : 2800);
}

async function api(path, opts) {
  const res = await fetch(path, Object.assign({
    headers: { 'Content-Type': 'application/json' },
  }, opts || {}));
  let data = null;
  try { data = await res.json(); } catch (_) { /* 忽略非 JSON 响应 */ }
  if (!res.ok) {
    throw new Error((data && data.error) || ('请求失败 ' + res.status));
  }
  return data;
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function number(value) {
  return Number(value || 0).toLocaleString('zh-CN');
}

function relativeTime(ts) {
  if (!ts) return '—';
  const delta = Math.max(0, Math.floor(Date.now() / 1000) - Number(ts));
  if (delta < 10) return '刚刚';
  if (delta < 60) return delta + ' 秒前';
  if (delta < 3600) return Math.floor(delta / 60) + ' 分钟前';
  if (delta < 86400) return Math.floor(delta / 3600) + ' 小时前';
  return new Date(Number(ts) * 1000).toLocaleString('zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

// ---------- 状态 ----------

const COUNTER_LABELS = {
  dns_query: 'DNS 查询',
  dns_direct: 'DNS 直连',
  dns_proxy: 'DNS 改写',
  dns_block: '规则命中',
  connect: 'DNS 查询',       // 兼容旧运行态键名
  blocked: '规则命中',
  handled: '接管连接',
  dial_fail: '拨号失败',
  no_host: '目标未知',
  hinted: 'DNS 线索回退',
  v6_fastfail: 'IPv6 回落',
};

function renderStatus(st) {
  currentStatus = st;
  const grid = $('stat-grid');
  grid.textContent = '';

  const items = [
    ['运行时长', st.uptime || '—'],
    ['监听地址', st.listen || '—'],
    ['策略规则', number(st.rules) + ' 条'],
    ['运行内存', Number(st.memory_mb || 0).toFixed(1) + ' MB'],
  ];
  if (st.cert_until) items.push(['证书有效至', st.cert_until]);

  const counters = st.counters || {};
  const preferredKeys = ['dns_query', 'dns_block', 'dial_fail', 'hinted'];
  const legacyKeys = ['connect', 'blocked', 'v6_fastfail'];
  for (const key of preferredKeys) {
    if (key in counters) items.push([COUNTER_LABELS[key] || key, number(counters[key])]);
  }
  for (const key of legacyKeys) {
    if (items.length >= 8) break;
    if (key in counters && !((key === 'connect' && 'dns_query' in counters) || (key === 'blocked' && 'dns_block' in counters))) {
      items.push([COUNTER_LABELS[key] || key, number(counters[key])]);
    }
  }

  for (const [label, value] of items) {
    const box = el('div', 'stat');
    box.appendChild(el('span', 'stat-label', label));
    box.appendChild(el('span', 'stat-value', value));
    grid.appendChild(box);
  }

  const ad = st.ad_block || {};
  const hits = ad.hits || {};
  $('hero-uptime').textContent = st.uptime || '运行中';
  $('hero-dns').textContent = number(counters.dns_query !== undefined ? counters.dns_query : counters.connect);
  $('hero-blocked').textContent = number(hits.today);
  const activeEgress = (st.egress || []).find((item) => item.current);
  $('hero-egress').textContent = activeEgress ? (activeEgress.display || activeEgress.name) : 'DIRECT';

  renderAdBlock(ad);
  renderEgress(st.egress || [], st.domestic_ready);
}

function renderAdBlock(ad) {
  const hits = ad.hits || {};
  $('ad-today').textContent = number(hits.today);
  $('ad-total').textContent = number(hits.total);
  $('ad-domains').textContent = number(ad.domains);
  $('ad-allow-count').textContent = number(ad.allowlist);

  const toggle = $('adblock-toggle');
  toggle.disabled = false;
  toggle.dataset.enabled = ad.enabled ? 'true' : 'false';
  toggle.textContent = ad.enabled ? '● 已开启' : '○ 已关闭';
  toggle.className = 'btn btn-state ' + (ad.enabled ? 'btn-on' : 'btn-off');

  renderAdTrend(hits.daily || [], ad);
  renderAdExtras(ad.extras || [], ad.enabled);

  const recent = $('ad-recent');
  recent.textContent = '';
  const events = hits.recent || [];
  if (!events.length) {
    recent.appendChild(el('p', 'empty', ad.enabled ? '暂无成功拦截，等待首次命中。' : '开启后将在这里显示成功命中。'));
  } else {
    events.slice(0, 12).forEach((event) => {
      const row = el('div', 'hit-row');
      const main = el('div', 'hit-main');
      main.appendChild(el('span', 'hit-mark', '↳'));
      main.appendChild(el('code', 'hit-host', event.host));
      row.appendChild(main);
      row.appendChild(el('time', 'hit-time', relativeTime(event.at)));
      recent.appendChild(row);
    });
  }

  const top = $('ad-top');
  top.textContent = '';
  const domains = hits.top || [];
  if (!domains.length) {
    top.appendChild(el('p', 'empty', '暂无高频域名统计。'));
  } else {
    const max = Math.max(1, Number(domains[0].count || 0));
    domains.slice(0, 8).forEach((item, index) => {
      const row = el('div', 'top-row');
      const meta = el('div', 'top-meta');
      meta.appendChild(el('span', 'top-rank', String(index + 1).padStart(2, '0')));
      meta.appendChild(el('code', 'hit-host', item.host));
      meta.appendChild(el('strong', 'top-count', number(item.count)));
      row.appendChild(meta);
      const track = el('div', 'top-track');
      const fill = el('i', 'top-fill');
      fill.style.width = Math.max(4, Number(item.count || 0) / max * 100) + '%';
      track.appendChild(fill);
      row.appendChild(track);
      top.appendChild(row);
    });
  }

  const allowBox = $('ad-allow-list');
  allowBox.textContent = '';
  const allow = ad.allow_domains || [];
  if (!allow.length) {
    allowBox.appendChild(el('span', 'empty', '暂无白名单'));
  } else {
    allow.forEach((domain, index) => {
      const chip = el('span', 'allow-chip');
      chip.appendChild(el('code', null, domain));
      const rm = el('button', null, '×');
      rm.type = 'button';
      rm.title = '移除 ' + domain;
      rm.setAttribute('aria-label', '移除白名单 ' + domain);
      rm.onclick = () => adBlockAction('remove_allow', { index, domain });
      chip.appendChild(rm);
      allowBox.appendChild(chip);
    });
  }
}

function renderAdTrend(days, ad) {
  const box = $('ad-trend');
  box.textContent = '';
  const top = Math.max(1, ...days.map((d) => Number(d.count || 0)));
  days.forEach((d) => {
    const col = el('div', 'trend-col');
    col.title = d.date + '：' + number(d.count) + ' 次';
    const bar = el('i', 'trend-bar');
    bar.style.height = (d.count ? Math.max(6, Number(d.count) / top * 100) : 2) + '%';
    col.appendChild(bar);
    col.appendChild(el('span', 'trend-day', String(Number(d.date.slice(8)))));
    box.appendChild(col);
  });
  const meta = [];
  meta.push('近 7 天 ' + number((ad.hits || {}).days7) + ' 次');
  if (ad.updated_at) meta.push('anti-AD 规则 ' + relativeTime(ad.updated_at) + '更新');
  const on = (ad.extras || []).filter((x) => x.enabled).map((x) => x.name);
  if (on.length) meta.push('附加：' + on.join('、'));
  $('ad-meta').textContent = meta.join(' · ');
}

function renderAdExtras(extras, enabled) {
  const box = $('ad-extras');
  box.textContent = '';
  extras.forEach((x) => {
    const item = el('button', 'extra-item' + (x.enabled ? ' on' : ''));
    item.type = 'button';
    item.setAttribute('aria-pressed', x.enabled ? 'true' : 'false');
    const head = el('span', 'extra-head');
    head.appendChild(el('span', 'extra-dot'));
    head.appendChild(el('strong', null, x.name));
    if (x.enabled && x.domains) head.appendChild(el('small', null, number(x.domains) + ' 条'));
    item.appendChild(head);
    item.appendChild(el('span', 'extra-desc', x.desc));
    if (x.warn) item.appendChild(el('span', 'extra-warn', '⚠ ' + x.warn));
    item.onclick = async () => {
      item.disabled = true;
      await adBlockAction('extra', { key: x.key, enabled: !x.enabled });
      item.disabled = false;
    };
    box.appendChild(item);
  });
  if (!enabled) box.appendChild(el('p', 'empty', '广告拦截未开启，勾选的列表会在开启后生效。'));
}

async function loadAdSuspects() {
  const box = $('ad-suspects');
  try {
    const data = await api('/api/adblock');
    const list = data.suspects || [];
    box.textContent = '';
    if (!list.length) {
      box.appendChild(el('p', 'empty', '暂时没有发现。手机正常使用一段时间后再来看；网关重启后会重新积累。'));
      return;
    }
    list.forEach((s) => {
      const row = el('div', 'hit-row');
      const main = el('div', 'hit-main');
      main.appendChild(el('code', 'hit-host', s.host));
      main.appendChild(el('span', 'hit-time', '×' + number(s.count) + ' · ' + relativeTime(s.last_at)));
      row.appendChild(main);
      const btn = el('button', 'btn btn-sm btn-danger', '拦截');
      btn.type = 'button';
      btn.onclick = async () => {
        btn.disabled = true;
        await adBlockAction('block', { domain: s.host });
        loadAdSuspects();
      };
      row.appendChild(btn);
      box.appendChild(row);
    });
  } catch (err) {
    box.textContent = '';
    box.appendChild(el('p', 'empty warning', err.message));
  }
}

async function adBlockAction(action, extra) {
  try {
    const data = await api('/api/adblock', {
      method: 'POST',
      body: JSON.stringify(Object.assign({ action }, extra || {})),
    });
    if (data.status) renderStatus(data.status);
    toast(data.message || '广告拦截设置已更新');
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- 出口 ----------

function renderEgress(list, domesticReady) {
  const box = $('egress-list');
  box.textContent = '';

  if (domesticReady === false) {
    box.appendChild(el('p', 'empty warning', '注意：国内规则未就绪，系统已安全回落到本机直连，暂不允许切换代理出口。'));
  }
  if (!list.length) {
    box.appendChild(el('p', 'empty', '暂无出口'));
    return;
  }

  for (const e of list) {
    const row = el('div', 'row');
    const main = el('div', 'row-main');
    const title = el('div', 'row-title');
    title.appendChild(el('span', null, e.display || e.name));
    if (e.current) title.appendChild(el('span', 'tag tag-current', '当前国外出口'));
    title.appendChild(el('span', 'tag', e.type));
    main.appendChild(title);
    if (e.server) main.appendChild(el('div', 'row-sub', e.server));
    row.appendChild(main);

    const acts = el('div', 'row-actions');
    if (!e.current) {
      const sw = el('button', 'btn btn-sm', '设为默认');
      sw.onclick = () => egressAction('switch', { name: e.name });
      acts.appendChild(sw);
    }
    const test = el('button', 'btn btn-sm', '测试');
    test.onclick = () => egressAction('test', { name: e.name });
    acts.appendChild(test);
    if (e.name !== 'DIRECT') {
      const rm = el('button', 'btn btn-sm btn-danger', '删除');
      rm.onclick = () => {
        if (confirm('确定删除出口 ' + e.name + '？')) egressAction('remove', { name: e.name });
      };
      acts.appendChild(rm);
    }
    row.appendChild(acts);
    box.appendChild(row);
  }
}

async function loadStatus() {
  try {
    renderStatus(await api('/api/status'));
  } catch (err) {
    toast(err.message, true);
  }
}

async function egressAction(action, extra) {
  try {
    const data = await api('/api/egress', {
      method: 'POST',
      body: JSON.stringify(Object.assign({ action }, extra)),
    });
    toast(data.message || '操作完成');
    if (data.status) renderStatus(data.status);
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- 规则 ----------

function renderRules(data) {
  const box = $('rules-list');
  box.textContent = '';
  const rules = data.rules || [];
  const pre = data.builtin_pre || [];
  const post = data.builtin_post || [];

  pre.forEach((rule) => box.appendChild(builtinRow(rule, '内置 · 优先')));
  if (!rules.length) {
    box.appendChild(el('p', 'empty', '暂无自定义规则。国内直连、国外走出口已由内置策略完成。'));
  }
  const problems = data.problems || {};
  rules.forEach((rule, index) => {
    const row = el('div', 'row');
    row.appendChild(el('span', 'rule-index', String(index + 1)));
    const main = el('div', 'row-main');
    main.appendChild(el('div', 'rule-text', rule));
    if (problems[index]) {
      main.appendChild(el('div', 'rule-problem', '不生效：' + problems[index]));
    }
    row.appendChild(main);
    const acts = el('div', 'row-actions');
    const rm = el('button', 'btn btn-sm btn-danger', '删除');
    rm.onclick = async () => {
      if (!confirm('确认删除这条规则？\n\n' + rule)) return;
      try {
        await api('/api/rules?index=' + index + '&rule=' + encodeURIComponent(rule), { method: 'DELETE' });
        await loadRules();
        toast('规则已删除');
      } catch (err) {
        toast(err.message, true);
      }
    };
    acts.appendChild(rm);
    row.appendChild(acts);
    box.appendChild(row);
  });
  post.forEach((rule) => box.appendChild(builtinRow(rule, '内置 · 兜底')));
}

function builtinRow(rule, label) {
  const row = el('div', 'row row-builtin');
  row.appendChild(el('span', 'rule-index', '内'));
  const main = el('div', 'row-main');
  main.appendChild(el('div', 'rule-text', rule));
  row.appendChild(main);
  const acts = el('div', 'row-actions');
  acts.appendChild(el('span', 'builtin-tag', label));
  row.appendChild(acts);
  return row;
}

async function loadRules() {
  try {
    renderRules(await api('/api/rules'));
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- 应用分流 ----------

let egressNames = {};

function appSub(a) {
  if (!a.egress) return el('div', 'app-sub', '跟随默认规则');
  if (!a.list_domains) {
    return el('div', 'app-sub app-warn', '清单尚未下载，先用内置 ' + a.core + ' 个核心域名');
  }
  return el('div', 'app-sub', '清单 ' + number(a.list_domains) + ' 条 + 内置 ' + a.core + ' 条');
}

function renderApps(data) {
  egressNames = {};
  for (const c of data.egress || []) egressNames[c.name] = c.display;
  const box = $('apps-grid');
  box.textContent = '';
  for (const a of data.apps || []) {
    const tile = el('div', 'app-tile' + (a.egress ? ' app-on' : ''));
    const logo = el('img', 'app-logo');
    logo.src = '/apps/' + a.key + '.webp';
    logo.alt = '';
    tile.appendChild(logo);
    const meta = el('div');
    meta.appendChild(el('div', 'app-name', a.name));
    meta.appendChild(appSub(a));
    tile.appendChild(meta);

    const ctl = el('div', 'app-ctl');
    const sel = el('select', 'app-select');
    sel.setAttribute('aria-label', a.name + ' 的出口');
    const opts = [['', '跟随默认']].concat((data.egress || []).map((c) => [c.name, c.display]));
    for (const [value, label] of opts) {
      const o = el('option', null, label);
      o.value = value;
      if (value === (a.egress || '')) o.selected = true;
      sel.appendChild(o);
    }
    sel.onchange = () => setApp(a, sel);
    ctl.appendChild(sel);
    if (a.egress) {
      const chk = el('button', 'btn btn-sm', '核对');
      chk.onclick = () => checkApp(a);
      ctl.appendChild(chk);
    }
    tile.appendChild(ctl);
    box.appendChild(tile);
  }
}

async function setApp(a, sel) {
  const egress = sel.value;
  sel.disabled = true;
  try {
    renderApps(await api('/api/apps', { method: 'POST', body: JSON.stringify({ key: a.key, egress }) }));
    toast(a.name + ' → ' + (egress ? (egressNames[egress] || egress) : '跟随默认'));
    if (!$('app-check').hidden) $('app-check').hidden = true;
  } catch (err) {
    toast(err.message, true);
    await loadApps();
  }
}

function windowText(r) {
  const minutes = Math.max(1, Math.round((Date.now() - Date.parse(r.since)) / 60000));
  const ago = minutes < 60 ? minutes + ' 分钟' : Math.round(minutes / 60) + ' 小时';
  if (r.since_kind === 'changed') return '改出口后 ' + ago;
  if (r.since_kind === 'started') return '网关启动后 ' + ago;
  return '最近 ' + ago;
}

function routeRows(box, list) {
  for (const r of list) {
    const row = el('div', 'check-row');
    const mark = r.blocked ? '⊘ ' : r.ok ? '✓ ' : '✗ ';
    const host = el('span', 'check-host' + (r.ok ? '' : ' bad'), mark + r.host);
    if (!r.ok && r.rule) host.appendChild(el('span', 'check-rule', r.rule));
    row.appendChild(host);
    row.appendChild(el('span', 'check-eg', r.blocked ? '广告拦截' : egressNames[r.egress] || r.egress));
    box.appendChild(row);
  }
}

function egressText(map) {
  return Object.entries(map)
    .sort((x, y) => y[1] - x[1])
    .map(([name, n]) => (egressNames[name] || name) + ' ×' + n)
    .join('、');
}

function checkRows(box, list) {
  for (const d of list) {
    const row = el('div', 'check-row');
    const host = el('span', 'check-host' + (d.ok ? '' : ' bad'), (d.ok ? '✓ ' : '✗ ') + d.host);
    if (!d.ok && d.rule) host.appendChild(el('span', 'check-rule', d.rule));
    row.appendChild(host);
    row.appendChild(el('span', 'check-eg', egressText(d.egresses)));
    box.appendChild(row);
  }
}

async function checkApp(a) {
  const box = $('app-check');
  box.hidden = false;
  box.textContent = '';
  box.appendChild(el('p', 'empty', '正在核对 ' + a.name + '…'));
  try {
    const r = await api('/api/apps/check?key=' + encodeURIComponent(a.key));
    box.textContent = '';
    box.appendChild(el('h3', null, a.name + ' · 选定 ' + r.egress_display));
    const current = r.current || [];
    if (current.length) {
      const blocked = current.filter((x) => x.blocked).length;
      box.appendChild(r.current_mismatch
        ? el('p', 'verdict bad', '按当前规则：' + r.current_mismatch + ' 个域名不走 ' + r.egress_display + '，灰字是命中的规则')
        : el('p', 'verdict', '按当前规则：' + (current.length - blocked) + ' 个域名全部走 ' + r.egress_display +
            (blocked ? '，' + blocked + ' 个广告域名被拦截' : '') + ' ✓'));
      routeRows(box, current);
    }
    const domains = r.domains || [];
    const suspects = r.suspects || [];
    box.appendChild(el('p', 'verdict', '实际连接 · ' + windowText(r)));
    if (!domains.length) {
      box.appendChild(el('p', 'empty', '还没有 ' + a.name + ' 的连接。手机走内网卡打开 ' + a.name + ' 用一会儿，再来核对。'));
    } else if (r.mismatch) {
      box.appendChild(el('p', 'verdict bad', r.mismatch + ' 个域名有连接没走 ' + r.egress_display + '，灰字是当时命中的规则'));
    } else {
      box.appendChild(el('p', 'verdict', domains.length + ' 个域名全部经 ' + r.egress_display + ' ✓'));
    }
    checkRows(box, domains);
    if (suspects.length) {
      box.appendChild(el('p', 'verdict bad', '疑似漏网：下面的域名带有 ' + a.name + ' 特征，但不在清单里，也没走 ' + r.egress_display));
      checkRows(box, suspects);
    }
  } catch (err) {
    box.textContent = '';
    box.appendChild(el('p', 'empty warning', err.message));
  }
}

async function loadApps() {
  try {
    renderApps(await api('/api/apps'));
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- 诊断 ----------

const STAGE_NAMES = {
  ingress: '入口', policy: '策略', egress: '出口',
  connect: '连接', app: '应用',
};
const STATUS_MARK = {
  ok: ['✓', 'probe-ok'], fail: ['✗', 'probe-err'],
  warn: ['!', 'probe-warn'], skipped: ['–', ''],
};

async function runProbe() {
  const target = $('probe-target').value.trim();
  if (!target) { toast('请输入要诊断的域名', true); return; }

  const btn = $('probe-run');
  const out = $('probe-out');
  btn.disabled = true;
  btn.textContent = '诊断中…';
  out.hidden = false;
  out.textContent = '正在诊断 ' + target + ' …';

  try {
    const data = await api('/api/probe?target=' + encodeURIComponent(target));
    out.textContent = '';
    (data.steps || []).forEach((step, index) => {
      const mark = STATUS_MARK[step.status] || ['?', ''];
      const line = el('span', 'probe-line ' + mark[1]);
      line.textContent = '[' + (index + 1) + '] ' + (STAGE_NAMES[step.stage] || step.stage) +
        '  ' + step.detail + '  ' + mark[0] + ' ' + Number(step.dur_ms || 0).toFixed(1) + 'ms';
      out.appendChild(line);
      if (step.err) out.appendChild(el('span', 'probe-line probe-err', '        └─ ' + step.err));
    });
    const verdict = el('span', 'probe-line ' + (data.ok ? 'probe-ok' : 'probe-err'));
    verdict.textContent = '结论：' + (data.ok ? '正常' : '失败') +
      '（总计 ' + Number(data.total || 0).toFixed(1) + 'ms）';
    out.appendChild(verdict);
  } catch (err) {
    out.textContent = '诊断失败：' + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = '开始诊断';
  }
}

// ---------- 事件绑定 ----------

$('adblock-toggle').onclick = () => {
  const enabled = currentStatus && currentStatus.ad_block && currentStatus.ad_block.enabled;
  if (enabled && !confirm('关闭后，广告域名将恢复正常解析。确认关闭？')) return;
  adBlockAction('toggle', { enabled: !enabled });
};

$('ad-allow-add').onclick = async () => {
  const input = $('ad-allow-input');
  const domain = input.value.trim();
  if (!domain) { toast('请输入要放行的域名', true); return; }
  await adBlockAction('allow', { domain });
  input.value = '';
};
$('ad-allow-input').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') $('ad-allow-add').click();
});

$('egress-add').onclick = async () => {
  const link = $('egress-link').value.trim();
  if (!link) { toast('请粘贴节点链接', true); return; }
  const btn = $('egress-add');
  btn.disabled = true;
  btn.textContent = '添加中…';
  try {
    await egressAction('add', { link });
    $('egress-link').value = '';
  } finally {
    btn.disabled = false;
    btn.textContent = '添加出口';
  }
};

$('rule-add').onclick = async () => {
  const rule = $('rule-input').value.trim();
  if (!rule) { toast('请输入规则', true); return; }
  try {
    const data = await api('/api/rules', { method: 'POST', body: JSON.stringify({ rule }) });
    await loadRules();
    $('rule-input').value = '';
    toast(data.message || '规则已添加');
  } catch (err) {
    toast(err.message, true);
  }
};

$('probe-run').onclick = runProbe;
$('probe-target').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') runProbe();
});
$('rule-input').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') $('rule-add').click();
});

loadStatus();
loadRules();
loadApps();
loadAdSuspects();
setInterval(loadStatus, 15000);
setInterval(loadAdSuspects, 60000);

// ---------- 健康监控 ----------

function fmtBytes(n) {
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + ' GB';
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n || 0) + ' B';
}

function healthDot(fail, count) {
  if (!count) return '⚪';
  const r = fail / count;
  if (r >= 0.2) return '🔴';
  if (r > 0) return '🟡';
  return '🟢';
}

function renderHealth(h) {
  const list = $('health-list');
  const sys = $('health-sys');
  if (!list || !sys) return;
  list.textContent = '';
  sys.textContent = '';
  if (!h || !h.enabled) {
    list.appendChild(el('div', 'intro', '监控未启用。'));
    return;
  }
  for (const e of (h.egress || [])) {
    const row = el('div', 'row');
    const left = el('div', 'row-main');
    left.appendChild(el('strong', '', healthDot(e.probe_1h.fail, e.probe_1h.count) + ' ' + e.name));
    const bits = [];
    if (e.probe_1h.count) {
      bits.push((e.probe_kind || '探测') + ' 均 ' + e.probe_1h.avg + ' · p95 ' + e.probe_1h.p95 + ' · 失败 ' + e.probe_1h.fail + '/' + e.probe_1h.count);
    }
    if (e.fw_1h.count) {
      bits.push('转发 ' + e.fw_1h.count + ' 次 · 均 ' + e.fw_1h.avg + ' · 失败 ' + e.fw_1h.fail);
    }
    if (e.up_bytes || e.down_bytes) {
      bits.push('↑ ' + fmtBytes(e.up_bytes) + ' · ↓ ' + fmtBytes(e.down_bytes));
    }
    left.appendChild(el('span', 'muted', bits.join('　') || '暂无数据'));
    row.appendChild(left);
    list.appendChild(row);
  }
  const stats = [
    ['DNS 1h', h.dns_1h.count ? ('均 ' + h.dns_1h.avg + ' / 失败 ' + h.dns_1h.fail) : '无查询'],
    ['TCP 会话', h.tcp.active + ' / ' + h.tcp.max],
    ['QUIC 会话', h.quic.max ? (h.quic.active + ' / ' + h.quic.max) : '未启用'],
    ['内存', (h.sys.memory_mb || 0).toFixed(1) + ' MB'],
    ['goroutine', String(h.sys.goroutines)],
    ['证书剩余', typeof h.sys.cert_days !== 'number' ? '—'
      : h.sys.cert_days < 0 ? ('已过期 ' + (-h.sys.cert_days) + ' 天')
      : (h.sys.cert_days + ' 天')],
  ];
  for (const [k, v2] of stats) {
    const s = el('div', 'stat');
    s.appendChild(el('span', 'stat-label', k));
    s.appendChild(el('span', 'stat-value', v2));
    sys.appendChild(s);
  }
}

async function loadHealth() {
  try {
    renderHealth(await api('/api/health'));
  } catch (_) { /* 健康数据失败不打扰 */ }
}

loadHealth();
setInterval(loadHealth, 30000);
