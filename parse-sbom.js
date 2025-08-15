/* global Chart */
(() => {
  // --------------------------- Utilities & State ---------------------------
  const $ = sel => document.querySelector(sel);
  const $$ = sel => [...document.querySelectorAll(sel)];
  const fmt = n => n.toLocaleString();
  const qs = new URLSearchParams(location.hash.replace(/^#/, ''));
  const state = {
    datasets: new Map(),       // name -> { vulns:[], comps: Map(), raw }
    allVulns: [],              // flattened with dataset attribution
    filters: {
      q: qs.get('q') || '',
      ds: qs.get('ds') || '',      // dataset name
      sev: qs.get('sev') || '',    // critical|high|medium|low
      fix: qs.get('fix') || '',    // hasfix|nofix
      cvss: Number(qs.get('cvss') || 0),
      onlyDirect: qs.get('dir') === '1' || false,
      tab: qs.get('tab') || 'vulns',
      page: Number(qs.get('page') || 1),
    },
    charts: { pie: null },
    pageSize: 50,
  };

  function setHash() {
    const h = new URLSearchParams({
      tab: state.filters.tab,
      q: state.filters.q,
      ds: state.filters.ds,
      sev: state.filters.sev,
      fix: state.filters.fix,
      cvss: String(state.filters.cvss || 0),
      dir: state.filters.onlyDirect ? '1' : '0',
      page: String(state.filters.page),
    });
    history.replaceState(null, '', `#${h.toString()}`);
  }

  function toBadge(sev) {
    const s = String(sev || '').toLowerCase();
    const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };
    const label = s ? s[0].toUpperCase() + s.slice(1) : '—';
    return `<span class="badge ${map[s] || 'bg-slate-100 text-slate-700 ring-1 ring-inset ring-slate-200'}">${label}</span>`;
  }

  function bestRating(v) {
    const ratings = v.ratings || v.score ? [{ severity: v.severity, score: v.score }] : [];
    const r = (v.ratings || ratings || []).reduce((acc, cur) => {
      const score = Number(cur.score || cur.baseScore || 0);
      const sev = (cur.severity || '').toLowerCase();
      if (!acc || score > acc.score) return { score, severity: sev };
      return acc;
    }, null);
    return r || { score: 0, severity: '' };
  }

  function hasFix(v) {
    // heuristics across CycloneDX properties and advisories
    if (v.analysis && /resolved|fixed/i.test(v.analysis.state || '')) return true;
    if (Array.isArray(v.properties)) {
      if (v.properties.some(p => /fix|fixed|upgrade|patched|version/i.test((p.value || '') + (p.name || '')))) return true;
    }
    if (typeof v.recommendation === 'string' && /upgrade|update|patch/i.test(v.recommendation)) return true;
    if (Array.isArray(v.advisories)) {
      if (v.advisories.some(a => /fix|patch|upgrade/i.test(a.url || ''))) return true;
    }
    return false;
  }

  function firstDate(v) {
    const candidates = [v.created, v.published, v.updated, v.timestamp, v.introduced];
    const d = candidates.map(x => x && new Date(x)).find(d => d && !isNaN(d));
    return d || null;
  }

  function ageDays(d) {
    if (!d) return 0;
    return Math.max(0, Math.round((Date.now() - d.getTime()) / 86400000));
    // 86_400_000 ms/day
  }

  // --------------------------- Data Loading ---------------------------
  async function loadDatasets() {
    // datasets from URL: ds=a.json,b.json (relative to /sboms/). if empty, try to auto-add from public sample listing.
    const dsParam = (state.filters.ds || '').trim();
    const list = dsParam ? dsParam.split(',').map(s => s.trim()).filter(Boolean) : [];
    if (list.length === 0) {
      // Try a default sample if exists; this is safe even if 404 (we just move on)
      await tryLoad('/sboms/sample.json', 'sample');
    }
    for (const item of list) {
      const path = item.match(/\.json$/i) ? `/sboms/${item}` : `/sboms/${item}.json`;
      await tryLoad(path, item.replace(/\.json$/i, ''));
    }
    if (state.datasets.size === 0) {
      // allow user to drag&drop later; but render empty UI
      renderAll();
    }
  }

  async function tryLoad(url, name) {
    try {
      const res = await fetch(url, { cache: 'no-store' });
      if (!res.ok) return;
      const json = await res.json();
      addDatasetFromCycloneDX(json, name);
    } catch (_) { /* ignore */ }
  }

  function addDatasetFromCycloneDX(bom, dataset) {
    // build components map
    const comps = new Map();
    (bom.components || []).forEach(c => {
      const id = c.bomRef || c['bom-ref'] || c.purl || `${c.name || 'component'}@${c.version || ''}`;
      comps.set(id, {
        id,
        name: c.name || c.purl || id,
        version: c.version || '',
        license: extractLicense(c),
        scope: c.scope || '',
        isDirect: !c.scope || /required|runtime|compile/i.test(c.scope), // heuristic
      });
    });

    // flatten vulnerabilities
    const flattened = [];
    (bom.vulnerabilities || []).forEach(v => {
      const rating = bestRating(v);
      const fix = hasFix(v);
      const published = firstDate(v);
      const links = collectLinks(v);
      const affects = (v.affects || v.affectsComponents || []).map(a => a.ref || a['ref'] || a.bomRef || a.purl).filter(Boolean);

      if (affects.length === 0) affects.push(null); // record as "global" if no mapping given

      affects.forEach(ref => {
        const comp = ref ? comps.get(ref) || guessByRef(comps, ref) : null;
        flattened.push({
          id: v.id || v.cve || v.source?.name || 'UNKNOWN',
          severity: rating.severity || inferSeverity(rating.score),
          score: rating.score || 0,
          dataset,
          component: comp?.name || ref || '—',
          version: comp?.version || '—',
          license: comp?.license || '—',
          isDirect: comp?.isDirect ?? true,
          refsCount: (v.references || v.advisories || []).length,
          links,
          published,
          openAgeDays: ageDays(published),
          raw: v,
        });
      });
    });

    state.datasets.set(dataset, { vulns: flattened, comps, raw: bom });
    rebuildAllVulns();
    refreshDatasetPickers();
  }

  function extractLicense(c) {
    try {
      const l = c.licenses?.[0];
      if (!l) return '—';
      if (l.license?.id) return l.license.id;
      if (l.license?.name) return l.license.name;
      if (l.expression) return l.expression;
    } catch (_) { /* noop */ }
    return '—';
  }

  function collectLinks(v) {
    const out = [];
    if (v.source?.url) out.push(v.source.url);
    if (Array.isArray(v.references)) v.references.forEach(r => r.url && out.push(r.url));
    if (Array.isArray(v.advisories)) v.advisories.forEach(a => a.url && out.push(a.url));
    if (v.url) out.push(v.url);
    return [...new Set(out)];
  }

  function guessByRef(map, ref) {
    // Try to match by purl suffix or name
    const arr = [...map.values()];
    return arr.find(c => c.id === ref || c.name === ref || (c.id && String(c.id).includes(ref))) || null;
  }

  function inferSeverity(score) {
    const s = Number(score || 0);
    if (s >= 9.0) return 'critical';
    if (s >= 7.0) return 'high';
    if (s >= 4.0) return 'medium';
    if (s > 0) return 'low';
    return '';
  }

  function rebuildAllVulns() {
    state.allVulns = [...state.datasets.values()].flatMap(d => d.vulns.map(v => ({ ...v })));
    renderAll();
  }

  function refreshDatasetPickers() {
    const names = [...state.datasets.keys()];
    const dsSel = $('#datasetSelect');
    const cmpA = $('#cmpA');
    const cmpB = $('#cmpB');
    [dsSel, cmpA, cmpB].forEach(sel => {
      if (!sel) return;
      const current = sel.value;
      sel.innerHTML = `<option value="">${sel === dsSel ? 'All datasets' : 'Pick Dataset ' + (sel === cmpA ? 'A' : 'B')}</option>` +
        names.map(n => `<option value="${n}">${n}</option>`).join('');
      if (names.includes(current)) sel.value = current;
    });
  }

  // --------------------------- Filtering & Derivations ---------------------------
  function getFiltered() {
    const f = state.filters;
    let rows = state.allVulns;

    if (f.q) {
      const q = f.q.toLowerCase();
      rows = rows.filter(r =>
        r.id.toLowerCase().includes(q) ||
        String(r.component).toLowerCase().includes(q) ||
        String(r.license).toLowerCase().includes(q) ||
        String(r.version).toLowerCase().includes(q)
      );
    }
    if (f.ds) rows = rows.filter(r => r.dataset === f.ds);
    if (f.sev) rows = rows.filter(r => r.severity === f.sev);
    if (f.fix === 'hasfix') rows = rows.filter(r => hasFix(r.raw));
    if (f.fix === 'nofix') rows = rows.filter(r => !hasFix(r.raw));
    if (f.cvss) rows = rows.filter(r => Number(r.score) >= Number(f.cvss));
    if (f.onlyDirect) rows = rows.filter(r => !!r.isDirect);

    return rows;
  }

  function severityBuckets(rows) {
    const buckets = { critical: 0, high: 0, medium: 0, low: 0 };
    rows.forEach(r => {
      const s = (r.severity || '').toLowerCase();
      if (buckets[s] !== undefined) buckets[s]++;
    });
    return buckets;
  }

  function fixRate(rows) {
    if (rows.length === 0) return 0;
    const fixed = rows.filter(r => hasFix(r.raw)).length;
    return Math.round((fixed / rows.length) * 100);
  }

  function medianOpenAge(rows) {
    const days = rows.map(r => r.openAgeDays || 0).filter(n => Number.isFinite(n));
    if (days.length === 0) return 0;
    days.sort((a,b)=>a-b);
    const mid = Math.floor(days.length / 2);
    return days.length % 2 ? days[mid] : Math.round((days[mid - 1] + days[mid]) / 2);
  }

  // --------------------------- Rendering ---------------------------
  function renderAll() {
    const rows = getFiltered();

    // KPIs
    $('#kpiTotal').textContent = fmt(rows.length);
    const b = severityBuckets(rows);
    $('#kpiCritical').textContent = fmt(b.critical);
    $('#kpiHigh').textContent = fmt(b.high);
    $('#kpiMedium').textContent = fmt(b.medium);
    $('#kpiLow').textContent = fmt(b.low);
    $('#kpiFixRate').textContent = fmt(fixRate(rows));
    $('#kpiOpenAge').textContent = `${fmt(medianOpenAge(rows))} days`;

    // Chart
    renderSeverityPie(b);

    // Top CVEs
    renderTopCves(rows);

    // Tables
    renderVulnTable(rows);
    renderComponentsTable(rows);
  }

  function renderSeverityPie(b) {
    const data = [b.critical, b.high, b.medium, b.low];
    const ctx = $('#severityPie');
    if (!ctx) return;
    if (state.charts.pie) state.charts.pie.destroy();
    state.charts.pie = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{ data }]
      },
      options: { plugins: { legend: { display: false } }, cutout: '70%' }
    });
  }

  function renderTopCves(rows) {
    const bucket = new Map(); // id -> {count, worstSev, maxScore, datasets:Set}
    rows.forEach(r => {
      const rec = bucket.get(r.id) || { count: 0, worstSev: r.severity, maxScore: r.score, datasets: new Set() };
      rec.count++;
      rec.maxScore = Math.max(rec.maxScore, Number(r.score || 0));
      rec.worstSev = worseSev(rec.worstSev, r.severity);
      rec.datasets.add(r.dataset);
      bucket.set(r.id, rec);
    });
    const top = [...bucket.entries()]
      .sort((a,b) => sevRank(b[1].worstSev) - sevRank(a[1].worstSev) || b[1].count - a[1].count)
      .slice(0, 12);

    $('#topCvesList').innerHTML = top.map(([id,meta]) => `
      <li class="card p-3 flex items-start gap-3">
        <div>${toBadge(meta.worstSev)}</div>
        <div class="flex-1">
          <button class="text-sm font-semibold hover:underline" data-cve-filter="${id}">${id}</button>
          <div class="mt-1 text-xs text-slate-500">Count: <b>${meta.count}</b> · Max CVSS: <b>${meta.maxScore}</b> · Datasets: <b>${meta.datasets.size}</b></div>
        </div>
      </li>
    `).join('') || `<div class="text-sm text-slate-500">No CVE IDs found in current data.</div>`;

    // click -> filter by this CVE id
    $$('[data-cve-filter]').forEach(el => el.addEventListener('click', () => {
      state.filters.q = el.getAttribute('data-cve-filter');
      $('#searchInput').value = state.filters.q;
      state.filters.page = 1;
      setHash(); renderAll();
    }));
    $('#clearCveFilter').onclick = () => { state.filters.q = ''; $('#searchInput').value=''; setHash(); renderAll(); };
  }

  function sevRank(s) {
    return { critical: 4, high: 3, medium: 2, low: 1 }[String(s).toLowerCase()] || 0;
  }
  function worseSev(a, b) { return sevRank(a) >= sevRank(b) ? a : b; }

  function renderVulnTable(rows) {
    const page = state.filters.page || 1;
    const start = (page - 1) * state.pageSize;
    const pageRows = rows.slice(start, start + state.pageSize);

    $('#vulnTbody').innerHTML = pageRows.map(r => `
      <tr class="hover:bg-slate-50">
        <td class="px-4 py-2">${toBadge(r.severity)}</td>
        <td class="px-4 py-2">${Number(r.score || 0).toFixed(1)}</td>
        <td class="px-4 py-2">${esc(r.component)}</td>
        <td class="px-4 py-2">${esc(r.version)}</td>
        <td class="px-4 py-2">${esc(r.license)}</td>
        <td class="px-4 py-2">
          <button class="text-slate-900 hover:underline font-medium" data-open-detail="${r.id}">${esc(r.id)}</button>
        </td>
        <td class="px-4 py-2">${esc(r.dataset)}</td>
        <td class="px-4 py-2">${r.links.slice(0,2).map(u => `<a class="text-slate-600 hover:text-slate-900 underline" target="_blank" href="${esc(u)}">link</a>`).join(' · ')}</td>
        <td class="px-4 py-2 text-slate-500">${r.published ? new Date(r.published).toISOString().slice(0,10) : '—'}</td>
        <td class="px-4 py-2 text-slate-500">${r.isDirect ? 'direct' : 'transitive'} — refs (${r.refsCount || 0})</td>
      </tr>
    `).join('');

    const pageCount = Math.max(1, Math.ceil(rows.length / state.pageSize));
    $('#pageNum').textContent = String(page);
    $('#pageCount').textContent = String(pageCount);
    $('#prevPageBtn').disabled = page <= 1;
    $('#nextPageBtn').disabled = page >= pageCount;
    $('#prevPageBtn').onclick = () => { if (state.filters.page > 1) { state.filters.page--; setHash(); renderAll(); } };
    $('#nextPageBtn').onclick = () => { if (state.filters.page < pageCount) { state.filters.page++; setHash(); renderAll(); } };

    // details
    $$('[data-open-detail]').forEach(btn => btn.addEventListener('click', () => openDetail(btn.getAttribute('data-open-detail'))));
  }

  function renderComponentsTable(rows) {
    const byComp = new Map(); // key -> {name, versions:Set, license:Set, datasets:Set, count, maxScore, worstSev}
    rows.forEach(r => {
      const key = `${r.component}@${r.version}`;
      const rec = byComp.get(key) || { name: r.component, versions: new Set(), licenses: new Set(), datasets: new Set(), count: 0, maxScore: 0, worstSev: r.severity };
      rec.count++;
      rec.versions.add(r.version);
      rec.licenses.add(r.license);
      rec.datasets.add(r.dataset);
      rec.maxScore = Math.max(rec.maxScore, Number(r.score || 0));
      rec.worstSev = worseSev(rec.worstSev, r.severity);
      byComp.set(key, rec);
    });
    $('#compTbody').innerHTML = [...byComp.values()].map(c => `
      <tr class="hover:bg-slate-50">
        <td class="px-4 py-2">${esc(c.name)}</td>
        <td class="px-4 py-2">${toBadge(c.worstSev)}</td>
        <td class="px-4 py-2">${c.maxScore.toFixed(1)}</td>
        <td class="px-4 py-2">${fmt(c.count)}</td>
        <td class="px-4 py-2">${fmt(c.datasets.size)}</td>
        <td class="px-4 py-2">${esc([...c.licenses].filter(x=>x && x!=='—').slice(0,2).join(', ') || '—')}</td>
      </tr>
    `).join('');
  }

  function openDetail(vulnId) {
    const rows = getFiltered().filter(r => r.id === vulnId);
    const first = rows[0];
    if (!first) return;
    $('#detailTitle').textContent = first.id;
    const list = rows.map(r => `
      <div class="border rounded-xl p-3">
        <div class="flex items-center justify-between">
          <div class="font-medium">${esc(r.component)} <span class="text-slate-500">v${esc(r.version)}</span></div>
          <div>${toBadge(r.severity)} <span class="ml-2 text-xs">CVSS ${Number(r.score || 0).toFixed(1)}</span></div>
        </div>
        <div class="mt-2 text-xs text-slate-600">Dataset: <b>${esc(r.dataset)}</b> · License: <b>${esc(r.license)}</b> · First seen: ${r.published ? new Date(r.published).toISOString().slice(0,10) : '—'} · ${r.isDirect?'Direct':'Transitive'}</div>
        <div class="mt-2 flex flex-wrap gap-2">${r.links.map(u => `<a class="underline text-slate-700" target="_blank" href="${esc(u)}">${esc(host(u))}</a>`).join('')}</div>
      </div>
    `).join('');

    $('#detailBody').innerHTML = `
      <div class="text-sm text-slate-600">Occurrences (${rows.length})</div>
      <div class="mt-2 space-y-2">${list}</div>
    `;
    $('#detailDrawer').classList.remove('hidden');
  }
  $$('[data-dismiss="drawer"]').forEach(b => b.addEventListener('click', () => $('#detailDrawer').classList.add('hidden')));

  function host(u){try{return new URL(u).host}catch(_){return u}}

  // --------------------------- Events & Controls ---------------------------
  function wireControls() {
    $('#searchInput').value = state.filters.q;
    $('#severitySelect').value = state.filters.sev;
    $('#fixSelect').value = state.filters.fix;
    $('#cvssMinInput').value = String(state.filters.cvss || 0);
    $('#onlyDirectChk').checked = !!state.filters.onlyDirect;

    $('#searchInput').addEventListener('input', e => { state.filters.q = e.target.value; state.filters.page=1; setHash(); renderAll(); });
    $('#severitySelect').addEventListener('change', e => { state.filters.sev = e.target.value; state.filters.page=1; setHash(); renderAll(); });
    $('#fixSelect').addEventListener('change', e => { state.filters.fix = e.target.value; state.filters.page=1; setHash(); renderAll(); });
    $('#cvssMinInput').addEventListener('change', e => { state.filters.cvss = Number(e.target.value || 0); state.filters.page=1; setHash(); renderAll(); });
    $('#onlyDirectChk').addEventListener('change', e => { state.filters.onlyDirect = e.target.checked; state.filters.page=1; setHash(); renderAll(); });

    // dataset select influences filter, not which files are loaded
    $('#datasetSelect').addEventListener('change', e => { state.filters.ds = e.target.value || ''; state.filters.page=1; setHash(); renderAll(); });

    // chips: critical / high / hasfix / direct
    $$('[data-chip]').forEach(ch => ch.addEventListener('click', () => {
      const key = ch.getAttribute('data-chip');
      if (key === 'critical' || key === 'high') { state.filters.sev = key; $('#severitySelect').value = key; }
      if (key === 'hasfix') { state.filters.fix = state.filters.fix === 'hasfix' ? '' : 'hasfix'; $('#fixSelect').value = state.filters.fix; }
      if (key === 'direct') { state.filters.onlyDirect = !state.filters.onlyDirect; $('#onlyDirectChk').checked = state.filters.onlyDirect; }
      state.filters.page=1; setHash(); renderAll();
    }));

    $('#resetBtn').onclick = () => {
      state.filters.q=''; state.filters.ds=''; state.filters.sev=''; state.filters.fix=''; state.filters.cvss=0; state.filters.onlyDirect=false; state.filters.page=1;
      $('#searchInput').value=''; $('#datasetSelect').value=''; $('#severitySelect').value=''; $('#fixSelect').value=''; $('#cvssMinInput').value='0'; $('#onlyDirectChk').checked=false;
      setHash(); renderAll();
    };

    // tabs
    $$('[data-tab]').forEach(btn => btn.addEventListener('click', () => {
      state.filters.tab = btn.getAttribute('data-tab');
      $$('[data-tab]').forEach(b => b.classList.remove('tab-active'));
      btn.classList.add('tab-active');
      ['vulns','components','compare'].forEach(id => $(`#tab-${id}`).classList.toggle('hidden', id !== state.filters.tab));
      setHash();
    }));
    // init tab
    $$('[data-tab]').forEach(b => b.classList.toggle('tab-active', b.getAttribute('data-tab') === state.filters.tab));
    ['vulns','components','compare'].forEach(id => $(`#tab-${id}`).classList.toggle('hidden', id !== state.filters.tab));

    // compare
    $('#runCompareBtn').onclick = runCompare;

    // export/save/load
    $('#exportCsvBtn').onclick = exportCsv;
    $('#saveViewBtn').onclick = saveView;
    $('#loadViewBtn').onclick = loadView;
  }

  function runCompare() {
    const a = $('#cmpA').value; const b = $('#cmpB').value;
    $('#cmpOnlyALabel').textContent = a || 'A';
    $('#cmpOnlyBLabel').textContent = b || 'B';
    const va = a ? [...(state.datasets.get(a)?.vulns || [])] : [];
    const vb = b ? [...(state.datasets.get(b)?.vulns || [])] : [];
    $('#cmpTotalA').textContent = fmt(va.length);
    $('#cmpTotalB').textContent = fmt(vb.length);
    $('#cmpBreakA').textContent = breakdown(va);
    $('#cmpBreakB').textContent = breakdown(vb);

    const setA = new Set(va.map(x => x.id + '|' + x.component));
    const setB = new Set(vb.map(x => x.id + '|' + x.component));
    const onlyB = [...setB].filter(x => !setA.has(x)).slice(0, 20);
    const onlyA = [...setA].filter(x => !setB.has(x)).slice(0, 20);

    $('#cmpDelta').textContent = fmt(vb.length - va.length);
    $('#cmpOnlyB').innerHTML = onlyB.map(x => `<li>${esc(x.split('|')[0])} in <i>${esc(x.split('|')[1])}</i></li>`).join('');
    $('#cmpOnlyA').innerHTML = onlyA.map(x => `<li>${esc(x.split('|')[0])} in <i>${esc(x.split('|')[1])}</i></li>`).join('');
  }

  function breakdown(arr) {
    const b = severityBuckets(arr);
    return `Critical ${b.critical} · High ${b.high} · Medium ${b.medium} · Low ${b.low}`;
  }

  // --------------------------- Export / Save / Load ---------------------------
  function exportCsv() {
    const rows = getFiltered();
    const header = ['severity','cvss','component','version','license','vuln_id','dataset','links','first_seen','direct','refs'];
    const lines = [header.join(',')];
    rows.forEach(r => {
      lines.push([
        r.severity, r.score, csv(r.component), csv(r.version), csv(r.license),
        r.id, r.dataset, csv(r.links.join(' ')),
        r.published ? new Date(r.published).toISOString() : '',
        r.isDirect ? 'direct' : 'transitive',
        r.refsCount || 0
      ].join(','));
    });
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'vulnerabilities.csv'; a.click();
    URL.revokeObjectURL(url);
  }
  function saveView(){
    localStorage.setItem('sbom-explorer-view', JSON.stringify(state.filters));
  }
  function loadView(){
    try{
      const v = JSON.parse(localStorage.getItem('sbom-explorer-view') || '{}');
      Object.assign(state.filters, v || {});
      wireControls(); setHash(); renderAll();
    }catch(_){}
  }

  function csv(s){ return `"${String(s ?? '').replace(/"/g,'""')}"`; }
  function esc(s){ return String(s ?? '').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m])); }

  // --------------------------- Boot ---------------------------
  document.addEventListener('DOMContentLoaded', async () => {
    wireControls();
    await loadDatasets(); // loads datasets listed in #ds= (comma-separated) or sample.json if present
    setHash();
  });
})();
