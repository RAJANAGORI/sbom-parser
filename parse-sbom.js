
/* parse-sbom.js — Enhanced with charts & rich insights */
(function () {
  const state = {
    index: null,
    history: [],
    tracker: { vulns: [] },
    manifest: null,
    sboms: [],
    components: [],
    vulns: [],
    vendors: new Map(),
    licenses: new Map(),
    charts: {},
  };

  // ---------- Utilities ----------
  const $  = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const esc = (s) => (s == null ? "" : String(s));
  const uniq = (arr) => Array.from(new Set(arr.filter(Boolean)));
  const by = (k) => (a, b) => esc(a[k]).localeCompare(esc(b[k]));
  const fmt = new Intl.NumberFormat();
  const setSubtitle = (t) => ($("#subtitle").textContent = t);

  function pill(text, tone='ok') {
    const cx = tone === 'bad' ? 'pill-bad' : tone === 'warn' ? 'pill-warn' : 'pill-ok';
    return `<span class="pill ${cx}">${esc(text)}</span>`;
  }
  function chip(text) { return `<span class="chip">${esc(text)}</span>` }
  async function jget(path) { const r=await fetch(path,{cache:'no-store'}); if(!r.ok) throw new Error(`${path}: ${r.status}`); return r.json(); }
  const get = (o,p,d=null)=>p.split('.').reduce((x,k)=>(x&&k in x?x[k]:d),o);
  function inc(map, key) { if (!key) return; map.set(key, (map.get(key) || 0) + 1); }

  // Normalize models
  function normalizeComponent(c, sbomName) {
    const licArray = get(c, 'licenses', []).map(l => l.license?.id || l.license?.name).filter(Boolean);
    const license = licArray[0] || '';
    const supplier = get(c, 'supplier.name') || get(c, 'publisher') || '';
    return {
      sbom: sbomName || '',
      name: c.name || '',
      version: c.version || '',
      purl: c.purl || '',
      license,
      licenses: licArray,
      supplier,
      scope: c.scope || '',
    };
  }
  function normalizeVulns(bom) {
    const vulns = get(bom, 'vulnerabilities', [])
      .map(v => ({
        id: v.id || v.source?.name || '',
        severity: v.ratings?.[0]?.severity || v.analysis?.state || '',
        affects: uniq((v.affects || []).map(a => a.ref)).join(', '),
        range: (v.affects || []).map(a => a.version || a.range).filter(Boolean).join(', '),
        description: v.description || v.detail || v.credits || '',
        refs: (v.advisories || v.references || []).map(r => r.url).filter(Boolean),
      }));
    return vulns;
  }

  // ---------- Rendering ----------
  function renderKPIs() {
    const uniqueVendors = state.vendors.size;
    const uniqueLicenses = state.licenses.size;
    const vulnCount = state.vulns.length;
    const compCount = state.components.length;

    const scopes = state.components.reduce((acc,c)=>{
      const s=(c.scope||'runtime').toLowerCase(); acc[s]=(acc[s]||0)+1; return acc;
    },{});
    const scopeText = Object.entries(scopes).map(([k,v])=>`${k}:${v}`).join(' • ');

    const tiles = [
      { label: 'Components', value: fmt.format(compCount) },
      { label: 'Runtime', value: fmt.format(scopes.runtime||0) },
      { label: 'Dev/Test', value: fmt.format((scopes.dev||0)+(scopes.test||0)) },
      { label: 'Vendors', value: fmt.format(uniqueVendors) },
      { label: 'Licenses', value: fmt.format(uniqueLicenses) },
      { label: 'Vulnerabilities', value: fmt.format(vulnCount), tone: vulnCount ? 'bad' : 'ok' },
    ];

    $('#kpis').innerHTML = tiles.map(t => `
      <div class="kpi">
        <div class="text-xs text-slate-500 mb-1">${t.label}</div>
        <div class="text-2xl font-extrabold">${t.value}</div>
      </div>`).join('');
  }

  function minibar(val, max) {
    const pct = max ? Math.max(2, Math.round((val / max) * 100)) : 0;
    return `<div class="w-40 bg-slate-200 rounded-full minibar"><div class="h-full bg-brand-500 rounded-full" style="width:${pct}%"></div></div>`;
  }

  function renderOverview() {
    const sbomList = $('#sbomList');
    const meta = $('#metaList');

    const entries = state.index?.sboms || [];
    const maxCount = Math.max(...entries.map(s => s.count || 0), 0);

    sbomList.innerHTML = entries.map(s => `
      <div class="card p-4 flex items-center justify-between gap-4">
        <div class="min-w-0">
          <div class="font-semibold truncate">${esc(s.name || s.path || 'SBOM')}</div>
          <div class="text-xs text-slate-500 mono truncate">${esc(s.path || '')}</div>
        </div>
        <div class="flex items-center gap-2">
          ${chip(esc(s.format || 'CycloneDX'))}
          ${chip('components: ' + (s.count ?? '—'))}
          ${minibar(s.count||0, maxCount)}
          <a class="btn" href="${'sboms/' + (s.path || '')}" target="_blank" rel="noreferrer">Open</a>
        </div>
      </div>`).join('');

    const kv = [];
    if (state.manifest) {
      kv.push(['Manifest name', get(state.manifest, 'name', '—')]);
      kv.push(['Version', get(state.manifest, 'version', '—')]);
      kv.push(['Created', get(state.manifest, 'metadata.timestamp', '—')]);
      const suppliers = uniq((get(state.manifest, 'components', []) || []).map(c => c.supplier?.name).filter(Boolean)).length;
      kv.push(['Suppliers', String(suppliers)]);
    }
    const scopes = state.components.reduce((acc,c)=>{const s=(c.scope||'runtime').toLowerCase(); acc[s]=(acc[s]||0)+1; return acc;},{});
    kv.push(['Scope split', Object.entries(scopes).map(([k,v])=>`${k}:${v}`).join(' • ')]);

    if (state.tracker?.vulns?.length) {
      const sev = (state.tracker.vulns || []).reduce((acc,v)=>{acc[v.severity]=(acc[v.severity]||0)+1;return acc;},{});
      kv.push(['Tracker vulns', JSON.stringify(sev)]);
    }
    meta.innerHTML = kv.map(([k,v]) => `
      <div><dt class="text-xs text-slate-500">${esc(k)}</dt><dd class="font-medium">${esc(v)}</dd></div>
    `).join('');
  }

  function renderClouds() {
    const licenseWrap = $('#licenseCloud');
    const vendorWrap = $('#vendorCloud');

    const topLicenses = Array.from(state.licenses.entries()).sort((a,b)=>b[1]-a[1]).slice(0, 12);
    const topVendors = Array.from(state.vendors.entries()).sort((a,b)=>b[1]-a[1]).slice(0, 12);

    licenseWrap.innerHTML = topLicenses.map(([l,c])=>`<button data-filter-license="${esc(l)}" class="btn">${esc(l)} ${chip(c)}</button>`).join('');
    vendorWrap.innerHTML  = topVendors.map(([v,c])=>`<button data-filter-vendor="${esc(v)}" class="btn">${esc(v)} ${chip(c)}</button>`).join('');
  }

  function renderComponents(filterText='') {
    const tbody = $('#componentsBody');
    const includeDev = $('#toggleDev').checked;
    const onlyWithLicense = $('#toggleNoLicense').checked;
    const f = filterText.toLowerCase();

    const rows = state.components.filter(c => {
      if (!includeDev && ['dev', 'test', 'optional'].includes((c.scope||'').toLowerCase())) return false;
      if (onlyWithLicense && !c.license) return false;
      const hay = [c.name, c.version, c.purl, c.license, c.supplier].join(' ').toLowerCase();
      return hay.includes(f);
    }).sort(by('name')).map(c => `
      <tr>
        <td>
          <div class="font-medium">${esc(c.name)}</div>
          <div class="text-xs text-slate-500 mono">${esc(c.purl||'')}</div>
        </td>
        <td class="mono">${esc(c.version)}</td>
        <td class="mono">${esc(c.purl)}</td>
        <td>${c.license ? pill(c.license, 'ok') : '<span class="text-slate-400">—</span>'}</td>
        <td>${esc(c.supplier||'')}</td>
        <td>${esc(c.scope||'')}</td>
      </tr>`).join('');

    tbody.innerHTML = rows || `<tr><td colspan="6" class="text-center text-slate-400 py-8">No components match.</td></tr>`;
    $('#compCount').textContent = fmt.format(rows ? rows.split('<tr>').length - 1 : 0);
  }

  function renderVulns(filterText='') {
    const tbody = $('#vulnsBody');
    const f = filterText.toLowerCase();
    const rows = state.vulns.filter(v => {
      const hay = [v.id, v.severity, v.affects, v.description].join(' ').toLowerCase();
      return hay.includes(f);
    }).map(v => `
      <tr>
        <td>
          <div class="font-semibold">${esc(v.id)}</div>
          ${v.refs?.slice(0,2).map(u => `<div class="text-xs"><a class="underline" href="${esc(u)}" target="_blank" rel="noreferrer">${esc(u)}</a></div>`).join('')}
        </td>
        <td>${v.severity ? pill(v.severity, (v.severity||'').match(/(high|critical)/i) ? 'bad' : (v.severity||'').match(/(medium)/i) ? 'warn' : 'ok') : '—'}</td>
        <td class="mono">${esc(v.affects || '—')}</td>
        <td class="mono">${esc(v.range || '—')}</td>
        <td>${esc(v.description || '—')}</td>
      </tr>`).join('');
    tbody.innerHTML = rows || `<tr><td colspan="5" class="text-center text-slate-400 py-8">No vulnerabilities recorded.</td></tr>`;
    $('#vulnCount').textContent = fmt.format(rows ? rows.split('<tr>').length - 1 : 0);
  }

  function renderHistory() {
    const wrap = $('#history');
    const items = (state.history || []).map(h => `
      <div class="card p-4">
        <div class="flex items-center justify-between">
          <div class="font-semibold">${esc(h.title || h.event || 'Event')}</div>
          <div class="text-xs text-slate-500">${esc(h.date || h.timestamp || '')}</div>
        </div>
        <div class="text-sm mt-2">${esc(h.description || h.notes || '')}</div>
      </div>`).join('');
    wrap.innerHTML = items || `<div class="text-slate-500">No history entries found.</div>`;
  }

  function renderFiles() {
    const pub = $('#publicFiles');
    const sbo = $('#sbomFiles');
    const p = state.index?.public ?? ['public/history.json', 'public/sbom-index.json', 'public/tracker.json'];
    const s = state.index?.sboms?.map(it => 'sboms/' + (it.path || it.name || '')) ?? [];

    pub.innerHTML = p.map(f => `<div class="card p-3 flex items-center justify-between"><span class="mono">${esc(f)}</span><a class="btn" href="${esc(f)}" target="_blank" rel="noreferrer">Open</a></div>`).join('');
    sbo.innerHTML = s.map(f => `<div class="card p-3 flex items-center justify-between"><span class="mono">${esc(f)}</span><a class="btn" href="${esc(f)}" target="_blank" rel="noreferrer">Open</a></div>`).join('');
  }

  // ---------- Charts ----------
  function destroyCharts() {
    Object.values(state.charts).forEach(ch => ch?.destroy());
    state.charts = {};
  }

  function ecosystemFromPurl(purl) {
    if (!purl) return 'unknown';
    // purl format: pkg:type/name@version
    const m = purl.match(/^pkg:([^/]+)/);
    return (m && m[1]) || 'unknown';
  }

  function chart(ctx, type, data, options={}) {
    return new Chart(ctx, { type, data, options: Object.assign({
      animation: { duration: 250 },
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: true, position: 'bottom' } },
      scales: (type==='bar' || type==='line') ? { y: { beginAtZero:true, ticks: { precision:0 } } } : {}
    }, options) });
  }

  function renderCharts() {
    destroyCharts();

    // Components by SBOM
    const labelsBySbom = (state.index?.sboms || []).map(s => s.name || s.path);
    const countsBySbom = (state.index?.sboms || []).map(s => s.count || 0);
    state.charts.bySbom = chart($('#chartBySbom'), 'bar', {
      labels: labelsBySbom, datasets: [{ label:'components', data: countsBySbom }]
    });

    // License distribution (top 8 + other)
    const licPairs = Array.from(state.licenses.entries()).sort((a,b)=>b[1]-a[1]);
    const topLic = licPairs.slice(0,8);
    const other = licPairs.slice(8).reduce((n, [,c])=>n+c,0);
    const licLabels = topLic.map(([l])=>l).concat(other?['other']:[]);
    const licData = topLic.map(([,c])=>c).concat(other?[other]:[]);
    state.charts.licenses = chart($('#chartLicenses'), 'doughnut', {
      labels: licLabels, datasets: [{ data: licData }]
    }, { plugins:{ legend:{ position:'right' }}});

    // Top vendors (top 8)
    const venPairs = Array.from(state.vendors.entries()).sort((a,b)=>b[1]-a[1]).slice(0,8);
    state.charts.vendors = chart($('#chartVendors'), 'bar', {
      labels: venPairs.map(([v])=>v),
      datasets: [{ label:'components', data: venPairs.map(([,c])=>c) }]
    });

    // Ecosystem from purl
    const ecoMap = new Map();
    state.components.forEach(c => {
      const e = ecosystemFromPurl(c.purl);
      ecoMap.set(e, (ecoMap.get(e)||0)+1);
    });
    const ecoPairs = Array.from(ecoMap.entries()).sort((a,b)=>b[1]-a[1]).slice(0,10);
    state.charts.eco = chart($('#chartEco'), 'doughnut', {
      labels: ecoPairs.map(([e])=>e),
      datasets: [{ data: ecoPairs.map(([,c])=>c) }]
    }, { plugins:{ legend:{ position:'right' }}});

    // Severity split
    const sevBuckets = { critical:0, high:0, medium:0, low:0, none:0, unknown:0 };
    state.vulns.forEach(v => {
      const s = (v.severity||'').toLowerCase();
      const key = /critical/.test(s) ? 'critical' :
                  /high/.test(s) ? 'high' :
                  /medium/.test(s) ? 'medium' :
                  /low/.test(s) ? 'low' :
                  /none/.test(s) ? 'none' : 'unknown';
      sevBuckets[key]++;
    });
    state.charts.sev = chart($('#chartSev'), 'bar', {
      labels: Object.keys(sevBuckets),
      datasets: [{ label:'count', data: Object.values(sevBuckets) }]
    });

    // Scope split
    const scopes = state.components.reduce((acc,c)=>{ const s=(c.scope||'runtime').toLowerCase(); acc[s]=(acc[s]||0)+1; return acc; },{});
    const scopePairs = Object.entries(scopes);
    state.charts.scopes = chart($('#chartScopes'), 'bar', {
      labels: scopePairs.map(([k])=>k),
      datasets: [{ label: 'components', data: scopePairs.map(([,v])=>v) }]
    });
  }

  // ---------- Interactions ----------
  function wireTabs() {
    $$('.tab').forEach(btn => btn.addEventListener('click', () => {
      $$('.tab').forEach(b => b.classList.remove('tab-active'));
      btn.classList.add('tab-active');
      const id = btn.getAttribute('data-tab');
      ['overview','components','vulns','history','files'].forEach(t => {
        $('#tab-'+t).classList.toggle('hidden', t !== id);
      });
    }));
  }
  function wireSearches() {
    $('#quickSearch').addEventListener('keydown', (e)=>{
      if (e.key === 'Enter') { $('#compSearch').value = e.currentTarget.value; renderComponents(e.currentTarget.value); document.querySelector('[data-tab="components"]').click(); }
    });
    $('#compSearch').addEventListener('input', (e)=> renderComponents(e.currentTarget.value));
    $('#vulnSearch').addEventListener('input', (e)=> renderVulns(e.currentTarget.value));
    $('#toggleDev').addEventListener('change', ()=> renderComponents($('#compSearch').value));
    $('#toggleNoLicense').addEventListener('change', ()=> renderComponents($('#compSearch').value));
    $('#downloadBtn').addEventListener('click', ()=>{
      const html = document.documentElement.outerHTML;
      const blob = new Blob([html], { type: 'text/html' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'sbom-explorer.html';
      a.click(); setTimeout(()=>URL.revokeObjectURL(a.href), 3000);
    });
  }
  function wireCloudFilters() {
    document.body.addEventListener('click', (e)=>{
      const lic = e.target.closest('[data-filter-license]')?.getAttribute('data-filter-license');
      const ven = e.target.closest('[data-filter-vendor]')?.getAttribute('data-filter-vendor');
      if (lic || ven) {
        const q = [lic, ven].filter(Boolean).join(' ');
        $('#compSearch').value = q;
        renderComponents(q);
        document.querySelector('[data-tab="components"]').click();
      }
    });
  }

  // ---------- Boot ----------
  async function boot() {
    try {
      state.index = await jget('public/sbom-index.json').catch(()=>({}));
      setSubtitle(state.index?.title || 'SBOMs & project metadata');

      const [history, tracker, manifest] = await Promise.all([
        jget('public/history.json').catch(()=>[]),
        jget('public/tracker.json').catch(()=>({ vulns: [] })),
        jget('sboms/manifest.json').catch(()=>null),
      ]);
      state.history = Array.isArray(history) ? history : (history.items || history.events || []);
      state.tracker = tracker || { vulns: [] };
      state.manifest = manifest;

      const sbomEntries = state.index?.sboms || [];
      const docs = await Promise.all(sbomEntries.map(async (s) => {
        const path = 'sboms/' + (s.path || s.name || '');
        const bom = await jget(path).catch(()=>null);
        return { entry: s, bom, name: s.name || s.path || 'SBOM' };
      }));

      state.sboms = docs.filter(d => d.bom).map(d => d.bom);

      for (const doc of docs) {
        if (!doc.bom) continue;
        const comps = get(doc.bom, 'components', []);
        for (const c of comps) {
          const nc = normalizeComponent(c, doc.name);
          state.components.push(nc);
          inc(state.vendors, nc.supplier);
          (nc.licenses || []).forEach(l => inc(state.licenses, l));
        }
        state.vulns.push(...normalizeVulns(doc.bom));
      }

      if (Array.isArray(state.tracker.vulns)) {
        state.vulns.push(...state.tracker.vulns.map(v => ({
          id: v.id || v.cve || v.alias || '',
          severity: v.severity || v.cvss?.severity || '',
          affects: (v.affects || v.components || []).join(', '),
          range: v.range || v.version || '',
          description: v.title || v.description || '',
          refs: v.refs || v.links || [],
        })));
      }

      // Paint UI
      renderKPIs();
      renderOverview();
      renderClouds();
      renderComponents('');
      renderVulns('');
      renderHistory();
      renderFiles();
      renderCharts();

      $('#downloadBtn').classList.remove('hidden');
    } catch (err) {
      console.error(err);
      setSubtitle('Failed to load assets. See console.');
    }
  }

  wireTabs(); wireSearches(); wireCloudFilters(); boot();
})();
