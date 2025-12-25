function app() {
    return {
      items: [],
      filtered: [],
      paged: [],
      datasets: [],
      // Performance: Indexes for faster lookups
      _componentIndex: new Map(),
      _datasetIndex: new Map(),
      _severityIndex: new Map(),
      _memoizedCounts: null,
      _memoizedHash: '',
      overall: { total: 0, severityCounts: {} },
      metrics: { fixAvailabilityRate: 0, topCVEs: [] },
      dataset: "",
      q: "",
      severity: "",
      fix: "",
      cvssMin: 0,
      mobileFilters: false,
      lastAction: "apply",
      sevBaseOrder: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'],
      sevOpts: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      sevCountsFiltered: {},
      fixRateFiltered: 0,
      filterSummary: "",
      perDatasetSev: {},
      sortKey: "severityRank",
      sortDir: "desc",
      page: 0,
      perPage: (matchMedia('(max-width: 640px)').matches ? 20 : 50),
      pages: 0,
      metaText: "",

      suggestions: [],
      showSuggest: false,
      selIdx: -1,
      _suggestTimer: null,
      _exportLastTime: 0,
      _exportCount: 0,
      _exportResetTime: 0,

      hideSuggest() { this.showSuggest = false; this.selIdx = -1; },
      moveSel(step) {
        if (!this.suggestions.length) return;
        const n = this.suggestions.length;
        this.selIdx = ((this.selIdx + step + n) % n);
      },
      applySel() {
        if (this.selIdx < 0 || this.selIdx >= this.suggestions.length) { this.hideSuggest(); return; }
        this.pick(this.suggestions[this.selIdx]);
      },
      pick(s) {
        this.q = s.query;
        this.applyFilters(true);
        this.hideSuggest();
        this.$nextTick(() => this.$refs.search?.focus());
      },
        _filterDebounceTimer: null,
        _worker: null,
        _useWorker: false, // Enable Web Worker for large datasets (>5000 items)
        
        _initWorker() {
          if (typeof Worker !== 'undefined' && this.items.length > 5000) {
            try {
              this._worker = new Worker('./scripts/worker-filter.mjs');
              this._worker.onmessage = (e) => {
                if (e.data.type === 'filtered') {
                  this.filtered = e.data.result;
                  this.page = 0;
                  this.paginate();
                  this._updateMetrics();
                } else if (e.data.type === 'aggregated') {
                  this.sevCountsFiltered = e.data.result.severityCounts;
                  this.fixRateFiltered = e.data.result.fixRate;
                }
              };
              this._useWorker = true;
            } catch (error) {
              console.warn('Web Worker not available, using main thread:', error);
              this._useWorker = false;
            }
          }
        },
        
        onInput(e) {
          // Sanitize search input
          const raw = e.target.value;
          this.q = window.SecurityUtils ? window.SecurityUtils.sanitizeSearchQuery(raw) : raw;
          
          // Debounce filter application (300ms delay)
          clearTimeout(this._filterDebounceTimer);
          this._filterDebounceTimer = setTimeout(() => {
            this.applyFilters(true);
          }, 300);
          
          // Debounce suggestions (120ms delay)
          clearTimeout(this._suggestTimer);
          const val = this.q.trim();
          if (!val) { this.suggestions = []; this.hideSuggest(); return; }
          this._suggestTimer = setTimeout(() => this.updateSuggestions(val), 120);
        },
      updateSuggestions(val) {
        const q = val.toLowerCase();
        const cand = [];
        const seen = new Set();
        const push = (group, label, query, meta = '') => {
          const key = group + '|' + label;
          if (seen.has(key)) return;
          seen.add(key);
          cand.push({ key, group, label, query, meta });
        };

        for (const r of this.items) {
          if (r.component && r.component.toLowerCase().includes(q))
            push('component', r.component, r.component, r.version || '');
          if (r.id && r.id.toLowerCase().includes(q))
            push('vuln id', r.id, r.id, r.severity || '');
          if (r.purl && r.purl.toLowerCase().includes(q))
            push('purl', r.purl, r.purl.split('@')[0] || r.purl, r.version || '');
          for (const L of (r.licenses || [])) {
            if (L && L.toLowerCase().includes(q)) push('license', L, L, '');
          }
          if (r.dataset && r.dataset.toLowerCase().includes(q))
            push('dataset', r.dataset, r.dataset, '');
        }

        const starts = [], contains = [];
        for (const s of cand) { (s.label.toLowerCase().startsWith(q) ? starts : contains).push(s); }
        const byLen = a => a.sort((x, y) => x.label.length - y.label.length);
        this.suggestions = [...byLen(starts), ...byLen(contains)].slice(0, 12);
        this.showSuggest = this.suggestions.length > 0;
        this.selIdx = this.suggestions.length ? 0 : -1;
      },

      ringCircumference: 2 * Math.PI * 18, // r=18
      get ringOffsetFix() {
        const pct = Math.max(0, Math.min(100, this.fixRateFiltered)) / 100;
        return this.ringCircumference * (1 - pct);
      },
        get ringColor() {
          const p = this.fixRateFiltered;
          if (p >= 67) return '#10b981';
          if (p >= 33) return '#f59e0b';
          return '#ef4444';
        },
        
        get riskScore() {
          // Calculate overall risk score based on severity distribution and CVSS scores
          const counts = this.sevCountsFiltered || {};
          const total = this.filtered.length || 1;
          
          // Weighted severity scores
          const criticalWeight = (counts.CRITICAL || 0) * 100;
          const highWeight = (counts.HIGH || 0) * 70;
          const mediumWeight = (counts.MEDIUM || 0) * 40;
          const lowWeight = (counts.LOW || 0) * 10;
          
          // Average CVSS score contribution (0-100 scale)
          const cvssScores = this.filtered
            .map(r => typeof r.cvss === 'number' ? r.cvss : null)
            .filter(v => v != null);
          const avgCVSS = cvssScores.length > 0 
            ? cvssScores.reduce((a, b) => a + b, 0) / cvssScores.length 
            : 0;
          const cvssContribution = (avgCVSS / 10) * 100;
          
          // Calculate weighted risk score (0-100)
          const severityScore = (criticalWeight + highWeight + mediumWeight + lowWeight) / total;
          const riskScore = Math.min(100, (severityScore * 0.7 + cvssContribution * 0.3));
          
          return Math.round(riskScore);
        },

      donutSegs: {
        CRITICAL: { dash: '0 1000', offset: 0, color: '#dc2626', count: 0 },
        HIGH: { dash: '0 1000', offset: 0, color: '#f87171', count: 0 },
        MEDIUM: { dash: '0 1000', offset: 0, color: '#f59e0b', count: 0 },
        LOW: { dash: '0 1000', offset: 0, color: '#10b981', count: 0 },
        INFO: { dash: '0 1000', offset: 0, color: '#9ca3af', count: 0 },
        UNKNOWN: { dash: '0 1000', offset: 0, color: '#d1d5db', count: 0 },
      },
      donutLegend: [],
      buildSeverityDonut() {
        const order = this.sevBaseOrder;
        const counts = this.sevCountsFiltered || {};
        const total = Object.values(counts).reduce((a, b) => a + (b || 0), 0) || 0;
        const r = 16, C = 2 * Math.PI * r;
        let acc = 0;
        this.donutLegend = [];
        for (const k of order) {
          this.donutSegs[k].dash = `0 ${C.toFixed(2)}`;
          this.donutSegs[k].offset = 0;
          this.donutSegs[k].count = 0;
        }
        for (const label of order) {
          const count = counts[label] || 0;
          if (!count) continue;
          const pct = count / Math.max(1, total);
          const segLen = pct * C;
          this.donutSegs[label].dash = `${segLen.toFixed(2)} ${(C - segLen).toFixed(2)}`;
          this.donutSegs[label].offset = (C * (1 - acc)).toFixed(2);
          this.donutSegs[label].count = count;
          acc += pct;
          this.donutLegend.push({ label, color: this.donutSegs[label].color, count });
        }
      },

      sparkW: 360,
      sparkH: 64,
      cvssPath: "",
      sparkGrid: "",
      cvssStatsText: "",
      buildCvssSpark() {
        const w = this.sparkW, h = this.sparkH, pad = 6;
        const xs = this.filtered.map(r => typeof r.cvss === 'number' ? r.cvss : null).filter(v => v != null);
        const n = xs.length;
        this.sparkGrid = `0,${h - 1} ${w},${h - 1} 0,${Math.round(h / 2)} ${w},${Math.round(h / 2)} 0,1 ${w},1`;
        if (!n) { this.cvssPath = ""; this.cvssStatsText = "no scores"; return; }
        const sorted = [...xs].sort((a, b) => a - b);
        const min = sorted[0];
        const q = (p) => sorted[Math.floor((sorted.length - 1) * p)];
        const med = q(0.5).toFixed(1);
        const step = Math.max(1, Math.floor(n / 80));
        const vals = xs.filter((_, i) => i % step === 0);
        const m = vals.length;
        const scaleX = (i) => pad + (i / (m - 1)) * (w - 2 * pad);
        const scaleY = (v) => pad + (1 - ((v - 0) / 10)) * (h - 2 * pad);
        this.cvssPath = vals.map((v, i) => `${scaleX(i)},${scaleY(v)}`).join(' ');
        this.cvssStatsText = `n=${n} · min=${min?.toFixed(1)} · med=${med} · p90=${q(0.9).toFixed(1)}`;
      },

      topComponents: [],
      buildTopComponents() {
        const counts = {};
        for (const r of this.filtered) {
          const name = r.component || 'unknown';
          counts[name] = (counts[name] || 0) + 1;
        }
        const arr = Object.entries(counts).map(([name, count]) => ({ name, count }));
        arr.sort((a, b) => b.count - a.count);
        const top = arr.slice(0, 6);
        const max = top[0]?.count || 1;
        this.topComponents = top.map(x => ({ ...x, pct: Math.round(100 * x.count / max) }));
      },

      topLicenses: [],
      buildTopLicenses() {
        const counts = {};
        for (const r of this.filtered) {
          const ls = Array.isArray(r.licenses) ? r.licenses : [];
          if (!ls.length) continue;
          for (const L of ls) {
            const name = (L || 'unknown').trim() || 'unknown';
            counts[name] = (counts[name] || 0) + 1;
          }
        }
        const arr = Object.entries(counts).map(([name, count]) => ({ name, count }));
        arr.sort((a, b) => b.count - a.count);
        const top = arr.slice(0, 6);
        const max = top[0]?.count || 1;
        this.topLicenses = top.map(x => ({ ...x, pct: Math.round(100 * x.count / max) }));
      },

      dsFixRates: [],
      buildDsFixRates() {
        const map = {};
        for (const r of this.filtered) {
          const d = r.dataset || 'unknown';
          if (!map[d]) map[d] = { name: d, total: 0, fix: 0 };
          map[d].total++;
          if ((r.fixedVersions || []).length) map[d].fix++;
        }
        const rows = Object.values(map).map(x => ({ name: x.name, rate: x.total ? Math.round(100 * x.fix / x.total) : 0 }));
        rows.sort((a, b) => b.rate - a.rate);
        this.dsFixRates = rows.slice(0, 6);
      },

      noFixSevBars: [],
      buildNoFixBars() {
        const nf = this.filtered.filter(r => !(r.fixedVersions || []).length);
        const counts = this.countSev(nf);
        const total = nf.length || 1;
        const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];
        this.noFixSevBars = order
          .filter(s => counts[s])
          .map(s => ({ label: s, count: counts[s], pct: Math.round(100 * counts[s] / total), color: this.donutSegs[s].color }));
      },

      updateSeverityOptions() {
        const q = this.q.trim().toLowerCase();
        const ds = this.dataset, fix = this.fix, cv = Number(this.cvssMin) || 0;
        const base = this.items.filter(r => {
          if (ds && r.dataset !== ds) return false;
          if (cv && (r.cvss ?? -1) < cv) return false;
          if (fix === 'has' && !(r.fixedVersions || []).length) return false;
          if (fix === 'none' && (r.fixedVersions || []).length) return false;
          if (q) {
            const t = [r.component, r.purl, r.id, (r.licenses || []).join(' '), (r.dataset || '')].join(' ').toLowerCase();
            if (!t.includes(q)) return false;
          }
          return true;
        });
        const c = this.countSev(base);
        const out = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        if ((c.INFO || 0) > 0) out.push('INFO');
        if ((c.UNKNOWN || 0) > 0) out.push('UNKNOWN');
        this.sevOpts = out;
      },

      async init() {
        try {
          // Try multiple paths for parse-sboms.json
          const paths = [
            "./parse-sboms.json",
            "parse-sboms.json", 
            "/parse-sboms.json",
            window.location.pathname.replace(/\/[^/]*$/, '/') + 'parse-sboms.json'
          ];
          let snap = null;
          let lastError = null;
          let triedPaths = [];
          
          for (const path of paths) {
            triedPaths.push(path);
            try {
              const response = await fetch(`${path}?_=${Date.now()}`);
              if (response.ok) {
                snap = await response.json();
                console.log(`✓ Loaded parse-sboms.json from: ${path}`);
                break;
              } else {
                console.warn(`✗ Failed to load from ${path}: ${response.status} ${response.statusText}`);
              }
            } catch (err) {
              lastError = err;
              console.warn(`✗ Error loading from ${path}:`, err.message);
              continue;
            }
          }
          
          if (!snap) {
            const errorMsg = `Failed to load parse-sboms.json from any path. Tried: ${triedPaths.join(', ')}. Last error: ${lastError?.message || 'All paths returned non-OK status'}`;
            console.error(errorMsg);
            throw new Error(errorMsg);
          }
          
          // Validate data structure
          if (!window.SecurityUtils || !window.SecurityUtils.validateSBOMData(snap)) {
            throw new Error('Invalid data structure received');
          }
          
          // Sanitize items before processing
          this.items = (snap.items || []).map((r, idx) => {
            const sanitized = window.SecurityUtils.sanitizeObject(r);
            return { ...sanitized, _key: (sanitized.dataset || 'ds') + '::' + (sanitized.id || (sanitized.component || 'comp') + '@' + (sanitized.version || '')) + '::' + idx };
          });
          
          this.datasets = (snap.datasets || [])
            .map((d, i) => {
              const sanitized = window.SecurityUtils.sanitizeObject(d);
              return { ...sanitized, _key: 'ds-' + (sanitized.id || i) };
            })
            .sort((a, b) => String(a.id).localeCompare(String(b.id)));
          
          this.overall = snap.overall || this.overall;
          this.metrics = snap.metrics || this.metrics;
          this.metaText = snap.generatedAt ? `updated ${new Date(snap.generatedAt).toLocaleString()}` : '';
        } catch (error) {
          console.error('Failed to initialize:', error);
          this.items = [];
          this.datasets = [];
          this.metaText = 'Error loading data. Please refresh the page.';
          // Show user-friendly error
          setTimeout(() => {
            alert('Failed to load SBOM data. Please check the console for details and refresh the page.');
          }, 100);
          return;
        }

          this.restoreFromHash();
          this.updateSeverityOptions();
          
          // Initialize Web Worker if dataset is large
          this._initWorker();
          
          this.applyFilters(true);

        document.addEventListener('click', (e) => {
          const wrap = this.$refs.searchWrap;
          const panel = this.$refs.suggest;
          if (!wrap) return;
          const t = e.target;
          const insideWrap = wrap.contains(t);
          const insidePanel = panel ? panel.contains(t) : false;
          if (!insideWrap && !insidePanel) this.hideSuggest();
        }, { capture: true });

        this.handleResize = this.debounce(() => {
          if (window.innerWidth < 640 && this.mobileFilters) {
            this.mobileFilters = false;
          }
          this.adjustLayoutForScreenSize();
          document.body.offsetHeight;
        }, 250);
        window.addEventListener('resize', this.handleResize);

          // Use requestIdleCallback for non-critical initialization
          const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 120));
          idle(() => { 
            this.buildTopComponents(); 
            this.buildTopLicenses(); 
            this.buildDsFixRates(); 
          }, { timeout: 2000 });

        this.adjustLayoutForScreenSize();

        setTimeout(() => {
          this.adjustLayoutForScreenSize();
        }, 100);
      },

      badge(sev) {
        const s = (sev || "").toUpperCase();
        const base = "px-2 py-0.5 rounded-lg text-xs font-semibold";
        if (s === "CRITICAL") return base + " bg-red-600 text-white";
        if (s === "HIGH") return base + " bg-red-900 text-red-200";
        if (s === "MEDIUM") return base + " bg-amber-900 text-amber-200";
        if (s === "LOW") return base + " bg-green-900 text-green-200";
        return base + " bg-[#2d3748] text-[#94a3b8]";
      },

        _filterCache: null,
        _lastFilterHash: '',
        applyFilters(buildGroup = false) {
          // Validate and sanitize filter inputs
          const utils = window.SecurityUtils;
          if (utils) {
            this.q = utils.sanitizeSearchQuery(this.q);
            this.dataset = utils.validateDatasetId(this.dataset);
            this.severity = utils.validateSeverity(this.severity);
            this.fix = utils.validateFixFilter(this.fix);
            this.cvssMin = utils.validateCVSS(this.cvssMin);
            this.sortKey = utils.validateSortKey(this.sortKey);
            this.sortDir = utils.validateSortDir(this.sortDir);
          }
          
          // Create filter hash for caching
          const currentFilterHash = `${this.q}|${this.dataset}|${this.severity}|${this.fix}|${this.cvssMin}|${this.sortKey}|${this.sortDir}`;
          
          // Use cached result if filters haven't changed
          if (this._filterCache && this._lastFilterHash === currentFilterHash) {
            this.paginate();
            return;
          }
          
          // Use Web Worker for large datasets
          if (this._useWorker && this._worker && this.items.length > 5000) {
            this._worker.postMessage({
              type: 'filter',
              data: this.items,
              filters: {
                q: this.q,
                dataset: this.dataset,
                severity: this.severity,
                fix: this.fix,
                cvssMin: this.cvssMin
              },
              sortKey: this.sortKey,
              sortDir: this.sortDir
            });
            return; // Worker will update filtered via onmessage
          }
          
          const q = this.q.trim().toLowerCase();
          const sev = this.severity, fix = this.fix, cv = Number(this.cvssMin) || 0, ds = this.dataset;
          this.filtered = this.items.filter(r => {
          if (ds && r.dataset !== ds) return false;
          if (sev && (r.severity || "").toUpperCase() !== sev) return false;
          if (cv && (r.cvss ?? -1) < cv) return false;
          if (fix === "has" && !(r.fixedVersions || []).length) return false;
          if (fix === "none" && (r.fixedVersions || []).length) return false;
          if (q) {
            const t = [r.component, r.purl, r.id, (r.licenses || []).join(" "), (r.dataset || "")].join(" ").toLowerCase();
            if (!t.includes(q)) return false;
          }
          return true;
        });

        // sorting
        const key = this.sortKey;
        const dir = this.sortDir === "desc" ? -1 : 1;
        this.filtered.sort((a, b) => {
          const A = (a[key] ?? ""), B = (b[key] ?? "");
          if (typeof A === "number" && typeof B === "number") return (A - B) * dir;
          return String(A).localeCompare(String(B)) * dir;
        });

          // Cache the filtered result
          this._filterCache = [...this.filtered];
          this._lastFilterHash = currentFilterHash;
          
          this.page = 0;
          this.paginate();

          // Use memoized counting if available
          const filterHash = `${this.filtered.length}-${this.filtered.slice(0, 10).map(r => r._key).join(',')}`;
          this._updateMetrics();

        this.updateSeverityOptions();
        this.persistToHash();

        this.adjustLayoutForScreenSize();

        setTimeout(() => {
          document.body.offsetHeight;
        }, 50);
      },

        buildLicensesIfNeeded() { this.buildTopLicenses(); },
        
        // Update all metrics (called after filtering)
        _updateMetrics() {
          this.sevCountsFiltered = this._memoizedCountSev(this.filtered, `${this.filtered.length}`);
          const hasFix = this.filtered.filter(r => (r.fixedVersions || []).length).length;
          this.fixRateFiltered = this.filtered.length ? Math.round(100 * (hasFix / this.filtered.length)) : 0;
          this.perDatasetSev = this.groupByDatasetSev(this.filtered);
          this.filterSummary = this.buildFilterSummary();

          // Lazy load visualizations (defer non-critical rendering)
          requestIdleCallback(() => {
            this.buildSeverityDonut();
            this.buildCvssSpark();
          }, { timeout: 1000 });
          
          // Defer less critical metrics
          setTimeout(() => {
            this.buildTopComponents();
            this.buildTopLicenses();
            this.buildDsFixRates();
            this.buildNoFixBars();
          }, 100);
        },
        
        // Performance: Build indexes for O(1) lookups
        _buildIndexes() {
          this._componentIndex.clear();
          this._datasetIndex.clear();
          this._severityIndex.clear();
          
          for (const item of this.items) {
            // Component index
            const compKey = item.component || 'unknown';
            if (!this._componentIndex.has(compKey)) {
              this._componentIndex.set(compKey, []);
            }
            this._componentIndex.get(compKey).push(item);
            
            // Dataset index
            const dsKey = item.dataset || 'unknown';
            if (!this._datasetIndex.has(dsKey)) {
              this._datasetIndex.set(dsKey, []);
            }
            this._datasetIndex.get(dsKey).push(item);
            
            // Severity index
            const sevKey = (item.severity || 'UNKNOWN').toUpperCase();
            if (!this._severityIndex.has(sevKey)) {
              this._severityIndex.set(sevKey, []);
            }
            this._severityIndex.get(sevKey).push(item);
          }
        },
        
        // Memoized severity counting
        _memoizedCountSev(list, listHash) {
          if (this._memoizedCounts && this._memoizedHash === listHash) {
            return this._memoizedCounts;
          }
          const counts = this.countSev(list);
          this._memoizedCounts = counts;
          this._memoizedHash = listHash;
          return counts;
        },

      paginate() {
        this.pages = Math.max(1, Math.ceil(this.filtered.length / this.perPage));
        const start = this.page * this.perPage;
        this.paged = this.filtered.slice(start, start + this.perPage);
      },
      next() { if (this.page + 1 < this.pages) { this.page++; this.paginate(); this.persistToHash(); } },
      prev() { if (this.page > 0) { this.page--; this.paginate(); this.persistToHash(); } },

      countSev(list) {
        const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
        for (const r of list) {
          const s = (r.severity || 'UNKNOWN').toUpperCase();
          out[s] = (out[s] || 0) + 1;
        }
        return out;
      },
      groupByDatasetSev(list) {
        const map = {};
        for (const r of list) {
          const ds = r.dataset || 'unknown';
          if (!map[ds]) map[ds] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0, total: 0 };
          const s = (r.severity || 'UNKNOWN').toUpperCase();
          map[ds][s] = (map[ds][s] || 0) + 1;
          map[ds].total++;
        }
        return map;
      },
      buildFilterSummary() {
        const bits = [];
        if (this.dataset) bits.push(`dataset=${this.dataset}`);
        if (this.severity) bits.push(`severity=${this.severity}`);
        if (this.fix) bits.push(`fix=${this.fix}`);
        if (this.cvssMin) bits.push(`cvss≥${this.cvssMin}`);
        if (this.q) bits.push(`q="${this.q}"`);
        return bits.length ? `Active: ${bits.join(' · ')}` : 'No active filters';
      },

      exportCSV() {
        // Rate limiting: max 10 exports per minute
        const now = Date.now();
        const oneMinute = 60000;
        
        if (this._exportResetTime < now - oneMinute) {
          this._exportCount = 0;
          this._exportResetTime = now;
        }
        
        if (this._exportCount >= 10) {
          const waitTime = Math.ceil((this._exportResetTime + oneMinute - now) / 1000);
          alert(`Export rate limit exceeded. Please wait ${waitTime} seconds before exporting again.`);
          return;
        }
        
        const rows = this.filtered;
        if (!rows.length) { alert("No rows to export."); return; }
        
        // Limit export size to prevent memory issues (max 50k rows)
        const exportRows = rows.slice(0, 50000);
        if (rows.length > 50000) {
          if (!confirm(`Large dataset detected (${rows.length} rows). Exporting first 50,000 rows only. Continue?`)) {
            return;
          }
        }
        
        this._exportCount++;
        this._exportLastTime = now;
        
        const header = ["severity", "cvss", "component", "version", "purl", "licenses", "id", "dataset"];
        const lines = [header.join(",")];
        for (const r of exportRows) {
          // Sanitize CSV values
          const csv = [
            (r.severity ?? "").replace(/"/g, '""'),
            r.cvss ?? "",
            (r.component ?? "").replace(/"/g, '""'),
            (r.version ?? "").replace(/"/g, '""'),
            (r.purl ?? "").replace(/"/g, '""'),
            ((r.licenses || []).join("|")).replace(/"/g, '""'),
            (r.id ?? "").replace(/"/g, '""'),
            (r.dataset ?? "").replace(/"/g, '""')
          ].map(x => `"${String(x).replace(/"/g, '""')}"`).join(",");
          lines.push(csv);
        }
        const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "sbom-filtered.csv";
        a.click();
        URL.revokeObjectURL(url);
      },

      persistToHash() {
        const h = new URLSearchParams({
          q: this.q || "",
          ds: this.dataset || "",
          sev: this.severity || "",
          fix: this.fix || "",
          cvss: String(this.cvssMin || 0),
          dir: this.sortDir,
          key: this.sortKey,
          p: String(this.page)
        }).toString();
        location.hash = h;
      },
      restoreFromHash() {
        const s = new URLSearchParams(location.hash.replace(/^#/, ""));
        const utils = window.SecurityUtils;
        if (utils) {
          this.q = utils.sanitizeSearchQuery(s.get("q") || this.q);
          this.dataset = utils.validateDatasetId(s.get("ds") || this.dataset);
          this.severity = utils.validateSeverity(s.get("sev") || this.severity);
          this.fix = utils.validateFixFilter(s.get("fix") || this.fix);
          this.cvssMin = utils.validateCVSS(s.get("cvss") || this.cvssMin || 0);
          this.sortDir = utils.validateSortDir(s.get("dir") || this.sortDir);
          this.sortKey = utils.validateSortKey(s.get("key") || this.sortKey);
          this.page = utils.validatePage(s.get("p") || this.page || 0, 1000); // Max 1000 pages
        } else {
          // Fallback if security utils not loaded
          this.q = s.get("q") || this.q;
          this.dataset = s.get("ds") || this.dataset;
          this.severity = s.get("sev") || this.severity;
          this.fix = s.get("fix") || this.fix;
          this.cvssMin = Number(s.get("cvss") || this.cvssMin || 0);
          this.sortDir = s.get("dir") || this.sortDir;
          this.sortKey = s.get("key") || this.sortKey;
          this.page = Number(s.get("p") || this.page || 0);
        }
      },

      applyTopCVE(id) { 
        const utils = window.SecurityUtils;
        this.q = utils ? utils.sanitizeSearchQuery(id || "") : (id || ""); 
        this.applyFilters(true); 
      },

      resetFilters() {
        this.q = "";
        this.dataset = "";
        this.severity = "";
        this.fix = "";
        this.cvssMin = 0;
        this.sortKey = "severityRank";
        this.sortDir = "desc";
        this.page = 0;
        this.lastAction = "reset";
        this.updateSeverityOptions();
        this.applyFilters(true);
      },

      toggleSidebar() {
        this.mobileFilters = !this.mobileFilters;
        setTimeout(() => {
          this.adjustLayoutForScreenSize();
          document.body.offsetHeight;
        }, 100);
      },

      saveView() { try { localStorage.setItem('sbom_view', location.hash); alert('View saved.'); } catch { } },
      loadView() { try { const h = localStorage.getItem('sbom_view'); if (h) { location.hash = h; this.restoreFromHash(); this.applyFilters(true); } } catch { } },

      debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
          const later = () => {
            clearTimeout(timeout);
            func(...args);
          };
          clearTimeout(timeout);
          timeout = setTimeout(later, wait);
        };
      },

      adjustLayoutForScreenSize() {
        const width = window.innerWidth;
        const isSidebarOpen = this.mobileFilters;

        let availableWidth = width;
        if (isSidebarOpen && width >= 640) {
          availableWidth = width - (width >= 1280 ? 512 : 448);
        }

        if (width < 640) {
          this.perPage = 20;
        } else if (width < 1024) {
          this.perPage = isSidebarOpen ? 30 : 40;
        } else if (width < 1280) {
          this.perPage = isSidebarOpen ? 40 : 50;
        } else {
          this.perPage = isSidebarOpen ? 45 : 60;
        }

        this.updateGridLayout(availableWidth);

        if (this.filtered.length > 0) {
          this.paginate();
        }
      },

      updateGridLayout(availableWidth) {
        const mainContent = document.querySelector('main');
        if (mainContent) {
          if (availableWidth < 768) {
            mainContent.classList.add('compact-layout');
          } else {
            mainContent.classList.remove('compact-layout');
          }
        }

        this.adjustTableLayout(availableWidth);
      },

      adjustTableLayout(availableWidth) {
        const table = document.querySelector('table');
        if (!table) return;

        if (availableWidth < 768) {
          table.classList.add('compact-table');
        } else {
          table.classList.remove('compact-table');
        }
      }
    }
  }
