#!/usr/bin/env node
// Build a fast index JSON from CycloneDX files under sboms/* (any subfolder).
// Outputs:
//   - public/sbom-index.json   (snapshot, metrics, deltas)
//   - public/history.json      (rolling history for sparklines)
//   - public/tracker.json      (per-vuln lifecycle for TTF & open age)

import fs from "fs";
import path from "path";
import { globSync } from "glob";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SBOMS_DIR = path.join(__dirname, "sboms");
const OUT_DIR   = path.join(__dirname, "public");
const SNAP_FILE = path.join(OUT_DIR, "sbom-index.json");
const HIST_FILE = path.join(OUT_DIR, "history.json");
const TRK_FILE  = path.join(OUT_DIR, "tracker.json");

function readJSON(p) { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; } }
function writeJSON(p, obj) { fs.writeFileSync(p, JSON.stringify(obj, null, 2)); }

function severityOrder(s) {
  const map = { critical:4, high:3, medium:2, low:1, info:0, none:0, unknown:0 };
  return map[String(s||"").toLowerCase()] ?? 0;
}
function pickCVSS(scores = []) {
  let best = null;
  for (const r of scores) {
    const score = r.score ?? r.baseScore;
    const severity = r.severity || r.baseSeverity;
    if (score == null && !severity) continue;
    const obj = { score: score ?? null, severity: (severity||"").toUpperCase(), method: r.method || r.source || null };
    if (!best || (obj.score ?? 0) > (best.score ?? 0)) best = obj;
  }
  return best;
}
function licenseNames(licenses) {
  if (!Array.isArray(licenses)) return [];
  const out = [];
  for (const l of licenses) {
    if (l.license?.id) out.push(l.license.id);
    else if (l.license?.name) out.push(l.license.name);
    else if (l.expression) out.push(l.expression);
  }
  return out;
}
function countSeverities(items) {
  const init = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0, UNKNOWN:0 };
  return items.reduce((acc, it) => {
    const s = (it.severity || "UNKNOWN").toUpperCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, init);
}
function median(arr) {
  const a = arr.filter(x => Number.isFinite(x)).sort((x,y)=>x-y);
  if (!a.length) return null;
  const m = Math.floor(a.length/2);
  return a.length % 2 ? a[m] : (a[m-1]+a[m])/2;
}
function daysBetween(aISO, bISO) {
  const a = new Date(aISO).getTime(), b = new Date(bISO).getTime();
  return Math.max(0, Math.round((b - a) / (1000*60*60*24)));
}

function indexCycloneDX(json, datasetId) {
  const componentMap = new Map();
  (json.components || []).forEach(c => {
    const key = c["bom-ref"] || c["bomRef"] || c.purl || `${c.name || "component"}@${c.version || ""}`;
    componentMap.set(key, c);
  });

  const vuls = [];
  for (const v of json.vulnerabilities || []) {
    const affects = (v.affects || []).map(a => a.ref).filter(Boolean);
    const rating = pickCVSS(v.ratings || v.cvss || []);
    const sev = (v.severity || rating?.severity || "UNKNOWN").toUpperCase();

    const targets = affects.length ? affects : [null];
    for (const ref of targets) {
      const c = ref ? (componentMap.get(ref) || {}) : {};
      const lic = licenseNames(c.licenses);
      vuls.push({
        dataset: datasetId,
        id: v.id || null,
        title: v.description?.slice(0, 200) || "Vulnerability",
        severity: sev,
        severityRank: severityOrder(sev),
        cvss: rating?.score ?? null,
        component: c.name || null,
        version: c.version || null,
        purl: c.purl || null,
        licenses: lic,
        direct: (c.scope || "").toLowerCase() !== "optional" && (c.scope || "").toLowerCase() !== "transitive",
        cwes: (v.cwes || []).map(x => x.id || x).filter(Boolean),
        urls: (v.references || []).map(r => r.url).filter(Boolean),
        fixedVersions: (v.analysis?.response || []).includes("update") ? ["*"] : []
      });
    }
  }

  return {
    dataset: datasetId,
    created: json.metadata?.timestamp || null,
    components: (json.components || []).length,
    vulnerabilities: vuls.length,
    items: vuls
  };
}

function makeKey(it) {
  // Stable key per vuln occurrence
  return `${it.dataset}::${it.id || (it.component || "comp")+"@"+(it.version||"")}`;
}

function buildTopCVEs(items) {
  const map = new Map();
  for (const it of items) {
    const id = it.id || "";
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) continue;
    const cur = map.get(id) || { id, count:0, datasets:new Set(), maxCVSS:null, worstSeverityRank:-1 };
    cur.count += 1;
    cur.datasets.add(it.dataset);
    if (it.cvss != null) cur.maxCVSS = Math.max(cur.maxCVSS ?? -Infinity, it.cvss);
    if ((it.severityRank ?? -1) > cur.worstSeverityRank) cur.worstSeverityRank = it.severityRank ?? -1;
    map.set(id, cur);
  }
  return [...map.values()]
    .map(x => ({ id:x.id, count:x.count, datasets:[...x.datasets].sort(), maxCVSS: x.maxCVSS, worstSeverityRank:x.worstSeverityRank }))
    .sort((a,b)=> (b.worstSeverityRank - a.worstSeverityRank) || (b.count - a.count) || (b.maxCVSS??0)-(a.maxCVSS??0))
    .slice(0, 10); // top 10
}

function main() {
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });
  const now = new Date().toISOString();

  // 1) Parse SBOMs
  const files = globSync("**/*.cyclonedx.json", { cwd: SBOMS_DIR, absolute: true, nodir: true });
  const datasets = [];
  for (const f of files) {
    const json = readJSON(f);
    if (!json) continue;
    const rel = path.relative(SBOMS_DIR, f).replace(/\\/g, "/");
    const datasetId = rel.split("/")[0];
    datasets.push(indexCycloneDX(json, datasetId));
  }
  const items = datasets.flatMap(d => d.items);

  // 2) Update tracker (firstSeen/lastSeen/closedAt)
  const tracker = readJSON(TRK_FILE) || { vulns: {} };
  const currentKeys = new Set();
  for (const it of items) {
    const key = makeKey(it);
    currentKeys.add(key);
    if (!tracker.vulns[key]) tracker.vulns[key] = { firstSeen: now, lastSeen: now, closedAt: null, meta: { id: it.id, component: it.component, dataset: it.dataset} };
    tracker.vulns[key].lastSeen = now;
    tracker.vulns[key].closedAt = null;
  }
  for (const [key, rec] of Object.entries(tracker.vulns)) {
    if (!currentKeys.has(key) && rec.closedAt === null) rec.closedAt = now;
  }
  const entries = Object.entries(tracker.vulns);
  if (entries.length > 12000) {
    const closed = entries.filter(([,r]) => r.closedAt).sort((a,b)=> new Date(b[1].closedAt)-new Date(a[1].closedAt));
    const keepClosed = new Set(closed.slice(0,5000).map(([k])=>k));
    for (const [k, r] of entries) {
      if (r.closedAt && !keepClosed.has(k)) delete tracker.vulns[k];
    }
  }
  writeJSON(TRK_FILE, tracker);

  // 3) Metrics
  const datasetSummaries = datasets.map(d => ({
    id: d.dataset,
    created: d.created,
    components: d.components,
    vulnerabilities: d.vulnerabilities,
    severityCounts: countSeverities(d.items)
  }));
  const overallSeverity = countSeverities(items);

  const prev = readJSON(SNAP_FILE);
  const prevMap = new Map();
  if (prev?.datasets) for (const pd of prev.datasets) prevMap.set(pd.id, pd);

  const datasetsWithDelta = datasetSummaries.map(d => {
    const p = prevMap.get(d.id);
    const delta = p ? (d.vulnerabilities - (p.vulnerabilities||0)) : null;
    const severityDelta = {};
    if (p?.severityCounts) for (const k of Object.keys(d.severityCounts)) severityDelta[k] = (d.severityCounts[k]||0)-(p.severityCounts[k]||0);
    else for (const k of Object.keys(d.severityCounts)) severityDelta[k] = null;
    return { ...d, delta, severityDelta };
  });

  const overallPrev = prev?.overall || null;
  const overallDelta = overallPrev ? (items.length - (overallPrev.total||0)) : null;
  const overallSevDelta = {};
  if (overallPrev?.severityCounts) for (const k of Object.keys(overallSeverity)) overallSevDelta[k] = (overallSeverity[k]||0)-(overallPrev.severityCounts[k]||0);
  else for (const k of Object.keys(overallSeverity)) overallSevDelta[k] = null;

  const fixAvailRate = items.length ? Math.round(100 * (items.filter(it => (it.fixedVersions||[]).length>0).length / items.length)) : 0;

  const ttfDays = Object.values(tracker.vulns).filter(r => r.closedAt)
    .map(r => daysBetween(r.firstSeen, r.closedAt));
  const ttfMedianDays = median(ttfDays);

  const nowISO = now;
  const openAgeDays = Object.entries(tracker.vulns).filter(([k]) => currentKeys.has(k))
    .map(([,r]) => daysBetween(r.firstSeen, nowISO));
  const openAgeMedianDays = median(openAgeDays);

  const oldestOpen = Object.entries(tracker.vulns).filter(([k]) => currentKeys.has(k))
    .map(([k,r]) => ({ key:k, days: daysBetween(r.firstSeen, nowISO), meta:r.meta }))
    .sort((a,b)=> b.days - a.days)
    .slice(0,5);

  const itemsWithAge = items.map(it => {
    const rec = tracker.vulns[makeKey(it)];
    return { ...it, firstSeen: rec?.firstSeen || null };
  });

  const topCVEs = buildTopCVEs(itemsWithAge);

  const snapshot = {
    generatedAt: now,
    datasets: datasetsWithDelta,
    items: itemsWithAge,
    overall: {
      total: itemsWithAge.length,
      severityCounts: overallSeverity,
      delta: overallDelta,
      severityDelta: overallSevDelta
    },
    metrics: {
      fixAvailabilityRate: fixAvailRate,
      ttfMedianDays,
      openAgeMedianDays,
      oldestOpen,
      topCVEs
    }
  };
  writeJSON(SNAP_FILE, snapshot);
  console.log(`Wrote ${SNAP_FILE} with ${itemsWithAge.length} vulns across ${datasets.length} dataset(s).`);

  // 4) History for sparklines
  const hist = readJSON(HIST_FILE) || { entries: [] };
  const perDataset = {};
  for (const d of datasetSummaries) perDataset[d.id] = d.severityCounts;
  hist.entries.push({
    generatedAt: now,
    overall: { total: snapshot.overall.total, severityCounts: snapshot.overall.severityCounts },
    datasets: perDataset
  });
  if (hist.entries.length > 50) hist.entries = hist.entries.slice(-50);
  writeJSON(HIST_FILE, hist);
  console.log(`Updated ${HIST_FILE} (entries: ${hist.entries.length}).`);
}
main();
