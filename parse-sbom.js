#!/usr/bin/env node
// Build a single JSON (parse-sboms.json) from CycloneDX files under sboms/* (any subfolder).
// No public/ folder, no extra files.
//
// Output (repo root):
//   - parse-sboms.json  (snapshot with datasets, items, overall + simple metrics)

import fs from "fs";
import path from "path";
import { globSync } from "glob";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SBOMS_DIR   = path.join(__dirname, "sboms");
const OUT_FILE    = path.join(__dirname, "parse-sboms.json");

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
    .slice(0, 10);
}

function main() {
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

  // 2) Summaries
  const datasetSummaries = datasets.map(d => ({
    id: d.dataset,
    created: d.created,
    components: d.components,
    vulnerabilities: d.vulnerabilities,
    severityCounts: countSeverities(d.items)
  })).sort((a,b)=> String(a.id).localeCompare(String(b.id)));

  const overallSeverity = countSeverities(items);
  const fixAvailRate = items.length ? Math.round(100 * (items.filter(it => (it.fixedVersions||[]).length>0).length / items.length)) : 0;
  const topCVEs = buildTopCVEs(items);

  const snapshot = {
    generatedAt: now,
    datasets: datasetSummaries,
    items,
    overall: {
      total: items.length,
      severityCounts: overallSeverity
    },
    metrics: {
      fixAvailabilityRate: fixAvailRate,
      topCVEs
    }
  };

  writeJSON(OUT_FILE, snapshot);
  console.log(`Wrote ${OUT_FILE} with ${items.length} vulns across ${datasets.length} dataset(s).`);
}

main();
