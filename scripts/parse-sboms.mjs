#!/usr/bin/env node
/**
 * @fileoverview Build parse-sboms.json from CycloneDX files found under sboms directory
 * @module parse-sboms
 */

import fs from "fs";
import path from "path";
import { globSync } from "glob";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SBOMS_DIR = path.join(__dirname, "..", "sboms");
const OUT_FILE  = path.join(__dirname, "..", "parse-sboms.json");

/**
 * Reads and parses a JSON file safely
 * @param {string} p - File path to read
 * @returns {object|null} Parsed JSON object or null if read/parse fails
 */
function readJSON(p) {
  try {
    if (!fs.existsSync(p)) {
      console.warn(`File not found: ${p}`);
      return null;
    }
    const content = fs.readFileSync(p, "utf8");
    if (!content || content.trim().length === 0) {
      console.warn(`Empty file: ${p}`);
      return null;
    }
    return JSON.parse(content);
  } catch (error) {
    console.error(`Error reading JSON from ${p}: ${error.message}`);
    return null;
  }
}

/**
 * Writes an object to a JSON file
 * @param {string} p - File path to write to
 * @param {object} obj - Object to serialize to JSON
 * @throws {Error} If file write fails
 */
function writeJSON(p, obj) {
  try {
    const dir = path.dirname(p);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const content = JSON.stringify(obj, null, 2);
    fs.writeFileSync(p, content, "utf8");
  } catch (error) {
    throw new Error(`Failed to write JSON to ${p}: ${error.message}`);
  }
}

/**
 * Maps severity string to numeric order for sorting
 * @param {string} s - Severity string (case-insensitive)
 * @returns {number} Numeric order (4=critical, 3=high, 2=medium, 1=low, 0=info/unknown)
 */
function severityOrder(s) {
  const map = { critical:4, high:3, medium:2, low:1, info:0, none:0, unknown:0 };
  return map[String(s||"").toLowerCase()] ?? 0;
}
/**
 * Selects the best CVSS rating from an array of ratings
 * @param {Array<object>} scores - Array of CVSS rating objects
 * @returns {object|null} Best rating object with score, severity, and method, or null
 */
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
/**
 * Extracts license names/IDs from license objects
 * @param {Array<object>} licenses - Array of license objects
 * @returns {Array<string>} Array of license names/IDs
 */
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
/**
 * Counts vulnerabilities by severity level
 * @param {Array<object>} items - Array of vulnerability items
 * @returns {object} Object with severity counts (CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN)
 */
function countSeverities(items) {
  const init = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0, UNKNOWN:0 };
  return items.reduce((acc, it) => {
    const s = (it.severity || "UNKNOWN").toUpperCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, init);
}

/**
 * Validates that a JSON object has the structure of a CycloneDX BOM
 * @param {object} json - JSON object to validate
 * @returns {{valid: boolean, error?: string}} Validation result
 */
function validateCycloneDX(json) {
  if (!json || typeof json !== 'object') {
    return { valid: false, error: 'Invalid JSON: not an object' };
  }
  
  // Check for required CycloneDX fields (bomFormat and specVersion)
  if (!json.bomFormat && !json.specVersion) {
    // Allow files without these if they have vulnerabilities or components
    if (!json.vulnerabilities && !json.components) {
      return { valid: false, error: 'Invalid CycloneDX: missing bomFormat/specVersion and no vulnerabilities/components' };
    }
  }
  
  return { valid: true };
}

/**
 * Indexes a CycloneDX BOM and extracts vulnerability data
 * @param {object} json - CycloneDX BOM JSON object
 * @param {string} datasetId - Dataset identifier for this BOM
 * @param {string} filePath - File path (for error messages)
 * @returns {object} Object with dataset info, component count, vulnerability count, and items array
 * @throws {Error} If BOM structure is invalid
 */
function indexCycloneDX(json, datasetId, filePath = '') {
  // Validate structure
  const validation = validateCycloneDX(json);
  if (!validation.valid) {
    throw new Error(`Invalid CycloneDX file ${filePath}: ${validation.error}`);
  }

  const componentMap = new Map();
  const components = Array.isArray(json.components) ? json.components : [];
  
  components.forEach((c, idx) => {
    if (!c || typeof c !== 'object') {
      console.warn(`  Warning: Invalid component at index ${idx} in ${filePath}`);
      return;
    }
    try {
      const key = c["bom-ref"] || c["bomRef"] || c.purl || `${c.name || "component"}@${c.version || ""}`;
      componentMap.set(key, c);
    } catch (error) {
      console.warn(`  Warning: Failed to process component at index ${idx}: ${error.message}`);
    }
  });

  const vuls = [];
  const vulnerabilities = Array.isArray(json.vulnerabilities) ? json.vulnerabilities : [];
  
  for (let idx = 0; idx < vulnerabilities.length; idx++) {
    const v = vulnerabilities[idx];
    if (!v || typeof v !== 'object') {
      console.warn(`  Warning: Invalid vulnerability at index ${idx} in ${filePath}`);
      continue;
    }
    
    try {
      const affects = Array.isArray(v.affects) ? v.affects.map(a => a?.ref).filter(Boolean) : [];
      const rating = pickCVSS(Array.isArray(v.ratings) ? v.ratings : (Array.isArray(v.cvss) ? v.cvss : []));
      const sev = (v.severity || rating?.severity || "UNKNOWN").toUpperCase();

      const targets = affects.length > 0 ? affects : [null];
      for (const ref of targets) {
        const c = ref ? (componentMap.get(ref) || {}) : {};
        const lic = licenseNames(Array.isArray(c.licenses) ? c.licenses : []);
        
        vuls.push({
          dataset: datasetId,
          id: v.id || null,
          title: (v.description && typeof v.description === 'string') ? v.description.slice(0, 200) : "Vulnerability",
          severity: sev,
          severityRank: severityOrder(sev),
          cvss: rating?.score ?? null,
          component: c.name || null,
          version: c.version || null,
          purl: c.purl || null,
          licenses: lic,
          direct: (c.scope || "").toLowerCase() !== "optional" && (c.scope || "").toLowerCase() !== "transitive",
          cwes: Array.isArray(v.cwes) ? v.cwes.map(x => x?.id || x).filter(Boolean) : [],
          urls: Array.isArray(v.references) ? v.references.map(r => r?.url).filter(Boolean) : [],
          fixedVersions: Array.isArray(v.analysis?.response) && v.analysis.response.includes("update") ? ["*"] : []
        });
      }
    } catch (error) {
      console.warn(`  Warning: Failed to process vulnerability at index ${idx} in ${filePath}: ${error.message}`);
    }
  }

  return {
    dataset: datasetId,
    created: json.metadata?.timestamp || null,
    components: components.length,
    vulnerabilities: vuls.length,
    items: vuls
  };
}

/**
 * Builds a list of top CVEs by count and severity
 * @param {Array<object>} items - Array of vulnerability items
 * @returns {Array<object>} Array of top 10 CVE objects with id, count, datasets, maxCVSS, worstSeverityRank
 */
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

/**
 * Main function: scans for CycloneDX files, parses them, and generates parse-sboms.json
 * @throws {Error} If fatal error occurs during processing
 */
function main() {
  try {
    // Check if SBOMs directory exists
    if (!fs.existsSync(SBOMS_DIR)) {
      throw new Error(`SBOMs directory not found: ${SBOMS_DIR}. Run sync:sboms first.`);
    }

    const now = new Date().toISOString();
    console.log(`Scanning for CycloneDX files in ${SBOMS_DIR}...`);

    let files;
    try {
      files = globSync("**/*.cyclonedx.json", { cwd: SBOMS_DIR, absolute: true, nodir: true });
    } catch (globError) {
      throw new Error(`Failed to scan for SBOM files: ${globError.message}`);
    }

    if (files.length === 0) {
      console.warn(`Warning: No *.cyclonedx.json files found in ${SBOMS_DIR}`);
      // Create empty snapshot
      const emptySnapshot = {
        generatedAt: now,
        datasets: [],
        items: [],
        overall: { total: 0, severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 } },
        metrics: { fixAvailabilityRate: 0, topCVEs: [] }
      };
      writeJSON(OUT_FILE, emptySnapshot);
      console.log(`Created empty snapshot at ${OUT_FILE}`);
      return;
    }

    console.log(`Found ${files.length} file(s) to process.\n`);

    const datasets = [];
    const errors = [];
    let processedCount = 0;

    for (const f of files) {
      try {
        const json = readJSON(f);
        if (!json) {
          errors.push({ file: f, error: 'Failed to read or parse JSON' });
          continue;
        }

        const rel = path.relative(SBOMS_DIR, f).replace(/\\/g, "/");
        const datasetId = rel.split("/")[0] || 'unknown';
        
        console.log(`Processing: ${rel}`);
        const result = indexCycloneDX(json, datasetId, rel);
        datasets.push(result);
        processedCount++;
        console.log(`  ✓ ${result.vulnerabilities} vulnerabilities, ${result.components} components\n`);
      } catch (error) {
        const errorMsg = error.message || String(error);
        console.error(`  ✗ Error processing ${f}: ${errorMsg}\n`);
        errors.push({ file: f, error: errorMsg });
      }
    }

    if (datasets.length === 0) {
      throw new Error('No valid SBOM files were processed. Check errors above.');
    }

    console.log(`Successfully processed ${processedCount} of ${files.length} file(s).`);
    if (errors.length > 0) {
      console.warn(`\nWarnings (${errors.length} file(s) failed):`);
      errors.forEach(({ file, error }) => {
        console.warn(`  - ${path.relative(SBOMS_DIR, file)}: ${error}`);
      });
    }

    const items = datasets.flatMap(d => d.items);

    const datasetSummaries = datasets.map(d => ({
      id: d.dataset,
      created: d.created,
      components: d.components,
      vulnerabilities: d.vulnerabilities,
      severityCounts: countSeverities(d.items)
    })).sort((a, b) => String(a.id).localeCompare(String(b.id)));

    const overallSeverity = countSeverities(items);
    const fixAvailRate = items.length > 0 
      ? Math.round(100 * (items.filter(it => (it.fixedVersions || []).length > 0).length / items.length)) 
      : 0;
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

    // Validate snapshot before writing
    if (!Array.isArray(snapshot.items) || !Array.isArray(snapshot.datasets)) {
      throw new Error('Invalid snapshot structure generated');
    }

    writeJSON(OUT_FILE, snapshot);
    console.log(`\n✓ Wrote ${OUT_FILE}`);
    console.log(`  - ${items.length} vulnerability record(s) across ${datasets.length} dataset(s)`);
    console.log(`  - Severity breakdown: CRITICAL=${overallSeverity.CRITICAL}, HIGH=${overallSeverity.HIGH}, MEDIUM=${overallSeverity.MEDIUM}, LOW=${overallSeverity.LOW}`);
    
    if (errors.length > 0) {
      process.exit(0); // Partial success
    }
  } catch (error) {
    console.error(`\nFatal error: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  }
}

main();
