#!/usr/bin/env node
/**
 * scripts/fetch-artifacts.js
 * Pull allowed Trivy artifacts (ZIPs) from RAJANAGORI/Nightingale and unzip them under sboms/<name>/
 * Requires env: NIGHTINGALE_TOKEN
 */
import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import https from "https";
import AdmZip from "adm-zip";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const NIGHTINGALE_OWNER = "RAJANAGORI";
const NIGHTINGALE_REPO  = "Nightingale";
const OUT_DIR = path.join(__dirname, "..", "sboms");
const MANIFEST = path.join(OUT_DIR, "manifest.json");
const GH_TOKEN = process.env.NIGHTINGALE_TOKEN;

if (!GH_TOKEN) {
  console.error("Missing NIGHTINGALE_TOKEN repo secret.");
  process.exit(1);
}

function log(...a){ console.log(...a); }

function ghGet(url, accept = "application/vnd.github+json") {
  return new Promise((resolve, reject) => {
    https.get(url, {
      headers: {
        "User-Agent": "sbom-parser-sync",
        "Authorization": `Bearer ${GH_TOKEN}`,
        "Accept": accept
      }
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        ghGet(res.headers.location, "*/*").then(resolve, reject); // follow redirects
        return;
      }
      const chunks = [];
      res.on("data", c => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    }).on("error", reject);
  });
}

function getAllowList() {
  if (fs.existsSync(MANIFEST)) {
    const j = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
    const arts = Array.isArray(j.artifacts) ? j.artifacts : [];
    return arts;
  }
  const zips = fs.existsSync(OUT_DIR) ? fs.readdirSync(OUT_DIR).filter(f => f.endsWith(".zip")) : [];
  return zips.map(z => path.basename(z, ".zip"));
}

function unzipUsingSystem(zipPath, destDir) {
  try {
    execSync(`unzip -o "${zipPath}" -d "${destDir}"`, { stdio: "inherit" });
    return true;
  } catch {
    return false;
  }
}

function unzipUsingLib(zipPath, destDir) {
  const zip = new AdmZip(zipPath);
  zip.extractAllTo(destDir, true);
}

(async () => {
  const allow = getAllowList();
  if (!allow.length) {
    log("No allowed artifact names (empty allow-list). Nothing to do.");
    process.exit(0);
  }
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

  const listUrl = `https://api.github.com/repos/${NIGHTINGALE_OWNER}/${NIGHTINGALE_REPO}/actions/artifacts?per_page=100`;
  const { status, body } = await ghGet(listUrl);
  if (status !== 200) {
    console.error("Artifact list failed:", status, body.toString());
    process.exit(1);
  }
  const { artifacts } = JSON.parse(body.toString());

  for (const want of allow) {
    // exact artifact name match (recommended)
    const hit = artifacts.find(a => a.name === want && !a.expired);
    if (!hit) { log(`Not found or expired: ${want}`); continue; }

    const zipPath = path.join(OUT_DIR, `${hit.name}.zip`);
    const destDir = path.join(OUT_DIR, hit.name);
    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });

    log(`Download ${hit.name} (#${hit.id})`);
    const dl = await ghGet(hit.archive_download_url, "application/octet-stream");
    if (dl.status !== 200) { console.error("Download failed", dl.status); continue; }
    fs.writeFileSync(zipPath, dl.body);

    log(`Unpack → ${destDir}`);
    const ok = unzipUsingSystem(zipPath, destDir);
    if (!ok) unzipUsingLib(zipPath, destDir);
  }

  log("Sync complete.");
})();
