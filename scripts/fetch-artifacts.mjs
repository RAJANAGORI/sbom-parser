#!/usr/bin/env node
/**
 * Download .zip artifacts listed in sboms/manifest.json from NIGHTINGALE_OWNER/NIGHTINGALE_REPO
 * and unzip into sboms/<dataset>/.
 *
 * Env:
 *   TOKEN               - PAT with repo + actions:read on NIGHTINGALE_REPO
 *   NIGHTINGALE_OWNER   - default "sidbhasin13"
 *   NIGHTINGALE_REPO    - default "nightingale"
 */
import fs from "fs";
import path from "path";
import { Octokit } from "@octokit/rest";
import AdmZip from "adm-zip";

const OWNER = process.env.NIGHTINGALE_OWNER || "sidbhasin13";
const REPO  = process.env.NIGHTINGALE_REPO  || "nightingale";
const TOKEN = process.env.TOKEN;

if (!TOKEN) {
  console.error("TOKEN is missing. Map your secret (TOKEN_SBOM) to env TOKEN in the workflow.");
  process.exit(1);
}

const octokit = new Octokit({ auth: TOKEN });
const ROOT = process.cwd();
const SBOMS_DIR = path.join(ROOT, "sboms");
const MANIFEST = path.join(SBOMS_DIR, "manifest.json");

function readManifest() {
  if (!fs.existsSync(MANIFEST)) {
    console.error(`Missing ${MANIFEST}.`);
    process.exit(1);
  }
  const j = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  if (!Array.isArray(j.artifacts)) {
    console.error("manifest.artifacts must be an array.");
    process.exit(1);
  }
  return j.artifacts;
}

async function findNewestArtifactByName(name) {
  let newest = null, page = 1;
  for (;;) {
    const { data } = await octokit.actions.listArtifactsForRepo({
      owner: OWNER, repo: REPO, per_page: 100, page
    });
    const arr = data.artifacts || [];
    for (const a of arr) {
      if (a.name === name && !a.expired) {
        if (!newest || new Date(a.created_at) > new Date(newest.created_at)) newest = a;
      }
    }
    if (arr.length < 100) break;
    page++;
  }
  return newest;
}

// IMPORTANT: download without Authorization header to the Azure blob SAS URL
async function downloadZip(artifactId, outFile) {
  // ask GitHub for pre-signed redirect
  const resp = await octokit.request(
    "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}",
    { owner: OWNER, repo: REPO, artifact_id: artifactId, archive_format: "zip", request: { redirect: "manual" } }
  );
  const location = resp.headers?.location || resp.url || resp.data?.url;
  if (!location) throw new Error("No Location header for artifact download");

  const blobRes = await fetch(location); // NO auth header!
  if (!blobRes.ok) {
    const text = await blobRes.text().catch(()=> "");
    throw new Error(`Blob download failed: ${blobRes.status} ${blobRes.statusText} ${text.slice(0,200)}`);
  }
  const ab = await blobRes.arrayBuffer();
  fs.writeFileSync(outFile, Buffer.from(ab));
}

async function main() {
  const items = readManifest();
  if (!fs.existsSync(SBOMS_DIR)) fs.mkdirSync(SBOMS_DIR, { recursive: true });

  for (const { name, dataset } of items) {
    if (!name || !dataset) { console.warn("Bad manifest entry:", { name, dataset }); continue; }

    console.log(`\nArtifact: ${name}`);
    const art = await findNewestArtifactByName(name);
    if (!art) { console.error(`Not found/expired: ${name}`); continue; }

    const tmp = path.join(ROOT, `${name}.zip`);
    console.log(`Downloading #${art.id} → ${tmp}`);
    await downloadZip(art.id, tmp);

    const targetDir = path.join(SBOMS_DIR, dataset);
    fs.mkdirSync(targetDir, { recursive: true });
    for (const f of fs.existsSync(targetDir) ? fs.readdirSync(targetDir) : []) {
      fs.rmSync(path.join(targetDir, f), { recursive: true, force: true });
    }

    console.log(`Unzipping → ${targetDir}`);
    new AdmZip(tmp).extractAllTo(targetDir, true);
    fs.rmSync(tmp, { force: true });

    const cyclonedx = fs.readdirSync(targetDir).filter(f => f.endsWith(".cyclonedx.json"));
    if (!cyclonedx.length) console.warn(`No *.cyclonedx.json found inside ${name}.zip`);
    else console.log(`Found: ${cyclonedx.join(", ")}`);
  }

  console.log("\nSync complete.");
}

main().catch(err => { console.error("Sync failed:", err); process.exit(1); });
