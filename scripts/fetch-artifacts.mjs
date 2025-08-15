#!/usr/bin/env node
/**
 * Pulls the exact .zip artifacts listed in sboms/manifest.json
 * from the Nightingale repo and unzips them into sboms/<dataset>/.
 */
import fs from "fs";
import path from "path";
import AdmZip from "adm-zip";
import { Octokit } from "@octokit/rest";

const OWNER = process.env.NIGHTINGALE_OWNER || "sidbhasin13";
const REPO  = process.env.NIGHTINGALE_REPO  || "nightingale";
const TOKEN = process.env.GH_TOKEN;

if (!TOKEN) {
  console.error("TOKEN is missing. Set it in GitHub Actions secrets (COMMON_PAT → TOKEN) or your shell.");
  process.exit(1);
}

const octokit = new Octokit({ auth: TOKEN });
const ROOT = process.cwd();
const SBOMS_DIR = path.join(ROOT, "sboms");
const MANIFEST = path.join(SBOMS_DIR, "manifest.json");

function readManifest() {
  if (!fs.existsSync(MANIFEST)) {
    console.error(`Missing ${MANIFEST}. Create it with an "artifacts" array (see example in script).`);
    process.exit(1);
  }
  try {
    const j = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
    if (!Array.isArray(j.artifacts)) throw new Error("manifest.artifacts must be an array");
    return j.artifacts;
  } catch (e) {
    console.error(`Failed to parse manifest: ${e.message}`);
    process.exit(1);
  }
}

async function findArtifactByName(name) {
  // List artifacts (paginated) and pick newest with that name
  const perPage = 100;
  let page = 1;
  let newest = null;

  for (;;) {
    const { data } = await octokit.actions.listArtifactsForRepo({
      owner: OWNER,
      repo: REPO,
      per_page: perPage,
      page
    });
    if (!data.artifacts?.length) break;

    for (const a of data.artifacts) {
      if (a.name === name) {
        if (!newest || new Date(a.created_at) > new Date(newest.created_at)) newest = a;
      }
    }
    if (data.artifacts.length < perPage) break;
    page++;
  }
  return newest;
}

async function downloadArtifactZip(artifactId, outPath) {
  const { url } = await octokit.request("GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}", {
    owner: OWNER,
    repo: REPO,
    artifact_id: artifactId,
    archive_format: "zip"
  });
  // Octokit returns the final buffer with .data for this endpoint too:
  const res = await octokit.request("GET " + url, { request: { decompress: false } });
  fs.writeFileSync(outPath, Buffer.from(res.data));
}

async function main() {
  const items = readManifest();
  if (!fs.existsSync(SBOMS_DIR)) fs.mkdirSync(SBOMS_DIR, { recursive: true });

  for (const { name, dataset } of items) {
    if (!name || !dataset) {
      console.warn(`Skipping invalid manifest entry: ${JSON.stringify({ name, dataset })}`);
      continue;
    }
    console.log(`\nLooking for artifact: ${name}`);
    const artifact = await findArtifactByName(name);
    if (!artifact) {
      console.error(`Not found: ${name}. Is it expired or named differently?`);
      continue;
    }
    if (artifact.expired) {
      console.error(`Artifact expired: ${name}. Re-run Nightingale to recreate it.`);
      continue;
    }

    const tmpZip = path.join(ROOT, `${name}.zip`);
    console.log(`Downloading artifact #${artifact.id} → ${tmpZip}`);
    await downloadArtifactZip(artifact.id, tmpZip);

    // Unzip into sboms/<dataset>/
    const targetDir = path.join(SBOMS_DIR, dataset);
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    // Clean target dir first (optional, keeps it tidy)
    for (const f of fs.readdirSync(targetDir)) {
      fs.rmSync(path.join(targetDir, f), { recursive: true, force: true });
    }

    console.log(`Unzipping → ${targetDir}`);
    const zip = new AdmZip(tmpZip);
    zip.extractAllTo(targetDir, true);

    // We only need CycloneDX JSON files under each dataset
    // Common names from your Trivy step: sbom-<IMAGE_NAME>.cyclonedx.json inside the zip.
    const files = fs.readdirSync(targetDir).filter(f => f.endsWith(".cyclonedx.json"));
    if (!files.length) {
      console.warn(`No *.cyclonedx.json found in ${name}.zip (check your Trivy step output).`);
    } else {
      console.log(`Found: ${files.join(", ")}`);
    }

    // Remove the temp zip
    fs.rmSync(tmpZip, { force: true });
  }

  console.log("\nSync complete.");
}

main().catch(err => {
  console.error("Sync failed:", err);
  process.exit(1);
});
