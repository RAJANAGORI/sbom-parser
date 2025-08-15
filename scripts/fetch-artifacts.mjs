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

// const octokit = new Octokit({ auth: TOKEN });
// const ROOT = process.cwd();
// const SBOMS_DIR = path.join(ROOT, "sboms");
// const MANIFEST = path.join(SBOMS_DIR, "manifest.json");

// function readManifest() {
//   if (!fs.existsSync(MANIFEST)) {
//     console.error(`Missing ${MANIFEST}.`);
//     process.exit(1);
//   }
//   const j = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
//   if (!Array.isArray(j.artifacts)) {
//     console.error("manifest.artifacts must be an array.");
//     process.exit(1);
//   }
//   return j.artifacts;
// }

// async function findNewestArtifactByName(name) {
//   let newest = null, page = 1;
//   for (;;) {
//     const { data } = await octokit.actions.listArtifactsForRepo({
//       owner: OWNER, repo: REPO, per_page: 100, page
//     });
//     const arr = data.artifacts || [];
//     for (const a of arr) {
//       if (a.name === name && !a.expired) {
//         if (!newest || new Date(a.created_at) > new Date(newest.created_at)) newest = a;
//       }
//     }
//     if (arr.length < 100) break;
//     page++;
//   }
//   return newest;
// }

// // IMPORTANT: download without Authorization header to the Azure blob SAS URL
// async function downloadZip(artifactId, outFile) {
//   // ask GitHub for pre-signed redirect
//   const resp = await octokit.request(
//     "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}",
//     { owner: OWNER, repo: REPO, artifact_id: artifactId, archive_format: "zip", request: { redirect: "manual" } }
//   );
//   const location = resp.headers?.location || resp.url || resp.data?.url;
//   if (!location) throw new Error("No Location header for artifact download");

//   const blobRes = await fetch(location); // NO auth header!
//   if (!blobRes.ok) {
//     const text = await blobRes.text().catch(()=> "");
//     throw new Error(`Blob download failed: ${blobRes.status} ${blobRes.statusText} ${text.slice(0,200)}`);
//   }
//   const ab = await blobRes.arrayBuffer();
//   fs.writeFileSync(outFile, Buffer.from(ab));
// }

// async function main() {
//   const items = readManifest();
//   if (!fs.existsSync(SBOMS_DIR)) fs.mkdirSync(SBOMS_DIR, { recursive: true });

//   for (const { name, dataset } of items) {
//     if (!name || !dataset) { console.warn("Bad manifest entry:", { name, dataset }); continue; }

//     console.log(`\nArtifact: ${name}`);
//     const art = await findNewestArtifactByName(name);
//     if (!art) { console.error(`Not found/expired: ${name}`); continue; }

//     const tmp = path.join(ROOT, `${name}.zip`);
//     console.log(`Downloading #${art.id} → ${tmp}`);
//     await downloadZip(art.id, tmp);

//     const targetDir = path.join(SBOMS_DIR, dataset);
//     fs.mkdirSync(targetDir, { recursive: true });
//     for (const f of fs.existsSync(targetDir) ? fs.readdirSync(targetDir) : []) {
//       fs.rmSync(path.join(targetDir, f), { recursive: true, force: true });
//     }

//     console.log(`Unzipping → ${targetDir}`);
//     new AdmZip(tmp).extractAllTo(targetDir, true);
//     fs.rmSync(tmp, { force: true });

//     const cyclonedx = fs.readdirSync(targetDir).filter(f => f.endsWith(".cyclonedx.json"));
//     if (!cyclonedx.length) console.warn(`No *.cyclonedx.json found inside ${name}.zip`);
//     else console.log(`Found: ${cyclonedx.join(", ")}`);
//   }

//   console.log("\nSync complete.");
// }

// main().catch(err => { console.error("Sync failed:", err); process.exit(1); });



const octokit = new Octokit({ auth: TOKEN });

const ROOT = path.join(__dirname, "..");
const SBOMS_DIR = path.join(ROOT, "sboms");
fs.mkdirSync(SBOMS_DIR, { recursive: true });

function sh(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { ...opts }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      resolve(stdout);
    });
  });
}

function inferDataset(artifactName) {
  // e.g. trivy-scan-results-ghcr_io_rajanagori_nightingale_stable
  const parts = artifactName.split("_");
  return parts[parts.length - 1]; // "stable", "arm64", etc.
}

async function downloadArtifactZip(artifact) {
  // GitHub returns the zip bytes for this route
  const { data } = await octokit.request(
    "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}",
    { owner: OWNER, repo: REPO, artifact_id: artifact.id, archive_format: "zip" }
  );
  const buf = Buffer.from(data);
  const zpath = path.join(ROOT, `${artifact.name}.zip`);
  fs.writeFileSync(zpath, buf);
  return zpath;
}

async function main() {
  console.log(`Listing artifacts from ${OWNER}/${REPO}…`);
  const arts = [];
  let page = 1;
  while (true) {
    const { data } = await octokit.actions.listArtifactsForRepo({
      owner: OWNER, repo: REPO, per_page: 100, page
    });
    arts.push(...data.artifacts);
    if (data.artifacts.length < 100) break;
    page++;
  }

  const wanted = arts
    .filter(a => a.name.startsWith("trivy-scan-results-") && !a.expired);

  if (!wanted.length) {
    console.log("No matching artifacts found.");
    return;
  }

  for (const a of wanted) {
    const dataset = inferDataset(a.name);
    const destDir = path.join(SBOMS_DIR, dataset);
    fs.mkdirSync(destDir, { recursive: true });

    console.log(`Artifact: ${a.name} (#${a.id}) → dataset "${dataset}"`);
    const zipPath = await downloadArtifactZip(a);

    // Clean previous JSONs for this dataset
    for (const f of fs.readdirSync(destDir)) {
      if (f.endsWith(".cyclonedx.json")) fs.unlinkSync(path.join(destDir, f));
    }

    // Unzip ONLY the CycloneDX files into dataset dir (runner has 'unzip')
    await sh("unzip", ["-o", "-j", zipPath, "sbom-*.cyclonedx.json", "-d", destDir])
      .catch(async () => {
        // fallback to bsdtar if unzip isn't present
        await sh("bsdtar", ["-xf", zipPath, "-C", destDir, "--strip-components", "0", "sbom-*.cyclonedx.json"]);
      });

    fs.unlinkSync(zipPath);
    console.log(`  → extracted CycloneDX JSON(s) to sboms/${dataset}/`);
  }

  console.log("SBOM sync complete.");
}

main().catch(e => {
  console.error("Sync failed:", e);
  process.exit(1);
});