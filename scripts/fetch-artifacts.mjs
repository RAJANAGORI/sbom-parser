#!/usr/bin/env node
/**
 * @fileoverview Fetches SBOM artifacts from GitHub Actions and extracts CycloneDX JSON files
 * @module fetch-artifacts
 * 
 * Environment Variables (set in GH Actions):
 *   TOKEN               - PAT with repo + actions:read on NIGHTINGALE_REPO (e.g., secrets.TOKEN_SBOM)
 *   NIGHTINGALE_OWNER   - default "rajanagori"
 *   NIGHTINGALE_REPO    - default "nightingale"
 */
import fs from "fs";
import path from "path";
import { Octokit } from "@octokit/rest";
import AdmZip from "adm-zip";

const OWNER = process.env.NIGHTINGALE_OWNER || "rajanagori";
const REPO  = process.env.NIGHTINGALE_REPO  || "nightingale";
const TOKEN = process.env.TOKEN;

if (!TOKEN) {
  console.error("TOKEN is missing. Map your secret (TOKEN_SBOM) to env TOKEN in the workflow.");
  process.exit(1);
}

// Security: Never log or expose token
// Validate token format (GitHub tokens start with ghp_ or are 40 char hex)
if (TOKEN.length < 20) {
  console.error("Invalid token format detected.");
  process.exit(1);
}

const octokit = new Octokit({ auth: TOKEN });
const ROOT = process.cwd();
const SBOMS_DIR = path.join(ROOT, "sboms"); // ephemeral workspace folder
const ARTIFACTS_JSON = path.join(ROOT, "artifacts.json");

/**
 * Reads and validates the artifacts.json configuration file (raw config)
 * Does NOT perform any GitHub calls or auto-discovery.
 * @returns {object} Parsed configuration object
 * @throws {Error} If file is missing, empty, or has invalid structure
 */
function readArtifactsConfig() {
  try {
    if (!fs.existsSync(ARTIFACTS_JSON)) {
      throw new Error(`Missing ${ARTIFACTS_JSON}.`);
    }
    const content = fs.readFileSync(ARTIFACTS_JSON, "utf8");
    if (!content || content.trim().length === 0) {
      throw new Error(`${ARTIFACTS_JSON} is empty.`);
    }
    let j;
    try {
      j = JSON.parse(content);
    } catch (parseError) {
      throw new Error(`Invalid JSON in ${ARTIFACTS_JSON}: ${parseError.message}`);
    }
    if (!j || typeof j !== "object") {
      throw new Error(`${ARTIFACTS_JSON} must contain a JSON object.`);
    }
    return j;
  } catch (error) {
    console.error(`Error reading artifacts config: ${error.message}`);
    process.exit(1);
  }
}

/**
 * Auto-discovers artifacts from GitHub Actions based on a naming convention.
 * This removes the need to manually list every artifact in artifacts.json.
 *
 * Expected config shape (in artifacts.json):
 * {
 *   "autoDiscover": true,
 *   "prefix": "trivy-scan-results-ghcr_io_rajanagori_nightingale_"
 * }
 *
 * @param {object} cfg - Parsed artifacts.json config
 * @returns {Promise<Array<{name: string, dataset: string}>>}
 */
async function autoDiscoverArtifacts(cfg) {
  const prefix =
    typeof cfg.prefix === "string" && cfg.prefix.trim().length > 0
      ? cfg.prefix.trim()
      : "trivy-scan-results-";

  // Require a specific workflow file so we ONLY process artifacts
  // coming from that Trivy workflow's latest run.
  if (typeof cfg.workflowFile !== "string" || !cfg.workflowFile.trim()) {
    throw new Error(
      "artifacts.json must define 'workflowFile' when autoDiscover is true so that only Trivy scan artifacts are processed."
    );
  }

  const workflowFile = cfg.workflowFile.trim();
  let workflowRunIdFilter = null;
  try {
    const { data } = await octokit.actions.listWorkflowRuns({
      owner: OWNER,
      repo: REPO,
      workflow_id: workflowFile,
      per_page: 1,
    });
    const latest = data?.workflow_runs?.[0];
    if (!latest) {
      throw new Error(
        `No workflow runs found for workflow file "${workflowFile}".`
      );
    }
    workflowRunIdFilter = latest.id;
    console.log(
      `Restricting auto-discovery to artifacts from workflow "${workflowFile}" latest run #${latest.run_number} (id ${latest.id}).`
    );
  } catch (e) {
    throw new Error(
      `Failed to resolve latest workflow run for "${workflowFile}": ${e.message}`
    );
  }

  console.log(
    `Auto-discovering artifacts from ${OWNER}/${REPO} with prefix "${prefix}"...`
  );

  const byName = new Map();
  let page = 1;

  for (;;) {
    const { data } = await octokit.actions.listArtifactsForRepo({
      owner: OWNER,
      repo: REPO,
      per_page: 100,
      page,
    });

    if (!data || !Array.isArray(data.artifacts)) {
      throw new Error(
        "Invalid response from GitHub API while auto-discovering artifacts"
      );
    }

    const arr = data.artifacts || [];
    for (const a of arr) {
      if (!a || typeof a.name !== "string") continue;
      if (!a.name.startsWith(prefix)) continue;
      if (a.expired) continue;
      if (
        workflowRunIdFilter &&
        (!a.workflow_run || a.workflow_run.id !== workflowRunIdFilter)
      ) {
        continue;
      }

      const existing = byName.get(a.name);
      if (!existing || new Date(a.created_at) > new Date(existing.created_at)) {
        const dataset = a.name.slice(prefix.length) || a.name;
        byName.set(a.name, { name: a.name, dataset });
      }
    }

    if (arr.length < 100) break;
    page++;
    if (page > 100) {
      console.warn(
        "Warning: Reached page limit (100) while auto-discovering artifacts."
      );
      break;
    }
  }

  const items = Array.from(byName.values());
  if (!items.length) {
    console.warn(
      "Warning: Auto-discovery did not find any matching artifacts. Check prefix, workflowFile, and repository settings."
    );
  } else {
    console.log(
      `Auto-discovered ${items.length} artifact(s): ${items
        .map((i) => `${i.name} → dataset "${i.dataset}"`)
        .join(", ")}`
    );
  }

  return items;
}

/**
 * Resolves the list of artifacts to process, either from explicit config
 * (artifacts array) or via auto-discovery if enabled.
 * @returns {Promise<Array<{name: string, dataset: string}>>}
 */
async function resolveArtifactsList() {
  const cfg = readArtifactsConfig();

  // Auto-discovery path
  if (cfg.autoDiscover === true) {
    return await autoDiscoverArtifacts(cfg);
  }

  // Backwards-compatible explicit configuration path
  if (!Array.isArray(cfg.artifacts)) {
    throw new Error("artifacts.json: 'artifacts' must be an array.");
  }
  if (cfg.artifacts.length === 0) {
    console.warn("Warning: artifacts.json contains an empty artifacts array.");
  }
  return cfg.artifacts;
}

/**
 * Finds the newest non-expired artifact by name from GitHub Actions
 * @param {string} name - Artifact name to search for
 * @param {number} retries - Number of retry attempts for server errors (default: 3)
 * @returns {Promise<object|null>} Artifact object or null if not found
 * @throws {Error} If repository not found, access denied, or other API errors
 */
async function findNewestArtifactByName(name, retries = 3) {
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    throw new Error('Invalid artifact name provided');
  }
  
  let newest = null, page = 1, lastError = null;
  
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      for (;;) {
        const { data } = await octokit.actions.listArtifactsForRepo({ 
          owner: OWNER, 
          repo: REPO, 
          per_page: 100, 
          page 
        });
        
        if (!data || !Array.isArray(data.artifacts)) {
          throw new Error('Invalid response from GitHub API: missing artifacts array');
        }
        
        const arr = data.artifacts || [];
        for (const a of arr) {
          if (a.name === name && !a.expired) {
            if (!newest || new Date(a.created_at) > new Date(newest.created_at)) {
              newest = a;
            }
          }
        }
        
        if (arr.length < 100) break;
        page++;
        
        // Safety limit: prevent infinite loops
        if (page > 100) {
          console.warn(`Warning: Reached page limit (100) while searching for artifact: ${name}`);
          break;
        }
      }
      return newest;
    } catch (error) {
      lastError = error;
      if (error.status === 404) {
        // Repository not found or no access
        throw new Error(`Repository ${OWNER}/${REPO} not found or access denied. Check token permissions.`);
      }
      if (error.status === 403) {
        throw new Error(`Access forbidden. Check token has 'actions:read' permission for ${OWNER}/${REPO}.`);
      }
      if (error.status >= 500) {
        // Server error, retry
        if (attempt < retries - 1) {
          const waitTime = Math.pow(2, attempt) * 1000; // Exponential backoff
          console.warn(`GitHub API error (${error.status}), retrying in ${waitTime}ms... (attempt ${attempt + 1}/${retries})`);
          await new Promise(resolve => setTimeout(resolve, waitTime));
          continue;
        }
      }
      throw error;
    }
  }
  
  throw lastError || new Error('Failed to find artifact after retries');
}

/**
 * Downloads a GitHub Actions artifact as a ZIP file
 * @param {number} artifactId - GitHub artifact ID
 * @param {string} outFile - Output file path for the ZIP
 * @param {number} retries - Number of retry attempts for server errors (default: 3)
 * @returns {Promise<void>}
 * @throws {Error} If download fails, file is invalid, or artifact expired
 */
async function downloadZip(artifactId, outFile, retries = 3) {
  if (!artifactId || typeof artifactId !== 'number') {
    throw new Error('Invalid artifact ID provided');
  }
  
  let lastError = null;
  
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const resp = await octokit.request(
        "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}",
        { 
          owner: OWNER, 
          repo: REPO, 
          artifact_id: artifactId, 
          archive_format: "zip", 
          request: { redirect: "manual" } 
        }
      );
      
      const location = resp.headers?.location || resp.url || resp.data?.url;
      if (!location) {
        throw new Error("No Location header for artifact download. Artifact may be expired or inaccessible.");
      }

      const blobRes = await fetch(location); // NO auth header!
      if (!blobRes.ok) {
        const text = await blobRes.text().catch(() => "");
        const errorMsg = `Blob download failed: ${blobRes.status} ${blobRes.statusText}`;
        if (blobRes.status === 410) {
          throw new Error(`Artifact ${artifactId} has expired or been deleted. ${errorMsg}`);
        }
        if (blobRes.status >= 500 && attempt < retries - 1) {
          // Server error, retry
          const waitTime = Math.pow(2, attempt) * 1000;
          console.warn(`Download error (${blobRes.status}), retrying in ${waitTime}ms... (attempt ${attempt + 1}/${retries})`);
          await new Promise(resolve => setTimeout(resolve, waitTime));
          continue;
        }
        throw new Error(`${errorMsg} ${text.slice(0, 200)}`);
      }
      
      const ab = await blobRes.arrayBuffer();
      if (!ab || ab.byteLength === 0) {
        throw new Error('Downloaded file is empty');
      }
      
      // Validate it's actually a zip file (starts with PK)
      const buffer = Buffer.from(ab);
      if (buffer.length < 4 || buffer[0] !== 0x50 || buffer[1] !== 0x4B) {
        throw new Error('Downloaded file does not appear to be a valid ZIP archive');
      }
      
      fs.writeFileSync(outFile, buffer);
      return; // Success
    } catch (error) {
      lastError = error;
      if (error.status === 404 || error.status === 410) {
        // Don't retry on not found/expired
        throw error;
      }
      if (attempt < retries - 1 && error.status >= 500) {
        continue; // Will retry
      }
      throw error;
    }
  }
  
  throw lastError || new Error('Failed to download artifact after retries');
}

/**
 * Main function: processes all artifacts from artifacts.json
 * Downloads, extracts, and validates SBOM files
 * @returns {Promise<void>}
 * @throws {Error} If fatal error occurs
 */
async function main() {
  let successCount = 0;
  let errorCount = 0;
  const errors = [];

  try {
    const items = await resolveArtifactsList();
    if (!fs.existsSync(SBOMS_DIR)) {
      fs.mkdirSync(SBOMS_DIR, { recursive: true });
    }

    if (items.length === 0) {
      console.warn("Warning: No artifacts to process.");
      return;
    }

    console.log(`Processing ${items.length} artifact(s)...\n`);

    for (const { name, dataset } of items) {
      if (!name || !dataset) {
        const error = `Bad artifacts.json entry: missing name or dataset`;
        console.warn(`Warning: ${error}`);
        errors.push({ artifact: name || 'unknown', error });
        errorCount++;
        continue;
      }

      try {
        console.log(`Artifact: ${name} (dataset: ${dataset})`);
        
        const art = await findNewestArtifactByName(name);
        if (!art) {
          const error = `Not found or expired: ${name}`;
          console.error(`Error: ${error}`);
          errors.push({ artifact: name, error });
          errorCount++;
          continue;
        }

        const tmp = path.join(ROOT, `${name}.zip`);
        console.log(`  Downloading artifact #${art.id} → ${tmp}`);
        
        try {
          await downloadZip(art.id, tmp);
        } catch (downloadError) {
          const error = `Download failed: ${downloadError.message}`;
          console.error(`  Error: ${error}`);
          errors.push({ artifact: name, error });
          errorCount++;
          continue;
        }

        const targetDir = path.join(SBOMS_DIR, dataset);
        try {
          fs.mkdirSync(targetDir, { recursive: true });
          
          // Clean existing files
          if (fs.existsSync(targetDir)) {
            const existingFiles = fs.readdirSync(targetDir);
            for (const f of existingFiles) {
              try {
                fs.rmSync(path.join(targetDir, f), { recursive: true, force: true });
              } catch (cleanError) {
                console.warn(`  Warning: Failed to clean existing file ${f}: ${cleanError.message}`);
              }
            }
          }
        } catch (dirError) {
          throw new Error(`Failed to create/clean target directory: ${dirError.message}`);
        }

        console.log(`  Unzipping → ${targetDir}`);
        try {
          const zip = new AdmZip(tmp);
          zip.extractAllTo(targetDir, true);
        } catch (zipError) {
          throw new Error(`Failed to extract ZIP: ${zipError.message}`);
        } finally {
          // Always clean up temp file
          try {
            if (fs.existsSync(tmp)) {
              fs.rmSync(tmp, { force: true });
            }
          } catch (cleanupError) {
            console.warn(`  Warning: Failed to remove temp file: ${cleanupError.message}`);
          }
        }

        // Verify extraction
        let cyclonedx = [];
        try {
          if (fs.existsSync(targetDir)) {
            cyclonedx = fs.readdirSync(targetDir).filter(f => f.endsWith(".cyclonedx.json"));
          }
        } catch (readError) {
          console.warn(`  Warning: Failed to read extracted files: ${readError.message}`);
        }

        if (!cyclonedx.length) {
          console.warn(`  Warning: No *.cyclonedx.json files found inside ${name}.zip`);
        } else {
          console.log(`  Found: ${cyclonedx.join(", ")}`);
        }

        successCount++;
        console.log(`  ✓ Success\n`);
      } catch (error) {
        const errorMsg = error.message || String(error);
        console.error(`  Error processing ${name}: ${errorMsg}`);
        errors.push({ artifact: name, error: errorMsg });
        errorCount++;
      }
    }

    // Summary
    console.log("\n" + "=".repeat(50));
    console.log(`Sync complete: ${successCount} succeeded, ${errorCount} failed`);
    if (errors.length > 0) {
      console.log("\nErrors:");
      errors.forEach(({ artifact, error }) => {
        console.log(`  - ${artifact}: ${error}`);
      });
    }
    console.log("=".repeat(50) + "\n");

    // Exit with error code if any failures
    if (errorCount > 0 && successCount === 0) {
      process.exit(1); // All failed
    } else if (errorCount > 0) {
      process.exit(0); // Partial success (warn but don't fail)
    }
  } catch (error) {
    console.error(`\nFatal error: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  }
}

main().catch(err => {
  console.error("\nSync failed with unhandled error:", err);
  console.error(err.stack);
  process.exit(1);
});
