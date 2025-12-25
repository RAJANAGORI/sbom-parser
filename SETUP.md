# Setup Guide

This guide will walk you through setting up the SBOM Parser project from scratch.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** 20.x or higher ([Download](https://nodejs.org/))
- **npm** (comes with Node.js) or **yarn**
- **Git** (for cloning the repository)
- **GitHub Personal Access Token** (for fetching artifacts)

### Verify Installation

```bash
node --version  # Should be v20.x or higher
npm --version   # Should be 9.x or higher
git --version   # Any recent version
```

## Step 1: Clone/Download the Project

If you have the project in a Git repository:

```bash
git clone <repository-url>
cd sbom-parser
```

Or if you already have the project files, navigate to the project directory:

```bash
cd /path/to/sbom-parser
```

## Step 2: Install Dependencies

Install all required npm packages:

```bash
npm install
```

This will install:
- `@octokit/rest` - GitHub API client
- `adm-zip` - ZIP file extraction
- `glob` - File pattern matching
- `vitest` - Testing framework (dev dependency)
- `@vitest/ui` - Test UI (dev dependency)
- `@vitest/coverage-v8` - Code coverage (dev dependency)

## Step 3: Configure GitHub Access

### Create GitHub Personal Access Token

1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Give it a name (e.g., "SBOM Parser")
4. Select scopes:
   - ✅ `repo` (Full control of private repositories)
   - ✅ `actions:read` (Read access to Actions)
5. Click "Generate token"
6. **Copy the token immediately** (you won't see it again!)

### Set Environment Variables

#### For Local Development

**macOS/Linux:**
```bash
export TOKEN="ghp_your_token_here"
export NIGHTINGALE_OWNER="rajanagori"  # Optional, defaults to this
export NIGHTINGALE_REPO="nightingale"   # Optional, defaults to this
```

**Windows (PowerShell):**
```powershell
$env:TOKEN="ghp_your_token_here"
$env:NIGHTINGALE_OWNER="rajanagori"
$env:NIGHTINGALE_REPO="nightingale"
```

**Windows (CMD):**
```cmd
set TOKEN=ghp_your_token_here
set NIGHTINGALE_OWNER=rajanagori
set NIGHTINGALE_REPO=nightingale
```

#### For GitHub Actions (CI/CD)

1. Go to your repository → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `TOKEN_SBOM`
4. Value: Your GitHub Personal Access Token
5. Click "Add secret"

The workflow will automatically use this secret.

## Step 4: Configure Artifacts

Edit `artifacts.json` to specify which GitHub Actions artifacts to fetch:

```json
{
  "artifacts": [
    { 
      "name": "trivy-scan-results-ghcr_io_rajanagori_nightingale_stable", 
      "dataset": "stable" 
    },
    { 
      "name": "trivy-scan-results-ghcr_io_rajanagori_nightingale_arm64", 
      "dataset": "arm64" 
    }
  ]
}
```

**Format:**
- `name`: Exact name of the GitHub Actions artifact
- `dataset`: Identifier for this dataset (used in the UI)

## Step 5: Run the Build Process

### Option A: Full Build (Recommended)

This syncs SBOMs and generates the snapshot:

```bash
npm run build
```

This runs:
1. `npm run sync:sboms` - Downloads artifacts from GitHub
2. `npm run build:snapshot` - Parses SBOMs and generates `parse-sboms.json`

### Option B: Step by Step

**Step 5a: Sync SBOMs from GitHub**

```bash
npm run sync:sboms
```

This will:
- Read `artifacts.json`
- Find latest artifacts in GitHub Actions
- Download ZIP files
- Extract to `sboms/{dataset}/` directories
- Look for `*.cyclonedx.json` files

**Expected output:**
```
Processing 2 artifact(s)...

Artifact: trivy-scan-results-ghcr_io_rajanagori_nightingale_stable (dataset: stable)
  Downloading artifact #12345 → stable.zip
  Unzipping → sboms/stable
  Found: sbom.cyclonedx.json

Artifact: trivy-scan-results-ghcr_io_rajanagori_nightingale_arm64 (dataset: arm64)
  Downloading artifact #12346 → arm64.zip
  Unzipping → sboms/arm64
  Found: sbom.cyclonedx.json

Sync complete: 2 succeeded, 0 failed
```

**Step 5b: Parse SBOMs**

```bash
npm run build:snapshot
```

This will:
- Scan `sboms/**/*.cyclonedx.json`
- Parse each CycloneDX file
- Generate `parse-sboms.json` with aggregated data

**Expected output:**
```
Scanning for CycloneDX files in /path/to/sboms...
Found 2 file(s) to process.

Processing: stable/sbom.cyclonedx.json
  ✓ 50 vulnerabilities, 100 components

Processing: arm64/sbom.cyclonedx.json
  ✓ 45 vulnerabilities, 95 components

Successfully processed 2 of 2 file(s).

✓ Wrote parse-sboms.json
  - 95 vulnerability record(s) across 2 dataset(s)
  - Severity breakdown: CRITICAL=5, HIGH=15, MEDIUM=30, LOW=45
```

## Step 6: Serve the Application

Start a local web server to view the dashboard:

```bash
npm run serve
```

This starts a server on `http://localhost:8080`

Open your browser and navigate to:
```
http://localhost:8080
```

You should see the SBOM Explorer dashboard with:
- Summary statistics
- Filterable vulnerability table
- Visualizations (donut charts, sparklines)
- Export functionality

## Step 7: Verify Setup

### Check Generated Files

```bash
# Verify parse-sboms.json exists
ls -lh parse-sboms.json

# Check file size (should be > 0)
du -h parse-sboms.json

# View structure (first few lines)
head -20 parse-sboms.json
```

### Test the Application

1. **Open the dashboard** in your browser
2. **Test filtering:**
   - Try searching for a component name
   - Filter by severity (CRITICAL, HIGH, etc.)
   - Set minimum CVSS score
3. **Test pagination:**
   - Navigate between pages
   - Verify page counts
4. **Test export:**
   - Click "Export CSV"
   - Verify file downloads

## Step 8: Run Tests (Optional)

Verify everything works with automated tests:

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests with UI
npm run test:ui
```

**Expected output:**
```
✓ tests/parse-sboms.test.mjs (5)
✓ tests/security.test.mjs (5)
✓ tests/fetch-artifacts.test.mjs (6)

Test Files  3 passed (3)
     Tests  16 passed (16)
```

## Troubleshooting

### Issue: "TOKEN is missing"

**Solution:**
- Ensure environment variable is set: `export TOKEN="your_token"`
- For GitHub Actions, check that `TOKEN_SBOM` secret is set

### Issue: "Repository not found or access denied"

**Solution:**
- Verify token has `repo` and `actions:read` permissions
- Check `NIGHTINGALE_OWNER` and `NIGHTINGALE_REPO` are correct
- Ensure token hasn't expired

### Issue: "No *.cyclonedx.json found"

**Solution:**
- Verify artifacts contain CycloneDX JSON files
- Check artifact names in `artifacts.json` are correct
- Ensure artifacts haven't expired (GitHub deletes after 90 days)

### Issue: "Failed to load SBOM data" in browser

**Solution:**
- Ensure `parse-sboms.json` exists in project root
- Check file is valid JSON: `cat parse-sboms.json | jq .`
- Verify file permissions allow reading
- Check browser console for detailed errors

### Issue: Web Worker not working

**Solution:**
- Workers require serving via HTTP (not `file://`)
- Use `npm run serve` instead of opening HTML directly
- Check browser console for CORS errors

### Issue: Tests failing

**Solution:**
- Ensure all dependencies installed: `npm install`
- Check Node.js version: `node --version` (should be 20+)
- Clear cache: `rm -rf node_modules package-lock.json && npm install`

## Next Steps

### Development

- Modify `artifacts.json` to add more datasets
- Customize UI in `index.html` and `app.js`
- Adjust styles in `styles.css`
- Add new visualizations or features

### Production Deployment

1. **Set up GitHub Actions:**
   - Workflow is already configured in `.github/workflows/sync-build.yml`
   - Ensure `TOKEN_SBOM` secret is set
   - Push to `main` branch to trigger

2. **Configure GitHub Pages:**
   - Go to repository → Settings → Pages
   - Source: GitHub Actions
   - Custom domain: Set `CNAME` file (already configured)

3. **Monitor:**
   - Check Actions tab for build status
   - Verify Pages deployment
   - Test live site

## File Structure Reference

```
sbom-parser/
├── .github/
│   └── workflows/
│       └── sync-build.yml      # CI/CD workflow
├── docs/
│   └── API.md                  # API documentation
├── scripts/
│   ├── fetch-artifacts.mjs     # Download artifacts
│   ├── parse-sboms.mjs         # Parse SBOMs
│   ├── security.js             # Client security utils
│   └── utils/
│       └── security.mjs        # Server security utils
├── tests/
│   ├── parse-sboms.test.mjs    # Parsing tests
│   ├── security.test.mjs       # Security tests
│   └── fetch-artifacts.test.mjs # Fetch tests
├── app.js                       # Main application logic
├── index.html                   # Dashboard UI
├── styles.css                   # Custom styles
├── artifacts.json               # Artifact configuration
├── parse-sboms.json            # Generated snapshot (output)
├── package.json                # Dependencies
├── vitest.config.mjs           # Test configuration
├── README.md                   # Project documentation
├── SETUP.md                    # This file
└── CNAME                       # Custom domain config
```

## Quick Reference Commands

```bash
# Install dependencies
npm install

# Sync SBOMs from GitHub
npm run sync:sboms

# Parse SBOMs
npm run build:snapshot

# Full build
npm run build

# Serve locally
npm run serve

# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

## Support

If you encounter issues:
1. Check this guide's Troubleshooting section
2. Review error messages in console/terminal
3. Check GitHub Actions logs (if using CI/CD)
4. Open an issue on GitHub with:
   - Error message
   - Steps to reproduce
   - Environment details (Node version, OS)

---

**You're all set!** 🎉 The SBOM Parser is ready to use.

