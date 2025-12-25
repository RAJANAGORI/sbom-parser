# GitHub Actions Workflows

## sync-build.yml

This workflow automatically builds and deploys the SBOM Parser to GitHub Pages.

### Triggers

1. **Repository Dispatch**: When triggered by the Nightingale repository after Trivy scans complete
2. **Schedule**: Monthly on the 1st at 10:30 UTC
3. **Manual**: Can be triggered manually from the Actions tab

### Workflow Steps

1. **Checkout**: Checks out the main branch
2. **Setup Node**: Installs Node.js 20
3. **Install Dependencies**: Runs `npm ci` or `npm install`
4. **Build**: Runs `npm run build` which:
   - Syncs SBOM artifacts from GitHub Actions (`sync:sboms`)
   - Parses CycloneDX files and generates `parse-sboms.json` (`build:snapshot`)
5. **Prepare Pages Files**: Creates a clean `pages-build/` directory with only files needed for GitHub Pages:
   - `index.html` - Main dashboard
   - `app.js` - Application logic
   - `styles.css` - Styles
   - `parse-sboms.json` - Generated snapshot
   - `artifacts.json` - Configuration
   - `scripts/security.js` - Security utilities
   - `scripts/worker-filter.mjs` - Web Worker (if exists)
   - `CNAME` - Custom domain (if exists)
6. **Upload Pages Artifact**: Uploads the clean build directory
7. **Deploy**: Deploys to GitHub Pages

### Required Secrets

- `TOKEN_SBOM`: GitHub Personal Access Token with:
  - `repo` scope (to read repository)
  - `actions:read` scope (to read artifacts)

### Environment Variables

- `NIGHTINGALE_OWNER`: GitHub username/organization (default: "rajanagori")
- `NIGHTINGALE_REPO`: Repository name (default: "nightingale")

### Output

The workflow generates:
- `parse-sboms.json` in the repository root (during build)
- Clean `pages-build/` directory with only deployment files
- Deployed site at: `https://<username>.github.io/sbom-parser/` or custom domain

### Troubleshooting

**Build fails with "TOKEN is missing":**
- Ensure `TOKEN_SBOM` secret is set in repository settings
- Check secret name matches exactly

**Build fails with "No artifacts found":**
- Verify artifact names in `artifacts.json` are correct
- Check artifacts haven't expired (GitHub deletes after 90 days)
- Ensure token has `actions:read` permission

**Deployment fails:**
- Check GitHub Pages is enabled in repository settings
- Verify Pages source is set to "GitHub Actions"
- Check workflow has `pages: write` permission

**Site shows "Failed to load SBOM data":**
- Verify `parse-sboms.json` exists in `pages-build/`
- Check file is valid JSON
- Ensure file is accessible (not blocked by CORS)

