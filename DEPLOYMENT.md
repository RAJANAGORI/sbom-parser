# Deployment Guide

This guide explains how the SBOM Parser is automatically deployed to GitHub Pages using GitHub Actions.

## How It Works

The deployment process is fully automated via GitHub Actions:

1. **Trigger**: Workflow runs on schedule, repository dispatch, or manual trigger
2. **Build**: Downloads SBOMs and generates `parse-sboms.json`
3. **Prepare**: Creates clean build directory with only necessary files
4. **Deploy**: Uploads to GitHub Pages

## Workflow Overview

```
GitHub Actions Workflow:
├── Checkout code
├── Setup Node.js 20
├── Install dependencies (npm ci)
├── Build (npm run build)
│   ├── Sync SBOMs from GitHub Actions artifacts
│   └── Parse and generate parse-sboms.json
├── Prepare Pages files
│   ├── Create pages-build/ directory
│   ├── Copy essential files only
│   └── Verify all files exist
├── Upload Pages artifact
└── Deploy to GitHub Pages
```

## Setup Instructions

### 1. Enable GitHub Pages

1. Go to your repository → **Settings** → **Pages**
2. Under **Source**, select: **GitHub Actions**
3. Save

### 2. Configure GitHub Secret

1. Go to repository → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `TOKEN_SBOM`
4. Value: Your GitHub Personal Access Token with:
   - ✅ `repo` scope
   - ✅ `actions:read` scope
5. Click **Add secret**

### 3. Configure Workflow (if needed)

Edit `.github/workflows/sync-build.yml` to adjust:
- Repository names (NIGHTINGALE_OWNER, NIGHTINGALE_REPO)
- Schedule (cron expression)
- Node version

### 4. Configure Artifacts

Edit `artifacts.json` with your artifact names:

```json
{
  "artifacts": [
    { "name": "your-artifact-name", "dataset": "dataset-id" }
  ]
}
```

## Deployment Files

The workflow creates a clean `pages-build/` directory with only these files:

```
pages-build/
├── index.html              # Main dashboard
├── app.js                  # Application logic
├── styles.css              # Styles
├── parse-sboms.json        # Generated snapshot (from build)
├── artifacts.json          # Configuration
├── CNAME                   # Custom domain (if exists)
└── scripts/
    ├── security.js         # Security utilities
    └── worker-filter.mjs   # Web Worker (if exists)
```

**Excluded files:**
- `node_modules/` - Not needed (using CDN)
- `sboms/` - Temporary downloaded files
- `tests/` - Test files
- `docs/` - Documentation
- `.git/` - Git metadata
- Other development files

## Manual Deployment

You can trigger the workflow manually with branch selection:

1. Go to repository → **Actions** tab
2. Select **Sync SBOMs & Build UI** workflow
3. Click **Run workflow** button (top right)
4. **Select branch**: 
   - Enter any branch name (e.g., `main`, `develop`, `feature/test`)
   - Default is `main`
5. Click **Run workflow**

**Note**: For scheduled and repository_dispatch triggers, the workflow uses the branch that triggered it automatically.

## Monitoring Deployment

### Check Workflow Status

1. Go to **Actions** tab
2. Click on the latest workflow run
3. View logs for each step

### Verify Deployment

1. Go to **Settings** → **Pages**
2. Check deployment status
3. Visit the site URL (shown in Pages settings)

### Common Issues

**Workflow fails at "Build" step:**
- Check `TOKEN_SBOM` secret is set correctly
- Verify token has required permissions
- Check artifact names in `artifacts.json`

**Workflow fails at "Prepare Pages files":**
- Verify `parse-sboms.json` was generated
- Check file permissions
- Review workflow logs for specific errors

**Site shows "Failed to load SBOM data":**
- Verify `parse-sboms.json` exists in deployment
- Check file is valid JSON
- Ensure file size > 0
- Check browser console for CORS errors

**Custom domain not working:**
- Verify `CNAME` file exists in repository root
- Check DNS settings point to GitHub Pages
- Wait for DNS propagation (up to 48 hours)

## Deployment URL

After successful deployment, your site will be available at:

- **Default**: `https://<username>.github.io/sbom-parser/`
- **Custom domain**: As configured in `CNAME` file

## Automatic Updates

The workflow is configured to run:

1. **Monthly**: On the 1st at 10:30 UTC (via schedule)
2. **On demand**: When triggered by repository_dispatch from Nightingale
3. **Manually**: Via workflow_dispatch from Actions tab

## Build Output

The build process generates:
- `parse-sboms.json` - Aggregated SBOM data (included in deployment)
- `sboms/` - Downloaded SBOM files (excluded from deployment, ephemeral)

## Troubleshooting

### View Workflow Logs

```bash
# In GitHub UI:
# Actions → Select workflow run → View logs
```

### Test Locally

Before deploying, test the build locally:

```bash
# Set token
export TOKEN="your-token"

# Build
npm run build

# Verify output
ls -lh parse-sboms.json
cat parse-sboms.json | jq '.overall.total'

# Test locally
npm run serve
```

### Check Deployment Files

After workflow runs, you can see what was deployed:

1. Go to **Actions** → Latest run
2. Expand **Prepare Pages files** step
3. View the file list and sizes

## Customization

### Change Deployment Branch

Edit `.github/workflows/sync-build.yml`:

```yaml
- name: Checkout main branch
  uses: actions/checkout@v6
  with:
    ref: main  # Change to your branch
```

### Add More Files to Deployment

Edit the "Prepare Pages files" step:

```yaml
- name: Prepare Pages files
  run: |
    # ... existing code ...
    cp additional-file.js pages-build/  # Add your file
```

### Change Build Command

Edit `package.json`:

```json
{
  "scripts": {
    "build": "your-custom-build-command"
  }
}
```

## Security Notes

- Tokens are stored as GitHub Secrets (encrypted)
- Tokens are never logged or exposed in workflow logs
- Only necessary files are deployed (no secrets, no node_modules)
- CSP headers protect against XSS attacks

## Next Steps

After deployment:
1. Visit your site URL
2. Test filtering and search
3. Verify visualizations load
4. Test export functionality
5. Monitor for errors in browser console

---

For setup instructions, see [SETUP.md](./SETUP.md)
For API documentation, see [docs/API.md](./docs/API.md)

