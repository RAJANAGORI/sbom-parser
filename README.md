# SBOM Parser & Explorer

A comprehensive Node.js tool that fetches CycloneDX SBOM files from GitHub Actions artifacts and displays them in a responsive, interactive HTML dashboard with advanced filtering, visualization, and export capabilities.

## Features

- **Automated SBOM Sync**: Fetches SBOM artifacts from GitHub Actions automatically
- **Interactive Dashboard**: Beautiful, responsive UI built with Alpine.js and Tailwind CSS
- **Advanced Filtering**: Search, filter by severity, CVSS score, dataset, and fix availability
- **Data Visualizations**: Severity donut charts, CVSS sparklines, component/license breakdowns
- **Export Capabilities**: Export filtered data as CSV (with rate limiting)
- **Security**: Input sanitization, XSS prevention, Content Security Policy
- **Performance**: Debounced filtering, result caching, optimized rendering
- **Error Handling**: Comprehensive error handling with retry logic

## Architecture

### Data Pipeline

1. **Fetch Script** (`scripts/fetch-artifacts.mjs`): Downloads SBOM zip artifacts from GitHub Actions
2. **Parse Script** (`scripts/parse-sboms.mjs`): Parses CycloneDX JSON files and generates consolidated snapshot
3. **Frontend** (`index.html`): Interactive dashboard that loads and displays the parsed data

### File Structure

```
sbom-parser/
├── scripts/
│   ├── fetch-artifacts.mjs    # Downloads artifacts from GitHub
│   ├── parse-sboms.mjs        # Parses CycloneDX files
│   ├── security.js            # Client-side security utilities
│   └── utils/
│       └── security.mjs       # Server-side security utilities
├── tests/                     # Test files
├── index.html                 # Main dashboard UI
├── app.js                     # Alpine.js application logic
├── styles.css                 # Custom styles
├── artifacts.json             # Configuration for artifacts to fetch
└── parse-sboms.json          # Generated snapshot (output)
```

## Quick Start

For detailed setup instructions, see [SETUP.md](./SETUP.md).

### Quick Setup

```bash
# 1. Install dependencies
npm install

# 2. Set GitHub token
export TOKEN="your-github-token"

# 3. Configure artifacts (edit artifacts.json)
# 4. Build
npm run build

# 5. Serve
npm run serve
```

Open `http://localhost:8080` in your browser.

**For complete setup instructions, troubleshooting, and configuration details, see [SETUP.md](./SETUP.md).**

## Usage

### Development

```bash
# Sync SBOMs from GitHub Actions
npm run sync:sboms

# Parse SBOMs and generate snapshot
npm run build:snapshot

# Build everything (sync + parse)
npm run build

# Serve locally
npm run serve
```

### Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests with UI
npm run test:ui
```

### Production Build

The build process:
1. Fetches latest SBOM artifacts from GitHub Actions
2. Extracts and parses CycloneDX JSON files
3. Generates `parse-sboms.json` snapshot
4. Deploys to GitHub Pages (via CI/CD)

## CI/CD

The project includes a GitHub Actions workflow (`.github/workflows/sync-build.yml`) that:
- Triggers on repository dispatch, monthly schedule, or manual trigger
- Syncs SBOMs from the Nightingale repository
- Builds the snapshot
- Deploys to GitHub Pages

### Environment Variables

Set in GitHub Secrets:
- `TOKEN_SBOM`: GitHub Personal Access Token with `actions:read` permission

## Data Structure

### Input: CycloneDX JSON

The parser expects CycloneDX format JSON files with:
- `components`: Array of software components
- `vulnerabilities`: Array of vulnerability records
- `metadata`: BOM metadata including timestamp

### Output: parse-sboms.json

```json
{
  "generatedAt": "ISO timestamp",
  "datasets": [
    {
      "id": "dataset-id",
      "created": "timestamp",
      "components": 100,
      "vulnerabilities": 50,
      "severityCounts": { "CRITICAL": 5, "HIGH": 10, ... }
    }
  ],
  "items": [
    {
      "dataset": "dataset-id",
      "id": "CVE-2024-0001",
      "severity": "HIGH",
      "cvss": 7.5,
      "component": "package-name",
      "version": "1.0.0",
      "purl": "pkg:npm/package@1.0.0",
      "licenses": ["MIT"],
      ...
    }
  ],
  "overall": {
    "total": 50,
    "severityCounts": { ... }
  },
  "metrics": {
    "fixAvailabilityRate": 60,
    "topCVEs": [ ... ]
  }
}
```

## Security

### Implemented Security Features

- **Input Sanitization**: All user inputs are sanitized to prevent XSS
- **Content Security Policy**: CSP headers prevent inline script execution
- **Data Validation**: All data from parse-sboms.json is validated before rendering
- **Rate Limiting**: Export functions are rate-limited (10 exports/minute)
- **Secure Token Handling**: GitHub tokens are never logged or exposed

### Security Utilities

- `scripts/security.js`: Client-side sanitization and validation
- `scripts/utils/security.mjs`: Server-side security utilities

## Performance Optimizations

- **Debounced Filtering**: 300ms debounce on filter inputs
- **Result Caching**: Filter results are cached to avoid redundant computations
- **Lazy Loading**: Visualizations load on demand
- **Optimized Rendering**: Only visible table rows are rendered

## Error Handling

### Fetch Script
- Network failure retries with exponential backoff
- Invalid artifact detection
- Missing file handling
- Detailed error messages

### Parse Script
- CycloneDX schema validation
- Malformed JSON handling
- Missing field handling
- Per-file error tracking

### UI
- User-friendly error messages
- Graceful degradation
- Data validation before rendering

## Development

### Code Organization

- **Modular Structure**: JavaScript and CSS extracted to separate files
- **Security Utilities**: Centralized security functions
- **Error Handling**: Comprehensive error handling throughout

### Testing

Tests are located in `tests/` directory:
- Unit tests for parsing logic
- Security utility tests
- Integration tests (planned)

## Deployment

The project is automatically deployed to GitHub Pages via GitHub Actions.

### Automatic Deployment

The workflow (`.github/workflows/sync-build.yml`) automatically:
1. Runs `npm run build` to sync SBOMs and generate snapshot
2. Creates a clean `pages-build/` directory with only necessary files
3. Deploys to GitHub Pages

**Setup:**
1. Enable GitHub Pages: Settings → Pages → Source: **GitHub Actions**
2. Set secret: `TOKEN_SBOM` (GitHub token with `repo` + `actions:read`)
3. Push to `main` branch or trigger workflow manually

**Triggers:**
- Monthly schedule (1st of month at 10:30 UTC)
- Repository dispatch from Nightingale
- Manual trigger from Actions tab

**For detailed deployment instructions, see [DEPLOYMENT.md](./DEPLOYMENT.md)**

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

[Add your license here]

## Screenshots

![SBOM Explorer Dashboard](https://github.com/user-attachments/assets/15ea9489-4524-4555-a4d0-8101c3cf5ff6)

## Support

For issues and questions, please open an issue on GitHub.
