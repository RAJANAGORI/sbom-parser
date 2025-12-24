# API Documentation

## Data Structures

### parse-sboms.json Schema

The main output file containing processed SBOM data.

```typescript
interface SBOMSnapshot {
  generatedAt: string; // ISO 8601 timestamp
  datasets: DatasetSummary[];
  items: VulnerabilityItem[];
  overall: OverallStats;
  metrics: Metrics;
}

interface DatasetSummary {
  id: string; // Dataset identifier (e.g., "stable", "arm64")
  created: string | null; // ISO timestamp from BOM metadata
  components: number; // Total component count
  vulnerabilities: number; // Total vulnerability count
  severityCounts: SeverityCounts;
}

interface VulnerabilityItem {
  dataset: string; // Dataset identifier
  id: string | null; // CVE ID (e.g., "CVE-2024-0001")
  title: string; // Vulnerability description (max 200 chars)
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
  severityRank: number; // Numeric rank for sorting (4=critical, 3=high, etc.)
  cvss: number | null; // CVSS score (0-10)
  component: string | null; // Component name
  version: string | null; // Component version
  purl: string | null; // Package URL (e.g., "pkg:npm/package@1.0.0")
  licenses: string[]; // Array of license identifiers
  direct: boolean; // True if not optional/transitive dependency
  cwes: string[]; // CWE IDs
  urls: string[]; // Reference URLs
  fixedVersions: string[]; // Array of fixed versions (["*"] if update available)
  _key: string; // Internal unique key
}

interface SeverityCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFO: number;
  UNKNOWN: number;
}

interface OverallStats {
  total: number; // Total vulnerability count
  severityCounts: SeverityCounts;
}

interface Metrics {
  fixAvailabilityRate: number; // Percentage (0-100)
  topCVEs: TopCVE[];
}

interface TopCVE {
  id: string; // CVE ID
  count: number; // Occurrence count
  datasets: string[]; // Datasets containing this CVE
  maxCVSS: number | null; // Highest CVSS score
  worstSeverityRank: number; // Worst severity rank
}
```

## CycloneDX Mapping

### Input: CycloneDX BOM Structure

The parser expects CycloneDX JSON format with the following structure:

```typescript
interface CycloneDXBOM {
  bomFormat?: string; // "CycloneDX"
  specVersion?: string; // e.g., "1.4"
  version?: number;
  metadata?: {
    timestamp?: string; // ISO timestamp
  };
  components?: Component[];
  vulnerabilities?: Vulnerability[];
}

interface Component {
  "bom-ref"?: string; // Component reference ID
  "bomRef"?: string; // Alternative ref field
  type?: string; // e.g., "library"
  name?: string;
  version?: string;
  purl?: string; // Package URL
  licenses?: License[];
  scope?: string; // "required" | "optional" | "transitive"
}

interface Vulnerability {
  id?: string; // CVE ID
  description?: string;
  severity?: string; // "critical" | "high" | "medium" | "low"
  ratings?: CVSSRating[];
  cvss?: CVSSRating[]; // Alternative field name
  affects?: AffectedComponent[];
  cwes?: CWE[];
  references?: Reference[];
  analysis?: {
    response?: string[]; // ["update"] indicates fix available
  };
}

interface CVSSRating {
  method?: string; // "CVSSv3", "CVSSv2", etc.
  source?: string;
  score?: number; // 0-10
  baseScore?: number; // Alternative field
  severity?: string;
  baseSeverity?: string; // Alternative field
}

interface AffectedComponent {
  ref?: string; // Component bom-ref
}

interface CWE {
  id?: string | number;
}

interface Reference {
  url?: string;
}

interface License {
  license?: {
    id?: string; // e.g., "MIT"
    name?: string;
  };
  expression?: string; // SPDX expression
}
```

### Mapping Rules

1. **Severity Mapping**: CycloneDX severity strings are normalized to uppercase:
   - `critical` → `CRITICAL`
   - `high` → `HIGH`
   - `medium` → `MEDIUM`
   - `low` → `LOW`
   - `info` → `INFO`
   - Unknown/missing → `UNKNOWN`

2. **CVSS Selection**: The parser selects the best CVSS rating:
   - Prefers highest score
   - Falls back to severity if score unavailable
   - Supports both `ratings` and `cvss` fields

3. **Component Matching**: Vulnerabilities are matched to components via:
   - `affects[].ref` → `components[].bom-ref` or `components[].bomRef`
   - Falls back to `purl` matching
   - Creates orphaned vulnerability if no match

4. **License Extraction**: Extracts license identifiers in order:
   - `license.id` (preferred)
   - `license.name` (fallback)
   - `expression` (SPDX expression)

5. **Fix Detection**: Checks `analysis.response` array for `"update"` string

## Script APIs

### fetch-artifacts.mjs

**Function: `readArtifactsList()`**
- Reads `artifacts.json` from project root
- Validates structure (must have `artifacts` array)
- Returns array of `{name, dataset}` objects

**Function: `findNewestArtifactByName(name, retries)`**
- Searches GitHub Actions artifacts by name
- Returns newest non-expired artifact
- Implements exponential backoff retry logic
- Throws on 404/403, retries on 5xx errors

**Function: `downloadZip(artifactId, outFile, retries)`**
- Downloads artifact ZIP from GitHub
- Validates ZIP file format (PK header)
- Implements retry logic for server errors
- Throws on expired artifacts (410)

**Function: `main()`**
- Orchestrates the fetch process
- Processes all artifacts from config
- Extracts ZIPs to `sboms/{dataset}/` directories
- Provides summary with success/error counts

### parse-sboms.mjs

**Function: `readJSON(path)`**
- Safely reads and parses JSON file
- Returns `null` on error (logs warning)

**Function: `writeJSON(path, object)`**
- Writes object as formatted JSON
- Creates directory if needed
- Throws on write failure

**Function: `severityOrder(severity)`**
- Maps severity string to numeric rank
- Returns: critical=4, high=3, medium=2, low=1, info/unknown=0

**Function: `pickCVSS(ratings)`**
- Selects best CVSS rating from array
- Prefers highest score
- Returns `{score, severity, method}` or `null`

**Function: `licenseNames(licenses)`**
- Extracts license identifiers from license objects
- Returns array of strings

**Function: `countSeverities(items)`**
- Counts vulnerabilities by severity
- Returns `SeverityCounts` object

**Function: `validateCycloneDX(json)`**
- Validates CycloneDX BOM structure
- Returns `{valid: boolean, error?: string}`

**Function: `indexCycloneDX(json, datasetId, filePath)`**
- Processes CycloneDX BOM into vulnerability items
- Builds component map for matching
- Returns dataset summary with items array

**Function: `buildTopCVEs(items)`**
- Analyzes CVE occurrences across datasets
- Returns top 10 CVEs sorted by severity and count

**Function: `main()`**
- Scans for `*.cyclonedx.json` files
- Processes each file and aggregates results
- Generates `parse-sboms.json` snapshot

## Security Utilities

### Client-side (security.js)

All functions are available via `window.SecurityUtils`:

- `sanitizeHTML(str)` - Escapes HTML entities
- `sanitizeText(str)` - Removes HTML tags
- `sanitizeSearchQuery(query)` - Sanitizes search input (max 500 chars)
- `validateSeverity(severity)` - Validates against allowed values
- `validateDatasetId(dataset)` - Validates alphanumeric + dash/underscore
- `validateCVSS(cvss)` - Validates 0-10 range
- `validateFixFilter(fix)` - Validates "has"|"none"|""
- `validatePage(page, maxPages)` - Validates pagination
- `validateSortKey(key)` - Validates sort field
- `validateSortDir(dir)` - Validates "asc"|"desc"
- `sanitizeObject(obj, depth)` - Recursively sanitizes object
- `validateVulnerabilityItem(item)` - Validates item structure
- `validateSBOMData(data)` - Validates snapshot structure

### Server-side (utils/security.mjs)

Same functions exported as ES modules for use in Node.js scripts.

## Performance Features

### Indexing
- Component index: `Map<componentName, VulnerabilityItem[]>`
- Dataset index: `Map<dataset, VulnerabilityItem[]>`
- Severity index: `Map<severity, VulnerabilityItem[]>`

### Caching
- Filter results cached with hash-based invalidation
- Memoized severity counts
- Debounced filter application (300ms)

### Web Workers
- Automatic worker initialization for datasets >5000 items
- Offloads filtering and sorting to background thread
- Falls back to main thread if workers unavailable

### Lazy Loading
- Visualizations deferred via `requestIdleCallback`
- Non-critical metrics loaded with timeout delays

