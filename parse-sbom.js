// parse-sbom.js
// Usage: npm install adm-zip && node parse-sbom.js

const fs     = require('fs');
const path   = require('path');
const AdmZip = require('adm-zip');
const badgeClasses = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH:     'bg-orange-100 text-orange-800',
  MEDIUM:   'bg-yellow-100 text-yellow-800',
  LOW:      'bg-green-100 text-green-800',
  UNKNOWN:  'bg-gray-100 text-gray-800'
};
// Helper: determine severity from vulnerability object
function extractSeverity(v) {
  // Use top-level severity if present
  if (v.severity) {
    return v.severity.toUpperCase();
  }
  // Fallback to CycloneDX ratings array
  if (Array.isArray(v.ratings) && v.ratings.length) {
    return v.ratings
      .map(r => r.severity.toUpperCase())
      .sort((a, b) =>
        ['LOW','MEDIUM','HIGH','CRITICAL'].indexOf(b) -
        ['LOW','MEDIUM','HIGH','CRITICAL'].indexOf(a)
      )[0];
  }
  // Default
  return 'UNKNOWN';
}
let totalComponents = 0;
let totalVulns = 0;
let severityCounts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };

const SBOM_DIR = path.join(__dirname, 'sboms');
const zipFiles = fs.existsSync(SBOM_DIR)
  ? fs.readdirSync(SBOM_DIR).filter(f => f.endsWith('.zip'))
  : [];

if (!zipFiles.length) {
  console.error(`❌ No .zip files found in ${SBOM_DIR}`);
  process.exit(1);
}

// --- Pre-calc totals before rendering ---
zipFiles.forEach(zipFile => {
  const zipPath = path.join(SBOM_DIR, zipFile);
  const zip     = new AdmZip(zipPath);
  const entry   = zip.getEntries().find(e => e.entryName.toLowerCase().endsWith('.cyclonedx.json'));
  let sbom = { components: [], vulnerabilities: [] };
  if (entry) {
    try {
      sbom = JSON.parse(entry.getData().toString('utf8'));
    } catch {}
  }
  totalComponents += sbom.components.length;
  totalVulns += sbom.vulnerabilities.length;
  sbom.vulnerabilities.forEach(v => {
    const sev = extractSeverity(v);
    if (severityCounts.hasOwnProperty(sev)) {
      severityCounts[sev]++;
    }
  });
});

// --- HTML boilerplate start ---
let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Multi-SBOM Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>summary::-webkit-details-marker{display:none;}</style>
</head>
<body class="bg-gray-50 text-gray-800">
  <div class="max-w-6xl mx-auto p-6 space-y-8">
      <section class="bg-white shadow rounded-lg p-6 mb-8">
        <h2 class="text-2xl font-semibold mb-4">📊 Summary Dashboard</h2>
        <div class="grid grid-cols-2 gap-4 text-center">
          <div>
            <div class="text-sm text-gray-600">SBOMs Processed</div>
            <div class="text-xl font-bold">${zipFiles.length}</div>
          </div>
          <div>
            <div class="text-sm text-gray-600">Total Components</div>
            <div class="text-xl font-bold">${totalComponents}</div>
          </div>
          <div>
            <div class="text-sm text-gray-600">Total Vulnerabilities</div>
            <div class="text-xl font-bold">${totalVulns}</div>
          </div>
          <div>
            <div class="text-sm text-gray-600">Severity Breakdown</div>
            <div class="flex justify-center space-x-2">
              <span class="px-2 py-1 rounded-full bg-red-100 text-red-800">Critical: ${severityCounts.CRITICAL}</span>
              <span class="px-2 py-1 rounded-full bg-orange-100 text-orange-800">High: ${severityCounts.HIGH}</span>
              <span class="px-2 py-1 rounded-full bg-yellow-100 text-yellow-800">Medium: ${severityCounts.MEDIUM}</span>
              <span class="px-2 py-1 rounded-full bg-green-100 text-green-800">Low: ${severityCounts.LOW}</span>
            </div>
          </div>
        </div>
        <div class="mt-6">
          <input type="text" id="global-filter" placeholder="Global search across all SBOMs..." class="w-full px-3 py-2 border rounded" />
        </div>
      </section>
`;

// --- Generate one section per archive ---
zipFiles.forEach(zipFile => {
  const title   = path.basename(zipFile, '.zip');
  const zipPath = path.join(SBOM_DIR, zipFile);
  const zip     = new AdmZip(zipPath);
  const entry   = zip.getEntries().find(e => e.entryName.toLowerCase().endsWith('.cyclonedx.json'));

  let sbom = { components: [], vulnerabilities: [] };
  if (entry) {
    try {
      sbom = JSON.parse(entry.getData().toString('utf8'));
    } catch (e) {
      console.warn(`⚠️  Could not parse JSON in ${zipFile}:`, e.message);
    }
  } else {
    console.warn(`⚠️  No .json found inside ${zipFile}`);
  }


  // Start this SBOM’s section
  html += `
    <section>
      <details open class="bg-white shadow rounded-lg">
        <summary class="px-6 py-4 flex justify-between items-center cursor-pointer">
          <span class="text-2xl font-semibold">📦 ${title}</span>
          <svg class="w-5 h-5 transform transition-transform" data-open-icon
               xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M19 9l-7 7-7-7" />
          </svg>
        </summary>
        <div class="px-6 pb-6 space-y-6">

            <details open class="bg-gray-50 rounded-lg border my-6">
              <summary class="px-6 py-3 font-medium cursor-pointer flex justify-between items-center">
                <span>Components</span>
                <svg class="w-5 h-5 transform transition-transform" data-open-icon
                     xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M19 9l-7 7-7-7" />
                </svg>
              </summary>
              <div class="px-6 pb-6 space-y-4">

          <!-- Components -->
          <div>
            <input type="text" id="filter-${title}-comps"
                   placeholder="Filter components…"
                   class="mb-4 w-full px-3 py-2 border rounded" />
            <div class="overflow-x-auto">
              <table id="comps-${title}" class="min-w-full bg-white">
                <thead class="bg-gray-200">
                  <tr>
                    <th class="px-4 py-2 text-left">Name</th>
                    <th class="px-4 py-2 text-left">Version</th>
                    <th class="px-4 py-2 text-left">Group</th>
                    <th class="px-4 py-2 text-left">PURL</th>
                    <th class="px-4 py-2 text-left">Licenses</th>
                  </tr>
                </thead>
                <tbody>\n`;

  sbom.components.forEach(c => {
    const nm       = c.name    || '—';
    const ver      = c.version || '—';
    const grp      = c.group   || '—';
    const purl     = c.purl    || '—';
    const lic      = Array.isArray(c.licenses)
      ? c.licenses.map(l => l.license?.name||'').join(', ')
      : '—';
    html += `                  <tr class="border-b hover:bg-gray-50">
                    <td class="px-4 py-2">${nm}</td>
                    <td class="px-4 py-2">${ver}</td>
                    <td class="px-4 py-2">${grp}</td>
                    <td class="px-4 py-2 break-words">${purl}</td>
                    <td class="px-4 py-2">${lic}</td>
                  </tr>\n`;
  });

  html += `                </tbody>
              </table>
            </div>
          </div>
              </div>
            </details>

            <details open class="bg-gray-50 rounded-lg border my-6">
              <summary class="px-6 py-3 font-medium cursor-pointer flex justify-between items-center">
                <span>Vulnerabilities</span>
                <svg class="w-5 h-5 transform transition-transform" data-open-icon
                     xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M19 9l-7 7-7-7" />
                </svg>
              </summary>
              <div class="px-6 pb-6 space-y-4">

          <!-- Vulnerabilities -->
          <div>
            <input type="text" id="filter-${title}-vulns"
                   placeholder="Filter vulnerabilities…"
                   class="mb-4 w-full px-3 py-2 border rounded" />
            <div class="overflow-x-auto">
              <table id="vulns-${title}" class="min-w-full bg-white">
                <thead class="bg-gray-200">
                  <tr>
                    <th class="px-4 py-2 text-left">ID</th>
                    <th class="px-4 py-2 text-left">Severity</th>
                    <th class="px-4 py-2 text-left">Description</th>
                    <th class="px-4 py-2 text-left">Component Ref</th>
                  </tr>
                </thead>
                <tbody>\n`;

  sbom.vulnerabilities.forEach(v => {
    const vid  = v.id || '—';
    const sev = extractSeverity(v);
    const badge = `<span class="px-2 py-1 rounded-full ${badgeClasses[sev]||'bg-gray-100 text-gray-800'}">${sev}</span>`;
    const txt  = (v.description||'').replace(/\r?\n/g,' ');
    const cref = v.component||v.componentRef||'—';
    html += `                  <tr class="border-b hover:bg-gray-50">
                    <td class="px-4 py-2">${vid}</td>
                    <td class="px-4 py-2">${badge}</td>
                    <td class="px-4 py-2">${txt}</td>
                    <td class="px-4 py-2">${cref}</td>
                  </tr>\n`;
  });

  html += `                </tbody>
              </table>
            </div>
          </div>
              </div>
            </details>

        </div>
      </details>
    </section>\n`;
});

// --- Close out HTML + scripts for toggles & filters ---
html += `  </div>
  <script>
    // Arrow rotation
    document.querySelectorAll('details').forEach(d => {
      const icon = d.querySelector('[data-open-icon]');
      d.addEventListener('toggle', () => icon.classList.toggle('rotate-180', d.open));
    });

    // Per-section filters
    ${zipFiles.map(z => {
      const t = path.basename(z,'.zip');
      return `
    document.getElementById('filter-${t}-comps')
      .addEventListener('input', e => {
        const f=e.target.value.toLowerCase();
        document.querySelectorAll('#comps-${t} tbody tr')
          .forEach(r=> r.style.display = r.textContent.toLowerCase().includes(f) ? '' : 'none');
      });
    document.getElementById('filter-${t}-vulns')
      .addEventListener('input', e => {
        const f=e.target.value.toLowerCase();
        document.querySelectorAll('#vulns-${t} tbody tr')
          .forEach(r=> r.style.display = r.textContent.toLowerCase().includes(f) ? '' : 'none');
      });
      `;
    }).join('')}

    // Global filter
    document.getElementById('global-filter').addEventListener('input', e => {
      const f = e.target.value.toLowerCase();
      document.querySelectorAll('table tbody tr').forEach(r => {
        r.style.display = r.textContent.toLowerCase().includes(f) ? '' : 'none';
      });
    });

    // Table sorting
    document.querySelectorAll('th').forEach(th => {
      th.classList.add('cursor-pointer');
      th.addEventListener('click', () => {
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const index = Array.from(th.parentNode.children).indexOf(th);
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const asc = !th.classList.contains('asc');
        rows.sort((a,b) => {
          const aText = a.children[index].textContent.trim().toLowerCase();
          const bText = b.children[index].textContent.trim().toLowerCase();
          return aText.localeCompare(bText) * (asc ? 1 : -1);
        });
        rows.forEach(r => tbody.appendChild(r));
        table.querySelectorAll('th').forEach(h => h.classList.remove('asc','desc'));
        th.classList.add(asc ? 'asc' : 'desc');
      });
    });
  </script>
</body>
</html>`;

// Write the final report
fs.writeFileSync('index.html', html, 'utf8');
console.log(`✅ Generated report with ${zipFiles.length} SBOM sections.`);