/**
 * Web Worker for filtering and sorting large datasets
 * Offloads heavy computations to prevent UI blocking
 */

self.onmessage = function(e) {
  const { type, data, filters, sortKey, sortDir } = e.data;
  
  if (type === 'filter') {
    const { q, dataset, severity, fix, cvssMin } = filters;
    const qLower = q.trim().toLowerCase();
    
    const filtered = data.filter(item => {
      if (dataset && item.dataset !== dataset) return false;
      if (severity && (item.severity || "").toUpperCase() !== severity) return false;
      if (cvssMin && (item.cvss ?? -1) < cvssMin) return false;
      if (fix === "has" && !(item.fixedVersions || []).length) return false;
      if (fix === "none" && (item.fixedVersions || []).length) return false;
      if (qLower) {
        const searchText = [
          item.component,
          item.purl,
          item.id,
          (item.licenses || []).join(" "),
          item.dataset || ""
        ].join(" ").toLowerCase();
        if (!searchText.includes(qLower)) return false;
      }
      return true;
    });
    
    // Sort
    const dir = sortDir === "desc" ? -1 : 1;
    filtered.sort((a, b) => {
      const A = (a[sortKey] ?? ""), B = (b[sortKey] ?? "");
      if (typeof A === "number" && typeof B === "number") return (A - B) * dir;
      return String(A).localeCompare(String(B)) * dir;
    });
    
    self.postMessage({ type: 'filtered', result: filtered });
  } else if (type === 'aggregate') {
    // Count severities
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
    for (const item of data) {
      const s = (item.severity || 'UNKNOWN').toUpperCase();
      counts[s] = (counts[s] || 0) + 1;
    }
    
    // Count fixes
    const hasFix = data.filter(r => (r.fixedVersions || []).length).length;
    const fixRate = data.length ? Math.round(100 * (hasFix / data.length)) : 0;
    
    self.postMessage({ 
      type: 'aggregated', 
      result: { 
        severityCounts: counts, 
        fixRate,
        total: data.length 
      } 
    });
  }
};

