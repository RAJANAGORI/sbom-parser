/**
 * Security utilities for input sanitization and validation
 */

/**
 * Sanitizes a string to prevent XSS attacks by escaping HTML entities
 * @param {string} str - Input string to sanitize
 * @returns {string} - Sanitized string safe for HTML rendering
 */
export function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
  };
  return str.replace(/[&<>"'/]/g, (char) => map[char]);
}

/**
 * Sanitizes text content for safe display (removes HTML tags)
 * @param {string} str - Input string
 * @returns {string} - Sanitized string with HTML tags removed
 */
export function sanitizeText(str) {
  if (typeof str !== 'string') return '';
  // Remove HTML tags and decode entities
  return str
    .replace(/<[^>]*>/g, '')
    .replace(/&[#\w]+;/g, '')
    .trim();
}

/**
 * Validates and sanitizes search query input
 * @param {string} query - Search query
 * @returns {string} - Sanitized query (max 500 chars)
 */
export function sanitizeSearchQuery(query) {
  if (typeof query !== 'string') return '';
  // Remove control characters and limit length
  return query
    .replace(/[\x00-\x1F\x7F]/g, '')
    .slice(0, 500)
    .trim();
}

/**
 * Validates severity value against allowed values
 * @param {string} severity - Severity value
 * @returns {string} - Valid severity or empty string
 */
export function validateSeverity(severity) {
  const allowed = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN', ''];
  const upper = String(severity || '').toUpperCase();
  return allowed.includes(upper) ? upper : '';
}

/**
 * Validates dataset ID (alphanumeric, dash, underscore only)
 * @param {string} dataset - Dataset ID
 * @returns {string} - Valid dataset ID or empty string
 */
export function validateDatasetId(dataset) {
  if (typeof dataset !== 'string') return '';
  // Allow alphanumeric, dash, underscore, dot (for dataset names like "backend-amd64")
  if (/^[a-zA-Z0-9._-]+$/.test(dataset) && dataset.length <= 100) {
    return dataset;
  }
  return '';
}

/**
 * Validates CVSS score (0-10)
 * @param {number|string} cvss - CVSS score
 * @returns {number} - Valid CVSS score or 0
 */
export function validateCVSS(cvss) {
  const num = typeof cvss === 'number' ? cvss : parseFloat(cvss);
  if (isNaN(num)) return 0;
  return Math.max(0, Math.min(10, num));
}

/**
 * Validates fix filter value
 * @param {string} fix - Fix filter value
 * @returns {string} - Valid fix value or empty string
 */
export function validateFixFilter(fix) {
  const allowed = ['has', 'none', ''];
  return allowed.includes(fix) ? fix : '';
}

/**
 * Validates pagination page number
 * @param {number|string} page - Page number
 * @param {number} maxPages - Maximum pages
 * @returns {number} - Valid page number
 */
export function validatePage(page, maxPages = 1) {
  const num = typeof page === 'number' ? page : parseInt(page, 10);
  if (isNaN(num) || num < 0) return 0;
  return Math.min(num, Math.max(0, maxPages - 1));
}

/**
 * Validates sort key
 * @param {string} key - Sort key
 * @returns {string} - Valid sort key or default
 */
export function validateSortKey(key) {
  const allowed = ['severityRank', 'cvss', 'component', 'dataset', 'id'];
  return allowed.includes(key) ? key : 'severityRank';
}

/**
 * Validates sort direction
 * @param {string} dir - Sort direction
 * @returns {string} - Valid direction or 'desc'
 */
export function validateSortDir(dir) {
  return dir === 'asc' || dir === 'desc' ? dir : 'desc';
}

/**
 * Sanitizes an object's string properties recursively
 * @param {any} obj - Object to sanitize
 * @param {number} depth - Maximum depth to recurse (prevents stack overflow)
 * @returns {any} - Sanitized object
 */
export function sanitizeObject(obj, depth = 10) {
  if (depth <= 0) return null;
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeText(obj);
  if (typeof obj === 'number' || typeof obj === 'boolean') return obj;
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, depth - 1));
  }
  if (typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      // Sanitize keys too
      const safeKey = sanitizeText(String(key));
      sanitized[safeKey] = sanitizeObject(value, depth - 1);
    }
    return sanitized;
  }
  return obj;
}

/**
 * Validates vulnerability item structure
 * @param {any} item - Vulnerability item to validate
 * @returns {boolean} - True if valid structure
 */
export function validateVulnerabilityItem(item) {
  if (!item || typeof item !== 'object') return false;
  // Required fields
  if (typeof item.dataset !== 'string') return false;
  // Optional but should be correct types
  if (item.severity !== undefined && typeof item.severity !== 'string') return false;
  if (item.cvss !== undefined && typeof item.cvss !== 'number' && item.cvss !== null) return false;
  if (item.component !== undefined && typeof item.component !== 'string' && item.component !== null) return false;
  if (item.licenses !== undefined && !Array.isArray(item.licenses)) return false;
  return true;
}

/**
 * Validates parse-sboms.json structure
 * @param {any} data - Data to validate
 * @returns {boolean} - True if valid structure
 */
export function validateSBOMData(data) {
  if (!data || typeof data !== 'object') return false;
  if (!Array.isArray(data.items)) return false;
  if (!Array.isArray(data.datasets)) return false;
  // Validate items
  for (const item of data.items) {
    if (!validateVulnerabilityItem(item)) return false;
  }
  return true;
}

