/**
 * Client-side security utilities for input sanitization and validation
 * Prevents XSS attacks by sanitizing user inputs
 */

(function() {
  'use strict';

  /**
   * Sanitizes a string to prevent XSS attacks by escaping HTML entities
   */
  function sanitizeHTML(str) {
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
   */
  function sanitizeText(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/<[^>]*>/g, '')
      .replace(/&[#\w]+;/g, '')
      .trim();
  }

  /**
   * Validates and sanitizes search query input
   */
  function sanitizeSearchQuery(query) {
    if (typeof query !== 'string') return '';
    // Remove control characters and limit length
    return query
      .replace(/[\x00-\x1F\x7F]/g, '')
      .slice(0, 500)
      .trim();
  }

  /**
   * Validates severity value against allowed values
   */
  function validateSeverity(severity) {
    const allowed = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN', ''];
    const upper = String(severity || '').toUpperCase();
    return allowed.includes(upper) ? upper : '';
  }

  /**
   * Validates dataset ID (alphanumeric, dash, underscore only)
   */
  function validateDatasetId(dataset) {
    if (typeof dataset !== 'string') return '';
    if (/^[a-zA-Z0-9._-]+$/.test(dataset) && dataset.length <= 100) {
      return dataset;
    }
    return '';
  }

  /**
   * Validates CVSS score (0-10)
   */
  function validateCVSS(cvss) {
    const num = typeof cvss === 'number' ? cvss : parseFloat(cvss);
    if (isNaN(num)) return 0;
    return Math.max(0, Math.min(10, num));
  }

  /**
   * Validates fix filter value
   */
  function validateFixFilter(fix) {
    const allowed = ['has', 'none', ''];
    return allowed.includes(fix) ? fix : '';
  }

  /**
   * Validates pagination page number
   */
  function validatePage(page, maxPages = 1) {
    const num = typeof page === 'number' ? page : parseInt(page, 10);
    if (isNaN(num) || num < 0) return 0;
    return Math.min(num, Math.max(0, maxPages - 1));
  }

  /**
   * Validates sort key
   */
  function validateSortKey(key) {
    const allowed = ['severityRank', 'cvss', 'component', 'dataset', 'id'];
    return allowed.includes(key) ? key : 'severityRank';
  }

  /**
   * Validates sort direction
   */
  function validateSortDir(dir) {
    return dir === 'asc' || dir === 'desc' ? dir : 'desc';
  }

  /**
   * Sanitizes an object's string properties recursively (limited depth)
   */
  function sanitizeObject(obj, depth = 10) {
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
        const safeKey = sanitizeText(String(key));
        sanitized[safeKey] = sanitizeObject(value, depth - 1);
      }
      return sanitized;
    }
    return obj;
  }

  /**
   * Validates vulnerability item structure
   */
  function validateVulnerabilityItem(item) {
    if (!item || typeof item !== 'object') return false;
    if (typeof item.dataset !== 'string') return false;
    if (item.severity !== undefined && typeof item.severity !== 'string') return false;
    if (item.cvss !== undefined && typeof item.cvss !== 'number' && item.cvss !== null) return false;
    if (item.component !== undefined && typeof item.component !== 'string' && item.component !== null) return false;
    if (item.licenses !== undefined && !Array.isArray(item.licenses)) return false;
    return true;
  }

  /**
   * Validates parse-sboms.json structure
   */
  function validateSBOMData(data) {
    if (!data || typeof data !== 'object') return false;
    if (!Array.isArray(data.items)) return false;
    if (!Array.isArray(data.datasets)) return false;
    // Validate first few items to avoid performance issues
    for (let i = 0; i < Math.min(100, data.items.length); i++) {
      if (!validateVulnerabilityItem(data.items[i])) return false;
    }
    return true;
  }

  // Export to window for use in Alpine.js
  window.SecurityUtils = {
    sanitizeHTML,
    sanitizeText,
    sanitizeSearchQuery,
    validateSeverity,
    validateDatasetId,
    validateCVSS,
    validateFixFilter,
    validatePage,
    validateSortKey,
    validateSortDir,
    sanitizeObject,
    validateVulnerabilityItem,
    validateSBOMData,
  };
})();

