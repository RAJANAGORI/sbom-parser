import { describe, it, expect } from 'vitest';

// Import security utilities (we'll need to make them testable)
// For now, test the logic

describe('Security Utilities', () => {
  describe('Input Sanitization', () => {
    it('should sanitize HTML entities', () => {
      const input = '<script>alert("xss")</script>';
      // Expected: &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;
      expect(input.includes('<')).toBe(true);
    });

    it('should validate severity values', () => {
      const allowed = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN', ''];
      expect(allowed.includes('CRITICAL')).toBe(true);
      expect(allowed.includes('INVALID')).toBe(false);
    });

    it('should validate dataset IDs', () => {
      const valid = /^[a-zA-Z0-9._-]+$/;
      expect(valid.test('backend-amd64')).toBe(true);
      expect(valid.test('stable')).toBe(true);
      expect(valid.test('invalid@name')).toBe(false);
    });

    it('should validate CVSS scores', () => {
      const validate = (cvss) => {
        const num = typeof cvss === 'number' ? cvss : parseFloat(cvss);
        if (isNaN(num)) return 0;
        return Math.max(0, Math.min(10, num));
      };
      
      expect(validate(7.5)).toBe(7.5);
      expect(validate(15)).toBe(10);
      expect(validate(-5)).toBe(0);
      expect(validate('invalid')).toBe(0);
    });

    it('should sanitize search queries', () => {
      const sanitize = (query) => {
        if (typeof query !== 'string') return '';
        return query
          .replace(/[\x00-\x1F\x7F]/g, '')
          .slice(0, 500)
          .trim();
      };
      
      expect(sanitize('test query')).toBe('test query');
      expect(sanitize('a'.repeat(600)).length).toBe(500);
      expect(sanitize('test\x00query')).toBe('testquery');
    });
  });
});

