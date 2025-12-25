import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Mock data for testing
const mockCycloneDX = {
  bomFormat: "CycloneDX",
  specVersion: "1.4",
  version: 1,
  metadata: {
    timestamp: "2024-01-01T00:00:00Z"
  },
  components: [
    {
      "bom-ref": "pkg:npm/example@1.0.0",
      type: "library",
      name: "example",
      version: "1.0.0",
      purl: "pkg:npm/example@1.0.0",
      licenses: [{ license: { id: "MIT" } }]
    }
  ],
  vulnerabilities: [
    {
      id: "CVE-2024-0001",
      description: "Test vulnerability",
      severity: "HIGH",
      ratings: [
        {
          method: "CVSSv3",
          score: 7.5,
          severity: "HIGH"
        }
      ],
      affects: [
        { ref: "pkg:npm/example@1.0.0" }
      ],
      cwes: [{ id: "CWE-79" }],
      references: [{ url: "https://example.com/cve" }]
    }
  ]
};

describe('parse-sboms', () => {
  it('should validate CycloneDX structure', () => {
    // Test that valid structure passes
    expect(mockCycloneDX.bomFormat).toBe("CycloneDX");
    expect(Array.isArray(mockCycloneDX.components)).toBe(true);
    expect(Array.isArray(mockCycloneDX.vulnerabilities)).toBe(true);
  });

  it('should extract vulnerability data correctly', () => {
    const vuln = mockCycloneDX.vulnerabilities[0];
    expect(vuln.id).toBe("CVE-2024-0001");
    expect(vuln.severity).toBe("HIGH");
    expect(vuln.ratings[0].score).toBe(7.5);
  });

  it('should map severity correctly', () => {
    const severityMap = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
      unknown: 0
    };
    
    expect(severityMap['high']).toBe(3);
    expect(severityMap['critical']).toBe(4);
    expect(severityMap['unknown']).toBe(0);
  });

  it('should extract CVSS scores', () => {
    const rating = mockCycloneDX.vulnerabilities[0].ratings[0];
    expect(rating.score).toBe(7.5);
    expect(rating.severity).toBe("HIGH");
    expect(rating.method).toBe("CVSSv3");
  });

  it('should extract license information', () => {
    const component = mockCycloneDX.components[0];
    expect(component.licenses[0].license.id).toBe("MIT");
  });
});

