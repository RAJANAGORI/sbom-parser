# sbom-parser
A Node.js tool that converts CycloneDX SBOM JSON into a responsive, Tailwind CSS–styled HTML report with collapsible sections and live filtering.

# SBOM HTML Report Generator

This small Node.js script ingests a CycloneDX SBOM JSON and spits out a standalone HTML file styled with Tailwind CSS. It features:

- **Collapsible** sections for Components & Vulnerabilities  
- **Live filtering** of rows via text inputs  
- **Zero-build** setup: runs as CommonJS, CDN-hosted Tailwind  

Perfect for quickly embedding an interactive SBOM dashboard in your frontend or documentation.
