# Security

## Known Vulnerabilities

### Dev Dependencies (4 moderate)

All 4 moderate vulnerabilities are in the `vitest` → `vite` → `esbuild` dev dependency chain (GHSA-67mh-4wv8-2f99). These only affect the development/test environment and do **not** ship in the published npm package.

Fix requires upgrading to vitest v4+ which is a breaking change. Will be addressed in a future release.

## Reporting

Report security issues to mike@cavallo.dev.
