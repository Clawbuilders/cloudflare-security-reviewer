# Vendored from cloudflare/security-audit-skill

- Source: https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit
- Commit: `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (2026-09-14)
- License: MIT, Copyright (c) 2025-2026 Cloudflare, Inc. (see `LICENSE` in this directory)

These files are copied unmodified. `npm run skills:sync` extracts the parts each reviewer needs (the "Core discipline",
attack-class and "Validation rules" sections, and the candidate-verifier checklist) into
`starter/src/lib/skills.generated.ts`. Only the domains this reviewer uses are vendored; the full skill also covers
memory safety, desktop and mobile, protocols and RPC, and resource exhaustion.

To update: copy the files from a newer commit, update the commit above and `SKILL_COMMIT` in `scripts/sync-skills.mjs`,
then run `npm run skills:sync && npm test`.
