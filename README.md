# Enterprise Security Posture Engine with TypeSafe Jev

A Swiss-designed executive posture architecture and live reporting engine that translates raw findings from Datadog Compliance and Wiz CNAPP into actionable business risk decisions using TypeSafe Jev (System One decision model).

## Live Executive Dashboard
- **GitHub Pages**: [https://entscheidung-bot.github.io/jev-security-posture/](https://entscheidung-bot.github.io/jev-security-posture/)

## Architecture Summary
1. **Ingest**: Ingest findings from Datadog CSM and Wiz via REST & GraphQL APIs.
2. **Enrich**: Cross-reference with internal CMDB and network topology (Asset Tier, Internet Ingress, WAF, mTLS).
3. **Judge (Jev)**: Call TypeSafe Jev System One model for typed decisions (`MATERIAL_BUSINESS_RISK`, `CONTAINED_RESIDUAL_RISK`, `NOISE_SUPPRESSED`).
4. **Deliver**: Executives trigger on-demand evaluation runs via GitHub Actions `workflow_dispatch`.
