# Documentation Index

## Active Baseline

- Current architecture authority: [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md)
- Repository homepage and status summary: [`../README.md`](../README.md)
- Supplemental architecture notes: [`ARCHITECTURE.md`](./ARCHITECTURE.md)

When documents disagree, treat `CONNECTIVITY-SOLVER-BASELINE.md` as the source of truth for connectivity solver/session/strategy boundaries.

## Current Roadmap

- Accepted v2 direct-first plan and its Phase 0 exit record: [`proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md), [`PHASE0-EXIT-RECORD.md`](./PHASE0-EXIT-RECORD.md)
- Autonomous mesh control, peer transit, shortcut proof, and default-off `wink` lifecycle integration (Slices 1-4.5): [`ADR-AUTONOMOUS-MESH.md`](./ADR-AUTONOMOUS-MESH.md)
- Accepted Slice 4.5 C -> B -> A three-node product rollout: [`SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md`](./SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md)
- Three-node peer-coordinated rejoin plus direct routed-SSH field experiment: [`MESH-REJOIN-FIELD-EXPERIMENT.md`](./MESH-REJOIN-FIELD-EXPERIMENT.md)
- Post-r9 cached-endpoint self-bootstrap and recovery-card boundary: [`SELF-BOOTSTRAP-RECOVERY.md`](./SELF-BOOTSTRAP-RECOVERY.md)
- Phase 2D freeze gate: [`PHASE2D-FREEZE.md`](./PHASE2D-FREEZE.md)
- Phase 3A strategy portfolio entry: [`PHASE3A-STRATEGY-PORTFOLIO.md`](./PHASE3A-STRATEGY-PORTFOLIO.md)
- v0.1 freeze gate: [`V0.1-FREEZE.md`](./V0.1-FREEZE.md)
- v0.2 multipath/bootstrap freeze gate: [`V0.2-MULTIPATH-FREEZE.md`](./V0.2-MULTIPATH-FREEZE.md)
- Phase 3B+ working plan: [`../implementation_plan.md`](../implementation_plan.md)
- Protected direct multipath goal: [`MULTIPATH-PROTECTED-DIRECT.md`](./MULTIPATH-PROTECTED-DIRECT.md)
- Intermittent bootstrap broker: [`INTERMITTENT-BOOTSTRAP-BROKER.md`](./INTERMITTENT-BOOTSTRAP-BROKER.md)

## Operator Docs

- Phase 1a machine-wide governor namespace and setup command: [`MACHINE-SAFETY-NAMESPACE.md`](./MACHINE-SAFETY-NAMESPACE.md)
- Phase 1a explicit, lower per-user scope boundary: [`USER-ACKNOWLEDGED-SCOPE.md`](./USER-ACKNOWLEDGED-SCOPE.md)
- Phase 1a bounded cancellation and I/O drain contract: [`CANCELLATION-DRAIN-CONTRACT.md`](./CANCELLATION-DRAIN-CONTRACT.md)
- Phase 1a default no-packet report and explicit bounded STUN mode: [`PASSIVE-DIAGNOSE.md`](./PASSIVE-DIAGNOSE.md)
- Phase 1a local JSON-RPC v1 stdio API: [`STDIO-API-V1.md`](./STDIO-API-V1.md)
- Phase 1a pure-memory NAT simulation matrix and current coverage: [`NAT-SIMULATION-MATRIX.md`](./NAT-SIMULATION-MATRIX.md)
- Phase 1a governed synchronized direct-punch simulation boundary: [`DIRECT-PUNCH-SIMULATION.md`](./DIRECT-PUNCH-SIMULATION.md)
- Phase 1a loopback-only STUN Binding observation slice: [`STUN-OBSERVATION-CLIENT.md`](./STUN-OBSERVATION-CLIENT.md)
- Experimental response-only STUN Binding responder: [`STUN-RESPONDER.md`](./STUN-RESPONDER.md)
- Test-only in-memory observation exchange protocol and deployment boundary: [`SIGNAL-EXCHANGE.md`](./SIGNAL-EXCHANGE.md)
- First authorized real-network STUN observation procedure: [`FIELD-TEST-RUNBOOK.md`](./FIELD-TEST-RUNBOOK.md)
- Linux root-only namespace NAT laboratory: [`NAT-LAB.md`](./NAT-LAB.md)
- Draft Phase 1a one-time test pairing protocol and security gates: [`TEST-ONLY-PAIRING-MINI-SPEC.md`](./TEST-ONLY-PAIRING-MINI-SPEC.md)
- Draft Phase 1a test-pairing cryptographic candidate evaluation (no decision or implementation authority): [`adr/ADR-TEST-PAIRING-CRYPTO-CANDIDATE.md`](./adr/ADR-TEST-PAIRING-CRYPTO-CANDIDATE.md)
- Self-host quickstart: [`SELFHOST-QUICKSTART.md`](./SELFHOST-QUICKSTART.md)
- Experimental `meshnode` restart recovery and recovery-card operation: [`SELF-BOOTSTRAP-RECOVERY.md`](./SELF-BOOTSTRAP-RECOVERY.md)
- Long-running legacy/autonomous client configuration, status, and graceful-down workflow: [`LONG-RUNNING-CLIENT.md`](./LONG-RUNNING-CLIENT.md)
- Control-plane resilience notes: [`CONTROL-PLANE-RESILIENCE.md`](./CONTROL-PLANE-RESILIENCE.md)
- Multipath failover verification: [`MULTIPATH-FAILOVER-VERIFICATION.md`](./MULTIPATH-FAILOVER-VERIFICATION.md)
- In-band peer control boundary: [`INBAND-PEER-CONTROL.md`](./INBAND-PEER-CONTROL.md)
- Troubleshooting: [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md)
- Release process: [`RELEASE.md`](./RELEASE.md)

## Proposals

These files are proposal/RFC material for future architecture work. They remain useful context, but they are not active authority and should not override the baseline. The deep-analysis and improvement notes below come from the 2026-05 architecture overhaul pass.

- [`proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md) — **Accepted** (2026-08-13, [`PHASE0-EXIT-RECORD.md`](./PHASE0-EXIT-RECORD.md)) direct-first v2 product, architecture, safety, validation, and adoption plan; acceptance scope and non-authorized actions per its §20
- [`proposals/WINKYOU-V2-PLAN-REVIEW-2026-08-11.md`](./proposals/WINKYOU-V2-PLAN-REVIEW-2026-08-11.md) — code-backed expert review of the draft v2 plan
- [`proposals/WINKYOU-V2-PLAN-REVIEW-RESPONSE-2026-08-11.md`](./proposals/WINKYOU-V2-PLAN-REVIEW-RESPONSE-2026-08-11.md) — maintainer response and proposed resolution of the expert review
- [`proposals/WINKYOU-V2-PLAN-REVIEW-FOLLOWUP-2026-08-11.md`](./proposals/WINKYOU-V2-PLAN-REVIEW-FOLLOWUP-2026-08-11.md) — second-round review closing the response with third-party socket and machine-governor requirements
- [`proposals/WINKYOU-V2-PLAN-REVIEW-ROUND3-2026-08-11.md`](./proposals/WINKYOU-V2-PLAN-REVIEW-ROUND3-2026-08-11.md) — third-round acceptance review covering non-privileged governor scope and Phase 1a test-only pairing
- [`proposals/HTTP-CONNECT-WEBSOCKET-STRATEGY.md`](./proposals/HTTP-CONNECT-WEBSOCKET-STRATEGY.md)
- [`proposals/QUIC-DATAGRAM-STRATEGY.md`](./proposals/QUIC-DATAGRAM-STRATEGY.md)
- [`ARCHITECTURE-DEEP-ANALYSIS.md`](./ARCHITECTURE-DEEP-ANALYSIS.md)
- [`ARCHITECTURE-ROADMAP.md`](./ARCHITECTURE-ROADMAP.md)
- [`ARCHITECTURE-RISK-REGISTER.md`](./ARCHITECTURE-RISK-REGISTER.md)
- [`ARCHITECTURE-IMPROVEMENT-INDEX.md`](./ARCHITECTURE-IMPROVEMENT-INDEX.md)
- [`improvements/`](./improvements)

## Archive / Brainstorm

- Historical Windows emergency-stop principles (personal paths, IPs, builds, and topology removed): [`RUNBOOK-EMERGENCY-STOP-HISTORICAL-WINDOWS.md`](./RUNBOOK-EMERGENCY-STOP-HISTORICAL-WINDOWS.md)
- Legacy baseline notice: [`EXECUTION-BASELINE.md`](./EXECUTION-BASELINE.md)
- Historical legacy snapshot pointer: [`legacy/EXECUTION-BASELINE-legacy.md`](./legacy/EXECUTION-BASELINE-legacy.md)
- Historical task breakdowns: [`tasks/`](./tasks)
- Peer relay notes: [`PEER-RELAY-DESIGN.md`](./PEER-RELAY-DESIGN.md)
- Deployment questions log: [`DEPLOYMENT-QUESTIONS-2026-04-15.md`](./DEPLOYMENT-QUESTIONS-2026-04-15.md)
- Deployment hardening summary: [`../DEPLOYMENT-SUMMARY.md`](../DEPLOYMENT-SUMMARY.md)

Root-level archive/proposal documents:

- [`../winkplan.md`](../winkplan.md)
- [`../brainstorm.md`](../brainstorm.md)
- [`../selfdev.md`](../selfdev.md)
- [`../selfhost.md`](../selfhost.md)
- [`../manage.md`](../manage.md)
- [`../question.md`](../question.md)
- [`../guess.md`](../guess.md)
- [`../protocol.md`](../protocol.md)
- [`../wink-protocol-v1.md`](../wink-protocol-v1.md)
- [`../codex_summary.md`](../codex_summary.md)

Archive and brainstorm documents are preserved for traceability. Do not treat them as current implementation instructions unless a current roadmap entry explicitly references them.
