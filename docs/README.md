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
- Phase 1a merged literal-loopback connect-test and reproducible proof: [`LOOPBACK-CONNECT-TEST.md`](./LOOPBACK-CONNECT-TEST.md)
- Accepted first non-loopback connect-test authority boundary and merged N1 netns proof (mandatory Linux CI; no product or live-network authorization): [`adr/ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md`](./adr/ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md), [Issue #70](https://github.com/houyuwushang/winkyou/issues/70)
- Merged N2a/N2b zero-network direct-attempt protocol and NAT matrix evidence: [`N2-DIRECT-ATTEMPT-SIMULATION.md`](./N2-DIRECT-ATTEMPT-SIMULATION.md)
- Merged N2c disconnected governed rendezvous carrier and same-socket STUN evidence (literal loopback only; no product/live-network authority): [`N2C-RENDEZVOUS-CARRIER.md`](./N2C-RENDEZVOUS-CARRIER.md)
- Merged N2d dual-process namespace/NAT-lab composition proof (test-only, required Linux CI; no product/live-network authority): [`N2D-NAMESPACE-E2E.md`](./N2D-NAMESPACE-E2E.md)
- Accepted N3a product-entry, one-shot rendezvous, pairing-material and named live-window design (N3b implementation may start behind its acceptance gates; live I/O stays disabled), plus the blank authorization template: [`adr/ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md`](./adr/ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md), [`N3-LIVE-AUTHORIZATION-TEMPLATE.md`](./N3-LIVE-AUTHORIZATION-TEMPLATE.md)
- N3b explicit stdio v2 protocol and review evidence (implementation entry exists, but LAN/public deployment and live attempts remain unauthorized): [`STDIO-API-V2.md`](./STDIO-API-V2.md), [`N3B-PRODUCT-ENTRY-EVIDENCE.md`](./N3B-PRODUCT-ENTRY-EVIDENCE.md)
- Accepted N3c design for adopting an existing bounded OOB stream and handing a verified UDP socket to an independently leased data-plane consumer; its Gate A implementation remains limited to memory/loopback/netns evidence and does not itself authorize SSH assembly, WireGuard, product entry, or live I/O: [`adr/ADR-N3C-OOB-DIRECT-HANDOFF.md`](./adr/ADR-N3C-OOB-DIRECT-HANDOFF.md), [Issue #85](https://github.com/houyuwushang/winkyou/issues/85)
- Draft Gate A implementation evidence for the bounded OOB carrier, strict artifact/profile split, lease-bound transport handoff, 100-run NAT simulation, and required Linux namespace matrix; the implementation passed independent review and is merged (Gate B2, SSH assembly, WireGuard, product entry, and live I/O remain unauthorized): [`GATE-A-OOB-HANDOFF-EVIDENCE.md`](./GATE-A-OOB-HANDOFF-EVIDENCE.md)
- Accepted N3c Gate B design making bounded endpoint-dependent NAT solving the direct-path product target, with predictive, asymmetric birthday and separately gated hard-random campaign profiles; Gate B1, Gate A, Gate B2 and the Gate B3 isolated implementation are independently reviewed and merged. The no-budget-change selection-deadline fix was independently reviewed and merged in PR #103; Issue #100 is closed. The isolated evidence remains disconnected from live I/O: [`adr/ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md`](./adr/ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md), [`GATE-B3-HARD16-ISOLATED-EVIDENCE.md`](./GATE-B3-HARD16-ISOLATED-EVIDENCE.md), [Issue #87](https://github.com/houyuwushang/winkyou/issues/87), [Issue #100](https://github.com/houyuwushang/winkyou/issues/100)
- Accepted Gate C1 design for a fixed, key-only OpenSSH child stream and product handoff. Gate C1a is merged; C1b implementation is separately authorized under ADR §16/§17 for memory, literal loopback and required netns proof only. C1c/C2 and live I/O remain unauthorized: [`adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md`](./adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md), [`GATE-C1A-SSH-ASSEMBLY-EVIDENCE.md`](./GATE-C1A-SSH-ASSEMBLY-EVIDENCE.md), [`N3C-GATE-C-LIVE-AUTHORIZATION-TEMPLATE.md`](./N3C-GATE-C-LIVE-AUTHORIZATION-TEMPLATE.md), [Issue #98](https://github.com/houyuwushang/winkyou/issues/98)
- Gate C1b composition resumes under accepted R1 completion confirmation (ADR §19); root execution (§18), preserved failing evidence and outstanding real SSH/netns gates remain explicit: [`GATE-C1B-PRODUCT-COMPOSITION-EVIDENCE.md`](./GATE-C1B-PRODUCT-COMPOSITION-EVIDENCE.md)
- Accepted Gate B2 executor evidence for predictive APDM and asymmetric 128×512 birthday schedules, exact governor/ledger admission, Gate A transport handoff, natsim terminals, and required Linux namespace proofs; PR #93 passed independent review and is merged, without granting Gate B3, product, or live-network authority: [`GATE-B2-HARD-NAT-EXECUTOR-EVIDENCE.md`](./GATE-B2-HARD-NAT-EXECUTOR-EVIDENCE.md)
- Phase 1a pure-memory NAT simulation matrix and current coverage: [`NAT-SIMULATION-MATRIX.md`](./NAT-SIMULATION-MATRIX.md)
- Phase 1a governed synchronized direct-punch simulation boundary: [`DIRECT-PUNCH-SIMULATION.md`](./DIRECT-PUNCH-SIMULATION.md)
- Phase 1a simulation-only NNpsk0 implementation evidence and limits: [`NOISE-CORE.md`](./NOISE-CORE.md)
- Phase 1a cross-process and cross-restart pairing admission contract: [`PAIRING-RESTART-SAFETY-CONTRACT.md`](./PAIRING-RESTART-SAFETY-CONTRACT.md)
- Phase 1a machine-only persistent pairing admission journal implementation: [`PAIRING-ADMISSION-JOURNAL.md`](./PAIRING-ADMISSION-JOURNAL.md)
- Phase 1a zero-network pairing admission gate and parent-process restart witness: [`PAIRING-ADMISSION-GATE.md`](./PAIRING-ADMISSION-GATE.md)
- Phase 1a loopback-only STUN Binding observation slice: [`STUN-OBSERVATION-CLIENT.md`](./STUN-OBSERVATION-CLIENT.md)
- Experimental response-only STUN Binding responder: [`STUN-RESPONDER.md`](./STUN-RESPONDER.md)
- Test-only in-memory observation exchange protocol and deployment boundary: [`SIGNAL-EXCHANGE.md`](./SIGNAL-EXCHANGE.md)
- First authorized real-network STUN observation procedure: [`FIELD-TEST-RUNBOOK.md`](./FIELD-TEST-RUNBOOK.md)
- Linux root-only namespace NAT laboratory: [`NAT-LAB.md`](./NAT-LAB.md)
- Draft Phase 1a one-time test pairing protocol and security gates: [`TEST-ONLY-PAIRING-MINI-SPEC.md`](./TEST-ONLY-PAIRING-MINI-SPEC.md)
- Accepted Phase 1a test-pairing cryptographic candidate decision (protocol and simulation-only implementation; real-network authority separately gated): [`adr/ADR-TEST-PAIRING-CRYPTO-CANDIDATE.md`](./adr/ADR-TEST-PAIRING-CRYPTO-CANDIDATE.md)
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
