# Test-only pairing mini-spec (Phase 1a)

Status: **Draft; security review required before any cryptographic or network
adapter is implemented.**

This document defines the narrow authentication and control-channel boundary
for one operator-initiated `wink connect-test`. It does not authorize live
probing, a production socket, a public coordinator, a daemon, or any legacy
recovery path. Until the review gates in this document are closed, the only
permitted implementation is an in-memory simulation with no cryptography and
no network capability.

Any pre-review companion simulation MUST live in `internal/v2/testpairing` and
contain only a secret-free attempt context, process-local one-use ledger,
bounded message state machine, fake clock boundary, and one-frame in-memory
queues. Passing its tests is not security approval and is not evidence that a
real pairing channel exists.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are used as
normative requirements in this document.

## 1. Purpose

Phase 1a needs two test processes to coordinate a bounded attempt before the
Phase 2 roster and member identity exist. `TestPairingChannel` proves only that
both endpoints received the same one-time, high-entropy pairing material
through an operator-controlled out-of-band workflow.

It deliberately does not prove that either endpoint is a WinkYou member, owns
a stable NodeID, or should receive any persistent authority.

The intended lifecycle is:

```text
operator creates one attempt
        |
        v
OOB OFFER <-> ACCEPTANCE -> COMPLETE BUNDLE
        |
        v
atomically burn credential on both endpoints
        |
        v
authenticated stream -> PREPARE -> READY -> FIRE -> VERIFY
        |                                      |
        +---- any error/cancel/timeout --------+
                                               v
                                    close and destroy material
```

## 2. Non-goals and permanent authority boundary

`auth_scope` is the exact constant `test_only`. Code consuming this scope MUST
NOT:

- create or update a roster;
- create, assert, or bind a stable NodeID;
- bind a long-term WireGuard key;
- join a Mesh or produce a reusable invitation;
- grant transit, service, route-installation, port-mapping, or recovery
  authority;
- start Node Runtime, a background process, an automatic retry, prediction, or
  birthday-punch strategy;
- convert the pairing into a Phase 2 member session; or
- persist the pairing secret, traffic key, temporary key, or peer endpoint as
  reusable discovery state.

Production Node Runtime MUST reject `test_only` even if every message is
otherwise valid. Phase 2 uses roster-backed identity and a different
`SignalingChannel`; it does not upgrade this channel.

This protocol also does not solve discovery. Before a future real adapter can
start, the operator must provide a reviewed, reliable, ordered stream through a
static endpoint, an existing control underlay, or another explicitly approved
carrier. Peer-supplied addresses are data, not permission to dial or open a
socket.

## 3. Threat model and trust anchor

The protocol assumes an attacker can observe, drop, replay, reorder, delay, or
modify network traffic and can start arbitrary unauthenticated connections.
It also treats imported configuration, environment variables, remote RPC
fields, DNS answers, and peer messages as unable to grant local governor scope.

The trust anchor is the operator-controlled OOB transfer of a complete pairing
bundle. The OOB workflow MUST provide confidentiality and integrity for the
pairing secret. Suitable examples are a local QR transfer or a file moved over
an already authenticated operator channel. Public paste sites, ordinary chat
rooms, command history, logs, issue comments, and process arguments are not
suitable.

Possession of the unconsumed secret and complete bundle is sufficient to
impersonate a test endpoint. This protocol does not hide that limitation. A
compromised endpoint, operator channel, or local account remains outside the
protection of the handshake.

The protocol is intended to reject:

- wrong or modified pairing material;
- network replay and local credential reuse;
- cross-attempt and cross-generation messages;
- initiator/responder reflection;
- expired bundles;
- transcript tampering; and
- attempts to use `test_only` as production authority.

It does not claim anonymity, resistance to endpoint compromise, or a global
clock source.

## 4. Pairing artifacts

### 4.1 Encodings and entropy

All random values MUST be generated from the operating system cryptographic
random source. Identifiers are canonical, case-sensitive, unpadded base64url
strings encoding exactly 16 random bytes. The pairing secret is an unpadded
base64url string encoding exactly 32 random bytes (256 bits). Values are
opaque; no device name, username, IP address, MAC address, or stable identifier
may be embedded in them.

The artifacts use UTF-8 JSON. Parsers MUST reject duplicate object keys,
unknown fields, invalid UTF-8, non-canonical identifier encodings, numbers
outside their declared range, and documents larger than 4096 bytes. Fields
used in the cryptographic context are canonicalized with the JSON
Canonicalization Scheme (JCS) from [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html).
`observation_generation` is encoded as a decimal string to avoid cross-language
JSON integer ambiguity.

### 4.2 OFFER

The initiator creates:

```json
{
  "artifact": "offer",
  "protocol": "winkyou-test-pairing/1",
  "auth_scope": "test_only",
  "credential_id": "<16 random bytes>",
  "pairing_secret": "<32 random bytes>",
  "attempt_id": "<16 random bytes>",
  "observation_generation": "<positive uint64>",
  "initiator_participant_id": "<16 random bytes>",
  "initiator_governor_scope": "machine|user_acknowledged",
  "issued_at": "<RFC3339 UTC seconds>",
  "expires_at": "<RFC3339 UTC seconds>"
}
```

`expires_at - issued_at` MUST be positive and MUST NOT exceed ten minutes. The
initiator MUST also enforce a monotonic local deadline no later than ten
minutes after generation. There is no expiry grace period; clock skew may cause
a safe early rejection, never an automatic lifetime extension.

The initiator scope comes from the already acquired local governor. It MUST NOT
come from a config file or peer input.

### 4.3 ACCEPTANCE

After importing and locally validating the OFFER, the responder creates:

```json
{
  "artifact": "acceptance",
  "protocol": "winkyou-test-pairing/1",
  "auth_scope": "test_only",
  "credential_id": "<same credential_id>",
  "attempt_id": "<same attempt_id>",
  "observation_generation": "<same generation>",
  "initiator_participant_id": "<same initiator id>",
  "responder_participant_id": "<16 random bytes>",
  "initiator_governor_scope": "<same initiator scope>",
  "responder_governor_scope": "machine|user_acknowledged",
  "issued_at": "<same issued_at>",
  "expires_at": "<same expires_at>",
  "offer_fingerprint": "<SHA-256 of the JCS OFFER without pairing_secret>"
}
```

The responder scope is read from its own acquired local governor. The
acceptance is returned through the controlled OOB workflow. The initiator MUST
compare every repeated field and the fingerprint before producing a COMPLETE
BUNDLE. This two-way step ensures both random participant identifiers and both
actual local scope claims are known before the handshake.

The fingerprint is a correlation and operator-verification value, not a secret
and not an authentication MAC. Version 1 does not define a shortened manual
comparison code. If a short human-entered secret is added later, it requires a
separately reviewed PAKE, online rate limiting, and lockout; a low-entropy code
MUST NOT be used directly as a PSK.

### 4.4 COMPLETE BUNDLE and pairing context

The complete bundle consists of the validated OFFER and ACCEPTANCE. Each side
stores it only long enough to attempt one connection. The secret MUST be kept
separate from diagnostic DTOs, JSON reports, errors, tracing fields, crash
reports, and command-line arguments.

The `PairingContext` is the ACCEPTANCE object plus the following fixed fields:

```json
{
  "tls_profile": "tls13-epsk-importer-psk-dhe-x25519-aes128gcm-sha256/1",
  "initiator_transport_role": "tls_client",
  "responder_transport_role": "tls_server",
  "early_data": "disabled",
  "resumption": "disabled"
}
```

The external-PSK importer context is:

```text
SHA-256(
  UTF8("winkyou test-only pairing importer context v1\n") ||
  JCS(PairingContext)
)
```

This digest is only a standardized context-binding input to the reviewed PSK
importer. It is not a home-grown MAC or handshake. The external PSK identity is
the random `credential_id`; the base key is the 32-byte `pairing_secret`; the
single associated hash is SHA-256.

## 5. Provisional cryptographic profile

The only version-1 candidate is:

- TLS 1.3 exactly, as specified by
  [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html);
- imported external PSKs exactly as specified by
  [RFC 9258](https://www.rfc-editor.org/rfc/rfc9258.html);
- `psk_dhe_ke` only; PSK-only `psk_ke` is rejected;
- X25519 only for the fresh (EC)DHE share;
- `TLS_AES_128_GCM_SHA256` only;
- ALPN exactly `winkyou-test-pairing/1`;
- both endpoints authenticated by possession of the imported external PSK;
- no certificate fallback, anonymous fallback, version fallback, cipher
  negotiation outside this profile, or opportunistic plaintext;
- 0-RTT, session tickets, resumption, renegotiation, post-handshake
  authentication, and exported reusable credentials disabled; and
- one TLS connection for one attempt, closed after terminal VERIFY or CANCEL.

RFC 8446 binds the fresh client and server DHE public shares, selected
parameters, and Finished messages through the TLS handshake transcript. RFC
9258 binds the provisioned `PairingContext` to the protocol and KDF while
separating this external PSK from other uses. Application messages are then
integrity- and confidentiality-protected TLS records; WinkYou MUST NOT add its
own application MAC, custom key schedule, or second encryption layer.

This profile is intentionally not implemented yet. The Go standard library
[`crypto/tls`](https://pkg.go.dev/crypto/tls) exposes PSK controls for session
resumption but no external-PSK importer API. Session tickets, `WrapSession`, or
`UnwrapSession` MUST NOT be repurposed as an approximation. No TLS source fork,
copied handshake implementation, `unsafe` hook, or reflection hook is allowed.

Before implementation, a follow-up ADR must identify a maintained,
independently reviewed Go implementation that supports this exact profile and
interoperable test vectors. If none is acceptable, this candidate returns to
security review; it MUST NOT silently fall back to Noise, a bare X25519+hash
construction, a custom MAC, or unauthenticated TLS.

## 6. Single-use and replay ledger

Each endpoint maintains a replay ledger in its already selected canonical
machine or per-user safety namespace. The namespace is selected locally before
bundle import and MUST equal that endpoint's scope in `PairingContext`.

Immediately before sending or accepting the first handshake byte, each
endpoint MUST atomically transition its `credential_id` from absent to burned.
There is no rollback to fresh. A failed dial, rejected handshake, cancellation,
timeout, process crash, or malformed peer burns the credential. Retrying needs
a new OFFER and a new secret.

The burned record contains only:

- `credential_id`;
- `attempt_id`;
- the context digest;
- local scope;
- burn time and expiry; and
- terminal reason.

It contains no secret, traffic key, endpoint, or payload. The record MUST
survive process restart at least through `expires_at` plus the maximum local
clock-skew policy. Cleanup is bounded maintenance under the same namespace
owner; missing, corrupt, untrusted, or unavailable ledger state fails closed.

The simulated implementation uses an injected in-memory ledger and fake clock.
It MUST NOT be described as restart-safe evidence.

## 7. Authenticated control envelope

After TLS Finished succeeds, both endpoints exchange length-prefixed JSON
envelopes. The prefix is a four-byte unsigned big-endian payload length. Zero,
values above 4096, invalid JSON, duplicate/unknown fields, and trailing bytes
are rejected before dispatch.

Every envelope contains:

```json
{
  "protocol": "winkyou-test-pairing/1",
  "auth_scope": "test_only",
  "attempt_id": "<bound attempt>",
  "observation_generation": "<bound generation>",
  "from_participant_id": "<bound sender>",
  "to_participant_id": "<bound receiver>",
  "sender_role": "initiator|responder",
  "governor_scope": "machine|user_acknowledged",
  "sequence": 1,
  "type": "prepare|ready|fire|verify|cancel",
  "payload": {}
}
```

Sequence numbers start at one independently in each direction and increase by
exactly one. Every bound field is compared to `PairingContext` before payload
parsing. Role reflection, skipped/repeated sequence, unknown type, stale
generation, and wrong participant fail the entire channel closed.

The payload schemas belong to the future connect-test plan, not to this
authentication spec. Until independently reviewed, payload is a simulation-only
opaque byte string no larger than 2048 bytes. It MUST NOT be interpreted as an
endpoint, resource request, governor choice, strategy name, socket count, or
permission to perform I/O.

## 8. State machine and hard limits

Both endpoints send exactly one PREPARE after channel establishment. Each sends
exactly one READY only after receiving the peer PREPARE. Only the initiator can
send FIRE, and only after it has sent and received READY. The initiator sends at
most one VERIFY after sending FIRE and completing its local simulated action;
the responder sends at most one VERIFY after receiving FIRE and completing its
local simulated action. Receipt of the peer VERIFY after sending the local
VERIFY is the only successful terminal state.

CANCEL may be sent once from any non-terminal state. Receipt, local
cancellation, parser failure, TLS alert, EOF, timeout, or any invalid transition
closes the channel and produces a failed terminal result. No message is retried
inside this protocol; reliability belongs to the carrier. A new attempt needs a
new credential.

Compiled version-1 limits are:

| Limit | Hard ceiling |
| --- | ---: |
| TLS connections | 1 per attempt |
| Concurrent attempts per channel | 1 |
| Pairing lifetime | 10 minutes |
| Established control lifetime | 15 seconds |
| Frame body | 4096 bytes |
| Opaque simulation payload | 2048 bytes |
| Messages per direction | 4 plus one CANCEL |
| Messages total | 8 plus one CANCEL |
| Receive rate | 4 messages/second, burst 2 |
| Buffered inbound frames | 1 |
| Buffered outbound frames | 1 |

Configuration may lower, never raise, these values. The shorter local governor
deadline always wins. The channel owns no retry loop, ticker that outlives the
attempt, unbounded queue, or background recovery task.

## 9. Governor and cancellation coupling

A future real adapter MUST receive an already acquired connect-test attempt
capability; it cannot acquire a machine or user governor itself. Transport
connection cost, DNS work, and any later probe work must be separately reserved
under reviewed coarse or `probeio` leases before the relevant I/O begins.

If either endpoint reports `user_acknowledged`, the combined test report MUST
state:

```text
auth_scope: test_only
governor_assurance: user_acknowledged
machine_wide_safety_verified: false
```

A peer's scope is an authenticated claim by a pairing-secret holder, not remote
proof of its OS lock. It may lower report assurance but can never raise local
authority.

Before active work begins, the real channel must register a governor drain
witness. Cancellation first rejects new messages and I/O, then closes the
carrier, waits for admitted operations, completes the witness, destroys
ephemeral material best-effort, and records a terminal ledger reason. A drain
timeout trips the applicable safety scope. Go memory zeroing is best-effort and
MUST NOT be advertised as guaranteed erasure.

## 10. Reports and secret handling

Reports may include protocol version, auth scope, participant/attempt IDs,
generation, both reported governor scopes, context digest, timestamps, terminal
state, bounded counters, and sanitized failure class.

Reports, logs, errors, metrics, panics, and traces MUST NOT contain the pairing
secret, imported/derived PSK, TLS traffic secrets, raw OOB artifacts, payloads,
or a reusable carrier credential. Debug key logging is forbidden. Diagnostic
DTOs remain separate from domain objects containing secret material.

## 11. Permanent negative tests

The implementation gate includes deterministic tests for:

- malformed, duplicate-key, unknown-field, oversized, and non-canonical
  artifacts;
- secrets or identifiers with wrong length or encoding;
- duration over ten minutes, expiry, clock jump, and generation zero;
- wrong token, modified context, cross-attempt and cross-generation use;
- atomic burn, reuse after success/failure/cancel/crash simulation, corrupt
  ledger, and namespace mismatch;
- wrong role, role reflection, wrong participant, repeated/skipped sequence,
  invalid transition, message flood, and oversized frame/payload;
- cancellation and expiry at every state with no surviving goroutine or queued
  message;
- rejection by Mesh, Node Runtime, service, transit, recovery, mapping,
  prediction, birthday, and stable-key APIs;
- report downgrading when either endpoint is `user_acknowledged` and proof that
  peer input cannot raise local scope;
- absence of secret material from every report and error fixture;
- interoperation and negative vectors for the final reviewed TLS library; and
- the repository AST/dependency gate proving the simulated package has no raw
  or transitive network capability.

## 12. Review and implementation gates

All of the following are required before a real `TestPairingChannel` exists:

1. independent security review accepts this threat model, OOB workflow,
   importer context, single-use semantics, role binding, state machine, and
   limits;
2. a follow-up ADR selects a maintained and independently reviewed
   RFC 8446/RFC 9258 implementation for the exact fixed profile;
3. cross-language positive and negative test vectors are checked in;
4. the durable replay-ledger format, locking, ACL/ownership checks, corruption
   behavior, and bounded cleanup are reviewed for Windows and Linux;
5. TCP/DNS carrier costs and cancellation drains are integrated with the
   governor without giving this package a raw socket;
6. secret-redaction tests and fuzz/property tests pass; and
7. live-network validation receives separate explicit approval and remains
   isolated, bounded, observable, and kill-switch controlled.

Approval of this document would approve only an implementation attempt behind
these gates. It would not approve public rollout, live probing, daemon startup,
automatic recovery, or production identity.
