# Test-only pairing mini-spec (Phase 1a)

Status: **Draft; security review required before any cryptographic or network
adapter is implemented.**

Review disposition (2026-08-12): the first expert review accepted the direction
and required the S1/S2 changes recorded below. Review gate 1 remains open until
those changes are confirmed. This document is stacked on PR #23; every
statement about `machine` and `user_acknowledged` scope is conditional on an
independent review of #23's scope semantics and the stack must merge from the
bottom up.

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
- cross-attempt and non-version-1 generation messages;
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
JSON integer ambiguity. Phase 1a has no production network-observation system,
so version 1 operator tooling MUST assign the literal string `"1"` and parsers
MUST reject every other value. In this version it is an anti-mixup field, not a
claim of network freshness. Giving it another source or meaning requires a
versioned spec change and review.

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
  "observation_generation": "1",
  "initiator_participant_id": "<16 random bytes>",
  "initiator_governor_scope": "machine|user_acknowledged",
  "secure_channel_profile": "<one exact ADR-selected profile>",
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
  "observation_generation": "1",
  "initiator_participant_id": "<same initiator id>",
  "responder_participant_id": "<16 random bytes>",
  "initiator_governor_scope": "<same initiator scope>",
  "responder_governor_scope": "machine|user_acknowledged",
  "secure_channel_profile": "<same exact profile>",
  "issued_at": "<same issued_at>",
  "expires_at": "<same expires_at>",
  "offer_fingerprint": "<unpadded base64url SHA-256 digest>"
}
```

The responder scope is read from its own acquired local governor. The
acceptance is returned through the controlled OOB workflow. The initiator MUST
compare every repeated field and the fingerprint before producing a COMPLETE
BUNDLE. This two-way step ensures both random participant identifiers and both
actual local scope claims are known before the handshake.

`offer_fingerprint` is computed in exactly this order:

1. parse and validate the OFFER as an object;
2. construct a new object containing every validated OFFER member except the
   `pairing_secret` member;
3. apply JCS to that new object;
4. apply SHA-256 to the UTF-8 JCS bytes; and
5. encode the 32-byte digest as canonical unpadded base64url.

The member is removed from the data model before canonicalization. Textual
deletion from serialized JSON, hashing the original bytes, padded base64, and
hex encoding are all invalid. Positive and negative cross-language vectors
MUST freeze this ordering.

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
  "initiator_channel_role": "initiator",
  "responder_channel_role": "responder",
  "early_data": "disabled",
  "resumption": "disabled",
  "runtime_fallback": "disabled"
}
```

`secure_channel_profile` is not negotiated on the carrier. The follow-up ADR
selects one exact identifier, both OOB artifacts repeat it, and unknown or
mismatched values fail before any carrier I/O. Until that ADR is accepted there
is no valid real-channel value and only the secret-free simulation is allowed.
The simulation uses the internal sentinel
`simulation/no-crypto-no-network/1` solely to exercise context binding. Real
artifact parsers and adapters MUST reject that sentinel; it MUST NOT appear in
an OOB bundle or be promoted by the ADR.

Candidate A's external-PSK importer context is:

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

Candidate B MUST bind the exact same JCS `PairingContext` as the Noise prologue
using these bytes, with no alternate encoding:

```text
UTF8("winkyou test-only pairing Noise prologue v1\n") ||
JCS(PairingContext)
```

The selected Noise implementation must mix that prologue into its handshake
hash exactly as required by the reviewed Noise framework. It MUST NOT treat the
prologue as an application MAC or omit it when payloads are empty.

## 5. Provisional cryptographic profile

The follow-up ADR MUST select exactly one of the following parallel candidate
families and freeze it in `secure_channel_profile`. There is no on-wire
algorithm negotiation and no fallback between them. Selection of a library is
not selection of a protocol: the exact profile, context binding, framing,
failure behavior, and test vectors must all be accepted together.

### 5.1 Candidate A: TLS 1.3 external PSK importer

The proposed exact profile identifier is
`tls13-epsk-importer-psk-dhe-x25519-aes128gcm-sha256/1`. Its requirements are:

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

Candidate A is intentionally not implemented yet. The Go standard library
[`crypto/tls`](https://pkg.go.dev/crypto/tls) exposes PSK controls for session
resumption but no external-PSK importer API. Session tickets, `WrapSession`, or
`UnwrapSession` MUST NOT be repurposed as an approximation. No TLS source fork,
copied handshake implementation, `unsafe` hook, or reflection hook is allowed.

### 5.2 Candidate B: reviewed Noise framework implementation

Candidate B is an explicitly reviewed parallel candidate, not an automatic
fallback. It must use the official
[Noise Protocol Framework](https://noiseprotocol.org/noise.html), an
interactive PSK-modified named pattern, and fresh ephemeral Diffie-Hellman. The
ADR MUST freeze all of the following before this candidate has a valid
`secure_channel_profile` value:

- the exact standard pattern and `pskN` placement, with an independent review
  of its mutual authentication, key-confirmation, forward-secrecy, KCI, and
  identity-exposure properties for this OOB threat model;
- one exact standard Noise protocol name and suite, using 25519 and a standard
  Noise cipher/hash combination, with no application-defined token sequence,
  primitive, negotiation, or downgrade;
- how the 32-byte `pairing_secret` is supplied as the Noise PSK and how the
  section 4.4 prologue is checked on both sides;
- handshake and transport framing, nonce exhaustion, EOF/truncation handling,
  per-attempt key lifetime, and terminal close behavior within the section 8
  hard limits; and
- interoperable positive/negative vectors plus fuzz, concurrency, and secret
  redaction evidence for the selected Go implementation.

If the chosen pattern uses static key slots, those keypairs MUST be generated
for this attempt only, MUST NOT assert a stable NodeID, and MUST be destroyed
best-effort at terminal state. Candidate B permits neither 0-RTT nor PSK/key
reuse, resumption, rekey into a second attempt, or transport fallback.

`github.com/flynn/noise` is a possible ADR evaluation input, not a pre-approved
dependency. The ADR must establish current maintenance, release provenance,
security-review history, supported vectors, and suitability at selection time;
repository popularity or use of related primitives by another protocol is not
that evidence.

### 5.3 Common rejection rule

Before implementation, the ADR must identify a maintained, independently
reviewed implementation for one complete candidate profile. If neither is
acceptable, the implementation gate stays closed. WinkYou MUST NOT silently
switch candidate families or use a bare X25519+hash construction, custom MAC,
custom handshake, unauthenticated TLS, or a TLS source fork.

## 6. Single-use and replay ledger

Each endpoint maintains a replay ledger in its already selected canonical
machine or per-user safety namespace. The namespace is selected locally before
bundle import and MUST equal that endpoint's scope in `PairingContext`.

The pre-handshake scope admission in section 9 runs immediately before sending
or accepting the first secure-channel handshake byte. As part of that admission
each endpoint MUST atomically transition its `credential_id` from absent to
burned. There is no rollback to fresh. A scope mismatch, failed dial, rejected
handshake, cancellation, timeout, process crash, or malformed peer burns the
credential. Retrying needs a new OFFER and a new secret.

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

After the selected secure-channel handshake authenticates both endpoints (TLS
Finished for candidate A or reviewed Noise handshake completion for candidate
B), both endpoints exchange length-prefixed JSON envelopes. The prefix is a
four-byte unsigned big-endian payload length. Zero, values above 4096, invalid
JSON, duplicate/unknown fields, and trailing bytes are rejected before
dispatch.

Every envelope contains:

```json
{
  "protocol": "winkyou-test-pairing/1",
  "auth_scope": "test_only",
  "attempt_id": "<bound attempt>",
  "observation_generation": "1",
  "secure_channel_profile": "<bound profile>",
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
parsing. Role reflection, skipped/repeated sequence, unknown type, a generation
other than `"1"`, and wrong participant fail the entire channel closed.

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
cancellation, parser failure, secure-channel authentication failure or alert,
EOF, timeout, or any invalid transition closes the channel and produces a
failed terminal result. No message is retried inside this protocol; reliability
belongs to the carrier. A new attempt needs a new credential.

Compiled version-1 limits are:

| Limit | Hard ceiling |
| --- | ---: |
| Secure-channel carrier connections | 1 per attempt |
| Concurrent attempts per channel | 1 |
| Pairing lifetime | 10 minutes |
| Established control lifetime | 15 seconds |
| Frame body | 4096 bytes |
| Opaque simulation payload | 2048 bytes |
| Messages per direction | 4 plus one CANCEL |
| Messages total | 8 plus one CANCEL |
| Receive rate | 4 messages/second sustained, burst 4 |
| Buffered inbound frames | 1 |
| Buffered outbound frames | 1 |

Configuration may lower, never raise, these values. The shorter local governor
deadline always wins. The channel owns no retry loop, ticker that outlives the
attempt, unbounded queue, or background recovery task.

Receive-rate accounting MUST use the local monotonic clock. Burst 4 is the
minimum that permits the responder to receive the complete valid
PREPARE/READY/FIRE/VERIFY sequence without an artificial 250 ms delay. It is
still provisional: before a real adapter is accepted, sanitized test-only
timings must demonstrate that normal successful exchanges are not falsely
rate-limited. Raising the hard ceiling requires a reviewed spec change; flood
tests must still terminate within the same control lifetime.

## 9. Governor and cancellation coupling

A future real adapter MUST receive an already acquired connect-test attempt
capability; it cannot acquire a machine or user governor itself. Transport
connection cost, DNS work, and any later probe work must be separately reserved
under reviewed coarse or `probeio` leases before the relevant I/O begins.

Bundle-import validation is not sufficient because as much as ten minutes may
pass before the handshake. Each endpoint MUST perform this local admission
sequence immediately before sending or accepting the first secure-channel
handshake byte:

1. ask the same local governor authority that issued the attempt capability for
   a fresh scope/ownership observation;
2. classify whether the capability is live, its scope still exactly equals this
   endpoint's scope in `PairingContext`, and the canonical namespace owner or
   lock still authorizes that scope, without yet performing carrier I/O;
3. under that same authority, atomically burn the credential in the originally
   bound ledger namespace regardless of the classification; and
4. only if the pre-burn classification matched, recheck the local scope after
   the burn and then begin the handshake without an intervening wait, dial, DNS
   lookup, or other carrier I/O.

If either check differs, the capability is cancelled, the namespace owner
cannot be proven, or a `machine` namespace becomes ready while a
`user_acknowledged` attempt is pending, the endpoint MUST burn (or preserve a
prior burn), record `scope_changed`, and fail without a handshake byte. If it
cannot prove the burn in the originally bound namespace, that credential and
scope remain failed closed. It MUST NOT migrate the attempt, select a new
namespace, or silently downgrade/upgrade scope.

This admission must be serialized with #23's scope selection/ownership rules.
If a platform implementation cannot make the post-burn check stable through
the first handshake operation, the real adapter remains blocked on that
platform. Peer-reported scope is never an input to this local check.

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
secret, imported/derived PSK, secure-channel handshake or traffic secrets, raw
OOB artifacts, payloads, or a reusable carrier credential. Debug key logging is
forbidden. Diagnostic DTOs remain separate from domain objects containing
secret material.

## 11. Permanent negative tests

The implementation gate includes deterministic tests for:

- malformed, duplicate-key, unknown-field, oversized, and non-canonical
  artifacts;
- secrets, identifiers, or fingerprints with wrong length or encoding, plus
  cross-language fingerprint vectors that remove `pairing_secret` before JCS;
- duration over ten minutes, expiry, clock jump, and every
  `observation_generation` other than the literal `"1"`;
- wrong token, modified context, and cross-attempt or cross-profile use;
- atomic burn, reuse after success/failure/cancel/crash simulation, corrupt
  ledger, namespace mismatch, and local scope/owner changes between bundle
  import and the first handshake byte;
- wrong role, role reflection, wrong participant, repeated/skipped sequence,
  invalid transition, message flood, and oversized frame/payload;
- a complete valid exchange with no artificial inter-message delay, plus flood
  rejection under the provisional sustained-rate/burst limits;
- concurrent full-duplex sends with both one-frame queues full, proving bounded
  expiry and no blocked call or goroutine survives the 15-second control
  lifetime;
- cancellation and expiry at every state with no surviving goroutine or queued
  message;
- rejection by Mesh, Node Runtime, service, transit, recovery, mapping,
  prediction, birthday, and stable-key APIs;
- report downgrading when either endpoint is `user_acknowledged` and proof that
  peer input cannot raise local scope;
- absence of secret material from every report and error fixture;
- interoperation and negative vectors for the final reviewed secure-channel
  profile, including context/prologue mismatch and cross-profile rejection; and
- the repository AST/dependency gate proving the simulated package has no raw
  or transitive network capability.

## 12. Review and implementation gates

All of the following are required before a real `TestPairingChannel` exists.
Because this PR is stacked on #23, its approval is conditional on #23's scope
semantics being independently accepted and the stack merging bottom-up:

1. independent security review accepts this threat model, OOB workflow,
   candidate-specific context/prologue binding, single-use semantics, role
   binding, state machine, and limits;
2. a follow-up ADR selects one exact candidate A or candidate B profile and a
   maintained, independently reviewed implementation satisfying section 5;
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
