# ADR: test-only pairing cryptographic candidate

- Status: **Accepted (2026-08-21): protocol and simulation-only in-repository implementation approved; real-network and `connect_test` authority remain separately gated**
- Evidence snapshot: 2026-08-13
- Decision owner: WinkYou maintainers, with independent security review
- Selected candidate: **Candidate B at protocol level only (2026-08-14)**
- Selected implementation: **in-repository `internal/v2/noisecore` (PR #59), from-spec, zero new module dependencies; `flynn/noise` not adopted**
- Implementation authorization: **simulation plus the exact future loopback-carrier import boundary; no socket, signaling, runtime, or `connect_test` authority is added by this boundary-only revision**
- Boundary promotion: **`noisecore` and the extracted pure `punchproto` may be imported only by the exact reviewed loopback carrier package; this adds no socket and grants no non-loopback authority**

This ADR evaluates the two candidate families required by
[`TEST-ONLY-PAIRING-MINI-SPEC.md`](../TEST-ONLY-PAIRING-MINI-SPEC.md), sections
5 and 12. It does not approve a dependency, create a valid real-channel
`secure_channel_profile`, or authorize network code. With the 2026-08-21
acceptance, the permitted pairing implementations are the secret-free
in-memory simulator and the simulation-only `internal/v2/noisecore` core;
real-network use remains ungranted.

## 1. Context and decision boundary

Phase 1a needs a one-attempt authenticated stream for operator-initiated
`wink connect-test`. The complete OOB bundle supplies a uniformly random
32-byte `pairing_secret`, random correlation identifiers, fixed channel roles,
both locally admitted governor scopes, expiry, and the test-only authority
boundary. The secure channel must authenticate possession of that one-use
secret and bind the exact `PairingContext` without creating a second identity
system.

The decision is narrower than choosing a cryptographic library. A candidate is
eligible only if the exact profile, context binding, framing, failure behavior,
key lifetime, vectors, and implementation evidence are accepted together. The
following remain prohibited:

- modifying, copying, or hooking a TLS handshake implementation;
- substituting TLS resumption tickets for an external PSK importer;
- bare X25519 plus a home-grown KDF, MAC, or handshake;
- on-wire algorithm negotiation, downgrade, or fallback between candidates;
- 0-RTT, resumption, reusable credentials, or a second connection for the same
  attempt; and
- treating `test_only` as roster, NodeID, Mesh, routing, service, or recovery
  authority.

"Currently unavailable" below means unavailable under these constraints using
a maintained Go-facing implementation of the complete profile. It does not
mean that writing or forking a TLS stack is theoretically impossible; that is
explicitly outside this ADR.

## 2. Evaluation criteria

Each candidate is evaluated against the same requirements:

1. exact, externally specified protocol and primitive suite;
2. mutual proof of the OOB secret and exact context/role binding;
3. fresh ephemeral Diffie-Hellman and no application data before the full
   handshake completes;
4. one-use credentials, bounded messages, deterministic framing, and terminal
   fail-closed behavior;
5. a maintained implementation with review provenance and interoperable test
   vectors; and
6. an API that can run over a caller-owned, already admitted stream without
   opening sockets or gaining network authority itself.

## 3. Candidate A: TLS 1.3 external PSK importer

The mini-spec proposes the exact identifier
`tls13-epsk-importer-psk-dhe-x25519-aes128gcm-sha256/1`: TLS 1.3,
`psk_dhe_ke`, X25519, `TLS_AES_128_GCM_SHA256`, ALPN
`winkyou-test-pairing/1`, and the importer defined by
[RFC 9258](https://www.rfc-editor.org/rfc/rfc9258.html).

### 3.1 Why an ordinary external-PSK API is insufficient

RFC 9258 has two inseparable changes:

1. it derives an imported identity and imported key from the external identity,
   base key, context, target protocol, and target KDF; and
2. it changes TLS 1.3 binder-key derivation from `ext binder` to
   `imp binder`.

The second change occurs inside the TLS 1.3 key schedule. Pre-deriving a key in
application code and passing it to a conventional external-PSK API still causes
that stack to use `ext binder`; it is not RFC 9258 and must not be labeled as an
importer. Session tickets are likewise resumption PSKs and are not an acceptable
substitute.

The mini-spec's importer input would be:

- external identity: decoded random `credential_id`;
- EPSK base key: decoded 32-byte `pairing_secret`;
- EPSK-associated hash: SHA-256; and
- importer context:

```text
SHA-256(
  UTF8("winkyou test-only pairing importer context v1\n") ||
  JCS(PairingContext)
)
```

This mapping remains a specification input only; no eligible implementation was
found in the snapshot below.

### 3.2 Go ecosystem evidence snapshot

The review inspected the exported API and current upstream source, rather than
inferring support from the presence of a generic `pre_shared_key` extension.

| Stack | Snapshot result | Evidence and consequence |
| --- | --- | --- |
| Go `crypto/tls` 1.26.5 | **No external-PSK or RFC 9258 importer API.** Its public PSK controls are session resumption (`ClientSessionCache`, session tickets, `WrapSession`, and `UnwrapSession`). | [Official package API](https://pkg.go.dev/crypto/tls) (rendered as Go 1.26.5 in this evidence snapshot). Reusing resumption hooks would violate both RFC 9258 and the mini-spec. |
| `refraction-networking/utls` default branch | **Not implemented.** uTLS inherits the Go handshake and its current PSK file ends with an `ExternalPreSharedKeyExtension` TODO. The implemented extension is initialized from a TLS 1.3 session; its fake extension can write caller-supplied wire fields but does not provide the corresponding authenticated key schedule. | [uTLS PSK source](https://github.com/refraction-networking/utls/blob/master/u_pre_shared_key.go), [project scope](https://github.com/refraction-networking/utls). A fake ClientHello extension cannot establish an imported-PSK channel. |
| `bifurcation/mint` default branch | **Ordinary external PSK only; no importer.** The client state machine selects `labelExternalBinder`, not RFC 9258's `imp binder`. The project README calls mint primarily a learning effort and warns that its engineering quality may not suit integration; it has no tags or releases and its last source push in this snapshot was 2023-12-18. | [binder path](https://github.com/bifurcation/mint/blob/master/client-state-machine.go), [project warning](https://github.com/bifurcation/mint#mint---a-minimal-tls-13-stack). Changing the binder label would be a TLS-stack modification and mint does not meet the implementation gate. |
| AWS `s2n-tls` default branch | **Ordinary external PSK in an active C stack; no RFC 9258 importer evidence or Go implementation.** Its public API accepts an external identity and secret and documents conventional TLS 1.3 external PSKs. The current repository contains no Go binding source. | [s2n-tls PSK guide](https://aws.github.io/s2n-tls/usage-guide/ch12-preshared-keys.html), [C API](https://aws.github.io/s2n-tls/doxygen/s2n_8h.html). Adding cgo/native distribution plus a new importer-capable binding or source change is not an available Go candidate. |
| `quic-go` default branch | **No independent importer path.** Its TLS handshake is configured through Go `crypto/tls`, so it inherits the missing external-PSK/importer API. QUIC is also not the one-stream TLS profile specified here. | [quic-go repository](https://github.com/quic-go/quic-go), [Go API](https://pkg.go.dev/github.com/quic-go/quic-go). |
| Pion DTLS default branch | **Not the candidate profile.** Pion exposes PSK cipher suites for DTLS and documents DTLS 1.2/1.3 work, but not the TLS 1.3 RFC 9258 importer required here. | [Pion DTLS scope and PSK support](https://github.com/pion/dtls). It must not be substituted merely because it accepts a PSK callback. |

Absence claims are time-sensitive. A future decision review must repeat the
search against released versions and verify an actual client/server
interoperability test using `imp binder`; a README claim or extension type is
not sufficient.

### 3.3 Candidate A disposition

**Current result: not implementable under the approved constraints.** No
reviewed Go-facing stack in this snapshot exposes the complete RFC 9258
external-PSK importer on both client and server. Candidate A therefore stays in
the comparison, but it cannot be selected without new upstream implementation
evidence and an independent review. WinkYou must not fork TLS or approximate
the importer to make this row appear available.

## 4. Candidate B: concrete Noise profile proposal

This section freezes one proposal for expert review. Freezing the proposal does
not select it.

| Property | Proposed fixed value |
| --- | --- |
| `secure_channel_profile` | `noise-nnpsk0-25519-chachapoly-sha256/1` |
| Exact Noise protocol name | `Noise_NNpsk0_25519_ChaChaPoly_SHA256` |
| Pattern | `NNpsk0`: `-> psk, e`; `<- e, ee` |
| DH | Noise `25519` (X25519), fresh ephemeral keypair per side and attempt |
| Cipher | Noise `ChaChaPoly` (ChaCha20-Poly1305) |
| Hash | Noise `SHA256` |
| PSK | exactly the decoded 32-byte `pairing_secret` |
| Static keys | none; `NN` has no static-key slots |
| Handshake payloads | empty in both directions |
| Application data | prohibited until both parties complete the two-message handshake |
| Negotiation/fallback | none; the profile is fixed OOB and mismatches fail before carrier I/O |
| Connection lifetime | one admitted ordered stream for one attempt; terminal close after VERIFY, CANCEL, or any error |
| 0-RTT/resumption/rekey | disabled; no state or key crosses attempts |

The protocol name and modifier are defined by the official
[Noise Protocol Framework](https://noiseprotocol.org/noise.html). This proposal
does not create a custom token sequence or primitive.

### 4.1 Why `NNpsk0`

Both parties already possess the complete, high-entropy PSK before the first
carrier byte, so delayed PSK discovery is unnecessary. `psk0` mixes the PSK at
the beginning of the first message. In PSK mode, the following `e` token also
mixes the freshly generated ephemeral public key, satisfying Noise's key-reuse
validity rule.

With an empty first payload, the initiator still sends a 16-byte authentication
tag after its 32-byte ephemeral public key. The responder accepts the first
message only after authenticating that tag, which proves possession of the PSK
under the bound transcript before it enters the application state machine. The
second message mixes the responder's fresh ephemeral key and `ee`; its empty
payload tag provides initiator-side key confirmation. Transport keys therefore
depend on both the PSK and fresh ephemeral DH.

`NNpsk2` was rejected for this proposal because its first message is processed
before the `psk` token. It delays responder-side proof of initiator PSK
possession and adds no benefit when the correct PSK is already selected from the
complete OOB bundle. No static Noise identity is needed: this protocol proves
only possession of a one-use secret in one exact attempt context, which is the
mini-spec's authority model.

This is symmetric authentication. Compromise of the complete bundle lets an
attacker impersonate either role during its lifetime. The fixed role fields in
the prologue address cross-role transcript mixups, but they do not turn the PSK
into a durable identity or protect a compromised endpoint.

### 4.2 Exact prologue and role binding

Each side must parse, strictly validate, and independently reconstruct the same
`PairingContext` before opening or accepting the carrier. The Noise prologue is
the following byte string, with no digest, delimiter change, alternate JSON
encoding, BOM, or trailing newline:

```text
UTF8("winkyou test-only pairing Noise prologue v1\n") ||
JCS(PairingContext)
```

`PairingContext` is the validated ACCEPTANCE object reconstructed with the six
candidate-neutral channel-policy field names from mini-spec section 4.4. The
profile value is copied from ACCEPTANCE; the other five are fixed by version 1:

```json
{
  "secure_channel_profile": "noise-nnpsk0-25519-chachapoly-sha256/1",
  "initiator_channel_role": "initiator",
  "responder_channel_role": "responder",
  "early_data": "disabled",
  "resumption": "disabled",
  "runtime_fallback": "disabled"
}
```

The JCS object includes `secure_channel_profile`, both participant IDs, both
governor scopes, credential and attempt IDs, generation, issue/expiry times, and
the offer fingerprint. Consequently a role swap, scope drift, generation
change, profile change, or other accepted-field mismatch produces a different
handshake hash and fails authentication. Secrets are not members of the
context and must never be placed in the prologue.

Immediately before the first handshake byte, both sides must repeat the local
scope/expiry/profile admission and atomically burn the credential as required
by mini-spec sections 6 and 9. There is no unburn or retry on handshake failure.

### 4.3 Stream framing and bounded lifetime

Noise messages are not self-framing on an ordered byte stream. This proposal
uses a two-byte unsigned big-endian outer length followed by exactly one Noise
message. There is no preface or negotiation field.

Handshake framing is fixed:

- exactly two frames, initiator then responder;
- both Noise messages are exactly 48 bytes: a 32-byte X25519 ephemeral public
  key plus a 16-byte ChaChaPoly tag over an empty payload;
- any zero length, non-48 length, third handshake frame, truncated frame,
  trailing handshake payload, or out-of-order direction is terminal; and
- the complete handshake must fit the mini-spec's 15-second deadline.

After handshake completion, one Noise transport message carries exactly one
mini-spec control envelope. Its plaintext is the already specified four-byte
unsigned big-endian JSON length followed by 1..4096 JSON bytes. ChaChaPoly adds
16 bytes, so an outer transport length above 4116 is rejected before allocation
or decryption. After decryption, the inner length, strict JSON schema, sequence,
roles, attempt fields, and eight-message-per-direction limit are all checked.

EOF in a length prefix or body, authentication failure, nonce error, sequence
error, deadline, cancellation, an unexpected extra frame, or a peer close before
the terminal state ends the attempt, destroys in-memory key material
best-effort, and closes the carrier. Remote errors are generic; local structured
errors and diagnostics must not contain the PSK, traffic keys, ephemeral private
keys, prologue bytes, raw bundle, or sensitive peer data.

No `Rekey`, `SetNonce`, state export/import, reconnect, resumption, or transport
fallback is permitted. Send and receive state are serialized independently,
and no cipher state is shared between connections or attempts. The mini-spec's
eight-message cap makes nonce exhaustion unreachable in a valid attempt; an
implementation must still treat a library nonce-exhaustion error as terminal.

### 4.4 Security-property mapping

| Requirement | Proposed mapping and residual limit |
| --- | --- |
| OOB secret authentication | `psk0` authenticates the first empty payload tag; the second tag gives return key confirmation. It authenticates shared-secret possession, not a stable person or node identity. |
| Context and roles | Exact JCS `PairingContext` is mixed as the prologue. A mismatch fails on the first authenticated payload. The prologue is authenticated but is not secret key material. |
| Forward secrecy | No application data is sent before `ee`; transport keys include both fresh ephemerals. Later PSK compromise should not recover past transport keys if ephemeral private keys were destroyed and X25519 remains secure. Bundle compromise during the attempt still enables impersonation. |
| KCI / role compromise | A PSK is symmetric, so its compromise allows impersonating either side. Fixed roles prevent accidental/reflection transcript reuse but cannot provide asymmetric KCI resistance. |
| Replay | Durable one-use ledger burns the credential before first byte; fresh ephemerals, bound attempt ID, sequence numbers, expiry, and no resumption provide defense in depth. Missing/corrupt ledger state fails closed. |
| Identity exposure | No Noise static keys or identity payloads are sent. Network metadata and ciphertext lengths remain visible; anonymity and traffic-analysis resistance are not claimed. |
| Downgrade | Profile is repeated OOB and bound in the prologue. There is no on-wire suite negotiation or candidate fallback. |

## 5. `github.com/flynn/noise` evaluation

The library is evaluated only as an implementation input. It is **not approved**
by this draft.

### 5.1 API fit

Version `v1.1.0` exposes all mechanical inputs for the proposal:

- `HandshakeNN` plus `PresharedKeyPlacement: 0` constructs `NNpsk0`;
- `DH25519`, `CipherChaChaPoly`, and `HashSHA256` construct the exact suite;
- `Config.Prologue` and a 32-byte `Config.PresharedKey` map directly to the
  mini-spec inputs;
- `WriteMessage`/`ReadMessage` operate on caller-provided bytes and do not open
  sockets; and
- its vector harness includes PSK-modified Noise patterns and deterministic
  ephemeral/prologue inputs.

See the [`v1.1.0` API](https://pkg.go.dev/github.com/flynn/noise@v1.1.0),
[`state.go`](https://github.com/flynn/noise/blob/v1.1.0/state.go), and the
upstream [`vectors.txt`](https://github.com/flynn/noise/blob/v1.1.0/vectors.txt).

This API fit is necessary but not sufficient. Any future adapter would have to
be internal, accept only the exact profile, use caller-owned stream I/O, and
make dangerous APIs (`UnsafeKey`, `UnsafeNewCipherState`, `SetNonce`, direct
`Cipher`, and `Rekey`) unreachable by construction and architecture tests.

### 5.2 Maintenance and provenance snapshot

- The repository was not archived on 2026-08-13, but its latest tag is
  [`v1.1.0`](https://github.com/flynn/noise/tree/v1.1.0) at an unsigned
  2024-02-02 commit. GitHub lists tags but no GitHub Releases.
- The module declares Go 1.16 and pins a 2021 pseudo-version of
  `golang.org/x/crypto` in its own `go.mod`. A consumer can resolve newer
  transitive versions, but the stale module metadata increases review and
  reproducibility work.
- A CI workflow file exists, but tag signatures, release artifacts, and a
  release-specific CI attestation are absent. Source pinning by full commit and
  checksum would be required.
- The project has no repository `SECURITY.md` in this snapshot.

These facts do not prove insecurity. They do mean the project does not yet
satisfy the mini-spec's "maintained implementation" gate without an explicit
maintainer and dependency-lifecycle decision.

### 5.3 Review history and known issues

The published advisory
[`GHSA-g9mp-8g3h-3c5c`](https://github.com/flynn/noise/security/advisories/GHSA-g9mp-8g3h-3c5c)
records two nonce-handling defects found during a Cure53 audit of a downstream
user. They were fixed in `v1.0.0`. This is useful evidence that concrete defects
were reported and repaired, but it is not a comprehensive independent audit of
the library or of `v1.1.0`; the unsafe state-export APIs in `v1.1.0` postdate
that audit.

Open issue
[#16](https://github.com/flynn/noise/issues/16) notes that the library's
handshake payload limit does not subtract public keys and authentication tags
from Noise's 65535-byte message limit. The WinkYou proposal's exact 48-byte
handshake and 4116-byte transport cap avoid relying on that permissive check,
but the long-open correctness issue is a maintenance signal. Stateful handshake
and cipher objects also require strict single-owner serialization; the package
does not provide WinkYou's framing, deadlines, replay ledger, redaction, or
governor admission.

### 5.4 Library disposition

`github.com/flynn/noise@v1.1.0` is API-compatible enough to build vectors and a
future review prototype, but the current evidence does **not** establish the
maintained, independently reviewed implementation required for production of a
real test channel. Selection would require at least:

1. a focused cryptographic and misuse-resistance review of the exact pinned
   source and the proposed wrapper;
2. a named dependency owner, update policy, provenance/checksum policy, and
   security-response path;
3. byte-identical interoperability against an independent Noise
   implementation; and
4. all negative, fuzz, race, redaction, cancellation, and bounded-I/O gates in
   section 6.

If those conditions cannot be met, this library must be rejected rather than
vendored or silently forked.

### 5.5 In-repository implementation evidence (reviewed and accepted 2026-08-21)

Implementation evidence submitted and reviewed. A simulation-only,
from-spec implementation of the fixed
`Noise_NNpsk0_25519_ChaChaPoly_SHA256` profile now exists at
[`internal/v2/noisecore`](../../internal/v2/noisecore), with its scope and
limitations recorded in [`NOISE-CORE.md`](../NOISE-CORE.md).

The evidence adds no module dependency and gives the package no socket, file,
DNS, signaling, CLI, or runtime authority. Architecture tests keep it inside
the existing simulation-only boundary, reject production importers, reject
`net` imports, and keep the core independent of other WinkYou packages. The
WinkYou-specific test passes the exact bytes produced by
`testpairing.BuildNoisePrologue`; the core does not duplicate JCS or secret
derivation.

Byte-level interoperability is checked against the
[`Noise_NNpsk0_25519_ChaChaPoly_SHA256` Cacophony vector](https://raw.githubusercontent.com/haskell-cryptography/cacophony/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt)
from commit `8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247` (Unlicense; vector blob
`b8a271ed1aba8b4a56bf429e559d7947827123b4`). Tests reproduce both handshake
messages, the final handshake hash, and the subsequent bidirectional transport
messages byte for byte. Negative coverage includes wrong PSK and prologue,
every-byte handshake mutation, truncation, oversize input, ordering, replay,
all-zero/low-order X25519 input, nonce encoding/exhaustion, terminal
authentication failure, race tests, and fuzz seeds.

One prompt assumption was corrected to match revision 34: because `psk0`
executes before the first `e` token, the first empty handshake payload already
has an authentication tag. A one-bit PSK mismatch is therefore rejected by the
responder while reading message one, rather than waiting for message two.

This code was submitted as review evidence. Following the 2026-08-21 expert
review of PR #59/#60 (specification line-by-line verification, independent
upstream vector re-verification, negative matrix, race and fuzz batteries),
the maintainer accepted it as the selected implementation in section 9.
`connect_test` remains `not_implemented`, and no real-channel or network
authorization follows from this acceptance.

### 5.6 Punch-simulation integration evidence (reviewed and accepted 2026-08-21)

Additional implementation evidence connects completed `noisecore` sessions to
the existing pure-memory punch simulation behind an explicit opt-in. The
plaintext sentinel remains the default. The two 48-byte handshake messages are
carried as opaque `PREPARE` payloads over the existing test-only control
carrier, the peers compare the final handshake hash in `READY`, and no UDP punch
packet is sent before that exchange completes.

The simulation does not apply the ordered Noise `CipherState` API directly to
datagrams: a valid `SYN_ACK` can arrive after a preceding `SYN` was filtered,
which would otherwise present transport nonce 1 while the receiver still
expects nonce 0. It follows
[Noise revision 34 section 11.4](https://noiseprotocol.org/noise.html#out-of-order-transport-messages),
which sends the nonce with a lossy transport message and requires recipients to
track successful nonces and reject repeats. `Session.TakePacketCipher`
atomically transfers fresh, unused Split keys into a narrower packet adapter.
It exposes no key export and no arbitrary nonce setter; it admits only sequences
0 through 2, permits authenticated out-of-order receive, and closes a direction
on replay, range, or authentication failure. A compatibility test proves that
sequences 0 through 2 produce the same ciphertext bytes as the ordered Noise
transport state at those nonces. The clear packet header is bound as additional
data, while attempt ID, generation, sender role, and frame type are inside the
ciphertext.

Tests cover 100 consecutive secure EIM-by-EIM runs, wrong PSK before any UDP
punch, every-byte packet mutation, same-session packet replay, and injection of
a prior complete handshake and punch sequence into fresh ephemeral sessions.
The opt-in mode leaves the compiled punch envelope unchanged at one reused
socket, one new target and five-tuple, at most two outbound and two inbound
packets, two outbound PPS, 256 bytes per packet, and one second. The concrete
secure packet is 56 bytes. Full details and limitations are recorded in
[`DIRECT-PUNCH-SIMULATION.md`](../DIRECT-PUNCH-SIMULATION.md).

This packet adapter is application-layer review evidence, not part of the Noise
protocol vector claim and not an implementation approval. This section does not
change the ADR status or decision fields and grants no `connect_test`, runtime,
or live-network authority.

## 6. Test-vector and verification plan

No vector is normative until reviewed and committed with a schema version and
source provenance. The proposed fixture is UTF-8 JSON with lower-case hex for
bytes and contains only synthetic public test material:

```json
{
  "vector_schema": "winkyou-test-pairing-noise-vector/1",
  "profile": "noise-nnpsk0-25519-chachapoly-sha256/1",
  "noise_protocol_name": "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
  "pairing_context": {"<field>": "<string value>"},
  "pairing_context_jcs_hex": "<bytes>",
  "prologue_hex": "<bytes>",
  "psk_hex": "<32 bytes>",
  "initiator_ephemeral_private_hex": "<32 bytes>",
  "responder_ephemeral_private_hex": "<32 bytes>",
  "handshake_frames_hex": ["<2-byte length || message>", "<frame>"],
  "handshake_hash_hex": "<32 bytes>",
  "transport_cases": [
    {
      "direction": "initiator_to_responder",
      "plaintext_frame_hex": "<4-byte length || canonical JSON>",
      "noise_frame_hex": "<2-byte length || ciphertext>"
    }
  ]
}
```

Positive vectors must be produced from fixed ephemeral inputs and verified
byte-for-byte by both the selected Go implementation and an independent
implementation (proposed verifier: Rust
[`snow`](https://docs.rs/snow/latest/snow/struct.Builder.html), pinned by version
and commit).
The structured `pairing_context` is mandatory so every implementation can
independently recompute `pairing_context_jcs_hex` and `prologue_hex`; the hex
members are assertions, not substitutes for canonicalization.

The suite must first run the upstream Noise vectors for
`Noise_NNpsk0_25519_ChaChaPoly_SHA256`, then run the WinkYou-specific prologue,
outer framing, inner control framing, and terminal transcript. The verifier must
also recompute JCS from the structured `PairingContext`; accepting fixture bytes
without independently canonicalizing the object is insufficient.

Negative vectors must cover at least:

- wrong PSK and one-bit PSK changes;
- every bound context class changed independently: role, participant, attempt,
  credential, scope, generation, profile, expiry, and fingerprint;
- duplicate/unknown JSON members, non-JCS encodings, invalid UTF-8, and a secret
  inserted into context;
- modified ephemeral public key, tag, handshake hash input, or transport
  ciphertext;
- zero, oversized, truncated, sticky, reordered, duplicate, and extra frames;
- a non-empty handshake payload and application data before full completion;
- replay after burn, missing/corrupt ledger, scope drift immediately before the
  first byte, expiry, cancellation, deadline, and mid-frame EOF;
- sequence gaps, direction/role reversal, more than eight control messages,
  transport authentication failure, and nonce-exhaustion injection; and
- assertions that errors, logs, diagnostics, crash fixtures, and exported
  reports contain no PSK, key, raw bundle, prologue, or private endpoint data.

Acceptance additionally requires fuzzing both framing layers and the strict
context parser, `go test -race`, high-count cancellation/concurrency tests,
fault-injected short reads/writes, and a test transport that proves the crypto
adapter cannot open a socket. Test vectors and simulations do not authorize
live network validation.

## 7. Risk comparison

| Risk | Candidate A: TLS 1.3 importer | Candidate B: proposed Noise profile |
| --- | --- | --- |
| Protocol maturity | TLS 1.3 and RFC 9258 are IETF standards; the importer has explicit domain separation. | Noise revision 34 is marked `official/unstable`; the named pattern is standard within that framework but is not TLS. |
| Current Go availability | Blocking: no eligible complete importer implementation was found. | Protocol/API fit exists, but the evaluated Go library does not yet meet maintenance and independent-review gates. |
| Misuse surface | Low if a reviewed importer API exists; high and prohibited if emulated through tickets or TLS hooks. | Small handshake, but the application owns framing, state sequencing, failure handling, and dangerous library API isolation. |
| Context binding | RFC 9258 importer identity/key plus `imp binder`; strong explicit KDF/protocol separation. | Exact JCS context is authenticated as Noise prologue; it is not secret and must be identically encoded. |
| Forward secrecy | Profile requires `psk_dhe_ke` with X25519. | `NNpsk0` transport keys include fresh `ee`; no application data before completion. |
| Authentication limit | Symmetric OOB secret; no durable node identity. | Same, with no static Noise keys. PSK compromise permits either-role impersonation. |
| Interoperability | Strong standards story once an importer-capable stack exists. | Requires WinkYou framing vectors plus two independent Noise implementations. |
| Dependency/operations | Would reuse TLS record/framing behavior, but no current Go dependency satisfies the profile. | Caller-owned stream fits the governor boundary; library lifecycle and wrapper audit are unresolved. |
| Metadata | TLS ClientHello exposes the imported identity/context unless ECH is added; ECH is outside this profile. | No static identity is sent, but endpoint metadata and ciphertext lengths remain observable. |

## 8. Recommendation for review

The evidence currently favors continuing expert review of **Candidate B's exact
`Noise_NNpsk0_25519_ChaChaPoly_SHA256` protocol proposal**, because Candidate A
has no eligible Go implementation and must not be approximated. This is a
protocol-level preference, not approval of `flynn/noise` and not an
implementation decision.

The decision must remain open unless reviewers establish a maintained,
independently reviewed implementation for the whole selected profile. If
`flynn/noise` cannot meet that bar and no alternative implementation does, the
correct result is to keep `connect_test` gated as `not_implemented`. Availability
pressure is not a reason to weaken the cryptographic boundary.

## 9. Decision record

Maintainers and independent reviewers complete this section in separately
reviewable revisions. The 2026-08-14 revision records a **protocol-level**
selection only; every implementation-facing field stays TBD and keeps
`connect_test` gated as `not_implemented`.

- Selected candidate: **Candidate B, protocol level only.** The maintainer
  selected the Noise profile for the disposable test-only pairing channel
  after expert review verified RFC 9258 section 5.2 (`imp binder`) makes
  Candidate A unimplementable without a prohibited fork, and verified the
  Candidate B pattern, framing, and prologue binding. Candidate A remains a
  parallel candidate through the upstream contribution track in
  [issue #41](https://github.com/houyuwushang/winkyou/issues/41); if a
  maintained upstream importer ships, re-evaluating it requires a reviewed
  revision of this record.
- Selected `secure_channel_profile`: **`noise-nnpsk0-25519-chachapoly-sha256/1`**
  (`Noise_NNpsk0_25519_ChaChaPoly_SHA256`), exactly as frozen in section 4.
- Selected implementation and immutable source reference: **in-repository
  `internal/v2/noisecore` as merged in PR #59 (head `a03372f`) and integrated
  in PR #60 (head `5c9e4aa`).** The implementation is written from the Noise
  revision 34 specification against primitives already present in
  `golang.org/x/crypto`; it adds no module dependency. `github.com/flynn/noise`
  is **not adopted**: the section 5.4 conditions were never met, and the
  in-repository implementation removes the dependency-owner and maintenance
  risks recorded in section 5.
- Independent review reference: protocol-level expert review on
  [PR #39](https://github.com/houyuwushang/winkyou/pull/39) (verified: RFC 9258
  binder-label claim against the RFC text, `NNpsk0` message pattern and
  48-byte framing, prologue domain separation). This reference covers the
  protocol proposal only, not any implementation.
- Vector set and cross-language verifier reference: **cacophony upstream
  vectors, pinned to commit `8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247`
  (blob `b8a271ed1aba8b4a56bf429e559d7947827123b4`, Unlicense),** stored at
  `internal/v2/noisecore/testdata/` and asserted byte-for-byte across all six
  messages and both final handshake hashes. During the PR #59 review the
  extracted vector was independently re-downloaded from upstream and matched
  field-for-field, ruling out fabricated fixtures. These vectors are normative
  for this profile.
- Residual risks accepted by: maintainer, for the protocol-level selection of
  a symmetric one-use PSK channel as bounded in section 4.4, and — on
  2026-08-21 — for the simulation-only in-repository implementation, including
  the documented Go memory-zeroization limits in
  [`NOISE-CORE.md`](../NOISE-CORE.md). Real-network and dependency risks
  outside this scope are **not accepted**.
- Approval date: **2026-08-14 (protocol level); 2026-08-21 (simulation-only
  implementation, maintainer acceptance after expert review of PR #59/#60:
  specification line-by-line verification, independent upstream vector
  re-verification, negative matrix, race and fuzz batteries).**
- Mini-spec alignment follow-up: the 2026-08-14 vector-foundation revision
  proposes the required section 4.4 alignment and restricted-JCS fixtures. It
  closes this text drift only after independent review; it does not resolve the
  TBD implementation or interop fields above.

This ADR is Accepted for the protocol and its simulation-only in-repository
implementation. It still grants no real-network authority: `connect_test`
stays `not_implemented` until its own reviewed wiring change passes the
mini-spec section 12 gates and the field-test authorization items in the
runbook.
