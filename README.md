# Azure.Identity mTLS-PoP / FIC gaps

Concise gap analysis: **certificate-bound (mTLS Proof-of-Possession) tokens** for
Federated Identity Credential (FIC) flows in **Azure.Identity**, versus what **MSAL.NET** already
exposes.

> Built strictly from **public** sources (public MSAL.NET and `azure-sdk-for-net` repositories and the
> public PRs in §8). Verified against source 2026-07-12.

---

## 1. TL;DR

- MSAL.NET already has the primitives for cert-bound tokens: `WithMtlsProofOfPossession()`, cert-bound
  client assertions (`ClientSignedAssertion.TokenBindingCertificate` → `jwt-pop`), `mtls_pop` token type,
  and `AuthenticationResult.BindingCertificate`.
- Azure.Identity already wires mTLS-PoP for the **direct** `ManagedIdentityCredential`.
- The gap is the **confidential-client / FIC** path: it reduces every assertion to a **`string`**, so the
  binding certificate is lost before MSAL is called and the result is always a **Bearer** token.
- Fix = a **bound-assertion abstraction** + **explicit, opt-in, per-credential** mTLS-PoP intent
  (preferably **new bound credentials**) — **not** the single global `IsProofOfPossessionEnabled` flag.

---

## 2. Non-mTLS (Bearer) today — SNI / MSI / FIC

| Flow | MSAL.NET API | Azure.Identity credential | Result |
|---|---|---|---|
| **SNI** (cert / subject-name-issuer) | `WithCertificate(cert, sendX5C: true)` | `ClientCertificateCredential` (`SendCertificateChain`) | Bearer |
| **MSI** | `AcquireTokenForManagedIdentity(resource)` | `ManagedIdentityCredential` | Bearer |
| **FIC** (assertion) | `WithClientAssertion(string)` / `Func<CT,Task<string>>`; `WithFmiPath(...)` | `ClientAssertionCredential`, `WorkloadIdentityCredential`, `ManagedIdentityAsFederatedIdentityCredential` | Bearer |

All three FIC credentials converge on one path: **assertion → `string` → `MsalConfidentialClient` →
`WithClientAssertion(string)` → `AcquireTokenForClient` → Bearer.**

---

## 3. mTLS-PoP today — SNI / MSI / FIC

| Flow | MSAL.NET API | Result (MSAL) | Azure.Identity |
|---|---|---|:--:|
| **SNI** cert | `WithCertificate(cert, sendX5C:true)` + `.WithMtlsProofOfPossession()` | `TokenType=mtls_pop`, `BindingCertificate` set | ❌ `ClientCertificateCredential` never requests PoP |
| **FIC** cert-bound assertion | `WithClientAssertion(Func<AssertionRequestOptions,CT,Task<ClientSignedAssertion>>)` with `TokenBindingCertificate` → `client_assertion_type=jwt-pop` + `.WithMtlsProofOfPossession()` | `mtls_pop` bound to supplied cert | ❌ callback returns `string` only |
| **MSI** (IMDSv2) | `AcquireTokenForManagedIdentity(res).WithMtlsProofOfPossession()` (opt. `.WithAttestationSupport()`) | `mtls_pop`, IMDSv2-minted binding cert, RFC 8705 `cnf`/`x5t#S256` | ✅ **direct** MI wired; ❌ MI-as-FIC |
| **MSI un-attested** (design) | strong key (else in-memory RSA on Gen1/Linux), **no MAA**, scope-in-CSR → ESTS `mtls_pop` | `mtls_pop` without attestation | n/a (relies on MSAL/service) |

Key point: **attestation is independent from binding.** `WithMtlsProofOfPossession()` requests a bound
token; `.WithAttestationSupport()` only strengthens the key. The un-attested design (PR #6108) delivers
`mtls_pop` **without** MAA.

---

## 4. The gap in Azure.Identity

| # | Gap | Detail |
|---|---|---|
| G1 | **No bound-assertion abstraction** | Callback is `Func<CT,Task<string>>`; there is no way to return a `BindingCertificate`, so it is lost before MSAL is invoked. |
| G2 | **FIC path never requests PoP** | `MsalConfidentialClient` only calls string `WithClientAssertion`; it never calls `.WithMtlsProofOfPossession()`. |
| G3 | **PoP intent is one overloaded Boolean** | `TokenRequestContext.IsProofOfPossessionEnabled` is SHR/request-signature-shaped (nonce/URI/method). One flag can't distinguish SHR PoP vs mTLS binding, nor scope it per-app. |
| G4 | **Binding cert not propagated for FIC** | `AccessToken.BindingCertificate` **already exists** (return path is ready), but the FIC path never obtains or sets it. |

Return abstraction is largely ready (`AccessToken.TokenType` + `BindingCertificate`); the **request +
credential** side is missing.

---

## 5. Proposed solution

| Piece | Proposal |
|---|---|
| Bound assertion type | `ClientBoundAssertion { string Assertion; X509Certificate2 BindingCertificate; }` (maps to MSAL `ClientSignedAssertion`). |
| New callback overload | `ClientAssertionCredential(tenantId, clientId, Func<ClientAssertionRequestContext, CT, Task<ClientBoundAssertion>>, options)` — context carries token-endpoint hint + correlation id (mirrors MSAL `AssertionRequestOptions`). |
| Explicit PoP mode | `ProofOfPossessionMode { None, SignedHttpRequest, MutualTls }` **or** `EnableMtlsProofOfPossession` — do **not** rely solely on the global `IsProofOfPossessionEnabled`. |
| Wiring | In `MsalConfidentialClient`: use MSAL's cert-bound `WithClientAssertion` overload + `.WithMtlsProofOfPossession()`; surface `AccessToken.BindingCertificate`. |
| No silent downgrade | If binding requested but unavailable → **fail**, never silently return Bearer. |
| Attestation separate | `AttestationMode { Disabled, Preferred, Required }`, orthogonal to binding. |

**MSI-as-FIC target flow:** MSI mTLS-PoP token **+ its IMDSv2 binding cert** → bound client assertion →
`jwt-pop` exchange → `mtls_pop` app token. Today Azure.Identity extracts only `accessToken.Token` and
**discards the certificate** — that is exactly where the binding is lost.

---

## 6. Blockers of the existing path (reuse the global PoP Boolean)

| Blocker | Why it fails |
|---|---|
| **Coarse, all-or-nothing** | A single global flag cannot scope binding to specific client apps; it is on for all consumers or none. |
| **Ambiguous scheme** | `IsProofOfPossessionEnabled=true` can mean SHR PoP, mTLS binding, MI token binding, or FIC cert-bound — the runtime must *infer* from credential type. Same flag, different credential, different protocol. |
| **Silent behavior change** | If binding preconditions are relaxed (e.g. software keys), apps could begin emitting bound tokens without an explicit per-credential decision. Binding should be an explicit opt-in, not an implicit switch. |
| **Still loses the cert** | Even with the flag set, the FIC callback returns only a `string`; there is no channel for the binding certificate. |

Consumer note: the Key Vault beta (PR #60286) already sets `IsProofOfPossessionEnabled=true` and signals
`x-ms-tokenboundauth` — reinforcing that the *credential* must decide the scheme unambiguously and
per-app. `IsProofOfPossessionEnabled` defaults to **`false`** (opt-in) in production today.

---

## 7. Why new bound credentials are the better design

| | New bound credential(s) | Global flag on existing creds |
|---|---|---|
| Granularity | ✅ per-credential / per-app | ❌ all-or-nothing |
| Scheme clarity | ✅ explicit (mTLS binding by construction) | ❌ inferred, ambiguous |
| Downgrade safety | ✅ binding mandatory, no silent Bearer | ❌ easy silent downgrade |
| Binding cert channel | ✅ required in the contract | ❌ string callback loses it |
| Attestation policy | ✅ explicit, independent | ❌ not expressible |
| Cost | ⚠️ some credential proliferation | ✅ familiar option pattern |

Recommended shape (combination):
1. Add `ClientBoundAssertion` + a bound-assertion overload on `ClientAssertionCredential`.
2. Add explicit `MutualTls` PoP mode (not the SHR Boolean).
3. Optionally add a strict `BoundClientAssertionCredential` (binding mandatory) for security-sensitive
   callers who want no ambiguity or downgrade.
4. Fix the shared `MsalConfidentialClient` plumbing once so FIC sources can reuse it.

**Rollout order (by binding-material availability):**
`ClientCertificateCredential` → bound `ClientAssertionCredential` → **MSI-as-FIC** → Workload Identity
(needs a separate mechanism to supply a binding certificate) → other FIC sources.

---

## 8. Component responsibilities

| Layer | Owns |
|---|---|
| **MSAL.NET** | token-endpoint protocol, `jwt-pop` vs `jwt-bearer`, mTLS handshake, `TokenType`/`BindingCertificate` return, cache partitioning, authority/platform validation (mostly done). |
| **Azure.Identity / Azure.Core** | public credential surface, **request intent**, **bound-assertion callback**, **binding-cert propagation**, attestation policy, **no-downgrade** semantics, `AuthenticationResult`→`AccessToken` conversion. ← main gap. |
| **Platform (IMDS/ESTS)** | un-attested credential contract, scope-in-CSR OID + encoding, certificate issuance, token-binding validation, cross-platform support. |

---

## 9. References (public)

| Ref | What |
|---|---|
| `azure-sdk-for-net` PR #60286 | Key Vault PoP token-binding (beta): `ChallengeBasedAuthenticationPolicy` sets `IsProofOfPossessionEnabled=true` + `x-ms-tokenboundauth`; PoP-always-on preview, opt-in in prod. |
| MSAL.NET PR #6108 | Un-attested MSI V2 mTLS-PoP design (scope-in-CSR, no MAA, `mtls_pop`). |
| MSAL.NET PRs #6109 / #6110 / #6111 | Background docs: Azure.Identity credentials; FIC credentials; mTLS-PoP FIC gap. |
| MSAL.NET source | `ClientSignedAssertion`, `AssertionRequestOptions`, `ConfidentialClientApplicationBuilder.WithClientAssertion(...)`, `AcquireTokenForClientParameterBuilder.WithMtlsProofOfPossession()`, `ManagedIdentity/ManagedIdentityPopExtensions.cs`, `ManagedIdentity/ManagedIdentityClient.cs`. |
| Azure.Core source | `Identity/Credentials/ClientAssertionCredential.cs`, `WorkloadIdentityCredential.cs`, `Identity/MsalConfidentialClient.cs`, `Identity/MsalManagedIdentityClient.cs`, `AccessToken.cs`, `TokenRequestContext.cs`. |

*Scope: public API/design analysis only.*
