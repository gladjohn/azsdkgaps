# Azure.Identity mTLS-PoP / FIC gaps — a conversation starter

This note compares how MSAL.NET and Azure.Identity handle **certificate-bound tokens** (mTLS
Proof-of-Possession, or "PoP") for **Federated Identity Credential (FIC)** flows. It's meant to start a
discussion, not to propose a design.

> Public sources only (MSAL.NET, `azure-sdk-for-net`, the PRs in §9). On current `main`, Azure.Identity's
> credentials now live in **Azure.Core** (`sdk/core/Azure.Core/src/Identity/…`; `Azure.Identity` just
> forwards the types). Checked against source on 2026-07-12.
>
> Tags below: `[MSAL]` MSAL only · `[Az.Id]` wired in Azure.Identity · `[design]` a design doc, not
> shipping · `[open]` still needs discussion.

---

## 1. Summary

- **What MSAL.NET has today.** The pieces for cert-bound client tokens: `WithMtlsProofOfPossession()`
  (confidential clients and managed identity), cert-bound assertions (`ClientSignedAssertion` carrying a
  `TokenBindingCertificate`), and `AuthenticationResult.BindingCertificate`. This ships in the net8.0 API,
  and the two-leg FIC pattern is documented and tested in the MSAL repo (4.82.1+).
- **What Azure.Identity has today.** It turns on mTLS-PoP only for the direct `ManagedIdentityCredential`,
  and only when you ask for it (`IsProofOfPossessionEnabled`), the host supports token binding (IMDSv2), and
  the `Microsoft.Identity.Client.KeyAttestation` package is present.
- **The gap.** The FIC path (confidential client) turns every assertion into a plain `string` before it
  reaches MSAL and never asks for PoP, so it always returns a Bearer token. `AccessToken` can already hold a
  binding certificate, so the return side is mostly ready — the request side isn't.
- **The ask.** How should Azure.Identity let a caller request a cert-bound FIC token and get the binding
  certificate back? Mainly an API question, but it also touches MSAL and the IMDS/ESTS platform.

---

## 2. Bearer tokens today (SNI / MSI / FIC)

| Flow | MSAL.NET API | Azure.Identity credential | Result |
|---|---|---|---|
| **SNI** (subject-name-issuer cert) | `WithCertificate(cert, sendX5C:true)` | `ClientCertificateCredential` | Bearer |
| **MSI** | `AcquireTokenForManagedIdentity(resource)` | `ManagedIdentityCredential` | Bearer (unless PoP opted-in) |
| **FIC** (assertion) | `WithClientAssertion(string)` / `Func<…,Task<string>>` | `ClientAssertionCredential`; `WorkloadIdentityCredential`; internal `ManagedIdentityAsFederatedIdentityCredential` | Bearer |

The three FIC credentials are really one path. `WorkloadIdentityCredential` wraps `ClientAssertionCredential`,
and `ManagedIdentityAsFederatedIdentityCredential` builds one whose callback just returns a managed-identity
token's `.Token` string. They all end up at: assertion → `string` → `MsalConfidentialClient` →
`WithClientAssertion(string)` → `AcquireTokenForClient` → Bearer. `ClientAssertionCredential.GetToken` never
even looks at `IsProofOfPossessionEnabled`.

---

## 3. Cert-bound tokens today: MSAL vs Azure.Identity

| Flow | MSAL.NET `[MSAL]` | Azure.Identity `[Az.Id]` |
|---|---|---|
| **SNI cert** | `WithCertificate(cert)` + `WithMtlsProofOfPossession()` → `mtls_pop` + `BindingCertificate` | ❌ `ClientCertificateCredential` never requests PoP |
| **FIC cert-bound assertion** | `WithClientAssertion(Func<AssertionRequestOptions,CT,Task<ClientSignedAssertion>>)` with `TokenBindingCertificate` → `jwt-pop` (add `WithMtlsProofOfPossession()` for an `mtls_pop` result) | ❌ callback returns `string` only |
| **MSI (IMDSv2)** | `AcquireTokenForManagedIdentity(res).WithMtlsProofOfPossession()` | ✅ direct MI (opt-in + host + KeyAttestation-gated); ❌ MI-as-FIC |
| **MSI unattested** `[design]` | PR #6108 doc: strongest key else in-memory RSA, no MAA, scope-in-CSR (OID **TBD**) → `mtls_pop` | n/a (IMDS/ESTS + MSAL) |

Two things to keep straight:

- **`jwt-pop` and `mtls_pop` are different.** `jwt-pop` is the client assertion the app sends (the
  `client_assertion_type`). `mtls_pop` is the token ESTS returns (the `token_type`). A `jwt-pop` assertion —
  one carrying a `TokenBindingCertificate` — can request either a Bearer token or an `mtls_pop` token; you get
  `mtls_pop` only if that leg also calls `WithMtlsProofOfPossession()`.
- **Attestation and binding are separate in MSAL** (`WithMtlsProofOfPossession()` vs `WithAttestationSupport()`,
  which lives in the KeyAttestation package), and the unattested design still returns `mtls_pop`. But today
  Azure.Identity only tries mTLS-PoP for managed identity when the KeyAttestation package is present, so it
  ties the two together. Whether it should is `[open]`.

---

## 4. The gaps in Azure.Identity

| # | Gap | Why |
|---|---|---|
| G1 | **No way to pass a certificate** | `MsalConfidentialClient` callbacks are `Func<string>` / `Func<CT,Task<string>>`, so there's nowhere to return a `BindingCertificate`. |
| G2 | **The FIC path never asks for PoP** | `AcquireTokenForClientCoreAsync` never calls `WithMtlsProofOfPossession()`, and `ClientAssertionCredential` ignores `IsProofOfPossessionEnabled`. |
| G3 | **One flag, no scheme** | `IsProofOfPossessionEnabled` ships with SHR (Signed HTTP Request) fields — nonce, URI, method. The same flag means SHR PoP for broker, mTLS binding for MI, and nothing for FIC. |
| G4 | **The cert is never produced** | `AccessToken.BindingCertificate` exists and `ToAccessToken()` already copies `TokenType` and `BindingCertificate` — but the FIC path never produces a bound result to copy. |

On G4: this only covers the normal `TokenCredential` / `AccessToken` path. The newer `System.ClientModel`
`AuthenticationToken` has no field for a binding certificate (the conversion drops it), so newer pipelines
can't surface a bound token yet. `[open]`

---

## 5. How we might close the gap

Returning a cert-bound FIC token means changing the request side. Some options, all still open:

- **Carry the certificate.** Add an Azure.Core version of MSAL's `ClientSignedAssertion` (an assertion string
  plus an `X509Certificate2`) returned from a new callback. Should its context copy MSAL's
  `AssertionRequestOptions` (`TokenEndpoint`, `CorrelationId`, `ClientAssertionFmiPath`)?
- **Say which PoP scheme.** Instead of overloading `IsProofOfPossessionEnabled`, add an explicit choice
  (`None` / `SignedHttpRequest` / `MutualTls`). On the credential, the options, or the request?
- **Wire it up.** `MsalConfidentialClient` would call the cert-bound `WithClientAssertion` overload and
  `WithMtlsProofOfPossession()`. The result already flows back through `AccessToken.BindingCertificate`.
- **Decide what happens on failure.** If a caller asks for binding and it isn't available, do we fail or
  quietly return Bearer? Today the flag is just ignored on this path.

There's also work beyond carrying the certificate:

- **Transport.** For bound managed-identity tokens, MSAL uses its own `HttpClient` to do the mTLS handshake;
  the Azure.Core pipeline doesn't carry the mTLS credentials. A bound FIC path hits the same problem.
- **Resource calls.** An `mtls_pop` token has to be sent to the target service over mTLS with the binding
  certificate. That's the service client's job, not the credential's.
- **Lifecycle and caching.** Binding certificates have their own lifetime (the unattested design uses a
  7-day cert) and change how tokens are cached.
- **Ownership.** Nobody has decided who stores, rotates, or disposes the returned `X509Certificate2`.

**MSI-as-FIC** is the clearest example. The callback is `async _ => (await mi.GetTokenAsync(ctx)).Token`,
with no PoP on the inner call — so the managed-identity leg is Bearer and only `.Token` survives. Making it
bound takes more than keeping the certificate: get a bound MI token first, carry the cert through the
assertion, ask for mTLS-PoP on the second leg, and handle mTLS on both the second leg and the resource call.
(The second leg must be a confidential client — managed identity has no `WithClientAssertion`.)

---

## 6. Why one Boolean isn't enough

| Problem | Why |
|---|---|
| **No scheme** | `IsProofOfPossessionEnabled=true` doesn't say which PoP (SHR or mTLS). Credentials read it differently: broker = SHR, MI = mTLS, FIC = ignored. |
| **FIC ignores it** | Even when set, `ClientAssertionCredential` doesn't forward it, and the string callback has no place for a certificate. |
| **Implicit** | The scheme comes from the credential type, so changing preconditions could change the token shape with no explicit choice. |

`IsProofOfPossessionEnabled` is per request, not a global switch, and each credential is per app — so intent
can already be scoped. The real problems are that the Boolean doesn't say *which* PoP scheme you want, and
there's no channel for the certificate. The Key Vault beta (PR #60286) shows this: it sets
`IsProofOfPossessionEnabled = true` and adds an `x-ms-tokenboundauth` header, but what actually happens
depends entirely on the credential you pass in (with a `TODO` to read the scheme from the challenge later).

---

## 7. API options

| Option | Pros | Cons & open |
|---|---|---|
| **A. Extend `ClientAssertionCredential`** with a bound-assertion overload | small surface; reuses the type | overloads a Bearer-shaped type; discoverability |
| **B. New bound credential(s)** (binding required) | explicit; no silent downgrade; clear attestation policy | more credentials; migration |
| **C. Put the scheme on the request** (`TokenRequestContext` / options) | one place; composes with existing credentials | still needs a cert channel; per-request vs per-app scope |

These aren't mutually exclusive. The main questions: extend the existing credentials, add new bound ones, put
the intent on the request, or some mix — and is binding required or optional? Which credential goes first also
depends on what binding material it has. SNI `ClientCertificateCredential` and direct MI have it; Workload
Identity doesn't — its assertion is just a token file.

---

## 8. Who owns what

| Layer | Owns |
|---|---|
| **MSAL.NET** | the token-endpoint protocol (`jwt-pop` vs `jwt-bearer`), `WithMtlsProofOfPossession()`, the token-endpoint mTLS handshake and its `HttpClient`, and the `TokenType` / `BindingCertificate` return (mostly done). |
| **Azure SDK API review** | the credential and request surface, how a caller asks for binding, required vs optional, attestation policy, and failure behavior. |
| **Azure.Core / service clients** | passing the certificate through, the mTLS call to the resource plus connection reuse, and the certificate's lifecycle and ownership. |
| **Platform (IMDS/ESTS)** | the unattested contract and its scope-in-CSR OID and encoding (TBD), cert issuance and rotation, token-binding checks, and cross-platform support. |

---

## 9. References

| Ref | What |
|---|---|
| MSAL source | `ClientSignedAssertion`, `AssertionRequestOptions`, the `WithClientAssertion(...)` overloads, `AcquireTokenForClientParameterBuilder.WithMtlsProofOfPossession()`, `AuthenticationResult.BindingCertificate` — shipped `PublicAPI` (net8.0). |
| MSAL `.github/skills/msal-mtls-pop-fic-two-leg/` | Worked two-leg FIC mTLS-PoP examples and helpers; MSAL 4.82.1+; KeyAttestation package for `WithAttestationSupport()`. |
| MSAL PR #6108 | Design doc `msi_unattested_mtls_pop_design.md` — unattested MSI V2 mTLS-PoP (scope-in-CSR, no MAA); scope OID/encoding still open. |
| MSAL PRs #6109 / #6110 / #6111 | Background docs: Azure.Identity credentials; FIC credentials today; the mTLS-PoP FIC gap. |
| Azure SDK source | `Identity/Credentials/ClientAssertionCredential.cs`, `WorkloadIdentityCredential.cs`, `Identity/MsalConfidentialClient.cs`, `MsalManagedIdentityClient.cs`, `ManagedIdentityClient.cs`, `ChainedTokenCredentialFactory.cs`, `AuthenticationResultExtensions.cs`, `AccessToken.cs`, `TokenRequestContext.cs` (under `sdk/core/Azure.Core/src`). |
| Azure SDK PR #60286 | Key Vault beta PoP token-binding: `ChallengeBasedAuthenticationPolicy` sets `IsProofOfPossessionEnabled=true` and adds `x-ms-tokenboundauth` (always-on preview; `TODO` to read it from the challenge). |

---

## 10. Discussion questions for Azure SDK

1. **How to ask for it** — extend `ClientAssertionCredential`, add new bound credentials, put a scheme on the request, or a mix?
2. **The one flag** — should `IsProofOfPossessionEnabled` be replaced or joined by an explicit scheme (SHR vs mTLS)? Where does that live — credential, options, or request?
3. **Required or optional** — if binding isn't available, do we fail or fall back to Bearer? Do we need a strict, no-downgrade mode?
4. **The certificate channel** — what's the Azure.Core version of `ClientSignedAssertion`, and what does the callback need to know?
5. **Attestation** — keep it tied to binding (as MI is today) or make the two independent?
6. **Transport** — who does the mTLS handshake for the token endpoint (MSAL today) and for the resource call, and how does that fit the Azure.Core pipeline and connection reuse?
7. **Certificate lifecycle** — who stores, rotates, and disposes the binding `X509Certificate2`, and how are bound tokens cached?
8. **System.ClientModel** — should `AuthenticationToken` carry a binding certificate too?
9. **Rollout** — which credentials go first, and what do Workload Identity (no cert) and the unattested MSI design (scope OID TBD) need from the platform first?

---

*Public API and design analysis to start a discussion — not an implementation spec.*
