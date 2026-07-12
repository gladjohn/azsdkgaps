# Azure.Identity mTLS-PoP / FIC gaps — a conversation starter

Source-checked notes to **start a technical discussion** among Azure SDK engineers about
**certificate-bound (mTLS Proof-of-Possession) tokens** for **Federated Identity Credential (FIC)**
flows in **Azure.Identity**, relative to what **MSAL.NET** exposes. Listed directions are options to
debate, not decisions.

> Public sources only (MSAL.NET, `azure-sdk-for-net`, PRs in §9). In current `main`, Azure.Identity's
> credentials are consolidated into **Azure.Core** (`sdk/core/Azure.Core/src/Identity/…`; `Azure.Identity`
> is a type-forwarding facade). Verified against source 2026-07-12.

**Status tags:** `[Shipping]` public API today · `[MSAL]` in MSAL.NET, not surfaced by Azure.Identity ·
`[Az.Id]` wired in Azure.Identity/Azure.Core · `[Design]` design doc, not implemented · `[Open]` open
question · `[Correction]` fixes a prior overstatement.

---

## 1. TL;DR

- `[MSAL]` MSAL.NET has the primitives for cert-bound client tokens — `WithMtlsProofOfPossession()`
  (confidential + MI), cert-bound assertions (`ClientSignedAssertion.TokenBindingCertificate` →
  `client_assertion_type=jwt-pop`), and `AuthenticationResult.BindingCertificate` — all in the shipped
  net8.0 API; the two-leg FIC pattern is documented and tested in-repo (MSAL 4.82.1+).
- `[Az.Id]` Azure.Identity wires mTLS-PoP only for the **direct** `ManagedIdentityCredential`, and only
  **opt-in** (`IsProofOfPossessionEnabled`) when the host advertises token binding (IMDSv2) **and** the
  `Microsoft.Identity.Client.KeyAttestation` extension is present.
- `[Confirmed gap]` The **confidential-client / FIC** path reduces every assertion to a **`string`**
  before MSAL is called and never requests PoP, so it always returns **Bearer**. `AccessToken` can already
  carry a `BindingCertificate` (shared `ToAccessToken()` maps it), so the **return** side is largely
  ready; the **request/assertion** side is not.
- `[Open]` The central question is not "what is the fix" but **how Azure.Identity should let a caller
  express cert-bound FIC intent and carry a binding certificate** — spanning API review, MSAL, and IMDS/ESTS.

---

## 2. Non-mTLS (Bearer) today  `[Confirmed current behavior]`

| Flow | MSAL.NET API | Azure.Identity credential | Result |
|---|---|---|---|
| **SNI** (subject-name-issuer cert) | `WithCertificate(cert, sendX5C:true)` | `ClientCertificateCredential` | Bearer |
| **MSI** | `AcquireTokenForManagedIdentity(resource)` | `ManagedIdentityCredential` | Bearer (unless PoP opted-in) |
| **FIC** (assertion) | `WithClientAssertion(string)` / `Func<…,Task<string>>` | `ClientAssertionCredential`; `WorkloadIdentityCredential`; internal `ManagedIdentityAsFederatedIdentityCredential` | Bearer |

All three are **one path**: `WorkloadIdentityCredential` *wraps* `ClientAssertionCredential`;
`ManagedIdentityAsFederatedIdentityCredential` *constructs* one whose callback returns a managed-identity
token's `.Token` string. Convergence: **assertion → `string` → `MsalConfidentialClient` →
`WithClientAssertion(string)` → `AcquireTokenForClient` → Bearer**; `GetToken` never reads
`IsProofOfPossessionEnabled`.

---

## 3. mTLS-PoP today — what exists where

| Flow | MSAL.NET `[MSAL]` | Azure.Identity `[Az.Id]` |
|---|---|---|
| **SNI cert** | `WithCertificate(cert)` + `WithMtlsProofOfPossession()` → `mtls_pop` + `BindingCertificate` | ❌ `ClientCertificateCredential` never requests PoP |
| **FIC cert-bound assertion** | `WithClientAssertion(Func<AssertionRequestOptions,CT,Task<ClientSignedAssertion>>)` with `TokenBindingCertificate` → `jwt-pop` (+ `WithMtlsProofOfPossession()` for an `mtls_pop` result) | ❌ callback returns `string` only |
| **MSI (IMDSv2)** | `AcquireTokenForManagedIdentity(res).WithMtlsProofOfPossession()` | ✅ **direct** MI (opt-in + host + KeyAttestation-gated); ❌ MI-as-FIC |
| **MSI un-attested** `[Design]` | PR #6108 doc: strongest key else in-memory RSA, no MAA, scope-in-CSR (OID **TBD**) → `mtls_pop` | n/a (IMDS/ESTS + MSAL) |

- **`jwt-pop` needs both** an mTLS-PoP-enabled app **and** a `TokenBindingCertificate`; cert but no PoP
  request → `jwt-bearer`.
- **Attestation vs binding** are separate MSAL calls (`WithMtlsProofOfPossession()` vs `WithAttestationSupport()`,
  the latter in the `…KeyAttestation` package), and un-attested still yields `mtls_pop`. **But** today's
  Azure.Identity MI path only *attempts* mTLS-PoP when that extension resolves, so in practice the two are
  **coupled** there. `[Open]` whether they should be.

---

## 4. Confirmed gaps in Azure.Identity

| # | Gap | Evidence |
|---|---|---|
| G1 | **No bound-assertion channel** | `MsalConfidentialClient` callbacks are `Func<string>` / `Func<CT,Task<string>>`; no way to return a `BindingCertificate`. |
| G2 | **FIC path never requests PoP** | `AcquireTokenForClientCoreAsync` never calls `WithMtlsProofOfPossession()`; `ClientAssertionCredential` ignores `IsProofOfPossessionEnabled`. |
| G3 | **One PoP boolean, ambiguous scheme** | `IsProofOfPossessionEnabled` is paired with SHR fields (nonce/URI/method). The same flag means **SHR PoP** for broker, **mTLS binding** for MI, **nothing** for FIC. |
| G4 | **Cert never obtained on FIC path** | `AccessToken.BindingCertificate` exists and shared `ToAccessToken()` already copies `TokenType` + `BindingCertificate` — but the FIC path never produces a bound result to copy. |

G4 nuance `[Open]`: that readiness is for the `TokenCredential`/`AccessToken` path. `System.ClientModel`'s
`AuthenticationToken` has **no** binding-certificate field (`ToAuthenticationToken()` drops it), so SCM-based
pipelines could not surface a bound token today.

---

## 5. Possible implementation directions (not a chosen design)

A cert-bound FIC token needs changes on the **request/assertion** side. Each item below is an option/
consideration to debate, not a decision:

- **Carry the certificate** — e.g. an Azure.Core analogue of MSAL's `ClientSignedAssertion` (assertion +
  `X509Certificate2`) via a new callback overload. Open: mirror MSAL `AssertionRequestOptions`
  (`TokenEndpoint`, `CorrelationId`, `ClientAssertionFmiPath`)?
- **Express the scheme** — instead of overloading `IsProofOfPossessionEnabled`, an explicit scheme
  (`None`/`SignedHttpRequest`/`MutualTls`). On the credential, options, or request? Open.
- **Wire it** — `MsalConfidentialClient` would use the cert-bound `WithClientAssertion` overload +
  `WithMtlsProofOfPossession()`; the return already flows through `ToAccessToken()`.
- **Failure semantics** `[Open]` — if binding is requested but unavailable: fail, or silently return Bearer?
  Today the flag is silently ignored on the FIC path.

**Often-understated work** (confirmed to sit outside "just carry the cert"): **transport** — for bound MI
tokens MSAL manages **its own `HttpClient`** for the token-endpoint mTLS handshake; the Azure.Core transport
does **not** carry mTLS credentials; **resource-side TLS** — an `mtls_pop` token must be presented to the
target resource over mTLS (data-plane pipeline, not the credential); **lifecycle/caching** — bound certs
have their own lifetime (7-day cert in the un-attested design) and imply cache partitioning; **ownership** —
who stores/rotates/disposes the returned `X509Certificate2` is unspecified.

**MSI-as-FIC** `[Confirmed gap]`: the callback is `async _ => (await mi.GetTokenAsync(ctx)).Token` with **no**
PoP on the inner request, so the MI leg is Bearer and only `.Token` is kept. Binding it needs **more than
preserving the cert**: a bound MI token (leg 1), a cert channel through the assertion, mTLS-PoP on the
confidential exchange (leg 2), plus leg-2 and resource-side mTLS transport. (Leg 2 **must** be a confidential
client — managed identity has no `WithClientAssertion`.)

---

## 6. Why the single PoP boolean is insufficient

| Issue | Why |
|---|---|
| **Ambiguous scheme** | `IsProofOfPossessionEnabled=true` cannot say *which* PoP (SHR vs mTLS); credentials interpret it differently (broker=SHR, MI=mTLS, FIC=ignored). |
| **Confidential path ignores it** | Even when set, `ClientAssertionCredential` never forwards it, and the string callback has nowhere for a certificate. |
| **Implicit** | Scheme is inferred from credential type, so relaxing preconditions could change token shape without an explicit per-credential decision. |

`[Correction]` This is **not** primarily a "global flag" problem — `TokenRequestContext` is per-request and
credentials are per-app, so intent *can* be scoped. The real issues are **scheme ambiguity** and the
**missing certificate channel**. Concretely, the Key Vault beta (PR #60286) hard-codes
`IsProofOfPossessionEnabled=true` + `x-ms-tokenboundauth`, leaving *which scheme happens* to whichever
credential is supplied (with an in-code `TODO` to derive it from the challenge instead).

---

## 7. API-shape options and trade-offs  `[Open — API review]`

No single shape is recommended. At least three non-exclusive directions should be weighed together:

| Direction | For | Against / open |
|---|---|---|
| **A. Extend `ClientAssertionCredential`** with a bound-assertion overload | small surface; reuses the type | overloads a Bearer-shaped type; discoverability |
| **B. New bound credential(s)** (binding mandatory) | explicit; no silent downgrade; clear attestation policy | credential proliferation; migration |
| **C. Request-semantics** (explicit scheme on `TokenRequestContext`/options) | one place; composable | still needs a cert channel; per-request vs per-app scope |

Framing: **extend existing credentials, add new bound credentials, express intent through request semantics,
or a combination — and is binding mandatory or opt-in?** First adopters differ by available binding material
(SNI `ClientCertificateCredential` and direct MI have it; Workload Identity has none — its assertion is a
token file).

---

## 8. Where each decision lives

| Layer | Owns / decides |
|---|---|
| **MSAL.NET** | token-endpoint protocol (`jwt-pop` vs `jwt-bearer`), `WithMtlsProofOfPossession()`, token-endpoint mTLS handshake + its `HttpClient`, `TokenType`/`BindingCertificate` return (largely done). |
| **Azure SDK — API review** | credential/request surface, how binding intent is expressed, mandatory vs opt-in, attestation policy, downgrade semantics. |
| **Azure.Core / service clients** | bound-assertion channel, cert propagation, **resource-side mTLS** transport + connection reuse, cert lifecycle/ownership. |
| **Platform (IMDS/ESTS)** | un-attested contract + **scope-in-CSR OID/encoding (TBD)**, cert issuance/rotation, token-binding validation, cross-platform support. |

---

## 9. References (public)

| Ref | What |
|---|---|
| MSAL source | `ClientSignedAssertion`, `AssertionRequestOptions`, `WithClientAssertion(...)` overloads, `AcquireTokenForClientParameterBuilder.WithMtlsProofOfPossession()`, `AuthenticationResult.BindingCertificate` — shipped `PublicAPI` (net8.0). |
| MSAL `.github/skills/msal-mtls-pop-fic-two-leg/` | Worked two-leg FIC mTLS-PoP examples/helpers; MSAL 4.82.1+; `…KeyAttestation` for `WithAttestationSupport()`. |
| MSAL PR #6108 | **Design doc** `msi_unattested_mtls_pop_design.md` — un-attested MSI V2 mTLS-PoP (scope-in-CSR, no MAA); scope OID/encoding open. |
| MSAL PRs #6109 / #6110 / #6111 | Background doc series: Azure.Identity credentials; FIC credentials today; the mTLS-PoP FIC gap. |
| Azure SDK source | `Identity/Credentials/ClientAssertionCredential.cs`, `WorkloadIdentityCredential.cs`, `Identity/MsalConfidentialClient.cs`, `MsalManagedIdentityClient.cs`, `ManagedIdentityClient.cs`, `ChainedTokenCredentialFactory.cs`, `AuthenticationResultExtensions.cs`, `AccessToken.cs`, `TokenRequestContext.cs` (under `sdk/core/Azure.Core/src`). |
| Azure SDK PR #60286 | Key Vault **beta** PoP token-binding: `ChallengeBasedAuthenticationPolicy` sets `IsProofOfPossessionEnabled=true` + `x-ms-tokenboundauth` (always-on preview; `TODO` to derive from challenge). |

---

## 10. Discussion Questions for Azure SDK

1. **Intent surface** — Express cert-bound FIC intent via (A) extending `ClientAssertionCredential`, (B) new bound credentials, (C) explicit request/option scheme, or a combination?
2. **One flag, many schemes** — Replace/augment `IsProofOfPossessionEnabled` with an explicit scheme (SHR vs mTLS)? Where does it live — credential, options, or request?
3. **Mandatory vs best-effort** — If binding is unavailable: fail, or fall back to Bearer? Is a strict no-downgrade mode needed?
4. **Certificate channel** — What is the Azure.Core analogue of `ClientSignedAssertion`, and what context does the callback need?
5. **Attestation coupling** — Keep attestation and binding coupled (as MI is today) or make them independently selectable?
6. **Transport ownership** — Who owns the mTLS handshake for the token endpoint (MSAL today) and the **resource** call, and how does that interact with the Azure.Core pipeline and connection reuse?
7. **Certificate lifecycle** — Who stores, rotates, and disposes the binding `X509Certificate2`, and how are bound tokens cached/partitioned?
8. **SCM return path** — Should `System.ClientModel.AuthenticationToken` carry a binding certificate?
9. **Rollout & dependencies** — Which credentials first, and what do Workload Identity (no cert) and the un-attested MSI design (scope-OID TBD) need from the platform first?

---

*Scope: public API/design analysis to seed discussion — not an implementation spec.*
