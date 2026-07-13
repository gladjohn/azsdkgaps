# Azure.Identity mTLS-PoP / FIC gaps

MSAL.NET supports certificate-bound client assertions and mTLS Proof-of-Possession (PoP). Azure.Identity's
Federated Identity Credential (FIC) path does not use them: it reduces every assertion to a `string`, never
requests mTLS-PoP, and so returns Bearer tokens only. This note records that gap.

> Public sources only (MSAL.NET, `azure-sdk-for-net`, the PRs in §6). On current `main`, Azure.Identity's
> credentials live in **Azure.Core** (`sdk/core/Azure.Core/src/Identity/…`; `Azure.Identity` forwards the
> types). Checked against source on 2026-07-12.

---

## 1. Summary

- **MSAL.NET supports it.** Certificate-bound client tokens via `WithMtlsProofOfPossession()` (confidential
  clients and managed identity), cert-bound assertions (`ClientSignedAssertion` carrying a
  `TokenBindingCertificate`), and `AuthenticationResult.BindingCertificate`. This ships in the net8.0 API, and
  the two-leg FIC pattern is documented and tested in the MSAL repo (4.82.1+).
- **Azure.Identity's FIC path doesn't.** `ClientAssertionCredential`, `WorkloadIdentityCredential`, and the
  internal `ManagedIdentityAsFederatedIdentityCredential` all converge on a `string` assertion, never request
  PoP, and return Bearer tokens.
- **The gap.** There is no way, through these credentials, to pass a binding certificate or ask for an
  `mtls_pop` token. `AccessToken` can already carry a binding certificate, so the return side is mostly ready;
  the request side is not.

---

## 2. Bearer tokens today (SNI / MSI / FIC)

| Flow | MSAL.NET API | Azure.Identity credential | Result |
|---|---|---|---|
| **SNI** (subject-name-issuer cert) | `WithCertificate(cert, sendX5C:true)` | `ClientCertificateCredential` | Bearer |
| **MSI** | `AcquireTokenForManagedIdentity(resource)` | `ManagedIdentityCredential` | Bearer (unless PoP opted-in) |
| **FIC** (assertion) | `WithClientAssertion(string)` / `Func<…,Task<string>>` | `ClientAssertionCredential`; `WorkloadIdentityCredential`; internal `ManagedIdentityAsFederatedIdentityCredential` | Bearer |

The three FIC credentials are one path. `WorkloadIdentityCredential` wraps `ClientAssertionCredential`, and
`ManagedIdentityAsFederatedIdentityCredential` builds one whose callback returns a managed-identity token's
`.Token` string. They all end up at: assertion → `string` → `MsalConfidentialClient` →
`WithClientAssertion(string)` → `AcquireTokenForClient` → Bearer. `ClientAssertionCredential.GetToken` never
looks at `IsProofOfPossessionEnabled`.

---

## 3. Cert-bound tokens today: MSAL vs Azure.Identity

| Flow | MSAL.NET | Azure.Identity |
|---|---|---|
| **SNI cert** | `WithCertificate(cert)` + `WithMtlsProofOfPossession()` → `mtls_pop` + `BindingCertificate` | ❌ `ClientCertificateCredential` never requests PoP |
| **FIC cert-bound assertion** | `WithClientAssertion(Func<AssertionRequestOptions,CT,Task<ClientSignedAssertion>>)` with `TokenBindingCertificate` → `jwt-pop` (add `WithMtlsProofOfPossession()` for an `mtls_pop` result) | ❌ callback returns `string` only |
| **MSI (IMDSv2)** | `AcquireTokenForManagedIdentity(res).WithMtlsProofOfPossession()` | ✅ direct MI (opt-in; host + KeyAttestation-gated); ❌ MI-as-FIC |
| **MSI unattested (design)** | PR #6108 design: strongest key else in-memory RSA, no MAA, scope-in-CSR (OID TBD) → `mtls_pop` | n/a (IMDS/ESTS + MSAL) |

Two facts to keep straight:

- **`jwt-pop` and `mtls_pop` are different.** `jwt-pop` is the client assertion the app sends (the
  `client_assertion_type`). `mtls_pop` is the token ESTS returns (the `token_type`). A `jwt-pop` assertion —
  one carrying a `TokenBindingCertificate` — can result in either a Bearer or an `mtls_pop` token; you get
  `mtls_pop` only if that leg also calls `WithMtlsProofOfPossession()`.
- **Attestation and binding are separate in MSAL** (`WithMtlsProofOfPossession()` vs `WithAttestationSupport()`
  in the KeyAttestation package), and the unattested flow above is a design, not shipping. Today Azure.Identity
  only tries mTLS-PoP for managed identity when the KeyAttestation package is present, so it ties the two together.

Direct `ManagedIdentityCredential` can already get an `mtls_pop` token, but that is a separate flow and does
not close the FIC gap.

---

## 4. The gaps in Azure.Identity

| # | Gap | Why |
|---|---|---|
| G1 | **No way to pass a certificate** | `MsalConfidentialClient` callbacks are `Func<string>` / `Func<CT,Task<string>>`, so there is nowhere to return a `BindingCertificate`. |
| G2 | **The FIC path never asks for PoP** | `AcquireTokenForClientCoreAsync` never calls `WithMtlsProofOfPossession()`, and `ClientAssertionCredential` ignores `IsProofOfPossessionEnabled`. |
| G3 | **One flag, no scheme** | `IsProofOfPossessionEnabled` is per request, not global, and carries SHR (Signed HTTP Request) fields — nonce, URI, method. The same flag means SHR PoP for broker, mTLS binding for MI, and nothing for FIC, so a caller can set it and still get Bearer from `ClientAssertionCredential`. |
| G4 | **The cert is never produced** | `AccessToken.BindingCertificate` exists and `ToAccessToken()` already copies `TokenType` and `BindingCertificate` — but the FIC path never produces a bound result to copy. |

On G4: this covers the normal `TokenCredential` / `AccessToken` path. The newer `System.ClientModel`
`AuthenticationToken` has no field for a binding certificate (the conversion drops it).

---

## 5. What the FIC path is missing

Returning a cert-bound FIC token needs two things the request side does not have: a way for the assertion
callback to return a certificate (today it returns a `string`), and a way to request mTLS-PoP on the exchange.
MSAL already provides both halves — the cert-bound `WithClientAssertion` overload and
`WithMtlsProofOfPossession()` — and the result would flow back through `AccessToken.BindingCertificate`. How to
surface this in the public API (for example, extending a credential, adding one, or configuring it per request)
is a separate design decision, outside this note.

`ManagedIdentityAsFederatedIdentityCredential` shows the gap concretely. Its callback is
`async _ => (await mi.GetTokenAsync(ctx)).Token`, with no PoP on the inner call — so the managed-identity leg
is Bearer and only `.Token` survives. Binding it would need a bound MI token first, the certificate carried
through the assertion, and mTLS-PoP requested on the second leg. (The second leg must be a confidential client;
managed identity has no `WithClientAssertion`.)

Closing the gap also depends on work outside the credential: MSAL uses its own `HttpClient` for the
token-endpoint mTLS handshake (the Azure.Core pipeline does not carry mTLS credentials), the `mtls_pop` token
must reach the target service over mTLS with the binding certificate, and the binding certificate has its own
lifetime and owner. The unattested MSI flow (PR #6108) is a design and depends on IMDS/ESTS.

---

## 6. References

| Ref | What |
|---|---|
| MSAL source | `ClientSignedAssertion`, `AssertionRequestOptions`, the `WithClientAssertion(...)` overloads, `AcquireTokenForClientParameterBuilder.WithMtlsProofOfPossession()`, `AuthenticationResult.BindingCertificate` — shipped `PublicAPI` (net8.0). |
| MSAL `.github/skills/msal-mtls-pop-fic-two-leg/` | Worked two-leg FIC mTLS-PoP examples and helpers; MSAL 4.82.1+; KeyAttestation package for `WithAttestationSupport()`. |
| MSAL PR #6108 | Design doc `msi_unattested_mtls_pop_design.md` — unattested MSI V2 mTLS-PoP (scope-in-CSR, no MAA); scope OID/encoding still open. |
| MSAL PRs #6109 / #6110 / #6111 | Background docs: Azure.Identity credentials; FIC credentials today; the mTLS-PoP FIC gap. |
| Azure SDK source | `Identity/Credentials/ClientAssertionCredential.cs`, `WorkloadIdentityCredential.cs`, `Identity/MsalConfidentialClient.cs`, `MsalManagedIdentityClient.cs`, `ManagedIdentityClient.cs`, `ChainedTokenCredentialFactory.cs`, `AuthenticationResultExtensions.cs`, `AccessToken.cs`, `TokenRequestContext.cs` (under `sdk/core/Azure.Core/src`). |
| Azure SDK PR #60286 | Key Vault beta PoP token-binding: `ChallengeBasedAuthenticationPolicy` sets `IsProofOfPossessionEnabled=true` and adds `x-ms-tokenboundauth` (always-on preview; `TODO` to read it from the challenge). |
