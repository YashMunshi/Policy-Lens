# Security design and analysis limits

Policy Lens is an offline review tool. It consumes a seeded synthetic entitlement
snapshot and historical event fixture, produces findings and candidate decisions,
and never changes live user access. Browser inputs are untrusted; analyst identity
comes from server-side sessions. The local host, code, and database are trusted.

## Implemented controls

- Authenticated security-admin workspace; employees cannot call analysis endpoints.
- PBKDF2 password hashing, throttled login, opaque sessions, HttpOnly/SameSite cookies.
- Origin and Host validation, CSRF headers, restricted CSP, escaped UI text.
- Parameterized SQL filters and exact boolean policy schema.
- Seeded data reproducibility; paired evaluation writes isolated replay results.
- Explicit output limits for browser tables; full CSV export of synthetic evidence.

## Analytical risks

- Non-use in the observation window does not prove an entitlement is unnecessary.
- Cross-department access can be legitimate; findings require owner review.
- Volume spikes may represent a scheduled job, not compromise. The mean includes
  the flagged period and is not a robust or calibrated statistical baseline.
- Synthetic labels encode the specified policy. They do not replace independent
  adjudication of real traffic, and perfect agreement does not imply production accuracy.
- Candidate decisions omit real-world exceptions and policy interactions. Replay
  results should inform review, not trigger automatic rollout or privilege removal.
- Imported real logs would need schema validation, retention policy, privacy controls,
  stronger storage/access protection, and attention to spreadsheet formula injection
  in exports. This prototype only exports known synthetic fixture values.

## Deployment limits

The built-in server and public demo credentials are localhost-only. There is no
production identity provider, MFA, TLS, immutable evidence retention, or distributed
rate limiting. Audit utilities are ordinary local SQLite records. A production
analyst service would need trusted log ingestion, identity integration, protected
evidence storage, transport encryption, monitoring, and operational hardening.

## Hosted public-demo boundary
The hosted adapter deliberately exposes only deterministic synthetic analysis.
It provides no production authentication, tenant administration, external data
import, or live permission mutation. No sign-in is required. Validated browser
settings reconstruct request-local databases; they are not authorization tokens.
No shared policy state or durable server database exists. Cross-origin requests
are rejected, API responses are not cached, inputs are bounded and validated,
and queries remain parameterized. Clearing localStorage resets visitor state.
Replay timing can vary between reconstructed requests. Rate limiting and resource
protection at the edge are supplied by the hosting platform; localhost login-rate
limits and session revocation are not represented as hosted-demo features.
