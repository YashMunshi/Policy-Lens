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
