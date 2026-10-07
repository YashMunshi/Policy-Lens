# Policy Lens — access policy review

## Evidence scope
Synthetic Northstar access logs: 2400 events, 12 identities,
30 days, seed 412469. All conclusions are review candidates for this fictional dataset.

## Findings
- Unused permission candidates: 2.
- Cross-department identity/resource groups with successful access: 11.
- Sensitive export groups: 12.
- Hourly volume spikes: 1.

## Proposed actions
Review unused entitlements with resource owners; confirm business need before revocation.
Review cross-department exceptions and sensitive export privileges.
Investigate high-volume buckets using event evidence; a spike does not establish compromise.
Replay candidate controls before considering rollout; verify behavior on independently labeled real traffic.

## Limitations
Synthetic labels encode the desired policy rubric. No real incidents, live A/B experiment,
production access changes, or automatic revocations occur. Time-window non-use does not prove a permission is unnecessary.
In-process replay latency excludes HTTP/database overhead; Wilson intervals describe this sample only.

## Latest policy replay
Run 1; policy v1.
Observed false allows: 529; false denies: 0.
Candidate false allows: 0; false denies: 0.
Changed decisions: 529.

## Detailed evidence
```json
{
  "unused_permissions": [
    {
      "principal": "build-service",
      "resource": "finance-payroll",
      "action": "export",
      "successful_uses": 0
    },
    {
      "principal": "security-admin",
      "resource": "finance-payroll",
      "action": "export",
      "successful_uses": 0
    }
  ],
  "cross_department_access": [
    {
      "principal": "report-service",
      "resource": "finance-payroll",
      "count": 102,
      "example_event": 21
    },
    {
      "principal": "build-service",
      "resource": "sales-crm",
      "count": 51,
      "example_event": 52
    },
    {
      "principal": "engineering-3",
      "resource": "sales-crm",
      "count": 45,
      "example_event": 76
    },
    {
      "principal": "finance-1",
      "resource": "sales-crm",
      "count": 44,
      "example_event": 36
    },
    {
      "principal": "sales-2",
      "resource": "engineering-code",
      "count": 43,
      "example_event": 37
    },
    {
      "principal": "engineering-1",
      "resource": "sales-crm",
      "count": 42,
      "example_event": 8
    },
    {
      "principal": "engineering-3",
      "resource": "finance-payroll",
      "count": 9,
      "example_event": 285
    },
    {
      "principal": "finance-2",
      "resource": "sales-crm",
      "count": 7,
      "example_event": 988
    },
    {
      "principal": "engineering-2",
      "resource": "sales-crm",
      "count": 4,
      "example_event": 459
    },
    {
      "principal": "sales-1",
      "resource": "finance-payroll",
      "count": 3,
      "example_event": 371
    },
    {
      "principal": "finance-3",
      "resource": "engineering-code",
      "count": 2,
      "example_event": 1678
    }
  ],
  "sensitive_exports": [
    {
      "principal": "finance-3",
      "resource": "finance-payroll",
      "count": 10,
      "example_event": 552
    },
    {
      "principal": "engineering-3",
      "resource": "finance-payroll",
      "count": 9,
      "example_event": 285
    },
    {
      "principal": "finance-2",
      "resource": "finance-payroll",
      "count": 9,
      "example_event": 538
    },
    {
      "principal": "engineering-3",
      "resource": "engineering-code",
      "count": 8,
      "example_event": 288
    },
    {
      "principal": "build-service",
      "resource": "engineering-code",
      "count": 5,
      "example_event": 826
    },
    {
      "principal": "finance-1",
      "resource": "finance-payroll",
      "count": 5,
      "example_event": 815
    },
    {
      "principal": "security-admin",
      "resource": "engineering-code",
      "count": 5,
      "example_event": 70
    },
    {
      "principal": "engineering-1",
      "resource": "engineering-code",
      "count": 3,
      "example_event": 789
    },
    {
      "principal": "engineering-2",
      "resource": "engineering-code",
      "count": 3,
      "example_event": 92
    },
    {
      "principal": "sales-1",
      "resource": "finance-payroll",
      "count": 3,
      "example_event": 371
    },
    {
      "principal": "sales-2",
      "resource": "engineering-code",
      "count": 3,
      "example_event": 163
    },
    {
      "principal": "finance-3",
      "resource": "engineering-code",
      "count": 2,
      "example_event": 1678
    }
  ],
  "volume_spikes": [
    {
      "principal": "report-service",
      "day": 17,
      "hour": 3,
      "count": 60,
      "baseline_per_hour": 0.338,
      "threshold": 10
    }
  ],
  "limits": "Review candidates, not automatic revocation. Unused means no observed successful use in this 30-day synthetic window. Volume spikes are rate heuristics, not proof of compromise."
}
```
