# Resume and interview notes

Use once you can explain the implementation and reproduce the results.

**Policy Lens — Access Policy Analysis and Validation Lab**
Python, SQL, SQLite, JavaScript; access-log analytics, permission reviews, policy evaluation.

- Built an offline analysis lab for 2,400 synthetic access events across 12 human
  and service identities; used SQL to identify unused permission candidates,
  cross-department exposure, sensitive exports, and hourly volume spikes.
- Implemented reproducible policy replay with SQL confusion matrices, deny
  precision/recall, sample accuracy intervals, and evidence-backed review reports.
- Validated candidate policy impact on a labeled synthetic fixture: disabling
  department boundaries introduced 886 false allowances, compared with none for
  the full candidate rules.

Explain why non-use is not proof of excess privilege; why rate spikes do not prove
compromise; and why synthetic agreement does not establish production performance.
This project provides analytics evidence beyond the IAM implementation at ACL.
Pair with Agent Gate and describe KAIRO as a team hackathon project with your own
contribution made clear. Do not claim professional experience duration from this lab.
