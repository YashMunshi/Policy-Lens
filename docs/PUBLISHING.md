# Publish Policy Lens

Suggested repository name: `policy-lens` under `YashMunshi`.

## If ChatGPT will upload it

Create the repository at https://github.com/new, initialize it with a README,
and provide the repository URL. The GitHub connection supports file uploads to
existing repositories but does not expose repository creation.
Choose Public if you want recruiters to see the source.

## If you will upload it yourself

Create an empty repository. Extract the ZIP and upload the **contents** of the
`policy-lens` folder, not the archive or an extra wrapper folder. Include hidden
`.gitignore` and `.github` items. `app.py` and `README.md` belong at the repo root.

Or run inside the extracted directory:

```bash
git init -b main
git add .
git commit -m "Add Policy Lens access analysis lab"
git remote add origin https://github.com/YashMunshi/policy-lens.git
git push -u origin main
```

Description: Offline access-log analysis, permission usage review, and SQL-based policy validation.
Suggested topics: security-engineering, python, sqlite, access-control, security-analytics.

Authenticate through GitHub's supported login flow. Do not put tokens in source.
Publishing the repository does not host a running backend. The app runs locally
unless you later configure a Python-capable host.
