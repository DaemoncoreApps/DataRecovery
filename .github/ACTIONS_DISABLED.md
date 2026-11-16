# GitHub Actions spending safeguard

Hosted validation and installer workflows were removed on 2026-11-15 after the
DaemoncoreApps account exhausted its included Actions minutes. This prevents
this repository from starting runners through its checked-in workflows. Run
validation and packaging locally while Actions remain disabled.

The DaemoncoreApps account's Actions budget is already set to $0.00, and GitHub
shows its usage as blocked under Billing and licensing > Budgets and alerts
(verified 2026-11-15). This account-level cap protects other repositories owned
by the account from billable Actions usage too. Keep the cap in place before
restoring any hosted workflows.
