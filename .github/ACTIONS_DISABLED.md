# GitHub Actions spending safeguard

Hosted validation and installer workflows were removed on 2026-11-15 after the
DaemoncoreApps account exhausted its included Actions minutes. This prevents
this repository from starting runners through its checked-in workflows. Run
validation and packaging locally while Actions remain disabled.

This repository change does not set the organization billing limit. In GitHub,
set the Actions budget to $0 under the DaemoncoreApps organization billing
settings to block paid Actions overage across the organization. Keep that cap
in place before restoring any hosted workflows.
