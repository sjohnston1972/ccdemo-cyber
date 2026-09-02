# ccdemo-cyber

A small Python tool (`cisco_audit.py`) that connects to a Cisco switch over
SSH and runs read-only `show` commands to produce a non-intrusive security
audit report. Credentials are read from a `.env` file (`DEVICE_IP`,
`SSH_USERNAME`, `SSH_PASSWORD`) via `python-dotenv`.

## SSH host-key verification

By default the tool verifies the SSH host key presented by the device
against the system `known_hosts` and a project-local `known_hosts` file
(created next to `cisco_audit.py`, git-ignored). **An unknown or changed
host key is refused before any credentials are sent.**

### Onboarding a new device

A brand-new device's key is not yet trusted, so a first connection will
(correctly) be refused. To onboard it deliberately:

```bash
python cisco_audit.py --accept-new-hostkey
# or:
AUDIT_ACCEPT_NEW_HOSTKEY=1 python cisco_audit.py
```

With this opt-in flag set, a genuinely new host key is fetched, its SHA256
fingerprint is printed to the console, and it is saved to the project
`known_hosts` file. **Verify the printed fingerprint out-of-band (e.g.
against documentation from whoever provisioned the device) before trusting
the run's output.**

If a key is already on file for a host but the device now presents a
**different** key, the connection is always refused - with or without
`--accept-new-hostkey`. That situation is a possible man-in-the-middle
attack, not a first connection, and is never auto-trusted.

| Scenario | Default | `--accept-new-hostkey` |
|---|---|---|
| Unknown host (no key on file) | refused | fingerprint shown, trusted, saved |
| Known host, key unchanged | connects normally | connects normally |
| Known host, key **changed** | refused | **refused** (MITM case) |

## Audit reports are git-ignored by design

Running the tool generates `audit_report_<host>.txt`. These files are
excluded via `.gitignore` (`audit_report_*.txt`) and should **not** be
committed - a real report can disclose internal IPs, hostnames, and
network topology for the audited environment. See
[`audit_report_sample.txt`](audit_report_sample.txt) for a fully redacted
example of the report format, using a fictitious device on the RFC 5737
TEST-NET-2 documentation range (`198.51.100.0/24`).

## Do-not-commit policy

Never commit any of the following:

- `.env` or any file containing credentials, API keys, or community strings
- Real audit reports (`audit_report_*.txt`) - git-ignored by design; only
  the redacted `audit_report_sample.txt` is tracked
- The project-local `known_hosts` file (git-ignored) - it may contain real
  device host keys
- SSH private keys, database connection strings, or other secrets

Before pushing, run `git status` and review what's staged. As a
defence-in-depth backstop, GitHub's **secret scanning** and **push
protection** should be enabled on this repository (Settings -> Code
security and analysis) to catch known secret formats before they reach
the remote. Optionally, run a pre-commit secret scanner such as
[gitleaks](https://github.com/gitleaks/gitleaks) locally:

```bash
gitleaks protect --staged
```
