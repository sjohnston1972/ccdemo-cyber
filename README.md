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
