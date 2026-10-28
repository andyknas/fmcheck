# fmcheck

A read-only auditor for FileMaker Server hosts. Point it at servers you run
and it reports patch level, which web interfaces are exposed, whether any
hosted file allows guest/anonymous access, and TLS certificate expiry.

Written in response to the September 2026 FileMaker Server advisories and the
late-October 2026 wave of attacks against FileMaker hosts that chained weak
security practices (default admin passwords, guest access left on for
WebDirect / OData / Data API) with unpatched servers.

## What it checks, per host

- **Version vs. patched release.** Reads the running version from the
  unauthenticated Data API `productInfo` endpoint and compares it to the
  minimum fixed release for that version line.
- **Database inventory over the Data API.** Lists every hosted file that has
  the Data API (`fmrest`) privilege enabled — i.e. what is actually reachable
  over REST.
- **Guest / anonymous access.** For each exposed file, attempts an anonymous
  session over the Data API and an anonymous read over OData. A success means
  the file's `[Guest]` account is enabled for that interface. When OData
  answers without credentials, it also lists the exposed entity sets and
  probes one of them for a single row, to show whether actual records — not
  just the schema — are readable.
- **Interface exposure.** Reports whether OData, XML Custom Web Publishing,
  WebDirect, and the Admin Console (port 16000) answer from where the script
  is run.
- **TLS certificate expiry.** Flags certs expiring within 30 days.

## What it does NOT do

It is defensive and non-destructive. It only requests metadata/version
endpoints and attempts an anonymous login that it immediately logs out. It
writes nothing, guesses no passwords, and sends no exploit payloads. The only
time it reads a record is to confirm an OData endpoint that already answered
without credentials, and then at most one row, with field values never
printed. Some things can only be seen from inside the Admin Console
and are **not** covered here: admin password strength, account/privilege-set
review, and whether passwords are stored in fields. Those are left to a manual
checklist.

## Requirements

`bash`, `curl`, and `openssl` — present by default on macOS and most Linux.

## Usage

```
./fmcheck.sh                    # interactive: prompts for one host at a time
./fmcheck.sh hosts.txt          # one hostname per line in hosts.txt
./fmcheck.sh host1 host2 ...    # hostnames as arguments
./fmcheck.sh --help
```

Hostnames only, no scheme (e.g. `fms.example.com`). In `hosts.txt`, blank
lines and `#` comments are ignored.

Output is tagged `[OK]` / `[INFO]` / `[WARN]`. `[WARN]` lines need review;
`[INFO]` means a service is reachable — confirm that it is intended.

## Advisory reference

| Fixed in | CVEs | Notes |
|----------|------|-------|
| 26.0.3 | CVE-2026-86934, -86930, -86926 | XML WPE auth bypass (`X-FMI-PE-ExtendedPrivilege` header), WebDirect thumbnail out-of-bounds read, crafted `.fmp12` heap overflow → possible RCE |
| 26.0.1 | CVE-2026-43752 | Authenticated admin file-upload RCE |
| 22.0.4 / 21.1.7 | CVE-2025-46295 | Critical text-substitution RCE (CVSS 9.8) |
| 20.3.2 | CVE-2024-27794 | WebDirect login reflected XSS |

The September 2026 fixes are confirmed only in 26.0.3. On older lines, patch
to the line minimum above and confirm backport status with Claris.

## Scope / authorized use

Run this only against servers you own or are explicitly authorized to test.
Pointing it at third-party hosts sends unsolicited login attempts and may be
treated as unauthorized access.

## License

MIT.
