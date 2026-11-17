# credhunt

A plaintext credential hunter for post-exploitation enumeration — the kind of
pass you run once you have a foothold and want to find the passwords an admin or
an application left lying around in cleartext (or in a trivially recoverable
form): config files, answer files, the registry, saved sessions, histories,
notes, and service stores.

Two siblings, same job on each OS:

| Script         | Target  | Needs                                   |
| -------------- | ------- | --------------------------------------- |
| `credhunt.sh`  | Linux   | bash + coreutils/grep/find (no PCRE)    |
| `credhunt.ps1` | Windows | PowerShell 5.1 (in-box on Win10/11)     |

Both are dependency-free so they run on minimal or old boxes without installing
anything on the target.

## Design

- **Read-only.** It never modifies the target — no file, registry, service, or
  scheduled-task writes. The only thing it writes is the output file you pass
  explicitly.
- **A locator, not a privesc or dumping tool.** It reports *where* a credential
  is and what the raw value looks like. It does not touch LSASS, decrypt DPAPI
  blobs, or read browser credential stores — use dedicated offline tooling for
  that.
- **Tiered.** Default is a fast sweep of known locations and likely directories;
  a deep mode greps the wider filesystem for credential patterns.

## Usage

Linux:

```sh
./credhunt.sh [-o out.txt] [-q] [-d] [-r /path] [-s KB] [-H N] [-n] [-h]
```

Windows:

```powershell
powershell -ep bypass -f .\credhunt.ps1 [-OutFile out.txt] [-Quick] [-Deep] `
           [-Root D:\mount] [-MaxSizeKB 2048] [-MaxHits 25] [-NoColor]
```

Run `-h` / `Get-Help` for the full option list.

## Authorized use only

For use on systems you own or have **written permission** to test (pentest
engagements, CTFs, lab work, your own machines). You are responsible for how you
use it.
