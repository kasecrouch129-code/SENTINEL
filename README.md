# SENTINEL — repository setup in progress

> The documentation is published. The source package still needs to be uploaded before these commands can run from this repository.

# SENTINEL 4.0 — offline threat hunting workbench

Windows 10/11 first; Linux support for compatible collectors. Python 3.11+ (64-bit Python recommended on 64-bit Windows). Runs locally with no AI, APIs, keys, telemetry, reputation queries or sample execution. Scans are read-only by default, not an antivirus replacement. An explicitly enabled containment mode can rename a known-malware file in a dedicated user folder; it never deletes files, suspends processes, injects code, or blocks execution. Reports contain sensitive paths and indicators; store privately.

## Getting started

Extract the ZIP into a new folder. Open Command Prompt in the folder containing `sentinel/` and `QuickScan.cmd`. Run `Doctor.cmd` to check installed modules. For the full recommended offline setup, bring trusted wheels for your Python version, operating system and architecture into a `wheelhouse` folder from a separately prepared machine. No wheels or Python interpreter are bundled. Install from that folder only:

```bat
py -3 -m pip install --no-index --find-links=wheelhouse psutil yara-python
```

Additional modules listed in requirements.txt and requirements-extra.txt are optional; install individually from trusted wheels using the same flags. Basic file scanning needs only the standard library; host processes, memory and monitor require psutil. YARA requires yara-python. No Internet is required at runtime. Windows PowerShell and built-in collectors are used for fixed inventory commands. The tool never invokes a scanned file. Do not run as admin from a folder writable by untrusted users; test as a normal user first, and use an elevated terminal only if needed.

## Commands

```bat
py -3 -m sentinel doctor
py -3 -m unittest discover -s tests -v
py -3 -m sentinel file "C:\Users\YourName\Downloads\sample.exe"
py -3 -m sentinel directory "C:\Users\YourName\Downloads" --all-files
py -3 -m sentinel host --memory --require-yara
py -3 -m sentinel host --deep --memory --all-files --max-files 25000 --total-mib 32768 --memory-mib 128 --require-yara
py -3 -m sentinel watch "C:\Users\YourName\Downloads" --interval 5
```

`QuickScan.cmd`, `DeepScan.cmd`, `Watch.cmd`, and `Test.cmd` are conveniences. Watch runs in the foreground; Ctrl+C stops. Linux uses `python3 -m sentinel` in place of `py -3`.

## New in 4.0

- Desktop GUI (standard-library Tkinter, no local web server). Run `GUI.cmd` or `py -3 -m sentinel gui`. Quick/deep, file/folder, watch, dependency checks, and reports. Stop terminates the scan; an interrupted report may not be saved.
- 44 source-attributed hash indicators (29 additions) and 25 YARA rules. The four new generic rules are hunting indicators, not proven malware-family signatures. The database is a starter set, not comparable to a commercial antivirus database.
- Add trusted offline feeds as `rules/name.hashes.csv`, with columns `sha256,label,category,source`. Categories: `malware`, `dual-use`, or `unclassified`. Bundled entries take precedence. Never label legitimate tools as confirmed malware. No downloads or automatic feed fetching.
- Repeated cross-view process inventory: Windows Toolhelp snapshots versus psutil; Linux `/proc` versus psutil. Discrepancies are leads only; both views can depend on a compromised kernel.
- Optional local classifier: deterministic logistic regression, trained on your labeled individual-file scan reports. No pre-trained model, no claims of detection accuracy, no external ML service. Classification outputs are advisory and do not trigger containment. Direct hash findings are excluded from classifier features to reduce label leakage.
- Offline corpus evaluation reports true/false positives and negatives, recall, precision, and false-positive rate for your labeled reports. This is not a real-world validation result unless you provide an independent representative corpus.
- Explicit, optional exact-hash containment. Normal watch/scan commands remain read-only. Containment is a rename with a random suffix, not secure storage or a true execution block. Never open a contained file. It does not remove persistence or stop running malware. Use only on a dedicated test/download folder below your home, not system folders or shared/writable-by-others folders. A concurrent file replacement race cannot be completely excluded. Use regular Defender protection instead of relying on this feature.

### Optional containment (VM first)

Create a dedicated folder under your home called `SentinelIntake`. To monitor that folder and rename only exact known-malware SHA-256 matches found there (direct child files only):

```bat
py -3 -m sentinel watch "%USERPROFILE%\SentinelIntake" --contain-known --confirm --interval 2
```

For a single confirmed exact-hash file:

```bat
py -3 -m sentinel contain "%USERPROFILE%\SentinelIntake\suspect.exe" --root "%USERPROFILE%\SentinelIntake" --confirm
```

No heuristic, YARA, or local classifier verdict can trigger containment. Watch polls for changes; it can miss short-lived files and malware that executes before the next poll. Containment refuses unknown hashes, linked files, broad home folders and scanner files. The watch report records actions; single-file mode prints the original path, renamed path and hash. No automatic restoration is supplied.

### Local training and validation

Create a CSV manifest with columns `report,label`, where report paths point to completed individual-file JSON scan reports and labels are `benign` or `malware`. Obtain labels independently. Do not execute malware. Train on one set and evaluate using a separate representative set. Minimum five examples per class is a code guard only, not adequate training. Model scores are uncalibrated, and no pretrained model is bundled.

```bat
py -3 -m sentinel train training.csv model.json
py -3 -m sentinel classify sample-report.json model.json
py -3 -m sentinel evaluate validation.csv
```

`evaluate` measures high/critical scanner findings, not the optional classifier. The classifier's real-world efficacy has not been established.

## Previous release: 3.0

- 21 bundled YARA rules (eight new generic hunting rules, not confirmed malware signatures); the same 15 source-attributed hash indicators from v2.
- ZIP and GZIP member scanning in memory, including nested archives, member SHA-256, local hash/YARA checks, executable and script heuristics, and IOC extraction. No extraction to disk, even for path traversal names. Maximum 64 members per outer container, 2 MiB per member, 8 MiB expanded bytes per outer container, 128 MiB expanded bytes across a scan, and two unpacking levels. Encrypted, oversized, unsupported or malformed contents are explicitly marked partial. RAR and 7z are recognized but not unpacked.
- Limited direct PDF FlateDecode stream inspection for embedded active-content names. Not a full PDF parser; indirect filters, encryption, other encodings, complex object layouts and compressed content outside the sampled area may be missed.
- Coverage-gap accounting in the file scanner and monitoring mode. Missing optional engines are still listed separately; use `--require-yara` to require YARA.
- Offline baseline comparison: compare SHA-256 digests of files observed in two reports. Use a baseline from a known trusted state, same machine and scan scope. A changed file is not automatically malicious, and a missing observation does not mean a file was deleted.

```bat
py -3 -m sentinel baseline "C:\Reports\known-good.json" "C:\Reports\current.json"
```

In v3 the monitor was polling-based and alert-only. In v4 that is still the default; explicit exact-hash containment is optional. Native parsers run inside the scanner process; archive limits are not a security sandbox. Analyze untrusted samples inside a disposable isolated VM using a normal user account whenever possible.

## What changed from 1.0

| Area | 2.0 behavior |
|---|---|
| Completion | Explicit status and exit codes, including fully skipped files, scan budgets, detector errors and incomplete memory coverage. |
| Indicators | 15 SHA-256 entries from published Microsoft research (9 malware, 6 dual-use incident artifacts), with source and category for each. No malware samples included. This is a small starter list, not a comprehensive signature database. |
| Rules | 13 YARA rules total (3 original + 10 additional), including generic downloader, persistence, tampering, hollowing and memory indicators. Generic rules are not verified family signatures. |
| File coverage | Full-file hashing and streaming patterns (ASCII and UTF-16, 16 KiB overlap). Whole-file YARA when installed. Detailed PE/document parsing uses a bounded sample (32 MiB default), string extraction 8 MiB, script parser 2 MiB, XOR recovery 256 KiB. These limitations are intentional, visible in reports, and cannot detect all encoded/compressed content. |
| False positives | Lone generic high-priority static findings are downgraded when uncorroborated; correlated static signals contribute only once to the risk score. Dual-use hash matches are medium severity. No automatic allowlisting based on digital signatures. |
| Memory | Read-only content inspection of private readable executable regions, plus mapping inventory. Windows ReadProcessMemory; Linux /proc/PID/mem where permitted. Bounded 64 MiB total by default, 8 MiB per PID; process scan time budget 90s between regions. Skips sensitive system processes and itself; doesn't retain raw memory or extract credentials. YARA memory checks are chunk-based and may miss matches crossing chunks. |
| Rootkit hunting | Windows driver paths, boot configuration, Secure Boot and code-integrity event inventory, plus Linux module cross-view. These are user-mode indicators only; cannot verify a compromised kernel or detect every rootkit. Use trusted offline recovery media/Defender Offline for suspected kernel compromise. |
| Performance | Streaming reads, bounded overlap, file/byte/time limits, optional heavy XOR recovery on individual/deep host scans, bounded watch queue. No guaranteed throughput; full disk scans may take substantial time. |
| Monitoring | Foreground polling of new/changed files in selected roots and new process images/command lines, alert-only. Default polling interval 5s; can miss short-lived processes and changes between polls. No kernel driver, on-access prevention, automatic quarantine, or persistent service. |

## Interpreting results

Reports are local HTML, JSON and SQLite under `~/SentinelReports` by default. Reports use escaped HTML and a restrictive content security policy. The score is triage priority, not probability of malware. High priority means investigate, not automatically delete. Never treat no findings as proof a system is clean.

Exit codes: **0** completed within selected scope with no high/critical findings; **2** completed scope with high/critical findings (argument errors also use 2); **3** partial/incomplete, no high/critical findings; **4** partial plus high/critical findings. Unexpected runtime errors exit nonzero. `--require-yara` makes an unavailable YARA engine a partial result. Optional detectors may be unavailable even when a core scan completes; inspect limitations and dependency status. Budget-limited host scans are not whole-system coverage. Reparse points, symlinks, network shares, report directories and selected scope exclusions are not scanned. Windows protected processes and unavailable event logs can cause partial coverage.

## Local rule updates

`rules/hashes.json` maps lower-case hash to `{ "label": "...", "category": "malware" or "dual-use", "source": "..." }`. Add only independently verified indicators. Local `.yar`/`.yara` files are compiled with includes disabled. Do not import untrusted rules; arbitrary rules can consume resources. Restart the scanner after updates. No automatic update/download. The source links in the JSON are references only and never fetched by the scanner. SHA-256 exact matches only; changed variants need other detection layers.

## Testing and limitations

Run `Test.cmd` in a Windows VM first. Tests are harmless fixtures, not live malware. The test suite includes Windows API smoke tests which skip on Linux and optional YARA compile/full-file match tests which skip if yara-python is missing. The prior build-environment run passed 40 tests and skipped 4. GitHub Actions is configured to run harmless fixture tests on Windows and Linux; it has not yet run. Windows APIs, YARA runtime integration and detection efficacy against real malware are not validated in this build environment. Linux inventory and monitoring smoke tests are separate. A trusted OS is assumed. Keep your regular antivirus and real-time protection enabled. The scanner cannot certify a clean system, cannot reliably identify advanced kernel malware, and does not prevent infection.

## v4 validation

44 automated tests collected: 40 passed and 4 skipped (three Windows-only checks and one optional YARA test). Linux inventory smoke test wrote a report and returned partial coverage (exit 3). Tkinter GUI opened and closed successfully using a virtual Linux display. The monitor containment test used a harmless fixture and a synthetic test hash; no real malware was downloaded or executed. Windows runtime, YARA compilation/runtime and real-world detection accuracy remain unverified in this environment. `ValidateWindows.cmd` runs the tests and a GUI smoke test on a Windows PC or VM; it cannot establish real-world detection efficacy. Keep Microsoft Defender enabled. No testing or installation was performed on your PC.
