# File Integrity Checker (FIC)

A small tool that monitors critical system files using SHA-256
(sha256sum-compatible format).

## Features
- Baseline creation in sha256sum format
- Integrity check: modified, missing, new, and errors
- Monitor mode (periodic checks)
- Logging and optional report output
- Exclude patterns for paths you want to skip

## Objective
Detect unauthorized or unexpected changes to important system files and provide a
repeatable, auditable integrity verification process.

## Threat model
- Integrity violations (tampering, replacement, or deletion of critical files)
- Malware that modifies system binaries or configuration files
- Accidental changes by users or software updates (controlled by monitoring policy)

## Design overview
1) Baseline creation:
   - Read target paths from critical_files.txt (files or directories).
   - Compute SHA-256 for each file.
   - Store results in db/baseline.sha256.
2) Integrity check:
   - Recompute hashes and compare with the baseline.
   - Report modified, missing, new, and error states.
3) Monitoring:
   - Periodically run integrity checks and log results.

## Implementation details
- Language: Python 3.8+
- Hashing: hashlib.sha256 (sha256sum-compatible output)
- Storage: db/baseline.sha256 and db/last_scan.sha256
- Exclude patterns: glob-like matching against absolute paths
- Logging: logs/fic.log for audit trail

## Requirements
- Python 3.8+ (stdlib only)

## Quick start (Windows)
1) Copy example lists:
   - critical_files.example.txt -> critical_files.txt
   - exclude.example.txt -> exclude.txt (optional)
2) Edit critical_files.txt (and exclude.txt if used).
3) Initialize baseline:
   python fic.py init
4) Run a check:
   python fic.py check --report reports/report.txt --fail-on-change
5) Start monitoring:
   python fic.py monitor --interval 60

## Common commands
Create baseline:
python fic.py init [listfile] --exclude-file exclude.txt

Check integrity and fail with non-zero exit code if changes are detected:
python fic.py check [listfile] --exclude-file exclude.txt --report reports/report.txt --fail-on-change

Add or remove entries:
python fic.py add <path> [listfile]
python fic.py remove <path> [listfile]

Monitor every 30 seconds:
python fic.py monitor [listfile] --interval 30 --exclude-file exclude.txt

Use external sha256sum if it is available:
python fic.py check --sha256sum

## List file format
- One file or directory per line.
- Lines starting with # are comments.
- Relative paths are resolved relative to the list file location.

## Exclude patterns
Patterns are matched against absolute paths. Use forward slashes in patterns.
Examples:
- **/Temp/**
- **/*.log

## Project files
- fic.py                      Main CLI tool
- critical_files.example.txt  Example list of monitored paths
- exclude.example.txt         Example exclude patterns

## Notes
- Some system files may require administrator permissions to read.
- If critical_files.txt is missing, init/add will create a default list.
- If exclude.txt exists and you do not pass --exclude-file, it is used automatically.
- db/, logs/, reports/, and critical_files.txt are ignored by git by default.
- Hash files are stored in db/baseline.sha256 and db/last_scan.sha256.

## Limitations
- Access to some system files requires administrator permissions.
- Frequent system updates can produce expected changes (policy needed).
- Large directories may increase scan time.

## Future work
- Baseline signing and integrity protection
- Alerts (email, webhook) for detected changes
- Performance optimizations for large file sets

## References
- Python hashlib documentation: https://docs.python.org/3/library/hashlib.html
- sha256sum manual: https://www.gnu.org/software/coreutils/manual/html_node/sha2-utilities.html
