# Day 30 - Unified Persistence Triage Report (`persistreport`)

`persistreport` is a final consolidation utility that ingests multiple persistence artifact files and produces a single markdown triage report.

This is intended as a practical capstone for Days 18-30: combine outputs and raw exports from registry, tasks, services, and WMI investigations into one analyst-friendly summary.

## Features

- Multi-file analysis in one run
- Automatic artifact-type hints (`registry`, `task_xml`, `service_text`, `wmi`, `generic`)
- Shared weighted scoring heuristics across all files
- Per-file score + verdict (`LOW` / `MEDIUM` / `HIGH`)
- Consolidated "Top Signals" section
- Markdown report output for case notes

## Build

```powershell
zig build-exe .\persistreport.zig -target x86_64-windows-gnu -O ReleaseSmall -fstrip -femit-bin="persistreport.exe"
```

## Usage

```powershell
.\persistreport.exe [--out report.md] <artifact-file> [more-files...]
```

## Example

```powershell
.\persistreport.exe --out day30_report.md ..\Day Twenty Seven\suspect.reg ..\Day Twenty Eight\wmi_suspect.txt ..\Day Twenty Six\task_sample.xml
```

## Output

Creates a markdown report containing:

- overall risk and total score
- per-file summary table
- ranked top signals

Also prints high-level stats to stdout.

## Notes

- This is static triage and can produce false positives.
- Treat HIGH as "priority for deeper analysis," not direct malware proof.
