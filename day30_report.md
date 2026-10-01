# Day 30 Persistence Triage Report

Overall risk: **HIGH**
Overall score: **65**
Files analyzed: **4**

## Per-File Summary

| File | Kind | Score | Verdict | Signals |
|---|---|---:|---|---:|
| ..\Day Twenty Seven\suspect.reg | registry | 17 | MEDIUM | 3 |
| ..\Day Twenty Eight\wmi_suspect.txt | wmi | 16 | MEDIUM | 4 |
| ..\Day Twenty Six\task_sample.xml | task_xml | 15 | MEDIUM | 4 |
| ..\Day Twenty Nine\after_snapshot.txt | registry | 17 | MEDIUM | 3 |

## Top Signals

- [S5] ..\Day Twenty Seven\suspect.reg: IFEO debugger indicator
- [S5] ..\Day Twenty Seven\suspect.reg: encoded/deobfuscation marker
- [S5] ..\Day Twenty Eight\wmi_suspect.txt: encoded/deobfuscation marker
- [S5] ..\Day Twenty Six\task_sample.xml: encoded/deobfuscation marker
- [S5] ..\Day Twenty Nine\after_snapshot.txt: IFEO debugger indicator
- [S5] ..\Day Twenty Nine\after_snapshot.txt: encoded/deobfuscation marker
- [S4] ..\Day Twenty Six\task_sample.xml: script/LOLBin execution marker
- [S4] ..\Day Twenty Eight\wmi_suspect.txt: script/LOLBin execution marker
- [S4] ..\Day Twenty Seven\suspect.reg: script/LOLBin execution marker
- [S4] ..\Day Twenty Nine\after_snapshot.txt: script/LOLBin execution marker
- [S4] ..\Day Twenty Eight\wmi_suspect.txt: WMI persistence component triad
- [S3] ..\Day Twenty Six\task_sample.xml: elevated/hidden scheduled task setting
- [S2] ..\Day Twenty Eight\wmi_suspect.txt: startup/process event trigger
- [S2] ..\Day Twenty Six\task_sample.xml: boot/logon trigger
