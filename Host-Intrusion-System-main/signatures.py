KNOWN_MALICIOUS_HASHES = {
    # Example IOC list. Replace with your threat intel feed as needed.
    "31d6cfe0d16ae931b73c59d7e0c089c0",
    "b7e72f20851ee4f7fdbdf5ada23471f8",
    "d41d8cd98f00b204e9800998ecf8427e",
}

FILE_SIGNATURES = r"""
import "pe"

rule malicious_script {
    meta:
        description = "Detects suspicious PowerShell download and execution patterns"
        severity = "high"
    strings:
        $powershell = "powershell" nocase
        $invoke_expression = "Invoke-Expression" nocase
        $iex = "IEX" nocase
        $webclient = "Net.WebClient" nocase
        $download_string = "DownloadString" nocase
        $base64 = "FromBase64String" nocase
        $hidden = /-WindowStyle\s+Hidden/ nocase
    condition:
        ($powershell or $invoke_expression or $iex or $base64) and
        ($download_string and ($invoke_expression or $iex or $webclient) or ($base64 and $hidden))
}

rule obfuscated_script {
    meta:
        description = "Detects obfuscated scripts using encoding, execution wrappers and downloaders"
        severity = "high"
    strings:
        $ps = "powershell" nocase
        $encoded = /-encod(e|ed)command/ nocase
        $base64 = "FromBase64String" nocase
        $download = /(Invoke-WebRequest|wget|curl|Start-BitsTransfer|Invoke-RestMethod)/ nocase
        $exec = /(Invoke-Expression|IEX|Start-Process|cmd\.exe\s*\/c|rundll32|regsvr32|mshta)/ nocase
        $obfus = /(bypass|hidden|nop|repl|downloadstring|downloadfile|shelcode|AmsiScanBuffer)/ nocase
        $wscript = "WScript.Shell" nocase
    condition:
        ($ps and (($encoded and $base64) or ($download and $exec) or ($obfus and $exec))) or
        ($wscript and ($exec or $download))
}

rule suspicious_process_loader {
    meta:
        description = "Detects PE loaders with process injection and remote execution APIs"
        severity = "critical"
    strings:
        $mz = "MZ"
        $virtual_alloc = "VirtualAlloc" nocase wide ascii
        $write_process = "WriteProcessMemory" nocase wide ascii
        $create_thread = "CreateRemoteThread" nocase wide ascii
        $url_download = "URLDownloadToFile" nocase wide ascii
        $winexec = "WinExec" nocase wide ascii
        $internet_open = "InternetOpenA" nocase wide ascii
        $alloc = "NtAllocateVirtualMemory" nocase wide ascii
        $self_delete = "NtUnmapViewOfSection" nocase wide ascii
    condition:
        $mz at 0 and 1 of ($virtual_alloc,$write_process,$create_thread,$url_download,$winexec,$internet_open,$alloc,$self_delete)
}

rule suspicious_macro_document {
    meta:
        description = "Detects malicious VBA macro stubs and script-based persistence"
        severity = "high"
    strings:
        $vba = "VBA" nocase
        $autoopen = "AutoOpen" nocase
        $wscript = "WScript.Shell" nocase
        $cmd = "cmd.exe" nocase
        $powershell = "powershell" nocase
        $download = /https?:\/\// nocase
    condition:
        $vba and (1 of ($autoopen,$wscript,$cmd,$powershell,$download))
}

rule suspicious_executable {
    meta:
        description = "Detects known suspicious executable markers"
        severity = "critical"
    strings:
        $mz = "MZ"
        $s1 = "mimikatz" nocase wide ascii
        $s2 = "cobaltstrike" nocase wide ascii
        $s3 = "empire" nocase wide ascii
        $s4 = "psexec" nocase wide ascii
        $s5 = "rundll32" nocase wide ascii
        $s6 = "meterpreter" nocase wide ascii
    condition:
        $mz at 0 and any of ($s*)
}

rule temp_executable {
    meta:
        description = "Detects executable files with suspicious tool markers"
        severity = "medium"
    strings:
        $mz = "MZ"
        $tool = /(mimikatz|cobaltstrike|empire|meterpreter)/ nocase wide ascii
    condition:
        $mz at 0 and $tool and filesize < 10MB
}

rule trojan_or_ransomware_behavior {
    meta:
        description = "Detects trojan, ransomware and spyware-like behavior indicators"
        severity = "critical"
    strings:
        $ransom = /(ransom|decrypt|encrypt|bitcoin|wallet|restore files|.onion|paybitcoin|readme_for_your_files)/ nocase
        $trojan = /(copy.*startup|autorun|runonce|scheduled task|schtasks|run key|currentversion\\run|service create|wmi.*create|reg add)/ nocase
        $spyware = /(keylogger|clipboard|browser password|read sms|send sms|capture screen|record audio|camera access|steal token|credential)/ nocase
        $dropper = /(certutil|bitsadmin|mshta|powershell.*-enc|powershell.*-nop)/ nocase
    condition:
        any of them
}

rule shellcode_or_dropper {
    meta:
        description = "Detects shellcode stubs and dropper patterns in binary or script payloads"
        severity = "critical"
    strings:
        $shellcode = /\x90\x90\x90\x90\x90\x90|VirtualAlloc|CreateProcessA|WriteProcessMemory|CreateRemoteThread/ nocase
        $dropper = /(certutil|bitsadmin|schtasks|rundll32|regsvr32|mshta|bcdedit|sc\s+create)/ nocase
    condition:
        any of them
}
"""

PROCESS_SIGNATURES = r"""
rule suspicious_process_name_or_command {
    meta:
        description = "Detects known offensive tool names in process metadata"
        severity = "high"
    strings:
        $mimikatz = "mimikatz" nocase
        $bloodhound = "bloodhound" nocase
        $cobaltstrike = "cobaltstrike" nocase
        $empire = "empire" nocase
        $meterpreter = "meterpreter" nocase
        $rundll32 = "rundll32" nocase
        $powershell = "powershell" nocase
        $mshta = "mshta" nocase
        $certutil = "certutil" nocase
        $bitsadmin = "bitsadmin" nocase
    condition:
        any of them
}
"""