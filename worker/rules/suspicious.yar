rule suspicious_api_calls {
    meta:
        description = "Detects suspicious Windows API calls"
        author = "MalScan"
        severity = "medium"
    strings:
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx" ascii
        $api5 = "RtlCreateUserThread" ascii
        $api6 = "VirtualProtect" ascii
        $api7 = "LoadLibrary" ascii
        $api8 = "GetProcAddress" ascii
    condition:
        2 of them
}

rule persistence_registry {
    meta:
        description = "Detects registry persistence mechanisms"
        author = "MalScan"
        severity = "high"
    strings:
        $reg1 = "CurrentVersion\\Run" ascii nocase
        $reg2 = "CurrentVersion\\RunOnce" ascii nocase
        $reg3 = "Winlogon\\Shell" ascii nocase
        $reg4 = "CurrentVersion\\Policies\\Explorer\\Run" ascii nocase
        $reg5 = "CurrentVersion\\Explorer\\Shell Folders" ascii nocase
        $reg6 = "CurrentVersion\\Explorer\\User Shell Folders" ascii nocase
        $reg7 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii nocase
    condition:
        any of them
}

rule suspicious_process_injection {
    meta:
        description = "Detects process injection techniques"
        author = "MalScan"
        severity = "high"
    strings:
        $inject1 = "NtMapViewOfSection" ascii
        $inject2 = "NtUnmapViewOfSection" ascii
        $inject3 = "ZwMapViewOfSection" ascii
        $inject4 = "NtQueueApcThread" ascii
        $inject5 = "SetThreadContext" ascii
        $inject6 = "ResumeThread" ascii
        $inject7 = "SuspendThread" ascii
    condition:
        2 of them
}

rule suspicious_dll_injection {
    meta:
        description = "Detects DLL injection patterns"
        author = "MalScan"
        severity = "high"
    strings:
        $dll1 = "LoadLibraryA" ascii
        $dll2 = "LoadLibraryW" ascii
        $dll3 = "LdrLoadDll" ascii
        $ntdll = "ntdll.dll" ascii nocase
        $kernel32 = "kernel32.dll" ascii nocase
    condition:
        ($dll1 or $dll2 or $dll3) and ($ntdll or $kernel32)
}
