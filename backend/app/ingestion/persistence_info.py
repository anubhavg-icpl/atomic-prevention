"""Persistence-Info ingestor -- Windows persistence mechanism prevention tests.

Catalogs Windows persistence mechanisms based on the persistence-info project
(https://github.com/persistence-info/persistence-info.github.io) and generates
hardcoded, self-contained prevention tests for each technique.

Every test:
  1. Attempts to create a persistence entry (safely, using benign payloads)
  2. Verifies whether the entry was created (ALLOWED) or blocked (BLOCKED)
  3. Cleans up after itself

Data is fully hardcoded -- no external repository clone or API call required
at runtime.  The ``fetch()`` method is a no-op.
"""

import logging
from typing import Any

from backend.app.ingestion.base import BaseIngestor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hardcoded catalog of Windows persistence mechanisms
# ---------------------------------------------------------------------------
# Each entry describes a persistence technique with one or more concrete test
# variants.  Fields:
#
#   id           - unique slug for this mechanism
#   name         - human-readable name
#   description  - what the persistence mechanism does
#   technique_id - primary MITRE ATT&CK technique ID
#   technique_ids - all relevant MITRE technique IDs
#   reference    - URL for the persistence-info page
#   variants     - list of test variant dicts, each with:
#       variant_name   - variant identifier
#       executor       - "cmd" | "powershell"
#       elevation      - whether admin/SYSTEM is required
#       risk_level     - "low" | "medium" | "high"
#       command        - the test command (create persistence + check)
#       cleanup        - cleanup command to remove the persistence entry
#       description    - what this specific variant tests
# ---------------------------------------------------------------------------

_PERSISTENCE_CATALOG: list[dict[str, Any]] = [
    # ======================================================================
    # 1. Registry Run Keys (HKCU)
    # ======================================================================
    {
        "id": "reg-run-hkcu",
        "name": "Registry Run Key (HKCU)",
        "description": (
            "Adds a value to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            "so that a program executes every time the current user logs on. This is "
            "one of the most common persistence mechanisms used by malware and "
            "adversaries because it requires no elevation."
        ),
        "technique_id": "T1547.001",
        "technique_ids": ["T1547.001", "T1112"],
        "reference": "https://persistence-info.github.io/Data/run.html",
        "variants": [
            {
                "variant_name": "reg.exe add",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                    '/v AtomicPreventionPersistTest /t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f '
                    '&& reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v AtomicPreventionPersistTest >nul 2>&1 '
                    "&& (echo ALLOWED: HKCU Run key created successfully) "
                    "|| (echo BLOCKED: HKCU Run key creation was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                    "/v AtomicPreventionPersistTest /f 2>nul"
                ),
                "description": (
                    "Uses reg.exe to add a Run key under HKCU for the current user. "
                    "Security controls should detect or block unauthorized Run key modifications."
                ),
            },
            {
                "variant_name": "PowerShell Set-ItemProperty",
                "executor": "powershell",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$regPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'; "
                    "try { "
                    "Set-ItemProperty -Path $regPath -Name 'AtomicPreventionPersistTestPS' "
                    "-Value 'C:\\Windows\\System32\\calc.exe' -ErrorAction Stop; "
                    "$val = Get-ItemProperty -Path $regPath -Name 'AtomicPreventionPersistTestPS' -ErrorAction Stop; "
                    "if ($val) { Write-Host 'ALLOWED: HKCU Run key created via PowerShell' } "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
                    "-Name 'AtomicPreventionPersistTestPS' -Force -ErrorAction SilentlyContinue\""
                ),
                "description": (
                    "Uses PowerShell Set-ItemProperty to create a Run key under HKCU. "
                    "Tests whether PowerShell-based registry modification is monitored or blocked."
                ),
            },
        ],
    },
    # ======================================================================
    # 2. Registry Run Keys (HKLM) -- requires elevation
    # ======================================================================
    {
        "id": "reg-run-hklm",
        "name": "Registry Run Key (HKLM)",
        "description": (
            "Adds a value to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            "so that a program executes for ALL users at logon. Requires administrator "
            "privileges. Machine-wide persistence is higher impact than per-user."
        ),
        "technique_id": "T1547.001",
        "technique_ids": ["T1547.001", "T1112"],
        "reference": "https://persistence-info.github.io/Data/run.html",
        "variants": [
            {
                "variant_name": "reg.exe add (HKLM)",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                    '/v AtomicPreventionPersistTest /t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f '
                    '&& reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v AtomicPreventionPersistTest >nul 2>&1 '
                    "&& (echo ALLOWED: HKLM Run key created successfully) "
                    "|| (echo BLOCKED: HKLM Run key creation was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                    "/v AtomicPreventionPersistTest /f 2>nul"
                ),
                "description": (
                    "Uses reg.exe to add a machine-wide Run key under HKLM. "
                    "Requires admin. Tests whether elevated registry persistence is blocked."
                ),
            },
        ],
    },
    # ======================================================================
    # 3. Registry RunOnce Keys
    # ======================================================================
    {
        "id": "reg-runonce",
        "name": "Registry RunOnce Key",
        "description": (
            "Adds a value to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce "
            "which executes once at the next logon and then auto-deletes. Commonly used "
            "by malware for one-shot execution that leaves fewer forensic artifacts."
        ),
        "technique_id": "T1547.001",
        "technique_ids": ["T1547.001", "T1112"],
        "reference": "https://persistence-info.github.io/Data/runonce.html",
        "variants": [
            {
                "variant_name": "reg.exe add RunOnce",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" '
                    '/v AtomicPreventionPersistTest /t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f '
                    '&& reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v AtomicPreventionPersistTest >nul 2>&1 '
                    "&& (echo ALLOWED: RunOnce key created successfully) "
                    "|| (echo BLOCKED: RunOnce key creation was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" '
                    "/v AtomicPreventionPersistTest /f 2>nul"
                ),
                "description": (
                    "Creates a RunOnce registry entry that fires at next logon. "
                    "Tests whether security controls monitor single-use persistence entries."
                ),
            },
        ],
    },
    # ======================================================================
    # 4. Scheduled Task
    # ======================================================================
    {
        "id": "schtask-persist",
        "name": "Scheduled Task Persistence",
        "description": (
            "Creates a Windows Scheduled Task that runs at logon or on a schedule. "
            "Scheduled tasks are a favored persistence mechanism because they support "
            "complex triggers and can run as SYSTEM."
        ),
        "technique_id": "T1053.005",
        "technique_ids": ["T1053.005"],
        "reference": "https://persistence-info.github.io/Data/scheduledtasks.html",
        "variants": [
            {
                "variant_name": "schtasks /create (user context)",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    'schtasks /create /tn "AtomicPreventionPersistTest" /tr "C:\\Windows\\System32\\calc.exe" '
                    "/sc onlogon /f "
                    '&& schtasks /query /tn "AtomicPreventionPersistTest" >nul 2>&1 '
                    "&& (echo ALLOWED: Scheduled task created successfully) "
                    "|| (echo BLOCKED: Scheduled task creation was prevented)"
                ),
                "cleanup": (
                    'schtasks /delete /tn "AtomicPreventionPersistTest" /f 2>nul'
                ),
                "description": (
                    "Uses schtasks.exe to create a task triggered at user logon. "
                    "Tests whether task creation is blocked by application control or EDR."
                ),
            },
            {
                "variant_name": "schtasks /create (SYSTEM context)",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'schtasks /create /tn "AtomicPreventionPersistTestSys" '
                    '/tr "C:\\Windows\\System32\\calc.exe" '
                    "/sc onstart /ru SYSTEM /f "
                    '&& schtasks /query /tn "AtomicPreventionPersistTestSys" >nul 2>&1 '
                    "&& (echo ALLOWED: SYSTEM scheduled task created successfully) "
                    "|| (echo BLOCKED: SYSTEM scheduled task creation was prevented)"
                ),
                "cleanup": (
                    'schtasks /delete /tn "AtomicPreventionPersistTestSys" /f 2>nul'
                ),
                "description": (
                    "Creates a scheduled task that runs as SYSTEM at boot. "
                    "Requires elevation. Tests detection of high-privilege persistence."
                ),
            },
            {
                "variant_name": "PowerShell Register-ScheduledTask",
                "executor": "powershell",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$action = New-ScheduledTaskAction -Execute 'calc.exe'; "
                    "$trigger = New-ScheduledTaskTrigger -AtLogOn; "
                    "try { "
                    "Register-ScheduledTask -TaskName 'AtomicPreventionPersistTestPS' "
                    "-Action $action -Trigger $trigger -ErrorAction Stop | Out-Null; "
                    "Write-Host 'ALLOWED: Scheduled task created via PowerShell' "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "Unregister-ScheduledTask -TaskName 'AtomicPreventionPersistTestPS' "
                    "-Confirm:$false -ErrorAction SilentlyContinue\""
                ),
                "description": (
                    "Uses PowerShell Register-ScheduledTask cmdlet to create persistence. "
                    "Tests whether PowerShell-based task scheduling is monitored."
                ),
            },
        ],
    },
    # ======================================================================
    # 5. Windows Service Creation
    # ======================================================================
    {
        "id": "service-persist",
        "name": "Windows Service Persistence",
        "description": (
            "Creates a new Windows service that starts automatically at boot. "
            "Services run in Session 0 and can run as SYSTEM, making them a "
            "powerful persistence mechanism."
        ),
        "technique_id": "T1543.003",
        "technique_ids": ["T1543.003"],
        "reference": "https://persistence-info.github.io/Data/services.html",
        "variants": [
            {
                "variant_name": "sc.exe create",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'sc create AtomicPreventionPersistTestSvc binPath= "C:\\Windows\\System32\\calc.exe" '
                    "start= auto "
                    "&& sc query AtomicPreventionPersistTestSvc >nul 2>&1 "
                    "&& (echo ALLOWED: Windows service created successfully) "
                    "|| (echo BLOCKED: Windows service creation was prevented)"
                ),
                "cleanup": (
                    "sc stop AtomicPreventionPersistTestSvc 2>nul & "
                    "sc delete AtomicPreventionPersistTestSvc 2>nul"
                ),
                "description": (
                    "Uses sc.exe to create an auto-start service. Requires elevation. "
                    "Tests whether unauthorized service installation is blocked."
                ),
            },
            {
                "variant_name": "PowerShell New-Service",
                "executor": "powershell",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "try { "
                    "New-Service -Name 'AtomicPreventionPersistTestSvcPS' "
                    "-BinaryPathName 'C:\\Windows\\System32\\calc.exe' "
                    "-DisplayName 'AtomicPrevention Persistence Test' "
                    "-StartupType Automatic -ErrorAction Stop | Out-Null; "
                    "Write-Host 'ALLOWED: Windows service created via PowerShell' "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "Stop-Service -Name 'AtomicPreventionPersistTestSvcPS' -Force -ErrorAction SilentlyContinue; "
                    "sc.exe delete AtomicPreventionPersistTestSvcPS 2>$null\""
                ),
                "description": (
                    "Uses PowerShell New-Service to install a persistent service. "
                    "Tests whether the PowerShell service creation path is monitored."
                ),
            },
        ],
    },
    # ======================================================================
    # 6. WMI Event Subscription
    # ======================================================================
    {
        "id": "wmi-event-subscription",
        "name": "WMI Event Subscription",
        "description": (
            "Creates a permanent WMI event subscription (filter + consumer + binding) "
            "that triggers a command when a system event occurs. WMI subscriptions "
            "survive reboots and are notoriously difficult to detect without "
            "dedicated WMI monitoring."
        ),
        "technique_id": "T1546.003",
        "technique_ids": ["T1546.003"],
        "reference": "https://persistence-info.github.io/Data/wmieventsubscription.html",
        "variants": [
            {
                "variant_name": "PowerShell WMI Event Subscription",
                "executor": "powershell",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$filterName = 'AtomicPreventionPersistFilter'; "
                    "$consumerName = 'AtomicPreventionPersistConsumer'; "
                    "try { "
                    "$filter = Set-WmiInstance -Namespace 'root\\subscription' "
                    "-Class '__EventFilter' -Arguments @{ "
                    "Name = $filterName; "
                    "EventNamespace = 'root\\cimv2'; "
                    "QueryLanguage = 'WQL'; "
                    "Query = 'SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                    "WHERE TargetInstance ISA \\\"Win32_PerfFormattedData_PerfOS_System\\\" "
                    "AND TargetInstance.SystemUpTime >= 120' "
                    "} -ErrorAction Stop; "
                    "$consumer = Set-WmiInstance -Namespace 'root\\subscription' "
                    "-Class 'CommandLineEventConsumer' -Arguments @{ "
                    "Name = $consumerName; "
                    "CommandLineTemplate = 'cmd.exe /c echo AtomicPrevention_WMI_Test > %TEMP%\\\\wmi_persist_test.txt' "
                    "} -ErrorAction Stop; "
                    "$null = Set-WmiInstance -Namespace 'root\\subscription' "
                    "-Class '__FilterToConsumerBinding' -Arguments @{ "
                    "Filter = $filter; Consumer = $consumer "
                    "} -ErrorAction Stop; "
                    "Write-Host 'ALLOWED: WMI event subscription created successfully' "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "Get-WmiObject -Namespace 'root\\subscription' -Class '__FilterToConsumerBinding' | "
                    "Where-Object { $_.Filter -like '*AtomicPreventionPersistFilter*' } | "
                    "Remove-WmiObject -ErrorAction SilentlyContinue; "
                    "Get-WmiObject -Namespace 'root\\subscription' -Class 'CommandLineEventConsumer' | "
                    "Where-Object { $_.Name -eq 'AtomicPreventionPersistConsumer' } | "
                    "Remove-WmiObject -ErrorAction SilentlyContinue; "
                    "Get-WmiObject -Namespace 'root\\subscription' -Class '__EventFilter' | "
                    "Where-Object { $_.Name -eq 'AtomicPreventionPersistFilter' } | "
                    "Remove-WmiObject -ErrorAction SilentlyContinue; "
                    "Remove-Item -Path $env:TEMP\\\\wmi_persist_test.txt -Force -ErrorAction SilentlyContinue\""
                ),
                "description": (
                    "Creates a full WMI event subscription chain (filter, consumer, binding) "
                    "using PowerShell. This is a fileless persistence method that survives reboots."
                ),
            },
        ],
    },
    # ======================================================================
    # 7. Startup Folder
    # ======================================================================
    {
        "id": "startup-folder",
        "name": "Startup Folder",
        "description": (
            "Places a file or shortcut in the user's Startup folder "
            "(shell:startup) so it executes at logon. Simple but effective "
            "persistence that requires no registry changes."
        ),
        "technique_id": "T1547.001",
        "technique_ids": ["T1547.001"],
        "reference": "https://persistence-info.github.io/Data/startupfolder.html",
        "variants": [
            {
                "variant_name": "Copy to Startup folder (user)",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    'echo @echo off > "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AtomicPreventionPersistTest.bat" '
                    '&& echo echo AtomicPrevention Persistence Test >> "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AtomicPreventionPersistTest.bat" '
                    '&& if exist "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AtomicPreventionPersistTest.bat" '
                    "(echo ALLOWED: Startup folder persistence created) "
                    "else (echo BLOCKED: Startup folder write was prevented)"
                ),
                "cleanup": (
                    'del /f "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AtomicPreventionPersistTest.bat" 2>nul'
                ),
                "description": (
                    "Drops a batch file into the current user's Startup folder. "
                    "Tests whether file creation in Startup directories is monitored."
                ),
            },
            {
                "variant_name": "Copy to Startup folder (all users)",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'echo @echo off > "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AtomicPreventionPersistTest.bat" '
                    '&& echo echo AtomicPrevention Persistence Test >> "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AtomicPreventionPersistTest.bat" '
                    '&& if exist "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AtomicPreventionPersistTest.bat" '
                    "(echo ALLOWED: All-users Startup folder persistence created) "
                    "else (echo BLOCKED: All-users Startup folder write was prevented)"
                ),
                "cleanup": (
                    'del /f "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\AtomicPreventionPersistTest.bat" 2>nul'
                ),
                "description": (
                    "Drops a batch file into the common (all users) Startup folder. "
                    "Requires elevation. Tests machine-wide startup persistence."
                ),
            },
        ],
    },
    # ======================================================================
    # 8. DLL Search Order Hijacking
    # ======================================================================
    {
        "id": "dll-search-order-hijack",
        "name": "DLL Search Order Hijacking",
        "description": (
            "Plants a malicious DLL in a location that gets loaded before the "
            "legitimate one due to the Windows DLL search order. Targets writable "
            "directories that appear earlier in the search path than System32."
        ),
        "technique_id": "T1574.001",
        "technique_ids": ["T1574.001"],
        "reference": "https://persistence-info.github.io/Data/dllsearchorderhijacking.html",
        "variants": [
            {
                "variant_name": "DLL drop in application directory",
                "executor": "powershell",
                "elevation": False,
                "risk_level": "high",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$testDir = Join-Path $env:TEMP 'AtomicPreventionDLLTest'; "
                    "New-Item -ItemType Directory -Path $testDir -Force | Out-Null; "
                    "$dllPath = Join-Path $testDir 'version.dll'; "
                    "try { "
                    "[System.IO.File]::WriteAllText($dllPath, 'AtomicPrevention DLL hijack test placeholder'); "
                    "if (Test-Path $dllPath) { "
                    "Write-Host 'ALLOWED: DLL written to' $dllPath '- search order hijack possible' "
                    "} else { "
                    "Write-Host 'BLOCKED: DLL creation was prevented' } "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "Remove-Item -Path (Join-Path $env:TEMP 'AtomicPreventionDLLTest') "
                    "-Recurse -Force -ErrorAction SilentlyContinue\""
                ),
                "description": (
                    "Creates a test DLL (non-functional placeholder) in a temp directory "
                    "to validate whether endpoint security detects DLL drop operations. "
                    "Real attacks would use a compiled DLL targeting a specific application."
                ),
            },
        ],
    },
    # ======================================================================
    # 9. COM Object Hijacking
    # ======================================================================
    {
        "id": "com-object-hijack",
        "name": "COM Object Hijacking",
        "description": (
            "Hijacks a COM object by creating or modifying a CLSID entry in "
            "HKCU\\Software\\Classes\\CLSID to point to an attacker-controlled DLL "
            "or script. The HKCU hive takes precedence over HKLM, enabling "
            "user-level COM hijacking without elevation."
        ),
        "technique_id": "T1546.015",
        "technique_ids": ["T1546.015"],
        "reference": "https://persistence-info.github.io/Data/comhijacking.html",
        "variants": [
            {
                "variant_name": "HKCU CLSID InProcServer32 hijack",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "high",
                "command": (
                    'reg add "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32" '
                    '/t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f '
                    '&& reg query "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\\InprocServer32" >nul 2>&1 '
                    "&& (echo ALLOWED: COM object hijack CLSID entry created) "
                    "|| (echo BLOCKED: COM object hijack was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}" /f 2>nul'
                ),
                "description": (
                    "Hijacks a known COM CLSID by writing an InprocServer32 entry to HKCU. "
                    "The CLSID {b5f8350b-0548-48b1-a6ee-88bd00b4a5e7} is commonly targeted. "
                    "Tests detection of registry-based COM hijacking."
                ),
            },
            {
                "variant_name": "PowerShell COM hijack via ScriptletURL",
                "executor": "powershell",
                "elevation": False,
                "risk_level": "high",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$clsid = '{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}'; "
                    "$regPath = \\\"HKCU:\\Software\\Classes\\CLSID\\$clsid\\InprocServer32\\\"; "
                    "try { "
                    "New-Item -Path $regPath -Force | Out-Null; "
                    "Set-ItemProperty -Path $regPath -Name '(Default)' "
                    "-Value 'C:\\Windows\\System32\\scrobj.dll' -ErrorAction Stop; "
                    "Set-ItemProperty -Path $regPath -Name 'ThreadingModel' "
                    "-Value 'Both' -ErrorAction Stop; "
                    "New-ItemProperty -Path $regPath -Name 'ScriptletURL' "
                    "-Value 'https://example.com/test.sct' -PropertyType String -Force -ErrorAction Stop | Out-Null; "
                    "Write-Host 'ALLOWED: COM hijack with ScriptletURL created' "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "Remove-Item -Path 'HKCU:\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}' "
                    "-Recurse -Force -ErrorAction SilentlyContinue\""
                ),
                "description": (
                    "Creates a COM hijack with ScriptletURL pointing to an SCT file "
                    "(scrobj.dll as InprocServer32). Tests detection of scriptlet-based "
                    "COM persistence."
                ),
            },
        ],
    },
    # ======================================================================
    # 10. Winlogon Helper DLL
    # ======================================================================
    {
        "id": "winlogon-helper",
        "name": "Winlogon Helper DLL",
        "description": (
            "Modifies Winlogon registry keys (Shell, Userinit, Notify) to load "
            "a malicious DLL or executable during the Windows logon process. "
            "These keys are processed by winlogon.exe, which runs as SYSTEM."
        ),
        "technique_id": "T1547.004",
        "technique_ids": ["T1547.004"],
        "reference": "https://persistence-info.github.io/Data/winlogon.html",
        "variants": [
            {
                "variant_name": "Winlogon Shell modification",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" '
                    '/v Shell /t REG_SZ /d "explorer.exe, calc.exe" /f '
                    '&& reg query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell '
                    '| findstr /i "calc.exe" >nul 2>&1 '
                    "&& (echo ALLOWED: Winlogon Shell key modified to include calc.exe) "
                    "|| (echo BLOCKED: Winlogon Shell modification was prevented)"
                ),
                "cleanup": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" '
                    '/v Shell /t REG_SZ /d "explorer.exe" /f 2>nul'
                ),
                "description": (
                    "Appends calc.exe to the Winlogon Shell value so it launches alongside "
                    "explorer.exe at logon. Tests detection of Winlogon Shell tampering."
                ),
            },
            {
                "variant_name": "Winlogon Userinit modification",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" '
                    '/v Userinit /t REG_SZ /d "C:\\Windows\\System32\\userinit.exe,C:\\Windows\\System32\\calc.exe," /f '
                    '&& reg query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit '
                    '| findstr /i "calc.exe" >nul 2>&1 '
                    "&& (echo ALLOWED: Winlogon Userinit modified to include calc.exe) "
                    "|| (echo BLOCKED: Winlogon Userinit modification was prevented)"
                ),
                "cleanup": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" '
                    '/v Userinit /t REG_SZ /d "C:\\Windows\\System32\\userinit.exe," /f 2>nul'
                ),
                "description": (
                    "Appends calc.exe to the Winlogon Userinit value. Userinit.exe is "
                    "executed by winlogon.exe after user authentication. "
                    "Tests detection of Userinit tampering."
                ),
            },
        ],
    },
    # ======================================================================
    # 11. AppInit DLLs
    # ======================================================================
    {
        "id": "appinit-dlls",
        "name": "AppInit DLLs",
        "description": (
            "Configures the AppInit_DLLs registry value to inject a DLL into "
            "every process that loads user32.dll. This is a classic persistence "
            "and injection technique. Modern Windows versions require the DLL to "
            "be code-signed when Secure Boot is enabled."
        ),
        "technique_id": "T1546.010",
        "technique_ids": ["T1546.010"],
        "reference": "https://persistence-info.github.io/Data/appinitdlls.html",
        "variants": [
            {
                "variant_name": "AppInit_DLLs registry value",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" '
                    '/v AppInit_DLLs /t REG_SZ /d "C:\\Windows\\Temp\\AtomicPreventionTest.dll" /f '
                    '&& reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" '
                    "/v LoadAppInit_DLLs /t REG_DWORD /d 1 /f "
                    '&& reg query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs '
                    '| findstr /i "AtomicPreventionTest" >nul 2>&1 '
                    "&& (echo ALLOWED: AppInit_DLLs registry value set) "
                    "|| (echo BLOCKED: AppInit_DLLs modification was prevented)"
                ),
                "cleanup": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" '
                    '/v AppInit_DLLs /t REG_SZ /d "" /f 2>nul '
                    '&& reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" '
                    "/v LoadAppInit_DLLs /t REG_DWORD /d 0 /f 2>nul"
                ),
                "description": (
                    "Sets AppInit_DLLs to a test path and enables LoadAppInit_DLLs. "
                    "Tests whether the system allows DLL injection configuration changes. "
                    "On Secure Boot systems, unsigned DLLs will be rejected at load time."
                ),
            },
        ],
    },
    # ======================================================================
    # 12. Image File Execution Options (IFEO) Debugger
    # ======================================================================
    {
        "id": "ifeo-debugger",
        "name": "Image File Execution Options Debugger",
        "description": (
            "Sets a Debugger value under an Image File Execution Options (IFEO) "
            "registry key so that launching the target executable actually launches "
            "the 'debugger' instead. Commonly used to hijack accessibility tools "
            "(sethc.exe, utilman.exe) for backdoor access at the lock screen."
        ),
        "technique_id": "T1546.012",
        "technique_ids": ["T1546.012"],
        "reference": "https://persistence-info.github.io/Data/ifeo.html",
        "variants": [
            {
                "variant_name": "IFEO debugger for notepad.exe",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" '
                    '/v Debugger /t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f '
                    '&& reg query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /v Debugger >nul 2>&1 '
                    "&& (echo ALLOWED: IFEO debugger set for notepad.exe) "
                    "|| (echo BLOCKED: IFEO debugger creation was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /f 2>nul'
                ),
                "description": (
                    "Sets an IFEO Debugger for notepad.exe so launching Notepad actually "
                    "launches calc.exe. Uses a benign target to test detection safely. "
                    "Real attacks target sethc.exe/utilman.exe for lock-screen backdoors."
                ),
            },
            {
                "variant_name": "IFEO debugger for sethc.exe (Sticky Keys backdoor)",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" '
                    '/v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f '
                    '&& reg query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger >nul 2>&1 '
                    "&& (echo ALLOWED: Sticky Keys backdoor IFEO set - sethc.exe will launch cmd.exe) "
                    "|| (echo BLOCKED: Sticky Keys IFEO backdoor was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /f 2>nul'
                ),
                "description": (
                    "Creates the classic Sticky Keys backdoor by setting an IFEO debugger "
                    "for sethc.exe (Sticky Keys) to cmd.exe. This gives a SYSTEM shell at "
                    "the Windows lock screen. A high-value detection for any security team."
                ),
            },
        ],
    },
    # ======================================================================
    # 13. Logon Script (UserInitMprLogonScript)
    # ======================================================================
    {
        "id": "logon-script",
        "name": "Logon Script (UserInitMprLogonScript)",
        "description": (
            "Sets the UserInitMprLogonScript environment variable in the registry "
            "to execute a script at user logon. This legacy mechanism is often "
            "overlooked by security tools but is well-documented in persistence "
            "research."
        ),
        "technique_id": "T1037.001",
        "technique_ids": ["T1037.001"],
        "reference": "https://persistence-info.github.io/Data/logonscript.html",
        "variants": [
            {
                "variant_name": "UserInitMprLogonScript registry",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    'reg add "HKCU\\Environment" /v UserInitMprLogonScript /t REG_SZ '
                    '/d "C:\\Windows\\System32\\calc.exe" /f '
                    '&& reg query "HKCU\\Environment" /v UserInitMprLogonScript >nul 2>&1 '
                    "&& (echo ALLOWED: Logon script persistence set via UserInitMprLogonScript) "
                    "|| (echo BLOCKED: Logon script persistence was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKCU\\Environment" /v UserInitMprLogonScript /f 2>nul'
                ),
                "description": (
                    "Sets the UserInitMprLogonScript value in the HKCU Environment key. "
                    "This causes the specified program to run at every user logon. "
                    "Does not require elevation."
                ),
            },
        ],
    },
    # ======================================================================
    # 14. Screensaver Persistence
    # ======================================================================
    {
        "id": "screensaver-persist",
        "name": "Screensaver Persistence",
        "description": (
            "Configures a malicious screensaver (.scr) by modifying registry keys "
            "under HKCU\\Control Panel\\Desktop. The screensaver binary runs when "
            "the screen locks, providing an unusual but effective persistence vector."
        ),
        "technique_id": "T1546.002",
        "technique_ids": ["T1546.002"],
        "reference": "https://persistence-info.github.io/Data/screensaver.html",
        "variants": [
            {
                "variant_name": "Screensaver registry modification",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    'reg add "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /t REG_SZ '
                    '/d "C:\\Windows\\System32\\calc.exe" /f '
                    '&& reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f '
                    '&& reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeout /t REG_SZ /d 60 /f '
                    '&& reg query "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE '
                    '| findstr /i "calc.exe" >nul 2>&1 '
                    "&& (echo ALLOWED: Screensaver persistence set to calc.exe) "
                    "|| (echo BLOCKED: Screensaver modification was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /f 2>nul '
                    '&& reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d 0 /f 2>nul'
                ),
                "description": (
                    "Sets the screensaver to calc.exe and enables it with a 60-second timeout. "
                    "Tests whether screensaver-based persistence is detected."
                ),
            },
        ],
    },
    # ======================================================================
    # 15. Registry Load (Hive Loading)
    # ======================================================================
    {
        "id": "registry-load-hive",
        "name": "Registry Hive Load (reg load)",
        "description": (
            "Uses reg.exe to load an offline registry hive, enabling offline "
            "modification of another user's or the system's registry. Adversaries "
            "use this to plant persistence in hives that aren't currently mounted."
        ),
        "technique_id": "T1112",
        "technique_ids": ["T1112"],
        "reference": "https://persistence-info.github.io/Data/registryhive.html",
        "variants": [
            {
                "variant_name": "Load offline registry hive",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg save HKCU\\Software "%TEMP%\\AtomicPreventionHiveTest.hiv" /y >nul 2>&1 '
                    '&& reg load HKLM\\AtomicPreventionHiveTest "%TEMP%\\AtomicPreventionHiveTest.hiv" '
                    "&& (echo ALLOWED: Registry hive loaded successfully to HKLM\\AtomicPreventionHiveTest) "
                    "|| (echo BLOCKED: Registry hive load was prevented)"
                ),
                "cleanup": (
                    "reg unload HKLM\\AtomicPreventionHiveTest 2>nul & "
                    'del /f "%TEMP%\\AtomicPreventionHiveTest.hiv" 2>nul'
                ),
                "description": (
                    "Saves the current user's Software hive to disk, then loads it under "
                    "HKLM as a test. Detects whether offline hive manipulation is monitored."
                ),
            },
        ],
    },
    # ======================================================================
    # 16. Netsh Helper DLL
    # ======================================================================
    {
        "id": "netsh-helper-dll",
        "name": "Netsh Helper DLL",
        "description": (
            "Registers a DLL as a Netsh helper. Every time netsh.exe runs, it "
            "loads all registered helper DLLs, enabling persistent code execution "
            "through a legitimate system tool."
        ),
        "technique_id": "T1546.007",
        "technique_ids": ["T1546.007"],
        "reference": "https://persistence-info.github.io/Data/netshhelper.html",
        "variants": [
            {
                "variant_name": "Netsh add helper registry key",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\Software\\Microsoft\\NetSh" /v AtomicPreventionTest '
                    '/t REG_SZ /d "C:\\Windows\\Temp\\AtomicPreventionHelper.dll" /f '
                    '&& reg query "HKLM\\Software\\Microsoft\\NetSh" /v AtomicPreventionTest >nul 2>&1 '
                    "&& (echo ALLOWED: Netsh helper DLL registered in registry) "
                    "|| (echo BLOCKED: Netsh helper DLL registration was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\Software\\Microsoft\\NetSh" /v AtomicPreventionTest /f 2>nul'
                ),
                "description": (
                    "Registers a test DLL as a Netsh helper by adding a registry entry. "
                    "The DLL does not need to exist for the registry test to succeed. "
                    "Tests detection of Netsh persistence mechanism."
                ),
            },
        ],
    },
    # ======================================================================
    # 17. Print Monitor
    # ======================================================================
    {
        "id": "print-monitor",
        "name": "Print Monitor Persistence",
        "description": (
            "Registers a DLL as a Windows print monitor by adding a registry key "
            "under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors. "
            "The DLL is loaded by the spoolsv.exe (Print Spooler) service, "
            "which runs as SYSTEM."
        ),
        "technique_id": "T1547.010",
        "technique_ids": ["T1547.010"],
        "reference": "https://persistence-info.github.io/Data/printmonitor.html",
        "variants": [
            {
                "variant_name": "Print Monitor registry key",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\AtomicPreventionTest" '
                    '/v Driver /t REG_SZ /d "C:\\Windows\\Temp\\AtomicPreventionMonitor.dll" /f '
                    '&& reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\AtomicPreventionTest" /v Driver >nul 2>&1 '
                    "&& (echo ALLOWED: Print Monitor DLL registered) "
                    "|| (echo BLOCKED: Print Monitor registration was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\AtomicPreventionTest" /f 2>nul'
                ),
                "description": (
                    "Registers a test DLL as a Print Monitor. The Print Spooler loads "
                    "all registered monitor DLLs at startup as SYSTEM. Tests detection "
                    "of print subsystem abuse."
                ),
            },
        ],
    },
    # ======================================================================
    # 18. Security Support Provider (SSP)
    # ======================================================================
    {
        "id": "security-support-provider",
        "name": "Security Support Provider (SSP)",
        "description": (
            "Registers a DLL as a Security Support Provider by adding it to the "
            "Security Packages registry value. SSP DLLs are loaded by lsass.exe "
            "at boot, giving access to plaintext credentials as they are "
            "authenticated."
        ),
        "technique_id": "T1547.005",
        "technique_ids": ["T1547.005"],
        "reference": "https://persistence-info.github.io/Data/ssp.html",
        "variants": [
            {
                "variant_name": "SSP registry addition",
                "executor": "powershell",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
                    "try { "
                    "$current = (Get-ItemProperty -Path $regPath -Name 'Security Packages' -ErrorAction Stop).'Security Packages'; "
                    "if ($current -notcontains 'AtomicPreventionTestSSP') { "
                    "$new = $current + 'AtomicPreventionTestSSP'; "
                    "Set-ItemProperty -Path $regPath -Name 'Security Packages' -Value $new -ErrorAction Stop; "
                    "Write-Host 'ALLOWED: SSP added to Security Packages list' "
                    "} else { Write-Host 'SSP already present' } "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
                    "$current = (Get-ItemProperty -Path $regPath -Name 'Security Packages' -ErrorAction SilentlyContinue).'Security Packages'; "
                    "if ($current) { "
                    "$new = $current | Where-Object { $_ -ne 'AtomicPreventionTestSSP' }; "
                    "Set-ItemProperty -Path $regPath -Name 'Security Packages' -Value $new -ErrorAction SilentlyContinue }\""
                ),
                "description": (
                    "Adds a test SSP name to the Security Packages list in the LSA registry. "
                    "At next boot, lsass.exe would attempt to load this DLL. "
                    "Tests detection of LSASS credential interception persistence."
                ),
            },
        ],
    },
    # ======================================================================
    # 19. Authentication Package
    # ======================================================================
    {
        "id": "authentication-package",
        "name": "Authentication Package",
        "description": (
            "Registers a custom authentication package DLL that is loaded by "
            "lsass.exe at boot time. Similar to SSPs but loaded through the "
            "Authentication Packages registry value."
        ),
        "technique_id": "T1547.002",
        "technique_ids": ["T1547.002"],
        "reference": "https://persistence-info.github.io/Data/authenticationpackage.html",
        "variants": [
            {
                "variant_name": "Authentication Package registry addition",
                "executor": "powershell",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
                    "try { "
                    "$current = (Get-ItemProperty -Path $regPath -Name 'Authentication Packages' -ErrorAction Stop).'Authentication Packages'; "
                    "if ($current -notcontains 'AtomicPreventionTestAuth') { "
                    "$new = $current + 'AtomicPreventionTestAuth'; "
                    "Set-ItemProperty -Path $regPath -Name 'Authentication Packages' -Value $new -ErrorAction Stop; "
                    "Write-Host 'ALLOWED: Authentication Package added to LSA registry' "
                    "} else { Write-Host 'Auth package already present' } "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "$regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'; "
                    "$current = (Get-ItemProperty -Path $regPath -Name 'Authentication Packages' -ErrorAction SilentlyContinue).'Authentication Packages'; "
                    "if ($current) { "
                    "$new = $current | Where-Object { $_ -ne 'AtomicPreventionTestAuth' }; "
                    "Set-ItemProperty -Path $regPath -Name 'Authentication Packages' -Value $new -ErrorAction SilentlyContinue }\""
                ),
                "description": (
                    "Adds a test authentication package to the LSA Authentication Packages "
                    "registry value. Tests detection of LSASS persistence via custom "
                    "authentication providers."
                ),
            },
        ],
    },
    # ======================================================================
    # 20. Time Provider
    # ======================================================================
    {
        "id": "time-provider",
        "name": "Time Provider Persistence",
        "description": (
            "Registers a DLL as a Windows Time Service (W32Time) time provider. "
            "Time provider DLLs are loaded by svchost.exe running the W32Time "
            "service, providing persistence through an often-overlooked mechanism."
        ),
        "technique_id": "T1547.003",
        "technique_ids": ["T1547.003"],
        "reference": "https://persistence-info.github.io/Data/timeprovider.html",
        "variants": [
            {
                "variant_name": "Time Provider registry key",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\AtomicPreventionTest" '
                    '/v DllName /t REG_SZ /d "C:\\Windows\\Temp\\AtomicPreventionTime.dll" /f '
                    '&& reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\AtomicPreventionTest" '
                    "/v Enabled /t REG_DWORD /d 1 /f "
                    '&& reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\AtomicPreventionTest" /v DllName >nul 2>&1 '
                    "&& (echo ALLOWED: Time Provider DLL registered) "
                    "|| (echo BLOCKED: Time Provider registration was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\AtomicPreventionTest" /f 2>nul'
                ),
                "description": (
                    "Registers a test DLL as a W32Time time provider. The Windows Time "
                    "service loads registered provider DLLs, enabling persistence through "
                    "this rarely-monitored service."
                ),
            },
        ],
    },
    # ======================================================================
    # 21. Office Application Startup (Test macro template)
    # ======================================================================
    {
        "id": "office-startup",
        "name": "Office Application Startup",
        "description": (
            "Modifies the Office Trusted Location or startup folder to load "
            "a template or add-in when Office applications start. Can also "
            "abuse the XLSTART folder or Word STARTUP folder for persistence."
        ),
        "technique_id": "T1137.001",
        "technique_ids": ["T1137.001"],
        "reference": "https://persistence-info.github.io/Data/officestartup.html",
        "variants": [
            {
                "variant_name": "Word STARTUP folder drop",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    'if not exist "%APPDATA%\\Microsoft\\Word\\STARTUP" mkdir "%APPDATA%\\Microsoft\\Word\\STARTUP" '
                    '&& echo AtomicPrevention Persistence Test > "%APPDATA%\\Microsoft\\Word\\STARTUP\\AtomicPreventionTest.txt" '
                    '&& if exist "%APPDATA%\\Microsoft\\Word\\STARTUP\\AtomicPreventionTest.txt" '
                    "(echo ALLOWED: File dropped in Word STARTUP folder) "
                    "else (echo BLOCKED: Word STARTUP folder write was prevented)"
                ),
                "cleanup": (
                    'del /f "%APPDATA%\\Microsoft\\Word\\STARTUP\\AtomicPreventionTest.txt" 2>nul'
                ),
                "description": (
                    "Drops a test file into the Word STARTUP directory. Real attacks "
                    "would use a .dotm template with macros. Tests whether file "
                    "creation in Office startup directories is monitored."
                ),
            },
        ],
    },
    # ======================================================================
    # 22. BITS Jobs Persistence
    # ======================================================================
    {
        "id": "bits-job-persist",
        "name": "BITS Job Persistence",
        "description": (
            "Creates a Background Intelligent Transfer Service (BITS) job with "
            "a notification command. BITS jobs survive reboots and can be "
            "configured to execute a command upon completion, providing a "
            "stealthy persistence mechanism."
        ),
        "technique_id": "T1197",
        "technique_ids": ["T1197"],
        "reference": "https://persistence-info.github.io/Data/bitsjobs.html",
        "variants": [
            {
                "variant_name": "BITS job with notification command",
                "executor": "cmd",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    'bitsadmin /create /download AtomicPreventionPersistTest '
                    "&& bitsadmin /addfile AtomicPreventionPersistTest "
                    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt "
                    '"%TEMP%\\AtomicPreventionBITS.txt" '
                    "&& bitsadmin /setnotifycmdline AtomicPreventionPersistTest "
                    'C:\\Windows\\System32\\calc.exe "" '
                    "&& bitsadmin /resume AtomicPreventionPersistTest "
                    "&& bitsadmin /info AtomicPreventionPersistTest /verbose >nul 2>&1 "
                    "&& (echo ALLOWED: BITS job with notification command created) "
                    "|| (echo BLOCKED: BITS job creation was prevented)"
                ),
                "cleanup": (
                    "bitsadmin /cancel AtomicPreventionPersistTest 2>nul & "
                    'del /f "%TEMP%\\AtomicPreventionBITS.txt" 2>nul'
                ),
                "description": (
                    "Creates a BITS download job with a notification command (calc.exe). "
                    "When the download completes, BITS executes the notification command. "
                    "Tests detection of BITS-based persistence."
                ),
            },
        ],
    },
    # ======================================================================
    # 23. Windows Management Instrumentation (WMI) Provider
    # ======================================================================
    {
        "id": "wmi-provider",
        "name": "WMI Provider Registration",
        "description": (
            "Registers a custom WMI provider by adding registry entries under "
            "HKLM\\SOFTWARE\\Classes\\CLSID. WMI providers are loaded by the "
            "WMI service (svchost.exe) and can execute arbitrary code."
        ),
        "technique_id": "T1546.003",
        "technique_ids": ["T1546.003"],
        "reference": "https://persistence-info.github.io/Data/wmiprovider.html",
        "variants": [
            {
                "variant_name": "WMI Provider CLSID registration",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\SOFTWARE\\Classes\\CLSID\\{a1b2c3d4-e5f6-7890-abcd-ef1234567890}\\InprocServer32" '
                    '/t REG_SZ /d "C:\\Windows\\Temp\\AtomicPreventionWMIProv.dll" /f '
                    '&& reg query "HKLM\\SOFTWARE\\Classes\\CLSID\\{a1b2c3d4-e5f6-7890-abcd-ef1234567890}\\InprocServer32" >nul 2>&1 '
                    "&& (echo ALLOWED: WMI Provider CLSID registered) "
                    "|| (echo BLOCKED: WMI Provider CLSID registration was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\SOFTWARE\\Classes\\CLSID\\{a1b2c3d4-e5f6-7890-abcd-ef1234567890}" /f 2>nul'
                ),
                "description": (
                    "Registers a test CLSID with an InprocServer32 pointing to a test DLL. "
                    "Tests whether new WMI provider registration is detected."
                ),
            },
        ],
    },
    # ======================================================================
    # 24. Active Setup
    # ======================================================================
    {
        "id": "active-setup",
        "name": "Active Setup Persistence",
        "description": (
            "Creates an Active Setup registry entry under "
            "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components. "
            "Active Setup entries run once per user at logon, making this useful "
            "for machine-wide persistence that executes in each user context."
        ),
        "technique_id": "T1547.014",
        "technique_ids": ["T1547.014"],
        "reference": "https://persistence-info.github.io/Data/activesetup.html",
        "variants": [
            {
                "variant_name": "Active Setup registry key",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\AtomicPreventionTest" '
                    '/v StubPath /t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f '
                    '&& reg query "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\AtomicPreventionTest" /v StubPath >nul 2>&1 '
                    "&& (echo ALLOWED: Active Setup persistence entry created) "
                    "|| (echo BLOCKED: Active Setup persistence was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\AtomicPreventionTest" /f 2>nul'
                ),
                "description": (
                    "Creates an Active Setup entry with a StubPath that runs calc.exe. "
                    "Active Setup runs once per user profile, providing unique machine-wide "
                    "persistence. Tests detection of Active Setup abuse."
                ),
            },
        ],
    },
    # ======================================================================
    # 25. PowerShell Profile Persistence
    # ======================================================================
    {
        "id": "powershell-profile",
        "name": "PowerShell Profile Persistence",
        "description": (
            "Modifies the PowerShell profile script so that malicious commands "
            "execute every time a PowerShell session starts. Profiles exist at "
            "user level and machine level."
        ),
        "technique_id": "T1546.013",
        "technique_ids": ["T1546.013"],
        "reference": "https://persistence-info.github.io/Data/powershellprofile.html",
        "variants": [
            {
                "variant_name": "User PowerShell profile modification",
                "executor": "powershell",
                "elevation": False,
                "risk_level": "medium",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$profilePath = $PROFILE.CurrentUserAllHosts; "
                    "$backupPath = \\\"$profilePath.atomicprevention.bak\\\"; "
                    "$testLine = '# AtomicPrevention Persistence Test - Write-Host AtomicPreventionPersistenceActive'; "
                    "try { "
                    "if (Test-Path $profilePath) { Copy-Item $profilePath $backupPath -Force }; "
                    "Add-Content -Path $profilePath -Value $testLine -ErrorAction Stop; "
                    "$content = Get-Content $profilePath -Raw -ErrorAction Stop; "
                    "if ($content -match 'AtomicPreventionPersistenceActive') { "
                    "Write-Host 'ALLOWED: PowerShell profile persistence line added' "
                    "} else { Write-Host 'BLOCKED: Profile modification failed' } "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "$profilePath = $PROFILE.CurrentUserAllHosts; "
                    "$backupPath = \\\"$profilePath.atomicprevention.bak\\\"; "
                    "if (Test-Path $backupPath) { "
                    "Copy-Item $backupPath $profilePath -Force; "
                    "Remove-Item $backupPath -Force "
                    "} elseif (Test-Path $profilePath) { "
                    "$content = Get-Content $profilePath | Where-Object { $_ -notmatch 'AtomicPreventionPersistenceActive' }; "
                    "if ($content) { Set-Content $profilePath $content } "
                    "else { Remove-Item $profilePath -Force } }\""
                ),
                "description": (
                    "Appends a test line to the user's PowerShell profile. Backs up "
                    "the existing profile first for safe cleanup. Tests whether "
                    "profile-based persistence is monitored."
                ),
            },
        ],
    },
    # ======================================================================
    # 26. Accessibility Feature Backdoor (utilman.exe)
    # ======================================================================
    {
        "id": "accessibility-features",
        "name": "Accessibility Features Backdoor",
        "description": (
            "Replaces or redirects accessibility programs (utilman.exe, osk.exe, "
            "narrator.exe, magnify.exe) to cmd.exe using IFEO or direct "
            "replacement. These programs can be triggered from the lock screen "
            "without authentication."
        ),
        "technique_id": "T1546.008",
        "technique_ids": ["T1546.008"],
        "reference": "https://persistence-info.github.io/Data/accessibilityfeatures.html",
        "variants": [
            {
                "variant_name": "Utilman IFEO debugger backdoor",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe" '
                    '/v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f '
                    '&& reg query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe" /v Debugger >nul 2>&1 '
                    "&& (echo ALLOWED: Utility Manager backdoor via IFEO created) "
                    "|| (echo BLOCKED: Utilman IFEO backdoor was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe" /f 2>nul'
                ),
                "description": (
                    "Creates an IFEO debugger for utilman.exe (Utility Manager) pointing "
                    "to cmd.exe. This allows launching a SYSTEM command prompt from the "
                    "Windows lock screen by pressing Win+U."
                ),
            },
        ],
    },
    # ======================================================================
    # 27. AppCert DLLs
    # ======================================================================
    {
        "id": "appcert-dlls",
        "name": "AppCert DLLs",
        "description": (
            "Configures AppCertDLLs registry value to inject a DLL into every "
            "process that calls Win32 API functions like CreateProcess, "
            "CreateProcessAsUser, etc. Similar to AppInit DLLs but targets "
            "process creation APIs."
        ),
        "technique_id": "T1546.009",
        "technique_ids": ["T1546.009"],
        "reference": "https://persistence-info.github.io/Data/appcertdlls.html",
        "variants": [
            {
                "variant_name": "AppCertDLLs registry value",
                "executor": "cmd",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs" '
                    '/v AtomicPreventionTest /t REG_SZ /d "C:\\Windows\\Temp\\AtomicPreventionAppCert.dll" /f '
                    '&& reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs" /v AtomicPreventionTest >nul 2>&1 '
                    "&& (echo ALLOWED: AppCertDLLs entry created) "
                    "|| (echo BLOCKED: AppCertDLLs modification was prevented)"
                ),
                "cleanup": (
                    'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs" /v AtomicPreventionTest /f 2>nul'
                ),
                "description": (
                    "Adds a test DLL path to the AppCertDLLs registry key. DLLs listed "
                    "here are loaded into every process that calls CreateProcess and related "
                    "Win32 APIs. Tests detection of this DLL injection persistence method."
                ),
            },
        ],
    },
    # ======================================================================
    # 28. Port Monitor
    # ======================================================================
    {
        "id": "port-monitor",
        "name": "Port Monitor Persistence",
        "description": (
            "Registers a DLL as a port monitor under "
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors. "
            "Port monitors are loaded by spoolsv.exe (running as SYSTEM) and "
            "provide persistent, elevated code execution."
        ),
        "technique_id": "T1547.010",
        "technique_ids": ["T1547.010"],
        "reference": "https://persistence-info.github.io/Data/portmonitor.html",
        "variants": [
            {
                "variant_name": "Port Monitor registry entry via PowerShell",
                "executor": "powershell",
                "elevation": True,
                "risk_level": "high",
                "command": (
                    "powershell.exe -NoProfile -Command \""
                    "$monPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\AtomicPreventionPortMon'; "
                    "try { "
                    "New-Item -Path $monPath -Force | Out-Null; "
                    "Set-ItemProperty -Path $monPath -Name 'Driver' "
                    "-Value 'C:\\Windows\\Temp\\AtomicPreventionPortMon.dll' -ErrorAction Stop; "
                    "Write-Host 'ALLOWED: Port Monitor DLL registered' "
                    "} catch { Write-Host 'BLOCKED:' $_.Exception.Message }\""
                ),
                "cleanup": (
                    "powershell.exe -NoProfile -Command \""
                    "Remove-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\AtomicPreventionPortMon' "
                    "-Recurse -Force -ErrorAction SilentlyContinue\""
                ),
                "description": (
                    "Registers a test DLL as a Print Spooler port monitor using PowerShell. "
                    "Port monitors run in the context of spoolsv.exe (SYSTEM). "
                    "Tests detection of print subsystem persistence."
                ),
            },
        ],
    },
]


class PersistenceInfoIngestor(BaseIngestor):
    """Ingestor for persistence-info -- hardcoded Windows persistence tests.

    All persistence mechanism data is embedded directly in this module.
    No external repository clone or network fetch is required.  The
    ``fetch()`` method is intentionally a no-op.

    Each catalog entry produces one or more prevention tests that attempt
    to create a persistence mechanism, verify whether it succeeded, and
    clean up afterward.
    """

    @property
    def source_id(self) -> str:
        return "persistence-info"

    @property
    def display_name(self) -> str:
        return "Persistence-Info"

    @property
    def description(self) -> str:
        return (
            "Windows persistence mechanism prevention tests based on the "
            "persistence-info project. Tests registry Run keys, scheduled "
            "tasks, services, WMI subscriptions, COM hijacking, IFEO, "
            "AppInit DLLs, and 20+ other persistence techniques."
        )

    @property
    def repo_url(self) -> str:
        return "https://github.com/persistence-info/persistence-info.github.io"

    @property
    def platform(self) -> str:
        return "windows"

    # ------------------------------------------------------------------
    # Fetch: no-op -- all data is hardcoded
    # ------------------------------------------------------------------
    async def fetch(self) -> None:
        """No-op. Persistence test data is fully hardcoded in this module."""
        pass

    # ------------------------------------------------------------------
    # Parse: build prevention tests from the hardcoded catalog
    # ------------------------------------------------------------------
    async def parse(self) -> list[dict]:
        """Build prevention test dicts from the hardcoded persistence catalog."""
        tests: list[dict] = []

        for entry in _PERSISTENCE_CATALOG:
            entry_id = entry["id"]
            entry_name = entry["name"]
            entry_desc = entry["description"]
            technique_id = entry["technique_id"]
            technique_ids = entry.get("technique_ids", [technique_id])
            reference = entry.get("reference", "")

            for variant in entry["variants"]:
                variant_name = variant["variant_name"]
                test_name = f"Persistence: {entry_name} - {variant_name}"

                tests.append({
                    "name": test_name,
                    "description": (
                        f"{variant['description']} "
                        f"[{entry_desc[:300]}]"
                    ).strip(),
                    "command": variant["command"],
                    "executor": variant["executor"],
                    "technique_id": technique_id,
                    "technique_ids": technique_ids,
                    "binary_path": None,
                    "elevation_required": variant["elevation"],
                    "risk_level": variant["risk_level"],
                    "platforms": ["windows"],
                    "cleanup_command": variant["cleanup"],
                    "metadata": {
                        "source": "persistence-info",
                        "mechanism_id": entry_id,
                        "mechanism_name": entry_name,
                        "variant": variant_name,
                        "reference": reference,
                        "mitre_techniques": {
                            tid: self._technique_name(tid)
                            for tid in technique_ids
                        },
                    },
                    "guidance": {
                        "what_this_tests": (
                            f"Attempts to create {entry_name} persistence via "
                            f"{variant_name} and checks whether security controls "
                            f"block the operation."
                        ),
                        "if_blocked": (
                            f"Your security controls blocked {entry_name} "
                            f"persistence via {variant_name}. This persistence "
                            f"vector is covered."
                        ),
                        "if_allowed": (
                            f"ALLOWED: {entry_name} persistence was created via "
                            f"{variant_name}. Review your EDR/endpoint policies "
                            f"to detect or prevent this persistence mechanism."
                        ),
                        "mitre_reference": (
                            f"https://attack.mitre.org/techniques/"
                            f"{technique_id.replace('.', '/')}/"
                        ),
                    },
                })

        logger.info(
            "Persistence-Info: built %d persistence prevention tests from %d mechanisms",
            len(tests),
            len(_PERSISTENCE_CATALOG),
        )
        self._tests = tests
        return tests

    # ------------------------------------------------------------------
    # MITRE mappings
    # ------------------------------------------------------------------
    def get_mitre_mappings(self) -> dict[str, list[str]]:
        """Return mapping of test names to MITRE technique IDs."""
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            name = test.get("name", "")
            tids = test.get("technique_ids", [])
            if not tids:
                tid = test.get("technique_id", "")
                tids = [tid] if tid else []
            if tids:
                mappings.setdefault(name, []).extend(tids)
        return mappings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _technique_name(tid: str) -> str:
        """Return a human-readable name for well-known technique IDs."""
        names = {
            "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            "T1547.002": "Boot or Logon Autostart Execution: Authentication Package",
            "T1547.003": "Boot or Logon Autostart Execution: Time Providers",
            "T1547.004": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
            "T1547.005": "Boot or Logon Autostart Execution: Security Support Provider",
            "T1547.010": "Boot or Logon Autostart Execution: Port Monitors",
            "T1547.014": "Boot or Logon Autostart Execution: Active Setup",
            "T1053.005": "Scheduled Task/Job: Scheduled Task",
            "T1543.003": "Create or Modify System Process: Windows Service",
            "T1546.002": "Event Triggered Execution: Screensaver",
            "T1546.003": "Event Triggered Execution: WMI Event Subscription",
            "T1546.007": "Event Triggered Execution: Netsh Helper DLL",
            "T1546.008": "Event Triggered Execution: Accessibility Features",
            "T1546.009": "Event Triggered Execution: AppCert DLLs",
            "T1546.010": "Event Triggered Execution: AppInit DLLs",
            "T1546.012": "Event Triggered Execution: Image File Execution Options Injection",
            "T1546.013": "Event Triggered Execution: PowerShell Profile",
            "T1546.015": "Event Triggered Execution: Component Object Model Hijacking",
            "T1574.001": "Hijack Execution Flow: DLL Search Order Hijacking",
            "T1037.001": "Boot or Logon Initialization Scripts: Logon Script (Windows)",
            "T1197": "BITS Jobs",
            "T1112": "Modify Registry",
            "T1137.001": "Office Application Startup: Office Template Macros",
        }
        return names.get(tid, tid)
