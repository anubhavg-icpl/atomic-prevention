import asyncio
import json
from pathlib import Path

import yaml

from backend.app.ingestion.base import BaseIngestor


# ---------------------------------------------------------------------------
# Well-known RMM tools with download URLs and Atomic Red Team cross-references
# ---------------------------------------------------------------------------
# These are *legitimate* tools commonly abused by adversaries for persistent
# remote access.  The "test" is whether your security stack blocks an
# unauthorised download + execution — not whether the software itself is
# malicious.
#
# Fields:
#   url          - direct download link (empty string if account required)
#   exe          - expected executable filename after download
#   desc         - one-liner for test descriptions
#   vendor       - legitimate vendor name
#   abuse_reason - why adversaries abuse this tool
#   platforms    - list of supported OS platforms
#   safe_flag    - a flag that makes the binary exit quickly / print help
#   art_guid     - Atomic Red Team auto_generated_guid (if an ART test exists)
#   art_command  - verbatim ART command (when it adds value beyond our default)
#   art_cleanup  - verbatim ART cleanup command
#   account_required - True if download needs an account / custom URL
# ---------------------------------------------------------------------------

_RMM_CATALOG: dict[str, dict] = {
    "AnyDesk": {
        "url": "https://download.anydesk.com/AnyDesk.exe",
        "exe": "AnyDesk.exe",
        "desc": "AnyDesk remote desktop client",
        "vendor": "AnyDesk Software GmbH",
        "abuse_reason": (
            "Lightweight single-binary RMM frequently deployed by ransomware "
            "operators (Conti, Royal, BlackBasta) for hands-on-keyboard access "
            "after initial compromise."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "--help",
        "art_guid": "6b8b7391-5c0a-4f8c-baee-78d8ce0ce330",
        "art_command": (
            'Invoke-WebRequest -OutFile C:\\Users\\$env:username\\Desktop\\AnyDesk.exe '
            'https://download.anydesk.com/AnyDesk.exe\n'
            '$file1 = "C:\\Users\\" + $env:username + "\\Desktop\\AnyDesk.exe"\n'
            'Start-Process $file1 /S;'
        ),
        "art_cleanup": (
            '$file1 = "C:\\Users\\" + $env:username + "\\Desktop\\AnyDesk.exe"\n'
            'Remove-Item $file1 -ErrorAction Ignore'
        ),
        "account_required": False,
    },
    "TeamViewer": {
        "url": "https://download.teamviewer.com/download/TeamViewer_Setup.exe",
        "exe": "TeamViewer_Setup.exe",
        "desc": "TeamViewer remote support & access",
        "vendor": "TeamViewer Germany GmbH",
        "abuse_reason": (
            "One of the most widely-used legitimate RMMs, routinely abused by "
            "APT groups and ransomware affiliates as a stealthy C2 channel "
            "because it blends in with normal enterprise traffic."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "--help",
        "art_guid": "8ca3b96d-8983-4a7f-b125-fc98cc0a2aa0",
        "art_command": (
            'Invoke-WebRequest -OutFile C:\\Users\\$env:username\\Desktop\\TeamViewer_Setup.exe '
            'https://download.teamviewer.com/download/TeamViewer_Setup.exe\n'
            '$file1 = "C:\\Users\\" + $env:username + "\\Desktop\\TeamViewer_Setup.exe"\n'
            'Start-Process -Wait $file1 /S;\n'
            'Start-Process \'C:\\Program Files (x86)\\TeamViewer\\TeamViewer.exe\''
        ),
        "art_cleanup": (
            "$file = 'C:\\Program Files (x86)\\TeamViewer\\uninstall.exe'\n"
            "if(Test-Path $file){ Start-Process $file \"/S\" -ErrorAction Ignore | Out-Null }\n"
            '$file1 = "C:\\Users\\" + $env:username + "\\Desktop\\TeamViewer_Setup.exe"\n'
            "Remove-Item $file1 -ErrorAction Ignore | Out-Null"
        ),
        "account_required": False,
    },
    "ScreenConnect": {
        "url": "",
        "exe": "ScreenConnect.msi",
        "desc": "ConnectWise ScreenConnect (formerly Control) remote support",
        "vendor": "ConnectWise LLC",
        "abuse_reason": (
            "Heavily abused in BEC, ransomware, and tech-support scam campaigns. "
            "Threat actors generate custom agent installers tied to their own "
            "ScreenConnect instance for persistent access."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "--help",
        "art_guid": "4a18cc4e-416f-4966-9a9d-75731c4684c0",
        "art_command": (
            '$installer = "C:\\Users\\$env:username\\Downloads\\ScreenConnect.msi"\n'
            'Invoke-WebRequest -OutFile $installer '
            '"https://d1kuyuqowve5id.cloudfront.net/ScreenConnect_25.1.10.9197_Release.msi"\n'
            'msiexec /i $installer /qn'
        ),
        "art_cleanup": (
            '$installer = "C:\\Users\\$env:username\\Downloads\\ScreenConnect.msi"\n'
            'msiexec /x $installer /qn'
        ),
        "account_required": True,
    },
    "Atera": {
        "url": "",
        "exe": "AteraAgent.msi",
        "desc": "Atera RMM agent",
        "vendor": "Atera Networks Ltd",
        "abuse_reason": (
            "Cloud-based RMM abused by threat actors who register free trial "
            "accounts to generate agent installers. The agent provides full "
            "remote shell, file transfer, and persistence."
        ),
        "platforms": ["windows", "macos"],
        "safe_flag": "--help",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": True,
    },
    "Splashtop": {
        "url": "https://download.splashtop.com/winclient/STP/Splashtop_Personal_Win_v3.6.6.0.exe",
        "exe": "Splashtop_Personal.exe",
        "desc": "Splashtop Personal remote desktop",
        "vendor": "Splashtop Inc.",
        "abuse_reason": (
            "Remote desktop tool abused for persistent access. Some adversaries "
            "deploy the Splashtop Streamer component for unattended access."
        ),
        "platforms": ["windows", "macos"],
        "safe_flag": "/S",
        "art_guid": "b025c580-029e-4023-888d-a42710d76934",
        "art_command": (
            'New-Item -Type Directory "$env:TEMP\\ExternalPayloads\\" -ErrorAction Ignore -Force | Out-Null\n'
            'Invoke-WebRequest -OutFile "$env:TEMP\\ExternalPayloads\\splashtop_install.exe" '
            '"https://download.splashtop.com/winclient/STP/Splashtop_Personal_Win_v3.6.6.0.exe"\n'
            'Start-Process "$env:TEMP\\ExternalPayloads\\splashtop_install.exe" /S'
        ),
        "art_cleanup": 'Stop-Process -Name "strwinclt" -force -erroraction silentlycontinue',
        "account_required": False,
    },
    "RustDesk": {
        "url": "https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-1.3.8-x86_64.exe",
        "exe": "rustdesk.exe",
        "desc": "RustDesk open-source remote desktop",
        "vendor": "RustDesk (open source)",
        "abuse_reason": (
            "Open-source remote desktop with self-hostable relay server. "
            "Adversaries deploy self-hosted RustDesk infrastructure to avoid "
            "vendor takedowns and maintain covert C2 channels."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "--help",
        "art_guid": "f1641ba9-919a-4323-b74f-33372333bf0e",
        "art_command": (
            '$file = Join-Path $env:USERPROFILE "Desktop\\rustdesk-1.2.3-1-x86_64.exe"\n'
            'Invoke-WebRequest -OutFile $file '
            'https://github.com/rustdesk/rustdesk/releases/download/1.2.3-1/rustdesk-1.2.3-1-x86_64.exe\n'
            'Start-Process -FilePath $file "/S"'
        ),
        "art_cleanup": (
            '$file = Join-Path $env:USERPROFILE "Desktop\\rustdesk-1.2.3-1-x86_64.exe"\n'
            'Remove-Item $file -ErrorAction Ignore'
        ),
        "account_required": False,
    },
    "MeshCentral": {
        "url": "https://meshcentral.com/info/tools/MeshAgent64.exe",
        "exe": "MeshAgent64.exe",
        "desc": "MeshCentral open-source remote management agent",
        "vendor": "MeshCentral (open source, formerly Intel AMT)",
        "abuse_reason": (
            "Open-source, self-hostable RMM that gives full remote shell, "
            "file management, and desktop access. Increasingly used by "
            "ransomware affiliates as a free, customisable C2 platform."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "--help",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "TightVNC": {
        "url": "https://www.tightvnc.com/download/2.8.85/tightvnc-2.8.85-gpl-setup-64bit.msi",
        "exe": "tightvnc-setup.msi",
        "desc": "TightVNC open-source VNC remote desktop",
        "vendor": "GlavSoft LLC",
        "abuse_reason": (
            "Lightweight, open-source VNC server/viewer that can be installed "
            "silently. Used by threat actors for remote desktop access where "
            "commercial RMMs would be detected."
        ),
        "platforms": ["windows", "linux"],
        "safe_flag": "",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "UltraVNC": {
        "url": "https://www.uvnc.eu/download/1381/UltraVNC_1_3_81_X64_Setup.exe",
        "exe": "UltraVNC_Setup.exe",
        "desc": "UltraVNC open-source remote access",
        "vendor": "uvnc bvba (open source)",
        "abuse_reason": (
            "Open-source VNC implementation frequently deployed by threat "
            "actors as an alternative to commercial RMMs. Supports silent "
            "installation and can be configured with a pre-set password."
        ),
        "platforms": ["windows"],
        "safe_flag": "/silent",
        "art_guid": "42e51815-a6cc-4c75-b970-3f0ff54b610e",
        "art_command": (
            'New-Item -Type Directory "$env:TEMP\\ExternalPayloads\\" -ErrorAction Ignore -Force | Out-Null\n'
            'Invoke-WebRequest "https://www.uvnc.eu/download/1381/UltraVNC_1_3_81_X64_Setup.exe" '
            '-OutFile "$env:TEMP\\ExternalPayloads\\vncsetup.exe"\n'
            'start-process "$env:TEMP\\ExternalPayloads\\vncsetup.exe" /silent'
        ),
        "art_cleanup": 'Stop-Process -Name "vncviewer" -force -erroraction silentlycontinue',
        "account_required": False,
    },
    "Action1": {
        "url": "https://www.action1.com/download/action1_agent.exe",
        "exe": "action1_agent.exe",
        "desc": "Action1 free endpoint management agent",
        "vendor": "Action1 Corporation",
        "abuse_reason": (
            "Free-tier cloud RMM platform abused by threat actors who create "
            "accounts to generate custom agent installers. Provides remote "
            "shell, patch management, and software deployment."
        ),
        "platforms": ["windows"],
        "safe_flag": "--help",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "SimpleHelp": {
        "url": "https://simple-help.com/releases/SimpleHelp-windows-amd64.exe",
        "exe": "SimpleHelp.exe",
        "desc": "SimpleHelp remote support software",
        "vendor": "SimpleHelp Ltd",
        "abuse_reason": (
            "Self-hosted remote support tool. Adversaries compromise existing "
            "SimpleHelp servers or deploy their own to distribute agents to "
            "victim machines."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "--help",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "Level": {
        "url": "https://updates.level.io/level-windows-amd64.exe",
        "exe": "level.exe",
        "desc": "Level.io RMM agent",
        "vendor": "Level (level.io)",
        "abuse_reason": (
            "Cloud-based RMM platform. Free-tier accounts can be used to "
            "generate agent installers that provide persistent remote access."
        ),
        "platforms": ["windows", "macos"],
        "safe_flag": "--help",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "NetSupport Manager": {
        "url": "https://nsproducts.azureedge.net/nsm-1270/en/Setup.exe",
        "exe": "NetSupport_Setup.exe",
        "desc": "NetSupport Manager remote control",
        "vendor": "NetSupport Ltd",
        "abuse_reason": (
            "Widely abused by threat actors (TA569/SocGholish, TA505, Raspberry Robin). "
            "The client component (client32.exe) is frequently dropped as a "
            "RAT payload because it is a signed, legitimate binary."
        ),
        "platforms": ["windows"],
        "safe_flag": '/S /v/qn',
        "art_guid": "ecca999b-e0c8-40e8-8416-ad320b146a75",
        "art_command": (
            'New-Item -Type Directory "$env:TEMP\\ExternalPayloads\\" -ErrorAction Ignore -Force | Out-Null\n'
            '(New-Object Net.WebClient).DownloadFile('
            '"https://nsproducts.azureedge.net/nsm-1270/en/Setup.exe",'
            '"$env:TEMP\\ExternalPayloads\\T1219_NetSupport.exe")\n'
            'Start-Process "$env:TEMP\\ExternalPayloads\\T1219_NetSupport.exe" -ArgumentList "/S /v/qn"'
        ),
        "art_cleanup": 'Stop-Process -Name "client32" -force -erroraction silentlycontinue',
        "account_required": False,
    },
    "Ammyy Admin": {
        "url": "https://web.archive.org/web/20140625232737/http://www.ammyy.com/AA_v3.exe",
        "exe": "ammyy.exe",
        "desc": "Ammyy Admin remote desktop",
        "vendor": "Ammyy Group",
        "abuse_reason": (
            "Historically one of the most abused RMM tools. Its official "
            "website was compromised multiple times to distribute malware. "
            "Frequently used in tech-support scams and by APT groups."
        ),
        "platforms": ["windows"],
        "safe_flag": "",
        "art_guid": "0ae9e327-3251-465a-a53b-485d4e3f58fa",
        "art_command": (
            'New-Item -Type Directory "$env:TEMP\\ExternalPayloads\\" -ErrorAction Ignore -Force | Out-Null\n'
            'Invoke-WebRequest '
            '"https://web.archive.org/web/20140625232737/http://www.ammyy.com/AA_v3.exe" '
            '-OutFile "$env:TEMP\\ExternalPayloads\\ammyy.exe" -UseBasicParsing\n'
            'Start-Process "$env:TEMP\\ExternalPayloads\\ammyy.exe"'
        ),
        "art_cleanup": 'Stop-Process -Name "Ammyy" -force -erroraction silentlycontinue',
        "account_required": False,
    },
    "DWService": {
        "url": "https://www.dwservice.net/download/dwagent.exe",
        "exe": "dwagent.exe",
        "desc": "DWService open-source remote access",
        "vendor": "DWService (open source)",
        "abuse_reason": (
            "Free, open-source remote access agent. Adversaries create free "
            "DWService accounts and deploy agents to victim machines for "
            "persistent remote shell and file transfer access."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "--help",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "Tactical RMM": {
        "url": "https://github.com/amidaware/tacticalrmm/releases",
        "exe": "tacticalrmm.exe",
        "desc": "Tactical RMM open-source IT management",
        "vendor": "Amidaware (open source)",
        "abuse_reason": (
            "Open-source, self-hosted RMM that provides full remote shell, "
            "script execution, and file management. Increasingly popular "
            "with threat actors due to its self-hosted nature."
        ),
        "platforms": ["windows", "linux"],
        "safe_flag": "--help",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "LogMeIn": {
        "url": "https://secure.logmein.com/LogMeInIgnition.msi",
        "exe": "LogMeInIgnition.msi",
        "desc": "LogMeIn Ignition remote access",
        "vendor": "GoTo (formerly LogMeIn Inc.)",
        "abuse_reason": (
            "Enterprise remote access tool abused for persistent access. "
            "Adversaries install LogMeIn on compromised hosts to maintain "
            "access that blends with legitimate enterprise usage."
        ),
        "platforms": ["windows", "macos"],
        "safe_flag": "/quiet",
        "art_guid": "d03683ec-aae0-42f9-9b4c-534780e0f8e1",
        "art_command": (
            'Invoke-WebRequest -OutFile C:\\Users\\$env:username\\Desktop\\LogMeInIgnition.msi '
            'https://secure.logmein.com/LogMeInIgnition.msi\n'
            '$file1 = "C:\\Users\\" + $env:username + "\\Desktop\\LogMeInIgnition.msi"\n'
            'Start-Process -Wait $file1 /quiet;\n'
            "Start-Process 'C:\\Program Files (x86)\\LogMeIn Ignition\\LMIIgnition.exe' \"/S\""
        ),
        "art_cleanup": (
            "get-package *'LogMeIn Client'* -ErrorAction Ignore | uninstall-package\n"
            '$file1 = "C:\\Users\\" + $env:username + "\\Desktop\\LogMeInIgnition.msi"\n'
            "Remove-Item $file1 -ErrorAction Ignore"
        ),
        "account_required": False,
    },
    "RemotePC": {
        "url": "https://static.remotepc.com/downloads/rpc/140422/RemotePC.exe",
        "exe": "RemotePC.exe",
        "desc": "RemotePC remote desktop access",
        "vendor": "iDrive Inc.",
        "abuse_reason": (
            "Remote access software that can be silently installed. Creates "
            "multiple scheduled tasks for persistence and auto-start."
        ),
        "platforms": ["windows", "macos"],
        "safe_flag": "",
        "art_guid": "fbff3f1f-b0bf-448e-840f-7e1687affdce",
        "art_command": (
            'New-Item -Type Directory "$env:TEMP\\ExternalPayloads\\" -ErrorAction Ignore -Force | Out-Null\n'
            'Invoke-WebRequest "https://static.remotepc.com/downloads/rpc/140422/RemotePC.exe" '
            '-OutFile "$env:TEMP\\ExternalPayloads\\RemotePC.exe" -UseBasicParsing\n'
            'Start-Process "$env:TEMP\\ExternalPayloads\\RemotePC.exe"'
        ),
        "art_cleanup": (
            'Unregister-ScheduledTask -TaskName "RemotePC" -Confirm:$False -ErrorAction SilentlyContinue\n'
            'Unregister-ScheduledTask -TaskName "RPCServiceHealthCheck" -Confirm:$False -ErrorAction SilentlyContinue\n'
            'Stop-Process -Name "RemotePCService" -force -erroraction silentlycontinue\n'
            'Stop-Process -Name "RPCService" -force -erroraction silentlycontinue'
        ),
        "account_required": False,
    },
    "UltraViewer": {
        "url": "https://www.ultraviewer.net/en/UltraViewer_setup_6.5_en.exe",
        "exe": "UltraViewer_setup.exe",
        "desc": "UltraViewer remote support",
        "vendor": "DucFabulous Co., Ltd.",
        "abuse_reason": (
            "Free remote support tool popular in Asia-Pacific. Abused in "
            "tech-support scams and by threat actors as an alternative to "
            "more heavily monitored RMMs."
        ),
        "platforms": ["windows"],
        "safe_flag": "/silent",
        "art_guid": "19acf63b-55c4-4b6a-8552-00a8865105c8",
        "art_command": (
            'New-Item -Type Directory "$env:TEMP\\ExternalPayloads\\" -ErrorAction Ignore -Force | Out-Null\n'
            '(New-Object Net.WebClient).DownloadFile('
            '"https://www.ultraviewer.net/en/UltraViewer_setup_6.5_en.exe",'
            '"$env:TEMP\\ExternalPayloads\\T1219_UltraViewer.exe")\n'
            'Start-Process -Wait -FilePath "$env:TEMP\\ExternalPayloads\\T1219_UltraViewer.exe" '
            '-Argument "/silent" -PassThru\n'
            "Start-Process 'C:\\Program Files (x86)\\UltraViewer\\UltraViewer_Desktop.exe'"
        ),
        "art_cleanup": (
            'Stop-Process -Name "UltraViewer_Desktop" -Force -ErrorAction SilentlyContinue'
        ),
        "account_required": False,
    },
    "GoToAssist": {
        "url": "https://launch.getgo.com/launcher2/helper?token=e0-FaCddxmtMoX8_cY4czssnTeGvy83ihp8CLREfvwQshiBW0_RcbdoaEp8IA-Qn8wpbKlpGIflS-39gW6RuWRM-XHwtkRVMLBsp5RSKp-a3PBM-Pb1Fliy73EDgoaxr-q83WtXbLKqD7-u3cfDl9gKsymmhdkTGsXcDXir90NqKj92LsN_KpyYwV06lIxsdRekhNZjNwhkWrBa_hG8RQJqWSGk6tkZLVMuMufmn37eC2Cqqiwq5bCGnH5dYiSUUsklSedRLjh4N46qPYT1bAU0qD25ZPr-Kvf4Kzu9bT02q3Yntj02ZA99TxL2-SKzgryizoopBPg4Ilfo5t78UxKTYeEwo4etQECfkCRvenkTRlIHmowdbd88zz7NiccXnbHJZehgs6_-JSVjQIdPTXZbF9T5z44mi4BQYMtZAS3DE86F0C3D4Tcd7fa5F6Ve8rQWt7pvqFCYyiJAailslxOw0LsGyFokoy65tMF980ReP8zhVcTKYP8s8mhGXihUQJQPNk20Sw&downloadTrigger=restart&renameFile=1",
        "exe": "GoToAssist.exe",
        "desc": "GoTo Assist (GoTo) remote support",
        "vendor": "GoTo (formerly Citrix/LogMeIn)",
        "abuse_reason": (
            "Remote support tool from the GoTo (LogMeIn) family. Abused for "
            "persistent access and tech-support scams."
        ),
        "platforms": ["windows", "macos"],
        "safe_flag": "/S",
        "art_guid": "1b72b3bd-72f8-4b63-a30b-84e91b9c3578",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "MSP360 Connect": {
        "url": "",
        "exe": "Connect.exe",
        "desc": "MSP360 Connect (formerly CloudBerry) remote access",
        "vendor": "MSP360 (formerly CloudBerry Lab)",
        "abuse_reason": (
            "MSP-focused remote access tool. Can be deployed silently and "
            "provides full remote desktop capabilities."
        ),
        "platforms": ["windows"],
        "safe_flag": "",
        "art_guid": "b1b8128b-c5d4-4de9-bf70-e60419274562",
        "art_command": "",
        "art_cleanup": 'Stop-Process -Name "Connect" -force -erroraction silentlycontinue',
        "account_required": True,
    },
    "Zoho Assist": {
        "url": "",
        "exe": "ZohoAssist.exe",
        "desc": "Zoho Assist remote support and access",
        "vendor": "Zoho Corporation",
        "abuse_reason": (
            "Cloud-based remote support tool. Free tier allows adversaries to "
            "quickly generate agent installers for persistent access."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": True,
    },
    "Supremo": {
        "url": "https://www.supremocontrol.com/downloads/Supremo.exe",
        "exe": "Supremo.exe",
        "desc": "Supremo remote desktop control",
        "vendor": "Nanosystems S.r.l.",
        "abuse_reason": (
            "Italian remote desktop tool. Portable single-binary that can run "
            "without installation, making it attractive for adversaries."
        ),
        "platforms": ["windows"],
        "safe_flag": "",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "Parsec": {
        "url": "https://builds.parsec.app/package/parsec-windows.exe",
        "exe": "parsec-windows.exe",
        "desc": "Parsec remote desktop (gaming-focused)",
        "vendor": "Unity Technologies (Parsec)",
        "abuse_reason": (
            "Low-latency remote desktop designed for gaming. Provides high-quality "
            "interactive remote access that can evade RMM-focused detections."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "HopToDesk": {
        "url": "https://www.hoptodesk.com/download/HopToDesk.exe",
        "exe": "HopToDesk.exe",
        "desc": "HopToDesk free remote desktop",
        "vendor": "HopToDesk",
        "abuse_reason": (
            "Free, portable remote desktop tool. No installation required, "
            "single executable — ideal for adversary quick-deploy scenarios."
        ),
        "platforms": ["windows", "macos", "linux"],
        "safe_flag": "--help",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
    "Remote Utilities": {
        "url": "https://www.remoteutilities.com/download/RUSetup.exe",
        "exe": "RUSetup.exe",
        "desc": "Remote Utilities (RUT) remote access",
        "vendor": "Remote Utilities LLC",
        "abuse_reason": (
            "Remote access tool with a free-for-personal-use tier. Supports "
            "silent/unattended installation with pre-configured settings, "
            "making it useful for adversary deployment."
        ),
        "platforms": ["windows"],
        "safe_flag": "",
        "art_guid": "",
        "art_command": "",
        "art_cleanup": "",
        "account_required": False,
    },
}


class LOLRMMIngestor(BaseIngestor):
    """Ingestor for LOLRMM — Remote Monitoring and Management tool prevention tests.

    LOLRMM data is artifact-oriented (files, registry, network, services), not
    test-oriented. This ingestor generates meaningful prevention tests from those
    artifacts and cross-references them with Atomic Red Team T1219 tests.

    Test categories generated per RMM tool:

    1. **Download & execute prevention** — For tools with known free binaries,
       test if application control blocks download and execution.  Where an
       Atomic Red Team test exists for the same tool, its tested command is
       used instead of a generic template.
    2. **Installation/execution prevention** — Can the RMM executable run?
       Tests application control (AppLocker/WDAC) by checking install paths.
    3. **Service installation prevention** — Can the RMM service be created?
       Tests whether service creation for the tool is blocked.
    4. **Network connectivity prevention** — Can the endpoint reach the RMM C2?
       Tests DNS resolution and connectivity to known RMM domains.
    """

    @property
    def source_id(self) -> str:
        return "lolrmm"

    @property
    def display_name(self) -> str:
        return "LOLRMM"

    @property
    def description(self) -> str:
        return "Living Off The Land Remote Monitoring and Management tools"

    @property
    def repo_url(self) -> str:
        return "https://github.com/magicsword-io/LOLRMM"

    @property
    def platform(self) -> str:
        return "windows"

    # -- fetch -----------------------------------------------------------------

    async def fetch(self) -> None:
        repo_dir = self.data_dir
        if repo_dir.exists():
            proc = await asyncio.create_subprocess_exec(
                "git", "pull", cwd=str(repo_dir),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git pull failed for {self.source_id}: {stderr.decode()}")
        else:
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", self.repo_url, str(repo_dir),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(f"git clone failed for {self.source_id}: {stderr.decode()}")

    # -- parse -----------------------------------------------------------------

    async def parse(self) -> list[dict]:
        tests: list[dict] = []
        yaml_dir = self.data_dir / "yaml"

        # Track which catalog tools we've seen in the LOLRMM YAML data
        seen_catalog_tools: set[str] = set()

        if yaml_dir.exists():
            for yml_file in yaml_dir.rglob("*.yaml"):
                try:
                    data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                    if not data:
                        continue
                    name = data.get("Name", "")
                    if name:
                        seen_catalog_tools.add(name)
                    tests.extend(self._parse_rmm(data))
                except Exception:
                    continue

        # Generate tests for catalog tools not found in LOLRMM YAML data.
        # These are well-known abused RMMs that may not (yet) have a LOLRMM
        # YAML entry but should still be testable.
        for tool_name, catalog in _RMM_CATALOG.items():
            if tool_name in seen_catalog_tools:
                continue
            # Generate a standalone download+execute test from the catalog
            tests.extend(self._generate_catalog_only_tests(tool_name, catalog))

        self._tests = tests
        return tests

    # -- per-tool parsing from LOLRMM YAML ------------------------------------

    def _parse_rmm(self, data: dict) -> list[dict]:
        tests: list[dict] = []
        name = data.get("Name", "")
        description = data.get("Description", "")
        if not name:
            return tests

        details = data.get("Details", {}) or {}
        website = details.get("Website", "")
        supported_os = [s.lower() for s in (details.get("SupportedOS", []) or [])]
        artifacts = data.get("Artifacts", {}) or {}

        # Determine primary technique ID — T1219 for all RMM tools
        technique_id = "T1219"

        # Look up in our catalog for enriched data
        catalog = _RMM_CATALOG.get(name, {})
        vendor = catalog.get("vendor", "")
        abuse_reason = catalog.get("abuse_reason", "")

        # Determine platforms from LOLRMM SupportedOS + catalog
        platforms = self._resolve_platforms(supported_os, catalog)

        # --- Test 0: Download & Execute prevention ----------------------------
        tests.extend(
            self._build_download_execute_test(name, description, website,
                                              technique_id, catalog, platforms,
                                              vendor, abuse_reason)
        )

        # --- Test 1: Installation path / executable prevention ----------------
        tests.extend(
            self._build_execution_test(name, description, website,
                                       technique_id, details, platforms,
                                       vendor, abuse_reason)
        )

        # --- Test 2: Service prevention (if service artifacts exist) ----------
        tests.extend(
            self._build_service_test(name, description, website,
                                     technique_id, artifacts, vendor,
                                     abuse_reason)
        )

        # --- Test 3: Network connectivity prevention --------------------------
        tests.extend(
            self._build_network_test(name, description, website,
                                     technique_id, artifacts, platforms,
                                     vendor, abuse_reason)
        )

        return tests

    # -- test builders ---------------------------------------------------------

    def _build_download_execute_test(
        self, name: str, description: str, website: str,
        technique_id: str, catalog: dict, platforms: list[str],
        vendor: str, abuse_reason: str,
    ) -> list[dict]:
        """Generate a download-and-execute test for tools with known binaries."""
        if not catalog:
            return []

        dl_url = catalog.get("url", "")
        dl_exe = catalog.get("exe", "")
        dl_desc = catalog.get("desc", name)
        safe_flag = catalog.get("safe_flag", "--help")
        art_guid = catalog.get("art_guid", "")
        art_command = catalog.get("art_command", "")
        art_cleanup = catalog.get("art_cleanup", "")
        account_required = catalog.get("account_required", False)

        if not dl_url and not art_command:
            # No direct download and no ART command — generate a note-only test
            if not account_required:
                return []
            return self._build_account_required_test(
                name, description, website, technique_id, catalog,
                platforms, vendor, abuse_reason,
            )

        # Prefer Atomic Red Team command when available (tested, community-validated)
        if art_command:
            command = (
                f"# === LOLRMM + Atomic Red Team: {name} Download & Execute ===\n"
                f"# ART GUID: {art_guid}\n"
                f"# Source: Atomic Red Team T1219 + LOLRMM catalog\n"
                f"# This test downloads and executes {name} to validate that\n"
                f"# application control and endpoint protection prevent\n"
                f"# unauthorized RMM deployment.\n"
                f"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"
                f"{art_command}"
            )
            cleanup = art_cleanup if art_cleanup else None
        else:
            # Generate our standard download+execute+cleanup template
            command = (
                f"# === LOLRMM: {name} Download & Execute Prevention Test ===\n"
                f"# Source: LOLRMM catalog\n"
                f"# This test downloads and attempts to execute {name} to validate\n"
                f"# that your security stack blocks unauthorized RMM deployment.\n"
                f"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"
                f"$outPath = Join-Path $env:TEMP '{dl_exe}'\n"
                f"Write-Host '[*] Downloading {name} from {dl_url}...'\n"
                f"try {{\n"
                f"    Invoke-WebRequest -Uri '{dl_url}' -OutFile $outPath -UseBasicParsing -ErrorAction Stop\n"
                f"}} catch {{\n"
                f"    Write-Host \"BLOCKED: Download failed - $($_.Exception.Message)\"\n"
                f"    exit 0\n"
                f"}}\n"
                f"if (Test-Path $outPath) {{\n"
                f"    $hash = (Get-FileHash -Path $outPath -Algorithm SHA256).Hash\n"
                f"    Write-Host \"[*] Downloaded to: $outPath (SHA256: $hash)\"\n"
                f"    Write-Host '[*] Attempting execution...'\n"
                f"    try {{\n"
                f"        $proc = Start-Process -FilePath $outPath"
            )
            if safe_flag:
                command += f" -ArgumentList '{safe_flag}'"
            command += (
                f" -PassThru -NoNewWindow -ErrorAction Stop\n"
                f"        Start-Sleep -Seconds 5\n"
                f"        if (-not $proc.HasExited) {{ $proc.Kill() }}\n"
                f"        Write-Host 'ALLOWED: {name} executed successfully (PID:' $proc.Id ')'\n"
                f"    }} catch {{\n"
                f"        Write-Host \"BLOCKED: Execution prevented - $($_.Exception.Message)\"\n"
                f"    }}\n"
                f"}} else {{\n"
                f"    Write-Host 'BLOCKED: File not written to disk'\n"
                f"}}"
            )
            cleanup = (
                f"Remove-Item -Path \"$env:TEMP\\{dl_exe}\" -Force -ErrorAction SilentlyContinue"
            )

        test = {
            "name": f"LOLRMM: {name} - Download & Execute ({dl_exe})",
            "description": (
                f"Download and attempt to execute {name} ({dl_desc}). "
                f"This tests whether application control and endpoint protection "
                f"prevent the download, write-to-disk, and execution of an unauthorized "
                f"RMM tool. "
            ),
            "command": command,
            "executor": "powershell",
            "technique_id": technique_id,
            "binary_path": dl_exe,
            "elevation_required": False,
            "risk_level": "high",
            "platforms": platforms,
            "cleanup_command": cleanup,
            "metadata": {
                "rmm_tool": name,
                "vendor": vendor,
                "website": website,
                "test_type": "download_execute",
                "download_url": dl_url,
                "abuse_reason": abuse_reason,
                "art_guid": art_guid or None,
                "art_cross_reference": bool(art_command),
                "source": "lolrmm",
            },
        }

        if abuse_reason:
            test["description"] += abuse_reason

        return [test]

    def _build_account_required_test(
        self, name: str, description: str, website: str,
        technique_id: str, catalog: dict, platforms: list[str],
        vendor: str, abuse_reason: str,
    ) -> list[dict]:
        """Generate a guidance test for RMMs that require an account to download."""
        dl_exe = catalog.get("exe", f"{name}.exe")
        dl_desc = catalog.get("desc", name)

        command = (
            f"# === LOLRMM: {name} - Account-Required RMM Test ===\n"
            f"# {name} requires a vendor account to generate agent installers.\n"
            f"# This test checks if the {name} agent is already deployed.\n"
            f"#\n"
            f"# To perform a full download+execute test:\n"
            f"#   1. Create a trial account at {website or 'the vendor website'}\n"
            f"#   2. Generate an agent installer\n"
            f"#   3. Attempt to deploy it on this endpoint\n"
            f"#\n"
            f"$found = $false\n"
            f"# Check for running processes\n"
            f"$procs = Get-Process -Name '*{name.split()[0].lower()}*' -ErrorAction SilentlyContinue\n"
            f"if ($procs) {{\n"
            f"    Write-Host 'FOUND: {name} process running:' ($procs | Select-Object Name, Id | Out-String)\n"
            f"    $found = $true\n"
            f"}}\n"
            f"# Check for services\n"
            f"$svcs = Get-Service -Name '*{name.split()[0].lower()}*' -ErrorAction SilentlyContinue\n"
            f"if ($svcs) {{\n"
            f"    Write-Host 'FOUND: {name} service:' ($svcs | Select-Object Name, Status | Out-String)\n"
            f"    $found = $true\n"
            f"}}\n"
            f"if (-not $found) {{ Write-Host 'NOT FOUND: {name} not detected on this system' }}"
        )

        return [{
            "name": f"LOLRMM: {name} - Detect Existing Deployment",
            "description": (
                f"Check if {name} ({dl_desc}) is already deployed on this endpoint. "
                f"{name} requires an account to download agent installers. "
                f"{abuse_reason}"
            ),
            "command": command,
            "executor": "powershell",
            "technique_id": technique_id,
            "binary_path": None,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": platforms,
            "cleanup_command": None,
            "metadata": {
                "rmm_tool": name,
                "vendor": vendor,
                "website": website,
                "test_type": "detect_existing",
                "account_required": True,
                "abuse_reason": abuse_reason,
                "source": "lolrmm",
            },
        }]

    def _build_execution_test(
        self, name: str, description: str, website: str,
        technique_id: str, details: dict, platforms: list[str],
        vendor: str, abuse_reason: str,
    ) -> list[dict]:
        """Generate an execution test from LOLRMM install paths and PE metadata."""
        install_paths = details.get("InstallationPaths", [])
        pe_metadata = details.get("PEMetadata", [])

        # Get executable filenames from PEMetadata
        exe_names: list[str] = []
        if isinstance(pe_metadata, list):
            for pe in pe_metadata:
                if isinstance(pe, dict):
                    fn = pe.get("Filename", "") or pe.get("OriginalFileName", "")
                    if fn:
                        exe_names.append(fn)
        elif isinstance(pe_metadata, dict):
            fn = pe_metadata.get("Filename", "") or pe_metadata.get("OriginalFileName", "")
            if fn:
                exe_names.append(fn)

        if not exe_names:
            return []

        # Get concrete install paths
        concrete_paths: list[str] = []
        for p in (install_paths or []):
            if isinstance(p, str) and p.strip():
                # Keep paths that look like real Windows paths
                if "\\" in p and not p.endswith("*.exe"):
                    cleaned = p.replace("*", "").rstrip("\\")
                    if cleaned:
                        concrete_paths.append(cleaned)

        primary_exe = exe_names[0]

        # Build PowerShell command that checks install paths then tries to execute
        path_checks = []
        for cp in concrete_paths[:5]:
            full_path = cp
            if not cp.lower().endswith(".exe"):
                full_path = f"{cp}\\{primary_exe}"
            path_checks.append(f"'{full_path}'")

        if path_checks:
            check_script = (
                f"# === LOLRMM: {name} - Execution Prevention Test ===\n"
                f"# Check if {name} is installed and can execute\n"
                f"$paths = @({', '.join(path_checks)})\n"
                f"$found = $false\n"
                f"foreach ($p in $paths) {{\n"
                f"    if (Test-Path $p) {{\n"
                f"        Write-Host \"FOUND: $p\"\n"
                f"        $hash = (Get-FileHash -Path $p -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash\n"
                f"        Write-Host \"SHA256: $hash\"\n"
                f"        try {{\n"
                f"            $proc = Start-Process -FilePath $p -ArgumentList '--version' "
                f"-PassThru -NoNewWindow -ErrorAction Stop\n"
                f"            $proc | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue\n"
                f"            if (-not $proc.HasExited) {{ $proc.Kill() }}\n"
                f"            Write-Host 'ALLOWED: {name} executed'\n"
                f"        }} catch {{\n"
                f"            Write-Host \"BLOCKED: Execution prevented - $($_.Exception.Message)\"\n"
                f"        }}\n"
                f"        $found = $true; break\n"
                f"    }}\n"
                f"}}\n"
                f"if (-not $found) {{ Write-Host 'NOT INSTALLED: {name} not found at known paths' }}"
            )
        else:
            check_script = (
                f"# === LOLRMM: {name} - Execution Prevention Test ===\n"
                f"$exe = Get-Command '{primary_exe}' -ErrorAction SilentlyContinue\n"
                f"if ($exe) {{\n"
                f"    Write-Host \"FOUND: $($exe.Source)\"\n"
                f"    $hash = (Get-FileHash -Path $exe.Source -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash\n"
                f"    Write-Host \"SHA256: $hash\"\n"
                f"    try {{\n"
                f"        Start-Process -FilePath $exe.Source -ArgumentList '--version' "
                f"-PassThru -NoNewWindow -ErrorAction Stop | "
                f"Wait-Process -Timeout 5 -ErrorAction SilentlyContinue\n"
                f"        Write-Host 'ALLOWED: {name} executed'\n"
                f"    }} catch {{\n"
                f"        Write-Host \"BLOCKED: Execution prevented - $($_.Exception.Message)\"\n"
                f"    }}\n"
                f"}} else {{ Write-Host 'NOT INSTALLED: {primary_exe} not in PATH' }}"
            )

        return [{
            "name": f"LOLRMM: {name} - Execution ({primary_exe})",
            "description": (
                f"Test whether {name} RMM tool can execute from known installation paths. "
                f"Application control policies (AppLocker/WDAC) should prevent "
                f"unauthorized RMM tools from running. {description}"
            ),
            "command": check_script,
            "executor": "powershell",
            "technique_id": technique_id,
            "binary_path": primary_exe,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": platforms,
            "cleanup_command": None,
            "metadata": {
                "rmm_tool": name,
                "vendor": vendor,
                "website": website,
                "test_type": "execution",
                "install_paths": install_paths,
                "executables": exe_names,
                "abuse_reason": abuse_reason,
                "source": "lolrmm",
            },
        }]

    def _build_service_test(
        self, name: str, description: str, website: str,
        technique_id: str, artifacts: dict, vendor: str,
        abuse_reason: str,
    ) -> list[dict]:
        """Generate a service-existence test from LOLRMM EventLog artifacts."""
        event_logs = artifacts.get("EventLog", [])
        service_names: list[str] = []
        service_images: list[str] = []

        for evt in (event_logs or []):
            if isinstance(evt, dict) and evt.get("ServiceName"):
                svc = evt["ServiceName"]
                img = evt.get("ImagePath", "")
                if svc not in service_names:
                    service_names.append(svc)
                    if img:
                        service_images.append(img)

        if not service_names:
            return []

        svc_name = service_names[0]

        # Build a comprehensive service check
        svc_checks = " -or ".join(
            [f"$_.Name -eq '{s}'" for s in service_names[:5]]
        )

        command = (
            f"# === LOLRMM: {name} - Service Prevention Test ===\n"
            f"# Check if {name} RMM service exists or is running\n"
            f"$services = Get-Service | Where-Object {{ {svc_checks} }}\n"
            f"if ($services) {{\n"
            f"    foreach ($svc in $services) {{\n"
            f"        Write-Host \"SERVICE EXISTS: $($svc.Name) - Status: $($svc.Status)\"\n"
            f"        # Check service binary path\n"
            f"        $regPath = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$($svc.Name)\"\n"
            f"        $imgPath = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).ImagePath\n"
            f"        if ($imgPath) {{ Write-Host \"  ImagePath: $imgPath\" }}\n"
            f"    }}\n"
            f"}} else {{\n"
            f"    Write-Host 'NOT FOUND: No {name} services detected'\n"
            f"}}"
        )

        return [{
            "name": f"LOLRMM: {name} - Service ({svc_name})",
            "description": (
                f"Check if {name} RMM service '{svc_name}' exists or can be created. "
                f"Endpoint policies should prevent unauthorized RMM service installation."
            ),
            "command": command,
            "executor": "powershell",
            "technique_id": technique_id,
            "binary_path": None,
            "elevation_required": False,
            "risk_level": "medium",
            "platforms": ["windows"],
            "cleanup_command": None,
            "metadata": {
                "rmm_tool": name,
                "vendor": vendor,
                "website": website,
                "test_type": "service",
                "service_names": service_names,
                "service_images": service_images,
                "abuse_reason": abuse_reason,
                "source": "lolrmm",
            },
        }]

    def _build_network_test(
        self, name: str, description: str, website: str,
        technique_id: str, artifacts: dict, platforms: list[str],
        vendor: str, abuse_reason: str,
    ) -> list[dict]:
        """Generate a network connectivity test from LOLRMM Network artifacts."""
        network_artifacts = artifacts.get("Network", [])
        domains: list[str] = []
        ports: list[int] = []

        for net in (network_artifacts or []):
            if isinstance(net, dict):
                for d in (net.get("Domains", []) or []):
                    # Skip wildcard-only, regex, or placeholder domains
                    if isinstance(d, str) and d and not d.startswith("*") and "[" not in d:
                        # Also skip relay/regex patterns
                        if not any(c in d for c in ("[", "]", "(", ")")):
                            domains.append(d)
                for p in (net.get("Ports", []) or []):
                    if p and p not in ports:
                        ports.append(p)

        if not domains:
            return []

        # Test DNS resolution and TCP connectivity for up to 3 domains
        test_domains = domains[:3]
        port = ports[0] if ports else 443

        domain_checks = []
        for d in test_domains:
            domain_checks.append(
                f"    # Test: {d}\n"
                f"    $dns = Resolve-DnsName '{d}' -ErrorAction SilentlyContinue\n"
                f"    if ($dns) {{\n"
                f"        Write-Host \"RESOLVED: {d} ->\" ($dns | Where-Object {{ $_.IPAddress }} | "
                f"Select-Object -First 1 -ExpandProperty IPAddress)\n"
                f"        $tcp = Test-NetConnection -ComputerName '{d}' -Port {port} "
                f"-WarningAction SilentlyContinue -ErrorAction SilentlyContinue\n"
                f"        if ($tcp.TcpTestSucceeded) {{\n"
                f"            Write-Host \"ALLOWED: TCP connection to {d}:{port} succeeded\"\n"
                f"        }} else {{\n"
                f"            Write-Host \"BLOCKED: TCP connection to {d}:{port} failed\"\n"
                f"        }}\n"
                f"    }} else {{\n"
                f"        Write-Host \"BLOCKED: DNS resolution failed for {d}\"\n"
                f"    }}"
            )

        primary_domain = test_domains[0]
        command = (
            f"# === LOLRMM: {name} - Network Connectivity Prevention Test ===\n"
            f"# Test whether this endpoint can reach {name} RMM infrastructure\n"
            f"# DNS filtering and firewall rules should block these connections\n"
            + "\n".join(domain_checks)
        )

        return [{
            "name": f"LOLRMM: {name} - Network ({primary_domain})",
            "description": (
                f"Test whether the endpoint can resolve and reach {name} RMM "
                f"infrastructure at {primary_domain}. Network controls and DNS "
                f"filtering should block unauthorized RMM tool communications."
            ),
            "command": command,
            "executor": "powershell",
            "technique_id": technique_id,
            "binary_path": None,
            "elevation_required": False,
            "risk_level": "low",
            "platforms": platforms,
            "cleanup_command": None,
            "metadata": {
                "rmm_tool": name,
                "vendor": vendor,
                "website": website,
                "test_type": "network",
                "domains": domains,
                "ports": ports,
                "abuse_reason": abuse_reason,
                "source": "lolrmm",
            },
        }]

    # -- catalog-only tests (tools not in LOLRMM YAML) ------------------------

    def _generate_catalog_only_tests(
        self, name: str, catalog: dict,
    ) -> list[dict]:
        """Generate tests for RMM tools in our catalog but not in LOLRMM YAML."""
        tests: list[dict] = []
        technique_id = "T1219"
        vendor = catalog.get("vendor", "")
        abuse_reason = catalog.get("abuse_reason", "")
        website = ""
        platforms = catalog.get("platforms", ["windows"])

        # Download & execute test (or account-required detection)
        tests.extend(
            self._build_download_execute_test(
                name, "", website, technique_id, catalog,
                platforms, vendor, abuse_reason,
            )
        )

        return tests

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _resolve_platforms(
        supported_os: list[str], catalog: dict,
    ) -> list[str]:
        """Merge LOLRMM SupportedOS with catalog platforms."""
        platforms: set[str] = set()

        # Map LOLRMM SupportedOS values to our platform names
        os_map = {
            "windows": "windows",
            "mac": "macos",
            "macos": "macos",
            "linux": "linux",
            "android": "android",
            "ios": "ios",
            "chromeos": "chromeos",
        }
        for os_name in supported_os:
            mapped = os_map.get(os_name.lower(), "")
            if mapped:
                platforms.add(mapped)

        # Merge catalog platforms
        for p in catalog.get("platforms", []):
            platforms.add(p)

        # Default to windows if nothing determined
        if not platforms:
            platforms.add("windows")

        return sorted(platforms)

    # -- MITRE mappings --------------------------------------------------------

    def get_mitre_mappings(self) -> dict[str, list[str]]:
        mappings: dict[str, list[str]] = {}
        for test in getattr(self, "_tests", []):
            tid = test.get("technique_id", "")
            if tid:
                mappings.setdefault(test["name"], []).append(tid)
        return mappings
