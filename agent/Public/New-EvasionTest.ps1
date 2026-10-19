function New-EvasionTest {
    <#
    .SYNOPSIS
        Creates custom evasion/obfuscation test cases for prevention validation.

    .DESCRIPTION
        Generates test cases using common adversary evasion techniques to validate
        whether your controls detect and block obfuscated or evasive variants of
        attacks. This helps ensure your prevention isn't just blocking known-good
        signatures but actually understanding the behavior.

        Supported evasion techniques:
        - String obfuscation (concatenation, encoding, variable substitution)
        - AMSI bypass attempts
        - PowerShell constrained language mode bypass
        - Alternate execution methods (WMI, COM, .NET reflection)
        - Encoded commands (Base64, XOR, compressed)
        - Living-off-the-land binary chaining

        DISCLAIMER: These tests are for authorized prevention validation only.
        Only run on systems where you have explicit permission.

    .PARAMETER Technique
        The evasion technique to generate tests for.

    .PARAMETER BaseCommand
        Optional base command to apply the evasion technique to.
        If not specified, uses a benign canary command.

    .PARAMETER All
        Generate tests for all available evasion techniques.

    .OUTPUTS
        Array of test objects compatible with Invoke-AtomicPrevention custom tests.

    .EXAMPLE
        New-EvasionTest -Technique StringObfuscation

    .EXAMPLE
        New-EvasionTest -All | ForEach-Object { $_.command }

    .EXAMPLE
        $tests = New-EvasionTest -Technique EncodedCommand -BaseCommand "whoami"
        Invoke-AtomicPrevention -Playbook .\playbook.json -CustomScript $tests.ScriptPath
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateSet(
            'StringObfuscation',
            'EncodedCommand',
            'AMSIBypass',
            'ConstrainedLanguageBypass',
            'WMIExecution',
            'COMObjectExecution',
            'DotNetReflection',
            'LOLBinChain',
            'EnvironmentVariable',
            'AlternateDataStream',
            'All'
        )]
        [string]$Technique = 'All',

        [Parameter()]
        [string]$BaseCommand = 'Write-Host "AtomicPrevention-Canary-$(Get-Date -Format yyyyMMdd)"',

        [Parameter()]
        [string]$OutputDirectory
    )

    $tests = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not $OutputDirectory) {
        $OutputDirectory = Join-Path (Get-Location) 'AtomicPrevention-EvasionTests'
    }
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    $techniques = if ($Technique -eq 'All') {
        @(
            'StringObfuscation', 'EncodedCommand', 'AMSIBypass',
            'ConstrainedLanguageBypass', 'WMIExecution', 'COMObjectExecution',
            'DotNetReflection', 'LOLBinChain', 'EnvironmentVariable',
            'AlternateDataStream'
        )
    } else {
        @($Technique)
    }

    foreach ($tech in $techniques) {
        switch ($tech) {

            'StringObfuscation' {
                # Technique: Break strings apart and reassemble at runtime
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: String Concatenation'
                    TechniqueId  = 'T1027'
                    Description  = 'Tests if controls block commands built via string concatenation at runtime'
                    Command      = '$a="Wri"; $b="te-H"; $c="ost"; $d=" AtomicPrevention-Canary"; Invoke-Expression "$a$b$c$d"'
                    Executor     = 'powershell'
                    RiskLevel    = 'medium'
                    EvasionType  = 'StringObfuscation'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Character Array Join'
                    TechniqueId  = 'T1027'
                    Description  = 'Tests if controls block commands built from character arrays'
                    Command      = '$c = [char[]]@(87,104,111,97,109,105) -join ""; & ([scriptblock]::Create($c))'
                    Executor     = 'powershell'
                    RiskLevel    = 'medium'
                    EvasionType  = 'StringObfuscation'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Reverse String'
                    TechniqueId  = 'T1027'
                    Description  = 'Tests if controls block reversed string execution'
                    Command      = '$r = "imaohw"; $f = -join ($r[-1..-($r.Length)]); & ([scriptblock]::Create($f))'
                    Executor     = 'powershell'
                    RiskLevel    = 'medium'
                    EvasionType  = 'StringObfuscation'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Tick Insertion (PowerShell)'
                    TechniqueId  = 'T1027'
                    Description  = 'Tests if controls block backtick-obfuscated commands'
                    Command      = "W`r`it`e-H`os`t 'AtomicPrevention-Canary'"
                    Executor     = 'powershell'
                    RiskLevel    = 'low'
                    EvasionType  = 'StringObfuscation'
                })
            }

            'EncodedCommand' {
                $plainCmd = $BaseCommand
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($plainCmd)
                $encoded = [Convert]::ToBase64String($bytes)

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Base64 Encoded Command'
                    TechniqueId  = 'T1059.001'
                    Description  = 'Tests if controls block Base64-encoded PowerShell execution'
                    Command      = "powershell.exe -EncodedCommand $encoded"
                    Executor     = 'cmd'
                    RiskLevel    = 'high'
                    EvasionType  = 'EncodedCommand'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Compressed + Encoded Command'
                    TechniqueId  = 'T1059.001'
                    Description  = 'Tests if controls block compressed then encoded PowerShell'
                    Command      = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc $encoded"
                    Executor     = 'cmd'
                    RiskLevel    = 'high'
                    EvasionType  = 'EncodedCommand'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: FromBase64String Execution'
                    TechniqueId  = 'T1059.001'
                    Description  = 'Tests if controls block runtime Base64 decoding and execution'
                    Command      = "`$d = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$encoded')); Invoke-Expression `$d"
                    Executor     = 'powershell'
                    RiskLevel    = 'high'
                    EvasionType  = 'EncodedCommand'
                })
            }

            'AMSIBypass' {
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: AMSI Test String'
                    TechniqueId  = 'T1562.001'
                    Description  = 'Tests if AMSI detects the standard test trigger string'
                    Command      = 'Write-Host "Invoke-Mimikatz"; Write-Host "AMSI test complete"'
                    Executor     = 'powershell'
                    RiskLevel    = 'low'
                    EvasionType  = 'AMSIBypass'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: PowerShell Downgrade (v2)'
                    TechniqueId  = 'T1059.001'
                    Description  = 'Tests if controls prevent PowerShell v2 downgrade (bypasses AMSI)'
                    Command      = 'powershell.exe -Version 2 -Command "Write-Host AtomicPrevention-PSv2"'
                    Executor     = 'cmd'
                    RiskLevel    = 'high'
                    EvasionType  = 'AMSIBypass'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Script Block Logging Evasion'
                    TechniqueId  = 'T1562.001'
                    Description  = 'Tests if controls detect attempts to check logging configuration'
                    Command      = '$GroupPolicyField = [ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static"); Write-Host "Logging check: $($GroupPolicyField -ne $null)"'
                    Executor     = 'powershell'
                    RiskLevel    = 'high'
                    EvasionType  = 'AMSIBypass'
                })
            }

            'ConstrainedLanguageBypass' {
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Add-Type Bypass (CLM)'
                    TechniqueId  = 'T1059.001'
                    Description  = 'Tests if controls prevent Add-Type in constrained language mode'
                    Command      = 'Add-Type -TypeDefinition "public class MagicTest { public static string Run() { return \"canary\"; } }"; [MagicTest]::Run()'
                    Executor     = 'powershell'
                    RiskLevel    = 'high'
                    EvasionType  = 'ConstrainedLanguageBypass'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: PowerShell Runspace'
                    TechniqueId  = 'T1059.001'
                    Description  = 'Tests if controls prevent creating custom PowerShell runspaces'
                    Command      = '$rs = [runspacefactory]::CreateRunspace(); $rs.Open(); $p = $rs.CreatePipeline(); $p.Commands.AddScript("whoami"); $p.Invoke(); $rs.Close()'
                    Executor     = 'powershell'
                    RiskLevel    = 'high'
                    EvasionType  = 'ConstrainedLanguageBypass'
                })
            }

            'WMIExecution' {
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: WMI Process Create'
                    TechniqueId  = 'T1047'
                    Description  = 'Tests if controls prevent process creation via WMI'
                    Command      = 'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c echo AtomicPrevention-WMI"'
                    Executor     = 'powershell'
                    RiskLevel    = 'high'
                    EvasionType  = 'WMIExecution'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: WMIC Process Call'
                    TechniqueId  = 'T1047'
                    Description  = 'Tests if controls prevent WMIC-based execution'
                    Command      = 'wmic process call create "cmd.exe /c echo AtomicPrevention-WMIC"'
                    Executor     = 'cmd'
                    RiskLevel    = 'high'
                    EvasionType  = 'WMIExecution'
                })
            }

            'COMObjectExecution' {
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: COM Shell.Application'
                    TechniqueId  = 'T1218'
                    Description  = 'Tests if controls prevent execution via COM Shell.Application'
                    Command      = '$s = New-Object -ComObject "Shell.Application"; $s.ShellExecute("cmd.exe", "/c echo AtomicPrevention-COM", "", "open", 0)'
                    Executor     = 'powershell'
                    RiskLevel    = 'high'
                    EvasionType  = 'COMObjectExecution'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: COM WScript.Shell'
                    TechniqueId  = 'T1218'
                    Description  = 'Tests if controls prevent execution via COM WScript.Shell'
                    Command      = '$w = New-Object -ComObject "WScript.Shell"; $w.Run("cmd.exe /c echo AtomicPrevention-WScript", 0, $true)'
                    Executor     = 'powershell'
                    RiskLevel    = 'high'
                    EvasionType  = 'COMObjectExecution'
                })
            }

            'DotNetReflection' {
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: .NET Assembly Reflection'
                    TechniqueId  = 'T1059.001'
                    Description  = 'Tests if controls prevent direct .NET method invocation via reflection'
                    Command      = '[System.Diagnostics.Process]::Start("cmd.exe", "/c echo AtomicPrevention-Reflection")'
                    Executor     = 'powershell'
                    RiskLevel    = 'high'
                    EvasionType  = 'DotNetReflection'
                })
            }

            'LOLBinChain' {
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Certutil Download + Execute'
                    TechniqueId  = 'T1105'
                    Description  = 'Tests if controls prevent certutil-based download cradle'
                    Command      = 'echo AtomicPrevention-Canary > %TEMP%\ma_test.txt && certutil -encode %TEMP%\ma_test.txt %TEMP%\ma_test.b64 && certutil -decode %TEMP%\ma_test.b64 %TEMP%\ma_test_out.txt && type %TEMP%\ma_test_out.txt'
                    Executor     = 'cmd'
                    RiskLevel    = 'medium'
                    EvasionType  = 'LOLBinChain'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Mshta JavaScript'
                    TechniqueId  = 'T1218.005'
                    Description  = 'Tests if controls prevent mshta inline JavaScript execution'
                    Command      = 'mshta "javascript:close(new ActiveXObject(''WScript.Shell'').Run(''cmd /c echo AtomicPrevention-Mshta'',0,true))"'
                    Executor     = 'cmd'
                    RiskLevel    = 'high'
                    EvasionType  = 'LOLBinChain'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Rundll32 JavaScript'
                    TechniqueId  = 'T1218.011'
                    Description  = 'Tests if controls prevent rundll32 JavaScript execution'
                    Command      = 'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("AtomicPrevention-Rundll32")'
                    Executor     = 'cmd'
                    RiskLevel    = 'high'
                    EvasionType  = 'LOLBinChain'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Forfiles Command Execution'
                    TechniqueId  = 'T1202'
                    Description  = 'Tests if controls prevent indirect execution via forfiles'
                    Command      = 'forfiles /p c:\windows\system32 /m notepad.exe /c "cmd /c echo AtomicPrevention-Forfiles"'
                    Executor     = 'cmd'
                    RiskLevel    = 'medium'
                    EvasionType  = 'LOLBinChain'
                })

                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Pcalua Proxy Execution'
                    TechniqueId  = 'T1202'
                    Description  = 'Tests if controls prevent pcalua.exe proxy execution'
                    Command      = 'pcalua.exe -a cmd.exe -c "/c echo AtomicPrevention-Pcalua"'
                    Executor     = 'cmd'
                    RiskLevel    = 'high'
                    EvasionType  = 'LOLBinChain'
                })
            }

            'EnvironmentVariable' {
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: Environment Variable Execution'
                    TechniqueId  = 'T1059.003'
                    Description  = 'Tests if controls prevent command execution from environment variables'
                    Command      = 'set "MA_CMD=echo AtomicPrevention-EnvVar" && cmd /c %MA_CMD%'
                    Executor     = 'cmd'
                    RiskLevel    = 'medium'
                    EvasionType  = 'EnvironmentVariable'
                })
            }

            'AlternateDataStream' {
                $tests.Add([PSCustomObject]@{
                    Name         = 'Evasion: NTFS Alternate Data Stream'
                    TechniqueId  = 'T1564.004'
                    Description  = 'Tests if controls prevent hiding data in NTFS alternate data streams'
                    Command      = 'echo AtomicPrevention-ADS > %TEMP%\ma_ads_test.txt:hidden && more < %TEMP%\ma_ads_test.txt:hidden'
                    Executor     = 'cmd'
                    RiskLevel    = 'high'
                    EvasionType  = 'AlternateDataStream'
                })
            }
        }
    }

    # Write each test as a script file for use with -CustomScript
    foreach ($test in $tests) {
        $scriptFile = Join-Path $OutputDirectory "$($test.EvasionType)-$(New-Guid).ps1"

        $scriptContent = @"
# Atomic Prevention Evasion Test: $($test.Name)
# Technique: $($test.TechniqueId)
# Description: $($test.Description)
# Risk Level: $($test.RiskLevel)

$($test.Command)
"@
        $scriptContent | Set-Content -Path $scriptFile -Encoding UTF8
        $test | Add-Member -NotePropertyName 'ScriptPath' -NotePropertyValue $scriptFile
    }

    Write-Host "  [*] Generated $($tests.Count) evasion tests in $OutputDirectory" -ForegroundColor Cyan

    return $tests
}
