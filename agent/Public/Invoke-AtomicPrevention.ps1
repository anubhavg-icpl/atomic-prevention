function Invoke-AtomicPrevention {
    <#
    .SYNOPSIS
        Runs a Atomic Prevention prevention validation playbook.

    .DESCRIPTION
        This is the main entry point for the Atomic Prevention agent. It loads
        a playbook JSON file exported from the Atomic Prevention backend,
        iterates through each test, executes it via Test-Prevention, and
        collects the results. Results are saved locally as JSON and can
        optionally be uploaded to the backend server.

        DISCLAIMER: Atomic Prevention is an authorized prevention validation
        tool. It executes benign indicators of adversary techniques to test
        whether your endpoint security controls correctly block them. Only
        run this tool on systems where you have explicit authorization to
        perform security testing. The authors assume no liability for
        unauthorized use.

    .PARAMETER Playbook
        Path to a playbook JSON file exported from the Atomic Prevention
        backend (via GET /api/playbooks/{id}/export).

    .PARAMETER ServerUrl
        Optional base URL of the Atomic Prevention server for uploading
        results (e.g. http://localhost:3000). If omitted, results are
        saved locally only.

    .PARAMETER OutputDirectory
        Directory where result JSON files and logs are written.
        Defaults to ./AtomicPrevention-Results.

    .PARAMETER WhatIf
        Dry-run mode. Shows what tests would be executed without
        actually running any commands.

    .EXAMPLE
        Invoke-AtomicPrevention -Playbook .\apt29-playbook.json

    .EXAMPLE
        Invoke-AtomicPrevention -Playbook .\apt29-playbook.json -ServerUrl http://10.0.0.5:3000

    .EXAMPLE
        Invoke-AtomicPrevention -Playbook .\apt29-playbook.json -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({
            if (-not (Test-Path -Path $_ -PathType Leaf)) {
                throw "Playbook file not found: $_"
            }
            return $true
        })]
        [string]$Playbook,

        [Parameter()]
        [string]$ServerUrl,

        [Parameter()]
        [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'AtomicPrevention-Results'),

        [Parameter()]
        [string[]]$CustomPayloadUrl,

        [Parameter()]
        [string[]]$CustomScript,

        [Parameter()]
        [string[]]$CustomExe,

        [Parameter()]
        [string[]]$SkipTestId,

        [Parameter()]
        [string[]]$OnlyTechniqueId
    )

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------
    $banner = @"

    ============================================================
      Atomic Prevention  Prevention Validation Agent  v$Script:ModuleVersion
    ============================================================
      Authorized security testing only
      Ensure you have explicit permission before proceeding.
    ============================================================

"@
    Write-Host $banner -ForegroundColor Cyan

    # ------------------------------------------------------------------
    # Load the playbook
    # ------------------------------------------------------------------
    Write-Host '  [*] Loading playbook...' -ForegroundColor White

    try {
        $playbookContent = Get-Content -Path $Playbook -Raw -ErrorAction Stop
        $playbookData = $playbookContent | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Host "  [!] Failed to load playbook: $_" -ForegroundColor Red
        return
    }

    # Validate structure
    if (-not $playbookData.playbook -or -not $playbookData.tests) {
        Write-Host '  [!] Invalid playbook format. Expected "playbook" and "tests" keys.' -ForegroundColor Red
        return
    }

    $playbookMeta = $playbookData.playbook
    $tests = @($playbookData.tests)
    $config = $playbookData.config
    $timeoutSeconds = if ($config -and $config.timeout_seconds) { $config.timeout_seconds } else { 5 }
    $prerequisiteTimeoutSeconds = if ($config -and $config.prerequisite_timeout_seconds) { $config.prerequisite_timeout_seconds } else { 120 }
    $resultsEndpoint = if ($config -and $config.results_endpoint) { $config.results_endpoint } else { '/api/results/submit' }

    Write-Host "  [*] Playbook  : $($playbookMeta.name)" -ForegroundColor White
    Write-Host "  [*] Adversary : $($playbookMeta.adversary_group)" -ForegroundColor White
    Write-Host "  [*] Tests     : $($tests.Count)" -ForegroundColor White
    Write-Host "  [*] Timeout   : ${timeoutSeconds}s per test" -ForegroundColor White

    if ($WhatIfPreference) {
        Write-Host '  [*] Mode      : Dry run (no commands will be executed)' -ForegroundColor Yellow
    }

    Write-Host ''

    # ------------------------------------------------------------------
    # Prepare output directory and log
    # ------------------------------------------------------------------
    if (-not (Test-Path -Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    $runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $logPath = Join-Path -Path $OutputDirectory -ChildPath "atomic-prevention-$runTimestamp.log"
    $resultPath = Join-Path -Path $OutputDirectory -ChildPath "atomic-prevention-$runTimestamp.json"

    # ------------------------------------------------------------------
    # Custom payload injection
    # ------------------------------------------------------------------
    # Filter tests by technique if specified
    if ($OnlyTechniqueId) {
        $tests = @($tests | Where-Object { $_.technique_id -in $OnlyTechniqueId })
        Write-Host "  [*] Filtered to $($tests.Count) tests matching techniques: $($OnlyTechniqueId -join ', ')" -ForegroundColor White
    }

    # Remove skipped tests
    if ($SkipTestId) {
        $tests = @($tests | Where-Object { $_.id -notin $SkipTestId })
        Write-Host "  [*] Skipped $($SkipTestId.Count) test(s)" -ForegroundColor White
    }

    # Add custom payload URLs as additional tests
    if ($CustomPayloadUrl) {
        foreach ($url in $CustomPayloadUrl) {
            $fileName = [System.IO.Path]::GetFileName(([uri]$url).LocalPath)
            if (-not $fileName) { $fileName = 'custom-payload.exe' }

            $customTest = [PSCustomObject]@{
                id               = "custom-url-$(New-Guid)"
                name             = "Custom Payload: $fileName"
                description      = "User-supplied payload from $url"
                technique_id     = 'T0000'
                technique_name   = 'Custom Test'
                tactic           = @('custom')
                source           = 'custom'
                command          = "powershell.exe -NoProfile -Command `"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `$p = Join-Path `$env:TEMP '$fileName'; Invoke-WebRequest -Uri '$url' -OutFile `$p; Start-Process -FilePath `$p -PassThru`""
                executor         = 'powershell'
                cleanup_command  = "Remove-Item -Path `"`$env:TEMP\$fileName`" -Force -ErrorAction SilentlyContinue"
                elevation_required = $false
                risk_level       = 'high'
                platforms        = @('windows')
                guidance         = @{
                    what_this_tests = "Downloads and executes a custom payload from $url to test whether your controls block it."
                    if_blocked      = 'Your controls blocked the custom payload. This is the desired outcome.'
                    if_allowed      = "ALLOWED: The custom payload from $url was executed. Review your application control and download prevention policies."
                    mitre_reference = ''
                }
                resources        = @{ payload_url = $url }
            }

            $tests += $customTest
            Write-Host "  [+] Added custom payload: $url" -ForegroundColor Cyan
        }
    }

    # Add custom scripts as additional tests
    if ($CustomScript) {
        foreach ($scriptPath in $CustomScript) {
            if (-not (Test-Path $scriptPath)) {
                Write-Host "  [!] Custom script not found: $scriptPath" -ForegroundColor Red
                continue
            }
            $scriptName = [System.IO.Path]::GetFileName($scriptPath)
            $scriptExt = [System.IO.Path]::GetExtension($scriptPath).ToLower()

            $executor = 'powershell'
            $command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
            if ($scriptExt -eq '.bat' -or $scriptExt -eq '.cmd') {
                $executor = 'cmd'
                $command = "cmd.exe /c `"$scriptPath`""
            }
            elseif ($scriptExt -eq '.vbs') {
                $executor = 'cmd'
                $command = "cscript.exe //nologo `"$scriptPath`""
            }

            $customTest = [PSCustomObject]@{
                id               = "custom-script-$(New-Guid)"
                name             = "Custom Script: $scriptName"
                description      = "User-supplied script: $scriptPath"
                technique_id     = 'T0000'
                technique_name   = 'Custom Test'
                tactic           = @('custom')
                source           = 'custom'
                command          = $command
                executor         = $executor
                cleanup_command  = $null
                elevation_required = $false
                risk_level       = 'high'
                platforms        = @('windows')
                guidance         = @{
                    what_this_tests = "Executes the custom script $scriptName to test whether your controls prevent it."
                    if_blocked      = 'Your controls blocked the custom script execution.'
                    if_allowed      = "ALLOWED: $scriptName was executed. Review script execution policies."
                    mitre_reference = ''
                }
                resources        = @{ script_path = $scriptPath }
            }

            $tests += $customTest
            Write-Host "  [+] Added custom script: $scriptPath" -ForegroundColor Cyan
        }
    }

    # Add custom executables as additional tests
    if ($CustomExe) {
        foreach ($exePath in $CustomExe) {
            if (-not (Test-Path $exePath)) {
                Write-Host "  [!] Custom executable not found: $exePath" -ForegroundColor Red
                continue
            }
            $exeName = [System.IO.Path]::GetFileName($exePath)

            $customTest = [PSCustomObject]@{
                id               = "custom-exe-$(New-Guid)"
                name             = "Custom Executable: $exeName"
                description      = "User-supplied executable: $exePath"
                technique_id     = 'T0000'
                technique_name   = 'Custom Test'
                tactic           = @('custom')
                source           = 'custom'
                command          = "`"$exePath`""
                executor         = 'cmd'
                cleanup_command  = $null
                elevation_required = $false
                risk_level       = 'high'
                platforms        = @('windows')
                guidance         = @{
                    what_this_tests = "Attempts to execute $exeName (e.g. EDR killer, custom tool) to test if your controls prevent it."
                    if_blocked      = "Your controls blocked $exeName execution."
                    if_allowed      = "ALLOWED: $exeName was executed. Add this executable hash to your application control block list."
                    mitre_reference = ''
                }
                resources        = @{ exe_path = $exePath }
            }

            $tests += $customTest
            Write-Host "  [+] Added custom executable: $exePath" -ForegroundColor Cyan
        }
    }

    if ($CustomPayloadUrl -or $CustomScript -or $CustomExe) {
        Write-Host "  [*] Total tests (with custom): $($tests.Count)" -ForegroundColor White
        Write-Host ''
    }

    # ------------------------------------------------------------------
    # Pre-flight: Download resources if configured
    # ------------------------------------------------------------------
    $autoDownload = $false
    if ($config -and $config.auto_download_resources -eq $true) {
        $autoDownload = $true
    }

    if ($autoDownload -and -not $WhatIfPreference) {
        $resourceDir = Join-Path -Path $OutputDirectory -ChildPath 'resources'
        if (-not (Test-Path $resourceDir)) {
            New-Item -Path $resourceDir -ItemType Directory -Force | Out-Null
        }

        Write-Host '  [*] Checking test resources...' -ForegroundColor White

        foreach ($test in $tests) {
            if (-not $test.resources) { continue }
            $res = $test.resources

            # For LOLDrivers tests: note the SHA256 for reference
            if ($res.driver_sha256) {
                $driverNote = Join-Path $resourceDir "driver-$($res.driver_sha256.Substring(0, 12)).txt"
                if (-not (Test-Path $driverNote)) {
                    $driverInfo = @(
                        "Driver SHA256: $($res.driver_sha256)",
                        "LOLDrivers URL: $($res.loldrivers_url)",
                        "Test: $($test.name)",
                        "Note: Download the driver sample from a malware repository for testing.",
                        "The agent will attempt to load it if placed in $resourceDir."
                    ) -join "`r`n"
                    $driverInfo | Set-Content -Path $driverNote -Encoding UTF8
                    Write-Host "      Noted driver resource: $($res.driver_sha256.Substring(0, 12))..." -ForegroundColor DarkCyan
                }
            }

            # For Atomic Red Team: note the reference
            if ($res.atomic_url) {
                Write-Verbose "  Atomic test reference: $($res.atomic_url)"
            }
        }

        Write-Host ''
    }

    # ------------------------------------------------------------------
    # Execute tests
    # ------------------------------------------------------------------
    $runStartedAt = (Get-Date).ToUniversalTime().ToString('o')
    $allResults = [System.Collections.Generic.List[hashtable]]::new()
    $summary = @{ blocked = 0; detected = 0; allowed = 0; error = 0; skipped = 0 }
    $testIndex = 0

    foreach ($test in $tests) {
        $testIndex++
        $prefix = "  [$testIndex/$($tests.Count)]"

        # Show what this test validates
        if ($test.guidance -and $test.guidance.what_this_tests) {
            Write-Host "         $($test.guidance.what_this_tests)" -ForegroundColor DarkGray
        }

        # Check platform compatibility
        $platforms = @()
        if ($test.platforms) {
            $platforms = @($test.platforms)
        }
        if ($platforms.Count -gt 0 -and 'windows' -notin $platforms) {
            Write-Host "$prefix SKIP  $($test.technique_id) | $($test.name) (not a Windows test)" -ForegroundColor DarkGray
            $skipStartedAt = (Get-Date).ToUniversalTime().ToString('o')
            $allResults.Add(@{
                TestId = $test.id
                TestName = $test.name
                TechniqueId = $test.technique_id
                Verdict = 'skipped'
                StartedAt = $skipStartedAt
                started_at = $skipStartedAt
                executed_at = $skipStartedAt
                CompletedAt = $skipStartedAt
                completed_at = $skipStartedAt
                ExitCode = $null
                ErrorMessage = 'Test not applicable to platform: windows'
                ExecutionTimeMs = 0
                StdOut = ''
                StdErr = ''
                AgentLogs = @()
            })
            $summary.skipped++
            continue
        }

        # Check elevation requirement
        $isAdmin = $false
        try {
            $currentPrincipal = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
            $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch {
            # Non-Windows or unable to determine; proceed anyway
            $isAdmin = $true
        }

        if ($test.elevation_required -eq $true -and -not $isAdmin) {
            Write-Host "$prefix SKIP  $($test.technique_id) | $($test.name) (requires elevation)" -ForegroundColor DarkGray
            $skipStartedAt = (Get-Date).ToUniversalTime().ToString('o')
            $skipResult = @{
                TestId          = $test.id
                TestName        = $test.name
                TechniqueId     = $test.technique_id
                Verdict         = 'skipped'
                StartedAt       = $skipStartedAt
                started_at      = $skipStartedAt
                executed_at     = $skipStartedAt
                CompletedAt     = $skipStartedAt
                completed_at    = $skipStartedAt
                ExitCode        = $null
                ErrorMessage    = 'Test requires elevation but agent is not running as administrator'
                ExecutionTimeMs = 0
                StdOut          = ''
                StdErr          = ''
                AgentLogs       = @()
            }
            $allResults.Add($skipResult)
            $summary.skipped++

            Write-TestLog -LogPath $logPath `
                -TestName $test.name `
                -TechniqueId $test.technique_id `
                -Verdict 'error' `
                -Reason 'Skipped: requires elevation' `
                -ExecutionTimeMs 0

            continue
        }

        # Display the test being run
        Write-Host "$prefix Run   $($test.technique_id) | $($test.name)" -ForegroundColor White -NoNewline

        # Execute
        $testResult = Test-Prevention `
            -Test $test `
            -TimeoutSeconds $timeoutSeconds `
            -PrerequisiteTimeoutSeconds $prerequisiteTimeoutSeconds

        $allResults.Add($testResult)

        # Update summary
        $verdictKey = $testResult.Verdict
        if ($summary.ContainsKey($verdictKey)) {
            $summary[$verdictKey]++
        }
        else {
            $summary[$verdictKey] = 1
        }

        # Display verdict with color coding and guidance
        $tacticStr = if ($test.tactic) { ($test.tactic -join ', ') } else { '' }
        switch ($testResult.Verdict) {
            'blocked' {
                Write-Host "`r$prefix " -NoNewline
                Write-Host 'BLOCKED' -ForegroundColor Green -NoNewline
                Write-Host " $($test.technique_id) | $($test.name)" -ForegroundColor White
                if ($test.guidance -and $test.guidance.if_blocked) {
                    Write-Host "         $($test.guidance.if_blocked)" -ForegroundColor DarkGreen
                }
            }
            'allowed' {
                Write-Host "`r$prefix " -NoNewline
                Write-Host 'ALLOWED' -ForegroundColor Red -NoNewline
                Write-Host " $($test.technique_id) | $($test.name)" -ForegroundColor White
                if ($test.guidance -and $test.guidance.if_allowed) {
                    Write-Host "         $($test.guidance.if_allowed)" -ForegroundColor Yellow
                }
                if ($test.guidance -and $test.guidance.mitre_reference) {
                    Write-Host "         Reference: $($test.guidance.mitre_reference)" -ForegroundColor DarkCyan
                }
            }
            'detected' {
                Write-Host "`r$prefix " -NoNewline
                Write-Host 'DETECTED' -ForegroundColor Cyan -NoNewline
                Write-Host " $($test.technique_id) | $($test.name)" -ForegroundColor White
                if ($testResult.ErrorMessage) {
                    Write-Host "         $($testResult.ErrorMessage)" -ForegroundColor DarkCyan
                }
            }
            'error' {
                Write-Host "`r$prefix " -NoNewline
                Write-Host 'ERROR  ' -ForegroundColor Yellow -NoNewline
                Write-Host " $($test.technique_id) | $($test.name)" -ForegroundColor White
                if ($testResult.ErrorMessage) {
                    Write-Host "         $($testResult.ErrorMessage)" -ForegroundColor DarkYellow
                }
            }
            'skipped' {
                Write-Host "`r$prefix " -NoNewline
                Write-Host 'SKIP   ' -ForegroundColor DarkGray -NoNewline
                Write-Host " $($test.technique_id) | $($test.name)" -ForegroundColor White
            }
        }
        # Show resource info if verbose
        if ($VerbosePreference -eq 'Continue' -and $test.resources) {
            $res = $test.resources
            if ($res.lolbas_url) { Write-Verbose "  LOLBAS: $($res.lolbas_url)" }
            if ($res.loldrivers_url) { Write-Verbose "  LOLDrivers: $($res.loldrivers_url)" }
            if ($res.atomic_url) { Write-Verbose "  Atomic RT: $($res.atomic_url)" }
            if ($res.driver_sha256) { Write-Verbose "  Driver SHA256: $($res.driver_sha256)" }
        }

        # Write to log file
        $logVerdict = if ($testResult.Verdict -in @('blocked', 'detected', 'allowed', 'error')) {
            $testResult.Verdict
        } else {
            'error'
        }

        Write-TestLog -LogPath $logPath `
            -TestName $test.name `
            -TechniqueId $test.technique_id `
            -Verdict $logVerdict `
            -Reason $testResult.ErrorMessage `
            -ExecutionTimeMs $testResult.ExecutionTimeMs `
            -ExitCode $testResult.ExitCode

        # Run cleanup whenever the process may have run, including detection-only outcomes.
        if ($testResult.Verdict -in @('allowed', 'detected') -and $test.cleanup_command -and -not $WhatIfPreference) {
            try {
                $cleanup = Invoke-TestProcess `
                    -Command $test.cleanup_command `
                    -Executor $test.executor `
                    -TimeoutSeconds ([Math]::Min($prerequisiteTimeoutSeconds, 600))
                if (-not $cleanup.ProcessStarted -or $cleanup.TimedOut -or $cleanup.ExitCode -ne 0) {
                    Write-Host '         Cleanup did not complete successfully' -ForegroundColor DarkYellow
                }
            }
            catch {
                Write-Host "         Cleanup failed: $_" -ForegroundColor DarkYellow
            }
        }
    }

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    $runCompletedAt = (Get-Date).ToUniversalTime().ToString('o')
    $sensorLogs = Get-UecSensorLogs
    $debugLogs = New-DebugLogs -Results @($allResults) -Tests @($tests)
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '    Results summary' -ForegroundColor Cyan
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host "    Total tests : $($tests.Count)" -ForegroundColor White
    Write-Host '    Blocked     : ' -NoNewline -ForegroundColor White
    Write-Host "$($summary.blocked)" -ForegroundColor Green
    Write-Host '    Detected    : ' -NoNewline -ForegroundColor White
    Write-Host "$($summary.detected)" -ForegroundColor Cyan
    Write-Host '    Allowed     : ' -NoNewline -ForegroundColor White
    Write-Host "$($summary.allowed)" -ForegroundColor Red
    Write-Host '    Errors      : ' -NoNewline -ForegroundColor White
    Write-Host "$($summary.error)" -ForegroundColor Yellow
    Write-Host '    Skipped     : ' -NoNewline -ForegroundColor White
    Write-Host "$($summary.skipped)" -ForegroundColor DarkGray
    Write-Host '  ============================================================' -ForegroundColor Cyan

    # Prevention score
    $executed = $summary.blocked + $summary.detected + $summary.allowed
    $visible = $summary.blocked + $summary.detected
    if ($executed -gt 0) {
        $score = [math]::Round(($summary.blocked / $executed) * 100, 1)
        $scoreColor = if ($score -ge 80) { 'Green' } elseif ($score -ge 50) { 'Yellow' } else { 'Red' }
        Write-Host "    Prevention  : " -NoNewline -ForegroundColor White
        Write-Host "${score}% ($($summary.blocked)/$executed tests blocked)" -ForegroundColor $scoreColor
        $visibility = [math]::Round(($visible / $executed) * 100, 1)
        Write-Host '    Visibility  : ' -NoNewline -ForegroundColor White
        Write-Host "${visibility}% ($visible/$executed tests blocked or detected)" -ForegroundColor $scoreColor
        Write-Host '  ============================================================' -ForegroundColor Cyan
    }

    Write-Host ''

    # ------------------------------------------------------------------
    # Remediation Report (for ALLOWED tests)
    # ------------------------------------------------------------------
    $allowedTests = @($allResults | Where-Object { $_.Verdict -eq 'allowed' })
    if ($allowedTests.Count -gt 0) {
        Write-Host '  ============================================================' -ForegroundColor Red
    Write-Host '    Remediation needed' -ForegroundColor Red
        Write-Host '  ============================================================' -ForegroundColor Red
        Write-Host ''
        Write-Host "    The following $($allowedTests.Count) test(s) were not blocked:" -ForegroundColor White
        Write-Host ''

        $remediationIndex = 0
        foreach ($allowed in $allowedTests) {
            $remediationIndex++
            $matchingTest = $tests | Where-Object { $_.id -eq $allowed.TestId } | Select-Object -First 1

            Write-Host "    $remediationIndex. $($allowed.TechniqueId) | $($allowed.TestName)" -ForegroundColor Red

            if ($matchingTest -and $matchingTest.guidance -and $matchingTest.guidance.if_allowed) {
                Write-Host "       $($matchingTest.guidance.if_allowed)" -ForegroundColor Yellow
            }
            if ($matchingTest -and $matchingTest.technique_url) {
                Write-Host "       MITRE: $($matchingTest.technique_url)" -ForegroundColor DarkCyan
            }
            if ($matchingTest -and $matchingTest.resources) {
                $res = $matchingTest.resources
                if ($res.lolbas_url) { Write-Host "       LOLBAS: $($res.lolbas_url)" -ForegroundColor DarkCyan }
                if ($res.loldrivers_url) { Write-Host "       LOLDrivers: $($res.loldrivers_url)" -ForegroundColor DarkCyan }
                if ($res.atomic_url) { Write-Host "       Atomic: $($res.atomic_url)" -ForegroundColor DarkCyan }
            }
            Write-Host ''
        }
        Write-Host '  ============================================================' -ForegroundColor Red
    }

    Write-Host ''

    # ------------------------------------------------------------------
    # Save results locally
    # ------------------------------------------------------------------
    $hostName = try { [System.Net.Dns]::GetHostName() } catch { $env:COMPUTERNAME }
    $platform = if ($env:OS -eq 'Windows_NT') { 'windows' } elseif ($IsMacOS) { 'macos' } elseif ($IsLinux) { 'linux' } else { 'unknown' }
    $osVersion = try { [System.Environment]::OSVersion.VersionString } catch { '' }
    $outputPayload = @{
        atomic_prevention_version = $Script:ModuleVersion
        run_timestamp         = (Get-Date -Format 'o')
        agent_name            = 'powershell-agent'
        started_at            = $runStartedAt
        completed_at          = $runCompletedAt
        hostname              = $hostName
        platform              = $platform
        os_version            = $osVersion
        agent_version         = $Script:ModuleVersion
        playbook              = @{
            id              = $playbookMeta.id
            name            = $playbookMeta.name
            adversary_group = $playbookMeta.adversary_group
        }
        summary               = $summary
        performance           = @{}
        sensor_logs           = @($sensorLogs)
        debug_logs            = @($debugLogs)
        results                = @($allResults)
    }

    try {
        $outputPayload | ConvertTo-Json -Depth 10 | Set-Content -Path $resultPath -Encoding UTF8
        Write-Host "  [*] Results saved to: $resultPath" -ForegroundColor White
        Write-Host "  [*] Log saved to   : $logPath" -ForegroundColor White
    }
    catch {
        Write-Host "  [!] Failed to save results: $_" -ForegroundColor Red
    }

    # ------------------------------------------------------------------
    # Upload results to server (if configured)
    # ------------------------------------------------------------------
    if ($ServerUrl -and -not $WhatIfPreference) {
        $uploadResponse = Send-Results `
            -ServerUrl $ServerUrl `
            -PlaybookId $playbookMeta.id `
            -Results @($allResults) `
            -StartedAt $runStartedAt `
            -CompletedAt $runCompletedAt `
            -Platform $platform `
            -OsVersion $osVersion `
            -AgentVersion $Script:ModuleVersion `
            -SensorLogs @($sensorLogs) `
            -DebugLogs @($debugLogs) `
            -ResultsEndpoint $resultsEndpoint

        if ($uploadResponse.Success) {
            Write-Host "  [*] Results uploaded. Run ID: $($uploadResponse.RunId)" -ForegroundColor Green
        }
    }
    elseif ($ServerUrl -and $WhatIfPreference) {
        Write-Host '  [*] Dry-run mode: skipping result upload to server.' -ForegroundColor Yellow
    }

    Write-Host ''

    # Return the results for pipeline use
    return [PSCustomObject]@{
        PlaybookId = $playbookMeta.id
        PlaybookName = $playbookMeta.name
        Summary = $summary
        Results = @($allResults)
        ResultsFile = $resultPath
        LogFile = $logPath
    }
}
