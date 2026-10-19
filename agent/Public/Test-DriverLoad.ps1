function Test-DriverLoad {
    <#
    .SYNOPSIS
        Tests whether a vulnerable driver can be loaded on the endpoint.

    .DESCRIPTION
        Downloads a known-vulnerable driver binary, verifies its SHA256 hash,
        and attempts to load it as a kernel-mode service using multiple methods:

          1. sc.exe create + sc.exe start  (most common adversary method)
          2. PowerShell New-Service         (alternative .NET-based method)

        After each attempt the function checks whether HVCI, WDAC, driver
        signing enforcement, or other security controls blocked the load.
        All artifacts are cleaned up regardless of outcome.

        This function is the agent-side companion to the LOLDrivers ingestion
        in the Atomic Prevention backend.  It can also be used standalone for
        ad-hoc BYOVD prevention validation.

        DISCLAIMER: This function is for AUTHORIZED prevention validation
        only.  Driver loading requires Administrator privileges and can
        affect system stability.  Only run on systems where you have
        explicit permission to perform kernel-level security testing.

    .PARAMETER DriverUrl
        URL to download the driver .sys file from.  If omitted the function
        expects the file to already exist at the path implied by DriverName
        inside $env:TEMP.

    .PARAMETER DriverName
        The .sys filename the driver should be saved/renamed to (e.g.
        "procexp.sys").  This is the name sc.exe and New-Service will use
        when registering the kernel service.

    .PARAMETER DriverHash
        Expected SHA256 hash of the driver binary.  The function will
        refuse to load a driver whose hash does not match.

    .PARAMETER DriverPath
        Optional explicit path to a local driver file.  When provided the
        function skips the download step and uses this file directly.

    .PARAMETER Methods
        Which loading methods to attempt.  Accepts an array of one or more
        of: 'ScExe', 'NewService'.  Defaults to both.

    .PARAMETER SkipCleanup
        If specified, does NOT remove the service or driver file after
        testing.  Useful for debugging but not recommended for production
        validation runs.

    .OUTPUTS
        A PSCustomObject with properties:
          DriverName      - The .sys filename tested
          DriverHash      - SHA256 of the file on disk
          HashVerified    - $true if the hash matched expectations
          Methods         - Array of per-method result objects
          OverallVerdict  - 'blocked' | 'allowed' | 'error'
          CleanedUp       - $true if cleanup succeeded

    .EXAMPLE
        Test-DriverLoad -DriverName "procexp.sys" -DriverHash "ced9f5..."

    .EXAMPLE
        Test-DriverLoad -DriverUrl "https://example.com/driver.sys" `
                        -DriverName "rtcore64.sys" `
                        -DriverHash "01aa27..."

    .EXAMPLE
        Test-DriverLoad -DriverPath "C:\Samples\dbutil_2_3.sys" `
                        -DriverName "dbutil_2_3.sys" `
                        -DriverHash "0296e2..."
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string]$DriverUrl,

        [Parameter(Mandatory)]
        [ValidatePattern('\.sys$')]
        [string]$DriverName,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$DriverHash,

        [Parameter()]
        [string]$DriverPath,

        [Parameter()]
        [ValidateSet('ScExe', 'NewService')]
        [string[]]$Methods = @('ScExe', 'NewService'),

        [Parameter()]
        [switch]$SkipCleanup
    )

    # ------------------------------------------------------------------
    # Elevation check
    # ------------------------------------------------------------------
    $isAdmin = $false
    try {
        $currentPrincipal = [Security.Principal.WindowsPrincipal](
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )
        $isAdmin = $currentPrincipal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch {
        # Unable to determine; will likely fail at sc.exe anyway
    }

    if (-not $isAdmin) {
        Write-Warning 'Test-DriverLoad requires Administrator privileges.  Driver loading will almost certainly fail.'
    }

    # ------------------------------------------------------------------
    # Result template
    # ------------------------------------------------------------------
    $result = [PSCustomObject]@{
        DriverName     = $DriverName
        DriverHash     = $DriverHash
        HashVerified   = $false
        Methods        = [System.Collections.Generic.List[PSCustomObject]]::new()
        OverallVerdict = 'error'
        CleanedUp      = $false
        ErrorMessage   = $null
    }

    # ------------------------------------------------------------------
    # Step 1: Acquire the driver file
    # ------------------------------------------------------------------
    $targetPath = $null

    if ($DriverPath -and (Test-Path -Path $DriverPath -PathType Leaf)) {
        # Explicit local path provided
        $targetPath = $DriverPath
        Write-Host "  [*] Using local driver file: $targetPath" -ForegroundColor White
    }
    elseif ($DriverUrl) {
        # Download from URL
        $targetPath = Join-Path $env:TEMP $DriverName
        Write-Host "  [*] Downloading driver from: $DriverUrl" -ForegroundColor White

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $DriverUrl -OutFile $targetPath -UseBasicParsing -ErrorAction Stop
            Write-Host "  [*] Downloaded to: $targetPath" -ForegroundColor White
        }
        catch {
            $result.ErrorMessage = "Download failed: $($_.Exception.Message)"
            Write-Host "  [!] $($result.ErrorMessage)" -ForegroundColor Red
            return $result
        }
    }
    else {
        # Expect the file to already be in %TEMP%
        $targetPath = Join-Path $env:TEMP $DriverName
        if (-not (Test-Path -Path $targetPath -PathType Leaf)) {
            $result.ErrorMessage = (
                "Driver file not found at $targetPath. " +
                "Provide -DriverUrl to download or -DriverPath to specify a local file."
            )
            Write-Host "  [!] $($result.ErrorMessage)" -ForegroundColor Red
            return $result
        }
        Write-Host "  [*] Using existing file: $targetPath" -ForegroundColor White
    }

    # ------------------------------------------------------------------
    # Step 2: Verify SHA256 hash
    # ------------------------------------------------------------------
    Write-Host '  [*] Verifying SHA256 hash...' -ForegroundColor White
    try {
        $actualHash = (Get-FileHash -Path $targetPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        $expectedHash = $DriverHash.ToLower()

        if ($actualHash -eq $expectedHash) {
            $result.HashVerified = $true
            Write-Host "  [*] Hash verified: $actualHash" -ForegroundColor Green
        }
        else {
            $result.HashVerified = $false
            $result.ErrorMessage = "Hash mismatch! Expected: $expectedHash, Got: $actualHash"
            Write-Host "  [!] $($result.ErrorMessage)" -ForegroundColor Red
            Write-Host '  [!] Refusing to load unverified driver. Aborting.' -ForegroundColor Red
            return $result
        }
    }
    catch {
        $result.ErrorMessage = "Hash verification failed: $($_.Exception.Message)"
        Write-Host "  [!] $($result.ErrorMessage)" -ForegroundColor Red
        return $result
    }

    $result.DriverHash = $actualHash

    # ------------------------------------------------------------------
    # Step 3: Attempt driver loading via each requested method
    # ------------------------------------------------------------------
    $anyAllowed = $false
    $anyBlocked = $false

    foreach ($method in $Methods) {
        # Build a unique service name per method to avoid collisions
        $hashPrefix = $actualHash.Substring(0, 12)
        $svcSuffix = switch ($method) { 'ScExe' { 'sc' } 'NewService' { 'ps' } }
        $svcName = "AtomicPrevention_${hashPrefix}_${svcSuffix}"

        $methodResult = [PSCustomObject]@{
            Method       = $method
            ServiceName  = $svcName
            Verdict      = 'error'
            ExitCode     = $null
            Output       = ''
            ErrorMessage = $null
            DurationMs   = 0
        }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        if (-not $PSCmdlet.ShouldProcess("$DriverName via $method", 'Load kernel driver')) {
            $methodResult.Verdict = 'skipped'
            $methodResult.ErrorMessage = 'Dry-run mode'
            $sw.Stop()
            $methodResult.DurationMs = [int]$sw.Elapsed.TotalMilliseconds
            $result.Methods.Add($methodResult)
            continue
        }

        switch ($method) {
            # ----------------------------------------------------------
            # Method 1: sc.exe create + sc.exe start
            # ----------------------------------------------------------
            'ScExe' {
                Write-Host "  [>] Method: sc.exe create/start ($svcName)" -ForegroundColor Cyan

                try {
                    # Create the kernel service
                    $createOut = & sc.exe create $svcName type= kernel binPath= "$targetPath" 2>&1
                    $createExit = $LASTEXITCODE
                    Write-Host "      sc create exit=$createExit : $createOut" -ForegroundColor DarkGray

                    if ($createExit -ne 0) {
                        $methodResult.Verdict = 'blocked'
                        $methodResult.ExitCode = $createExit
                        $methodResult.Output = "$createOut"
                        $methodResult.ErrorMessage = "sc.exe create failed (exit $createExit)"
                        $anyBlocked = $true
                    }
                    else {
                        # Attempt to start
                        $startOut = & sc.exe start $svcName 2>&1
                        $startExit = $LASTEXITCODE
                        Write-Host "      sc start exit=$startExit : $startOut" -ForegroundColor DarkGray

                        $methodResult.ExitCode = $startExit
                        $methodResult.Output = "$startOut"

                        if ($startExit -eq 0) {
                            $methodResult.Verdict = 'allowed'
                            $anyAllowed = $true
                            Write-Host '      ALLOWED: Driver loaded successfully' -ForegroundColor Red
                        }
                        else {
                            # Check for known block indicators
                            $outStr = "$startOut"
                            $blockPatterns = @(
                                'blocked', 'denied', 'not valid',
                                'not trusted', 'hash', 'policy',
                                'cannot verify', 'signature',
                                '577', '1275', '1276'
                            )
                            $isBlock = $false
                            foreach ($pat in $blockPatterns) {
                                if ($outStr -like "*$pat*") {
                                    $isBlock = $true
                                    break
                                }
                            }

                            if ($isBlock) {
                                $methodResult.Verdict = 'blocked'
                                $anyBlocked = $true
                                Write-Host '      BLOCKED: Security control prevented driver start' -ForegroundColor Green
                            }
                            else {
                                # Non-zero but not a clear block -- treat as error
                                $methodResult.Verdict = 'error'
                                $methodResult.ErrorMessage = "sc.exe start returned exit $startExit (inconclusive)"
                            }
                        }
                    }
                }
                catch {
                    $methodResult.Verdict = 'blocked'
                    $methodResult.ErrorMessage = $_.Exception.Message
                    $anyBlocked = $true
                    Write-Host "      BLOCKED: $($_.Exception.Message)" -ForegroundColor Green
                }
            }

            # ----------------------------------------------------------
            # Method 2: PowerShell New-Service + Start-Service
            # ----------------------------------------------------------
            'NewService' {
                Write-Host "  [>] Method: New-Service ($svcName)" -ForegroundColor Cyan

                try {
                    New-Service -Name $svcName `
                        -BinaryPathName $targetPath `
                        -DisplayName 'AtomicPrevention HVCI Driver Test' `
                        -StartupType Manual `
                        -ServiceType KernelDriver `
                        -ErrorAction Stop | Out-Null

                    Write-Host '      Service created via New-Service' -ForegroundColor DarkGray

                    try {
                        Start-Service -Name $svcName -ErrorAction Stop
                        $methodResult.Verdict = 'allowed'
                        $methodResult.ExitCode = 0
                        $anyAllowed = $true
                        Write-Host '      ALLOWED: Driver loaded via New-Service' -ForegroundColor Red
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        $methodResult.Output = $errMsg
                        $methodResult.ExitCode = 1

                        $blockPatterns = @(
                            'blocked', 'denied', 'not valid',
                            'not trusted', 'policy', 'signature',
                            'hash', 'cannot verify',
                            '577', '1275', '1276'
                        )
                        $isBlock = $false
                        foreach ($pat in $blockPatterns) {
                            if ($errMsg -like "*$pat*") {
                                $isBlock = $true
                                break
                            }
                        }

                        if ($isBlock) {
                            $methodResult.Verdict = 'blocked'
                            $anyBlocked = $true
                            Write-Host "      BLOCKED: $errMsg" -ForegroundColor Green
                        }
                        else {
                            $methodResult.Verdict = 'error'
                            $methodResult.ErrorMessage = "Start-Service failed: $errMsg"
                        }
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    $methodResult.Verdict = 'blocked'
                    $methodResult.ErrorMessage = $errMsg
                    $methodResult.Output = $errMsg
                    $anyBlocked = $true
                    Write-Host "      BLOCKED: $errMsg" -ForegroundColor Green
                }
            }
        }

        $sw.Stop()
        $methodResult.DurationMs = [int]$sw.Elapsed.TotalMilliseconds
        $result.Methods.Add($methodResult)
    }

    # ------------------------------------------------------------------
    # Step 4: Determine overall verdict
    # ------------------------------------------------------------------
    if ($anyAllowed) {
        $result.OverallVerdict = 'allowed'
    }
    elseif ($anyBlocked) {
        $result.OverallVerdict = 'blocked'
    }
    else {
        $result.OverallVerdict = 'error'
    }

    # ------------------------------------------------------------------
    # Step 5: Cleanup
    # ------------------------------------------------------------------
    if (-not $SkipCleanup) {
        Write-Host '  [*] Cleaning up...' -ForegroundColor White
        $cleanupOk = $true

        foreach ($methodResult in $result.Methods) {
            $svc = $methodResult.ServiceName
            if (-not $svc) { continue }

            try {
                # Stop the service if running
                $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($svcObj -and $svcObj.Status -eq 'Running') {
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500
                }
                # Delete the service registration
                $null = & sc.exe delete $svc 2>&1
            }
            catch {
                $cleanupOk = $false
                Write-Host "      Cleanup warning ($svc): $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
        }

        # Remove the driver file (only if we put it in %TEMP%)
        if (-not $DriverPath) {
            try {
                $tempFile = Join-Path $env:TEMP $DriverName
                if (Test-Path $tempFile) {
                    Remove-Item -Path $tempFile -Force -ErrorAction Stop
                    Write-Host "      Removed: $tempFile" -ForegroundColor DarkGray
                }
            }
            catch {
                $cleanupOk = $false
                Write-Host "      Cleanup warning: could not remove $tempFile" -ForegroundColor DarkYellow
            }
        }

        $result.CleanedUp = $cleanupOk
        Write-Host '  [*] Cleanup complete.' -ForegroundColor White
    }
    else {
        Write-Host '  [!] SkipCleanup specified - services and files left in place.' -ForegroundColor Yellow
    }

    # ------------------------------------------------------------------
    # Summary line
    # ------------------------------------------------------------------
    $verdictColor = switch ($result.OverallVerdict) {
        'blocked' { 'Green' }
        'allowed' { 'Red' }
        default   { 'Yellow' }
    }
    Write-Host ''
    Write-Host "  Result: $($result.OverallVerdict.ToUpper()) - $DriverName" -ForegroundColor $verdictColor
    Write-Host ''

    return $result
}
