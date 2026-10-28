function Invoke-TestProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [Parameter(Mandatory)]
        [string]$Executor,

        [Parameter(Mandatory)]
        [ValidateRange(1, 600)]
        [int]$TimeoutSeconds
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    $commandFile = $null
    $processArgs = @{}

    switch ($Executor.ToLower()) {
        'powershell' {
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
            $processArgs = @{
                FilePath = 'powershell.exe'
                ArgumentList = @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded)
            }
        }
        { $_ -in @('cmd', 'command_prompt') } {
            $commandFile = Join-Path $env:TEMP "magic-atomic-$([guid]::NewGuid().ToString('N')).cmd"
            Set-Content -Path $commandFile -Value $Command -Encoding ASCII
            $processArgs = @{
                FilePath = 'cmd.exe'
                ArgumentList = @('/d', '/s', '/c', "`"$commandFile`"")
            }
        }
        default {
            return @{
                ProcessStarted = $false
                ExitCode = $null
                TimedOut = $false
                ErrorRecord = $null
                StdOut = ''
                StdErr = ''
                ErrorMessage = "Unsupported executor on Windows: $Executor"
                ExecutionTimeMs = 0
            }
        }
    }

    $process = $null
    $started = $false
    $timedOut = $false
    $errorRecord = $null
    $exitCode = $null
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()

    try {
        $process = Start-Process @processArgs -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -ErrorAction Stop
        $started = $true
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try {
                $process.Kill()
                $process.WaitForExit(2000) | Out-Null
            }
            catch {}
        }
        if ($process.HasExited) {
            $exitCode = $process.ExitCode
        }
    }
    catch {
        $errorRecord = $_
    }
    finally {
        $stopwatch.Stop()
    }

    $stdout = if (Test-Path $stdoutPath) { Get-Content $stdoutPath -Raw -ErrorAction SilentlyContinue } else { '' }
    $stderr = if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw -ErrorAction SilentlyContinue } else { '' }
    Remove-Item $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    if ($commandFile) {
        Remove-Item $commandFile -Force -ErrorAction SilentlyContinue
    }

    $errorMessage = $null
    if ($errorRecord) {
        $errorMessage = $errorRecord.Exception.Message
    }

    return @{
        StartedAt = (Get-Date).ToUniversalTime().ToString('o')
        ProcessStarted = $started
        ExitCode = $exitCode
        TimedOut = $timedOut
        ErrorRecord = $errorRecord
        StdOut = [string]$stdout
        StdErr = [string]$stderr
        ErrorMessage = $errorMessage
        ExecutionTimeMs = [int]$stopwatch.Elapsed.TotalMilliseconds
    }
}
