function Test-Prevention {
    <#
    .SYNOPSIS
        Executes one prevention test with verified prerequisite handling.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Test,

        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 5,

        [ValidateRange(1, 600)]
        [int]$PrerequisiteTimeoutSeconds = 120
    )

    process {
        $result = @{
            TestId = $Test.id
            TestName = $Test.name
            TechniqueId = $Test.technique_id
            Verdict = 'error'
            ExitCode = $null
            ErrorMessage = $null
            ExecutionTimeMs = 0
            StdOut = ''
            StdErr = ''
        }

        if ([string]::IsNullOrWhiteSpace($Test.command)) {
            $result.ErrorMessage = 'Test has no command defined'
            return $result
        }
        if ([string]::IsNullOrWhiteSpace($Test.executor)) {
            $result.ErrorMessage = 'Test has no executor defined'
            return $result
        }
        if ($Test.PSObject.Properties.Name -contains 'runnable' -and $Test.runnable -eq $false) {
            $result.ErrorMessage = 'Test is not marked runnable'
            return $result
        }
        if (-not $PSCmdlet.ShouldProcess(
            "$($Test.name) ($($Test.technique_id))",
            "Execute prevention test [$($Test.executor)]: $($Test.command)"
        )) {
            $result.Verdict = 'skipped'
            $result.ErrorMessage = 'Dry-run mode: test was not executed'
            return $result
        }

        foreach ($prerequisite in @($Test.prerequisites)) {
            if (-not $prerequisite) { continue }
            $executor = if ($prerequisite.executor) { $prerequisite.executor } else { $Test.executor }
            $checkCommand = [string]$prerequisite.check_command
            $getCommand = [string]$prerequisite.get_command
            $description = [string]$prerequisite.description

            if ([string]::IsNullOrWhiteSpace($checkCommand)) {
                if ([string]::IsNullOrWhiteSpace($getCommand)) { continue }
                $setupOnly = Invoke-TestProcess -Command $getCommand -Executor $executor -TimeoutSeconds $PrerequisiteTimeoutSeconds
                if (-not $setupOnly.ProcessStarted -or $setupOnly.TimedOut -or $setupOnly.ExitCode -ne 0) {
                    $result.ErrorMessage = "Prerequisite setup failed: $description"
                    $result.StdOut = $setupOnly.StdOut
                    $result.StdErr = $setupOnly.StdErr
                    return $result
                }
                continue
            }

            $check = Invoke-TestProcess -Command $checkCommand -Executor $executor -TimeoutSeconds $PrerequisiteTimeoutSeconds
            if ($check.ProcessStarted -and -not $check.TimedOut -and $check.ExitCode -eq 0) {
                continue
            }
            if ([string]::IsNullOrWhiteSpace($getCommand)) {
                $result.ErrorMessage = "Prerequisite is not satisfied and has no setup command: $description"
                $result.StdOut = $check.StdOut
                $result.StdErr = $check.StdErr
                return $result
            }

            $setup = Invoke-TestProcess -Command $getCommand -Executor $executor -TimeoutSeconds $PrerequisiteTimeoutSeconds
            if (-not $setup.ProcessStarted -or $setup.TimedOut -or $setup.ExitCode -ne 0) {
                $result.ErrorMessage = "Prerequisite setup failed: $description"
                $result.StdOut = $setup.StdOut
                $result.StdErr = $setup.StdErr
                return $result
            }

            $recheck = Invoke-TestProcess -Command $checkCommand -Executor $executor -TimeoutSeconds $PrerequisiteTimeoutSeconds
            if (-not $recheck.ProcessStarted -or $recheck.TimedOut -or $recheck.ExitCode -ne 0) {
                $result.ErrorMessage = "Prerequisite remains unsatisfied after setup: $description"
                $result.StdOut = $recheck.StdOut
                $result.StdErr = $recheck.StdErr
                return $result
            }
        }

        $execution = Invoke-TestProcess -Command $Test.command -Executor $Test.executor -TimeoutSeconds $TimeoutSeconds
        $result.ExitCode = $execution.ExitCode
        $result.ExecutionTimeMs = $execution.ExecutionTimeMs
        $result.StdOut = $execution.StdOut
        $result.StdErr = $execution.StdErr

        $verdict = Get-ExecutionVerdict `
            -ProcessStarted $execution.ProcessStarted `
            -ExitCode $execution.ExitCode `
            -TimedOut $execution.TimedOut `
            -ErrorRecord $execution.ErrorRecord `
            -StdOut $execution.StdOut `
            -StdErr $execution.StdErr

        $result.Verdict = $verdict.Verdict
        $result.ErrorMessage = $verdict.Reason
        return $result
    }
}
