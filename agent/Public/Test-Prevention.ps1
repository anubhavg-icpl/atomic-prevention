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
        function Complete-TestResult {
            param([hashtable]$Result)
            if (-not $Result.CompletedAt) {
                $Result.CompletedAt = (Get-Date).ToUniversalTime().ToString('o')
                $Result.completed_at = $Result.CompletedAt
            }
            return $Result
        }

        function Add-TestAgentLog {
            param(
                [hashtable]$Result,
                [ValidateSet('debug', 'info', 'error')]
                [string]$Level,
                [string]$Phase,
                [string]$Message = '',
                [string]$Command = '',
                [hashtable]$Execution = $null
            )

            $entry = @{
                timestamp = (Get-Date).ToUniversalTime().ToString('o')
                level     = $Level
                phase     = $Phase
                message   = Get-RedactedText $Message 1000
            }
            if ($Command) { $entry.command = Get-RedactedText $Command 2000 }
            if ($Execution) {
                $entry.exit_code = $Execution.ExitCode
                $entry.duration_ms = $Execution.ExecutionTimeMs
                $entry.error = Get-RedactedText $Execution.ErrorMessage 2000
                $entry.stdout = Get-RedactedText $Execution.StdOut 2000
                $entry.stderr = Get-RedactedText $Execution.StdErr 2000
            }
            $Result.AgentLogs.Add($entry)
        }

        $testStartedAt = (Get-Date).ToUniversalTime().ToString('o')
        $result = @{
            TestId = $Test.id
            TestName = $Test.name
            TechniqueId = $Test.technique_id
            Verdict = 'error'
            StartedAt = $testStartedAt
            started_at = $testStartedAt
            executed_at = $testStartedAt
            CompletedAt = $null
            completed_at = $null
            ExitCode = $null
            ErrorMessage = $null
            ExecutionTimeMs = 0
            StdOut = ''
            StdErr = ''
            AgentLogs = [System.Collections.Generic.List[hashtable]]::new()
        }

        if ([string]::IsNullOrWhiteSpace($Test.command)) {
            $result.ErrorMessage = 'Test has no command defined'
            Add-TestAgentLog -Result $result -Level error -Phase validate -Message $result.ErrorMessage
            return (Complete-TestResult $result)
        }
        if ([string]::IsNullOrWhiteSpace($Test.executor)) {
            $result.ErrorMessage = 'Test has no executor defined'
            Add-TestAgentLog -Result $result -Level error -Phase validate -Message $result.ErrorMessage
            return (Complete-TestResult $result)
        }
        if ($Test.PSObject.Properties.Name -contains 'runnable' -and $Test.runnable -eq $false) {
            $result.ErrorMessage = 'Test is not marked runnable'
            Add-TestAgentLog -Result $result -Level error -Phase validate -Message $result.ErrorMessage
            return (Complete-TestResult $result)
        }
        if (-not $PSCmdlet.ShouldProcess(
            "$($Test.name) ($($Test.technique_id))",
            "Execute prevention test [$($Test.executor)]: $($Test.command)"
        )) {
            $result.Verdict = 'skipped'
            $result.ErrorMessage = 'Dry-run mode: test was not executed'
            Add-TestAgentLog -Result $result -Level debug -Phase skip -Message $result.ErrorMessage
            return (Complete-TestResult $result)
        }

        Add-TestAgentLog -Result $result -Level debug -Phase start -Message "Prepared $($Test.executor) test" -Command $Test.command

        foreach ($prerequisite in @($Test.prerequisites)) {
            if (-not $prerequisite) { continue }
            $executor = if ($prerequisite.executor) { $prerequisite.executor } else { $Test.executor }
            $checkCommand = [string]$prerequisite.check_command
            $getCommand = [string]$prerequisite.get_command
            $description = [string]$prerequisite.description

            if ([string]::IsNullOrWhiteSpace($checkCommand)) {
                if ([string]::IsNullOrWhiteSpace($getCommand)) { continue }
                $setupOnly = Invoke-TestProcess -Command $getCommand -Executor $executor -TimeoutSeconds $PrerequisiteTimeoutSeconds
                Add-TestAgentLog -Result $result -Level debug -Phase prerequisite_setup -Command $getCommand -Execution $setupOnly
                if (-not $setupOnly.ProcessStarted -or $setupOnly.TimedOut -or $setupOnly.ExitCode -ne 0) {
                    $result.ErrorMessage = "Prerequisite setup failed: $description"
                    $result.StdOut = Get-RedactedText $setupOnly.StdOut
                    $result.StdErr = Get-RedactedText $setupOnly.StdErr
                    return (Complete-TestResult $result)
                }
                continue
            }

            $check = Invoke-TestProcess -Command $checkCommand -Executor $executor -TimeoutSeconds $PrerequisiteTimeoutSeconds
            Add-TestAgentLog -Result $result -Level debug -Phase prerequisite_check -Command $checkCommand -Execution $check
            if ($check.ProcessStarted -and -not $check.TimedOut -and $check.ExitCode -eq 0) {
                continue
            }
            if ([string]::IsNullOrWhiteSpace($getCommand)) {
                $result.ErrorMessage = "Prerequisite is not satisfied and has no setup command: $description"
                $result.StdOut = Get-RedactedText $check.StdOut
                $result.StdErr = Get-RedactedText $check.StdErr
                return (Complete-TestResult $result)
            }

            $setup = Invoke-TestProcess -Command $getCommand -Executor $executor -TimeoutSeconds $PrerequisiteTimeoutSeconds
            Add-TestAgentLog -Result $result -Level debug -Phase prerequisite_setup -Command $getCommand -Execution $setup
            if (-not $setup.ProcessStarted -or $setup.TimedOut -or $setup.ExitCode -ne 0) {
                $result.ErrorMessage = "Prerequisite setup failed: $description"
                $result.StdOut = Get-RedactedText $setup.StdOut
                $result.StdErr = Get-RedactedText $setup.StdErr
                return (Complete-TestResult $result)
            }

            $recheck = Invoke-TestProcess -Command $checkCommand -Executor $executor -TimeoutSeconds $PrerequisiteTimeoutSeconds
            Add-TestAgentLog -Result $result -Level debug -Phase prerequisite_recheck -Command $checkCommand -Execution $recheck
            if (-not $recheck.ProcessStarted -or $recheck.TimedOut -or $recheck.ExitCode -ne 0) {
                $result.ErrorMessage = "Prerequisite remains unsatisfied after setup: $description"
                $result.StdOut = Get-RedactedText $recheck.StdOut
                $result.StdErr = Get-RedactedText $recheck.StdErr
                return (Complete-TestResult $result)
            }
        }

        $execution = Invoke-TestProcess -Command $Test.command -Executor $Test.executor -TimeoutSeconds $TimeoutSeconds
        $result.ExitCode = $execution.ExitCode
        $result.ExecutionTimeMs = $execution.ExecutionTimeMs
        $result.ProcessStarted = $execution.ProcessStarted
        $result.TimedOut = $execution.TimedOut
        $result.StdOut = Get-RedactedText $execution.StdOut
        $result.StdErr = Get-RedactedText $execution.StdErr
        Add-TestAgentLog -Result $result -Level info -Phase execute -Command $Test.command -Execution $execution

        $verdict = Get-ExecutionVerdict `
            -ProcessStarted $execution.ProcessStarted `
            -ExitCode $execution.ExitCode `
            -TimedOut $execution.TimedOut `
            -ErrorRecord $execution.ErrorRecord `
            -StdOut $execution.StdOut `
            -StdErr $execution.StdErr

        $result.Verdict = $verdict.Verdict
        $result.ErrorMessage = $verdict.Reason
        $logLevel = if ($result.Verdict -in @('blocked', 'detected', 'allowed')) { 'info' } else { 'error' }
        Add-TestAgentLog -Result $result -Level $logLevel -Phase verdict -Message $verdict.Reason
        return (Complete-TestResult $result)
    }
}
