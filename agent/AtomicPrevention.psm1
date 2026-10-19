#Requires -Version 5.1

<#
.SYNOPSIS
    Atomic Prevention Prevention Validation Agent

.DESCRIPTION
    This module provides the execution engine for Atomic Prevention prevention
    validation playbooks. It loads playbook JSON files exported from the
    Atomic Prevention backend and runs each test to determine whether endpoint
    security controls BLOCK or ALLOW the adversary technique.

    DISCLAIMER: This tool is intended for authorized security testing only.
    Run it exclusively in environments where you have explicit permission to
    execute prevention validation tests. The authors accept no liability for
    misuse. All tests are derived from publicly documented adversary
    techniques and are designed to validate that security controls are
    functioning correctly.
#>

$Script:ModuleName = 'AtomicPrevention'
$Script:ModuleVersion = '0.1.0'

# Dot-source all private functions
$PrivatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'
if (Test-Path -Path $PrivatePath) {
    foreach ($script in (Get-ChildItem -Path $PrivatePath -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        . $script.FullName
    }
}

# Dot-source all public functions
$PublicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
if (Test-Path -Path $PublicPath) {
    foreach ($script in (Get-ChildItem -Path $PublicPath -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        . $script.FullName
    }
}

Export-ModuleMember -Function @(
    'Invoke-AtomicPrevention'
    'Test-Prevention'
    'Test-DriverLoad'
    'Send-Results'
    'New-EvasionTest'
)
