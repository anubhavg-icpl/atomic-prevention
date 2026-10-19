@{
    RootModule        = 'AtomicPrevention.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a3f7c8e1-9d42-4b6a-8e5f-1c2d3e4f5a6b'
    Author            = 'Atomic Prevention Project'
    CompanyName       = 'Atomic Prevention'
    Copyright         = '(c) 2026 Atomic Prevention Project. All rights reserved.'
    Description       = 'Prevention validation agent for Atomic Prevention. Executes playbook tests to determine whether endpoint security controls block or allow adversary techniques.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-AtomicPrevention'
        'Test-Prevention'
        'Test-DriverLoad'
        'Send-Results'
        'New-EvasionTest'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Security', 'Prevention', 'MITRE', 'ATT&CK', 'AtomicRedTeam')
            ProjectUri   = 'https://github.com/anubhavg-icpl/atomic-prevention'
            LicenseUri   = 'https://github.com/anubhavg-icpl/atomic-prevention/blob/main/LICENSE'
            ReleaseNotes = 'Initial release of the Atomic Prevention prevention validation agent.'
        }
    }
}
