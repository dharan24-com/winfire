[CmdletBinding()]
param(
    [string]$ArtifactRoot = (Join-Path $PSScriptRoot "..\artifacts"),
    [string]$MsixUrl = "https://firefox-ci-tc.services.mozilla.com/api/queue/v1/task/dX7_cQx7RHyrDTlnGpbFeA/artifacts/public/build/target.installer.msix",
    [string]$MsixSha256 = "a7d656acc321ed52cd547ede6f540cfb6dd7272fe89d405ab9ebce5daaba813c",
    [int]$BackgroundTaskWaitMinutes = 18
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)
$SourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\src"))
$Nonce = [Guid]::NewGuid().ToString("N")
$WorkRoot = Join-Path $env:RUNNER_TEMP "firefox-msix-poc-$Nonce"
$BuildRoot = Join-Path $WorkRoot "build"
$UnpackedRoot = Join-Path $WorkRoot "unpacked"
$ProfilesRoot = Join-Path $WorkRoot "profiles"
$InputMsix = Join-Path $WorkRoot "firefox-276bad1-unsigned.msix"
$SignedMsix = Join-Path $WorkRoot "firefox-276bad1-test-signed.msix"
$Driver = Join-Path $BuildRoot "poc_driver.exe"
$Payload = Join-Path $BuildRoot "renderer_payload.dll"
$LoadablePayload = $null
$VerdictPath = Join-Path $ArtifactRoot "verdict.json"
$SummaryPath = Join-Path $ArtifactRoot "summary.md"

$InstalledPackage = $null
$SigningCertificate = $null
$ExitCode = 0
$Verdict = [ordered]@{
    status = "HARNESS_ERROR"
    reason = "The harness did not reach a verdict."
    source_commit = "276bad1472c95b721d47f0829c571e6d5b5ef263"
    artifact_source_revision = "e852cbbdfb8baa2989b8d7db78d5ca929dcea9dd"
    autoland_pushlog_id = 276768
    taskcluster_repackage_task = "dX7_cQx7RHyrDTlnGpbFeA"
    api_success = $false
    controlled_arguments_observed = $false
    sandbox_token_observed = $false
    full_trust_token_observed = $false
    application_activation_success = $false
    application_activation_hresult = $null
    application_activation_pid = 0
    application_activation_process_observed = $false
    shell_execute_api_success = $false
    shell_execute_error = $null
    shell_execute_process_observed = $false
    app_exec_alias_success = $false
    app_exec_alias_error = $null
    app_exec_alias_pid = 0
    app_exec_alias_process_observed = $false
    shell_dispatch_api_success = $false
    shell_dispatch_hresult = $null
    shell_dispatch_process_observed = $false
    notification_activation_success = $false
    notification_activation_hresult = $null
    notification_activation_process_observed = $false
    parent_injection_access = $false
    parent_injection_open_error = $null
    sibling_injection_access = $false
    sibling_injection_pid = 0
    sibling_injection_open_error = $null
    background_access_hresult = $null
    background_access_status = $null
    background_task_registered = $false
    background_task_registration_hresult = $null
    background_proxy_process_observed = $false
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 12
    )
    $Value | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}

function Get-WindowsSdkTool {
    param([Parameter(Mandatory)][string]$Name)
    $SdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    $Candidates = @(Get-ChildItem -Path (Join-Path $SdkRoot "*\x64\$Name") -File -ErrorAction SilentlyContinue)
    if ($Candidates.Count -eq 0) {
        throw "Windows SDK tool not found: $Name"
    }
    return $Candidates | Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1
}

function Invoke-DriverJson {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$EvidenceName
    )
    $Output = @(& $Driver @Arguments 2>&1)
    $NativeExitCode = $LASTEXITCODE
    $Text = ($Output | ForEach-Object { $_.ToString() }) -join "`n"
    $Text | Set-Content -LiteralPath (Join-Path $ArtifactRoot $EvidenceName) -Encoding utf8NoBOM
    if ($NativeExitCode -ne 0) {
        throw "poc_driver failed with exit code $NativeExitCode`: $Text"
    }
    return $Text | ConvertFrom-Json
}

function Get-FirefoxProcesses {
    return @(Get-CimInstance Win32_Process -Filter "Name = 'firefox.exe'" -ErrorAction SilentlyContinue)
}

function Wait-FirefoxContentProcess {
    param([datetime]$Deadline)
    do {
        $Match = Get-FirefoxProcesses | Where-Object {
            $_.CommandLine -match "-contentproc" -and $_.CommandLine -match "-isForBrowser"
        } | Select-Object -First 1
        if ($null -ne $Match) {
            return $Match
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $Deadline)
    throw "Timed out waiting for a sandboxed Firefox browser content process."
}

function Wait-EscapedFirefoxProcess {
    param(
        [Parameter(Mandatory)][string]$ProfileMarker,
        [datetime]$Deadline
    )
    do {
        $Match = Get-FirefoxProcesses | Where-Object {
            $_.CommandLine -notmatch "-contentproc" -and $_.CommandLine -like "*$ProfileMarker*"
        } | Select-Object -First 1
        if ($null -ne $Match) {
            return $Match
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $Deadline)
    return $null
}

function Write-Summary {
    param([Parameter(Mandatory)]$Result)
    $Lines = @(
        "# Firefox MSIX full-trust launcher PoC",
        "",
        "**Verdict:** $($Result.status)",
        "",
        $Result.reason,
        "",
        "- Source commit: ``$($Result.source_commit)``",
        "- Artifact source revision: ``$($Result.artifact_source_revision)``",
        "- Autoland pushlog: ``$($Result.autoland_pushlog_id)``",
        "- Taskcluster MSIX task: ``$($Result.taskcluster_repackage_task)``",
        "- WinRT launch reported success: ``$($Result.api_success)``",
        "- Controlled launch marker observed: ``$($Result.controlled_arguments_observed)``",
        "- Restricted content token observed: ``$($Result.sandbox_token_observed)``",
        "- Full-trust token transition observed: ``$($Result.full_trust_token_observed)``",
        "- Renderer packaged-app activation succeeded: ``$($Result.application_activation_success)``",
        "- Packaged-app activation HRESULT: ``$($Result.application_activation_hresult)``",
        "- Packaged-app activation process observed: ``$($Result.application_activation_process_observed)``",
        "- ShellExecute packaged activation succeeded: ``$($Result.shell_execute_api_success)``",
        "- ShellExecute error: ``$($Result.shell_execute_error)``",
        "- ShellExecute process observed: ``$($Result.shell_execute_process_observed)``",
        "- AppExecAlias CreateProcess succeeded: ``$($Result.app_exec_alias_success)``",
        "- AppExecAlias error: ``$($Result.app_exec_alias_error)``",
        "- AppExecAlias process observed: ``$($Result.app_exec_alias_process_observed)``",
        "- Shell.Application activation succeeded: ``$($Result.shell_dispatch_api_success)``",
        "- Shell.Application HRESULT: ``$($Result.shell_dispatch_hresult)``",
        "- Shell.Application process observed: ``$($Result.shell_dispatch_process_observed)``",
        "- Notification COM activation succeeded: ``$($Result.notification_activation_success)``",
        "- Notification COM HRESULT: ``$($Result.notification_activation_hresult)``",
        "- Notification COM process observed: ``$($Result.notification_activation_process_observed)``",
        "- Renderer obtained parent injection access: ``$($Result.parent_injection_access)``",
        "- Parent OpenProcess error: ``$($Result.parent_injection_open_error)``",
        "- Renderer obtained sibling injection access: ``$($Result.sibling_injection_access)``",
        "- Sibling injection PID: ``$($Result.sibling_injection_pid)``",
        "- Sibling OpenProcess error: ``$($Result.sibling_injection_open_error)``",
        "- Background access request HRESULT: ``$($Result.background_access_hresult)``",
        "- Background access status: ``$($Result.background_access_status)``",
        "- Renderer registered package timer: ``$($Result.background_task_registered)``",
        "- Background registration HRESULT: ``$($Result.background_task_registration_hresult)``",
        "- Background-task proxy process observed: ``$($Result.background_proxy_process_observed)``"
    )
    $Lines | Set-Content -LiteralPath $SummaryPath -Encoding utf8NoBOM
}

New-Item -ItemType Directory -Path $ArtifactRoot, $WorkRoot, $BuildRoot, $UnpackedRoot, $ProfilesRoot -Force | Out-Null

try {
    $EnvironmentEvidence = [ordered]@{
        captured_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        os_version = [Environment]::OSVersion.VersionString
        windows_product_name = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
        windows_display_version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
        runner_os = $env:RUNNER_OS
        runner_arch = $env:RUNNER_ARCH
        image_os = $env:ImageOS
        image_version = $env:ImageVersion
        source_commit = $Verdict.source_commit
        source_commit_url = "https://github.com/dharan24-com/firefox_autoland/commit/$($Verdict.source_commit)"
        artifact_source_revision = $Verdict.artifact_source_revision
        artifact_source_url = "https://hg.mozilla.org/integration/autoland/rev/$($Verdict.artifact_source_revision)"
        autoland_pushlog_id = $Verdict.autoland_pushlog_id
        taskcluster_msix_url = $MsixUrl
        expected_msix_sha256 = $MsixSha256
    }
    Write-JsonFile -Value $EnvironmentEvidence -Path (Join-Path $ArtifactRoot "environment.json")

    $VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    $VisualStudio = (& $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
    if (-not $VisualStudio) {
        throw "Visual Studio with the x64 C++ toolchain was not found."
    }
    $VcVars = Join-Path $VisualStudio "VC\Auxiliary\Build\vcvars64.bat"
    $BuildScript = Join-Path $WorkRoot "build-poc.cmd"
    @"
@echo off
call "$VcVars" >nul
cl.exe /nologo /W4 /EHsc /std:c++20 /MT /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I"$SourceRoot" /LD "$SourceRoot\payload.cpp" /link /OUT:"$Payload" windowsapp.lib runtimeobject.lib ole32.lib oleaut32.lib shell32.lib advapi32.lib uuid.lib
if errorlevel 1 exit /b %errorlevel%
cl.exe /nologo /W4 /EHsc /std:c++20 /MT /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I"$SourceRoot" "$SourceRoot\driver.cpp" /link /OUT:"$Driver" ole32.lib advapi32.lib uuid.lib
exit /b %errorlevel%
"@ | Set-Content -LiteralPath $BuildScript -Encoding ascii
    @(& cmd.exe /d /c $BuildScript 2>&1) | Tee-Object -FilePath (Join-Path $ArtifactRoot "build.log") | Write-Host
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Driver) -or -not (Test-Path $Payload)) {
        throw "The native PoC harness failed to compile."
    }
    New-Item -ItemType Directory -Path (Join-Path $ArtifactRoot "binaries") -Force | Out-Null
    Copy-Item $Driver, $Payload -Destination (Join-Path $ArtifactRoot "binaries")

    Invoke-WebRequest -Uri $MsixUrl -OutFile $InputMsix
    $ActualHash = (Get-FileHash -LiteralPath $InputMsix -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $MsixSha256.ToLowerInvariant()) {
        throw "MSIX SHA-256 mismatch: expected $MsixSha256, got $ActualHash"
    }

    $MakeAppx = (Get-WindowsSdkTool -Name "makeappx.exe").FullName
    $SignTool = (Get-WindowsSdkTool -Name "signtool.exe").FullName
    @(& $MakeAppx unpack /p $InputMsix /d $UnpackedRoot /o /nv 2>&1) | Set-Content -LiteralPath (Join-Path $ArtifactRoot "makeappx.log") -Encoding utf8NoBOM
    if ($LASTEXITCODE -ne 0) {
        throw "MakeAppx failed to unpack the exact-revision MSIX."
    }

    $ManifestPath = Join-Path $UnpackedRoot "AppxManifest.xml"
    Copy-Item $ManifestPath (Join-Path $ArtifactRoot "AppxManifest.xml")
    [xml]$Manifest = Get-Content -LiteralPath $ManifestPath -Raw
    $Namespaces = [Xml.XmlNamespaceManager]::new($Manifest.NameTable)
    $Namespaces.AddNamespace("f", "http://schemas.microsoft.com/appx/manifest/foundation/windows10")
    $Namespaces.AddNamespace("desktop", "http://schemas.microsoft.com/appx/manifest/desktop/windows10")
    $Namespaces.AddNamespace("rescap", "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities")
    $Identity = $Manifest.SelectSingleNode("/f:Package/f:Identity", $Namespaces)
    $Application = $Manifest.SelectSingleNode("/f:Package/f:Applications/f:Application", $Namespaces)
    $RunFullTrust = $Manifest.SelectSingleNode("/f:Package/f:Capabilities/rescap:Capability[@Name='runFullTrust']", $Namespaces)
    $FullTrustExtension = $Manifest.SelectSingleNode("/f:Package/f:Applications/f:Application/f:Extensions/desktop:Extension[@Category='windows.fullTrustProcess']", $Namespaces)
    if ($null -eq $Identity -or $null -eq $Application -or $null -eq $RunFullTrust -or $null -eq $FullTrustExtension) {
        throw "The Taskcluster artifact does not contain the reported full-trust manifest surface."
    }
    $IdentityName = $Identity.GetAttribute("Name")
    $Publisher = $Identity.GetAttribute("Publisher")
    $PackageVersion = $Identity.GetAttribute("Version")
    $ApplicationId = $Application.GetAttribute("Id")
    $ApplicationExecutable = $Application.GetAttribute("Executable")
    $FullTrustExecutable = $FullTrustExtension.GetAttribute("Executable")
    if ($ApplicationExecutable -ne $FullTrustExecutable) {
        throw "The full-trust extension does not target the packaged Firefox executable."
    }

    $PackageInputEvidence = [ordered]@{
        sha256 = $ActualHash
        identity_name = $IdentityName
        publisher = $Publisher
        version = $PackageVersion
        application_id = $ApplicationId
        application_executable = $ApplicationExecutable
        run_full_trust = $true
        full_trust_process_executable = $FullTrustExecutable
    }
    Write-JsonFile -Value $PackageInputEvidence -Path (Join-Path $ArtifactRoot "package-input.json")

    $PackagedPayloadRelativePath = Join-Path ([IO.Path]::GetDirectoryName($ApplicationExecutable)) "renderer_payload.dll"
    $PackagedPayloadSource = Join-Path $UnpackedRoot $PackagedPayloadRelativePath
    Copy-Item $Payload $PackagedPayloadSource
    @(& $MakeAppx pack /d $UnpackedRoot /p $SignedMsix /o /nv 2>&1) | Set-Content -LiteralPath (Join-Path $ArtifactRoot "makeappx-pack.log") -Encoding utf8NoBOM
    if ($LASTEXITCODE -ne 0) {
        throw "MakeAppx failed to create the runner-local test package."
    }

    $SigningCertificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Publisher -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(2)
    $PublicCertificate = Join-Path $WorkRoot "test-signing.cer"
    Export-Certificate -Cert $SigningCertificate -FilePath $PublicCertificate | Out-Null
    Import-Certificate -FilePath $PublicCertificate -CertStoreLocation "Cert:\LocalMachine\TrustedPeople" | Out-Null
    @(& $SignTool sign /fd SHA256 /sha1 $SigningCertificate.Thumbprint /s My $SignedMsix 2>&1) | Set-Content -LiteralPath (Join-Path $ArtifactRoot "signtool-sign.log") -Encoding utf8NoBOM
    if ($LASTEXITCODE -ne 0) {
        throw "SignTool failed to apply the runner-local test signature."
    }
    @(& $SignTool verify /pa /v $SignedMsix 2>&1) | Set-Content -LiteralPath (Join-Path $ArtifactRoot "signtool-verify.log") -Encoding utf8NoBOM
    if ($LASTEXITCODE -ne 0) {
        throw "SignTool verification failed."
    }

    Get-AppxPackage -Name $IdentityName -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
    Add-AppxPackage -Path $SignedMsix
    $InstalledPackage = Get-AppxPackage -Name $IdentityName | Select-Object -First 1
    if ($null -eq $InstalledPackage) {
        throw "The test-signed Firefox MSIX was not installed."
    }
    $InstalledEvidence = [ordered]@{
        name = $InstalledPackage.Name
        package_family_name = $InstalledPackage.PackageFamilyName
        package_full_name = $InstalledPackage.PackageFullName
        install_location = $InstalledPackage.InstallLocation
        application_id = $ApplicationId
        aumid = "$($InstalledPackage.PackageFamilyName)!$ApplicationId"
        original_msix_sha256 = $ActualHash
        test_payload_relative_path = $PackagedPayloadRelativePath
        test_payload_sha256 = (Get-FileHash -LiteralPath $Payload -Algorithm SHA256).Hash.ToLowerInvariant()
        test_signed_msix_sha256 = (Get-FileHash -LiteralPath $SignedMsix -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Write-JsonFile -Value $InstalledEvidence -Path (Join-Path $ArtifactRoot "package-installed.json")

    $LoadablePayload = Join-Path $InstalledPackage.InstallLocation $PackagedPayloadRelativePath
    if (-not (Test-Path -LiteralPath $LoadablePayload)) {
        throw "The benign renderer payload was not installed beside the packaged Firefox binaries."
    }

    Get-FirefoxProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $InitialProfile = Join-Path $ProfilesRoot "initial-$Nonce"
    $EscapedProfile = Join-Path $ProfilesRoot "escaped-$Nonce"
    $ShellExecuteProfile = Join-Path $ProfilesRoot "shell-execute-$Nonce"
    $ShellDispatchProfile = Join-Path $ProfilesRoot "shell-dispatch-$Nonce"
    $AppExecAliasProfile = Join-Path $ProfilesRoot "app-exec-alias-$Nonce"
    $NotificationProfile = Join-Path $ProfilesRoot "notification-$Nonce"
    New-Item -ItemType Directory -Path $InitialProfile, $EscapedProfile, $ShellExecuteProfile, $ShellDispatchProfile, $AppExecAliasProfile, $NotificationProfile -Force | Out-Null
    @(
        'user_pref("browser.shell.checkDefaultBrowser", false);',
        'user_pref("browser.startup.page", 0);',
        'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
        'user_pref("toolkit.telemetry.enabled", false);'
    ) | Set-Content -LiteralPath (Join-Path $InitialProfile "user.js") -Encoding ascii

    $InitialArguments = "-no-remote -new-instance -profile $InitialProfile -headless https://example.com/"
    $Activation = Invoke-DriverJson -Arguments @("activate", "--aumid", $InstalledEvidence.aumid, "--launch-args", $InitialArguments) -EvidenceName "activation.json"
    $Parent = Invoke-DriverJson -Arguments @("inspect", "--pid", $Activation.pid.ToString()) -EvidenceName "parent.json"
    if ($Parent.package_family -ne $InstalledPackage.PackageFamilyName) {
        throw "The activated Firefox parent lacks the expected package identity."
    }

    $ContentProcess = Wait-FirefoxContentProcess -Deadline (Get-Date).AddSeconds(60)
    $Caller = Invoke-DriverJson -Arguments @("inspect", "--pid", $ContentProcess.ProcessId.ToString()) -EvidenceName "caller-before.json"
    $Verdict.sandbox_token_observed = [bool]($Caller.is_restricted -and $Caller.integrity_rid -lt 8192)
    if (-not $Verdict.sandbox_token_observed) {
        throw "The selected Firefox content process did not have a restricted low-integrity sandbox token."
    }

    Write-JsonFile -Value (Get-FirefoxProcesses | Select-Object ProcessId, ParentProcessId, CommandLine) -Path (Join-Path $ArtifactRoot "processes-before.json")
    $EscapedArguments = "-no-remote -new-instance -profile $EscapedProfile -headless about:blank"
    $ShellExecuteArguments = "-no-remote -new-instance -profile $ShellExecuteProfile -headless about:blank"
    $ShellDispatchArguments = "-no-remote -new-instance -profile $ShellDispatchProfile -headless about:blank"
    $AppExecAliasArguments = "-no-remote -new-instance -profile $AppExecAliasProfile -headless about:blank"
    $BackgroundMarker = "winfire-$Nonce"
    $BackgroundTaskName = "${BackgroundMarker}:-no-remote:-new-instance:-headless"
    $Injection = Invoke-DriverJson -Arguments @(
        "inject",
        "--pid", $ContentProcess.ProcessId.ToString(),
        "--dll", $LoadablePayload,
        "--local-dll", $Payload,
        "--expected-family", $InstalledPackage.PackageFamilyName,
        "--launch-args", $EscapedArguments,
        "--shell-execute-args", $ShellExecuteArguments,
        "--shell-dispatch-args", $ShellDispatchArguments,
        "--app-exec-alias-args", $AppExecAliasArguments,
        "--notification-profile", $NotificationProfile,
        "--background-task-name", $BackgroundTaskName,
        "--aumid", $InstalledEvidence.aumid
    ) -EvidenceName "injection.json"

    $Verdict.sandbox_token_observed = [bool](
        $Verdict.sandbox_token_observed -and
        $Injection.caller_inside.pid -eq $ContentProcess.ProcessId -and
        $Injection.caller_inside.is_restricted -and
        $Injection.caller_inside.integrity_rid -lt 8192
    )
    if (-not $Verdict.sandbox_token_observed) {
        throw "The injected call did not execute under the verified content-process sandbox token."
    }

    $Verdict.api_success = [bool]($Injection.call_hresult -eq 0 -and $Injection.launch_result -eq 0 -and $Injection.extended_error -eq 0)
    $Verdict.application_activation_success = [bool]($Injection.activation_hresult -eq 0 -and $Injection.activation_pid -gt 0)
    $Verdict.application_activation_hresult = $Injection.activation_hresult_hex
    $Verdict.application_activation_pid = $Injection.activation_pid
    $Verdict.shell_execute_api_success = [bool]$Injection.shell_execute_succeeded
    $Verdict.shell_execute_error = $Injection.shell_execute_error
    $Verdict.app_exec_alias_success = [bool]$Injection.app_exec_alias_succeeded
    $Verdict.app_exec_alias_error = $Injection.app_exec_alias_error
    $Verdict.app_exec_alias_pid = $Injection.app_exec_alias_pid
    $Verdict.shell_dispatch_api_success = [bool]($Injection.shell_dispatch_hresult -eq 0)
    $Verdict.shell_dispatch_hresult = $Injection.shell_dispatch_hresult_hex
    $Verdict.notification_activation_success = [bool]($Injection.notification_activation_hresult -eq 0)
    $Verdict.notification_activation_hresult = $Injection.notification_activation_hresult_hex
    $Verdict.parent_injection_access = [bool]$Injection.parent_injection_access
    $Verdict.parent_injection_open_error = $Injection.parent_injection_open_error
    $Verdict.sibling_injection_access = [bool]$Injection.sibling_injection_access
    $Verdict.sibling_injection_pid = $Injection.sibling_injection_pid
    $Verdict.sibling_injection_open_error = $Injection.sibling_injection_open_error
    $Verdict.background_access_hresult = $Injection.background_access_hresult_hex
    $Verdict.background_access_status = $Injection.background_access_status
    $Verdict.background_task_registered = [bool]$Injection.background_registered
    $Verdict.background_task_registration_hresult = $Injection.background_register_hresult_hex
    $LaunchedProcess = $null
    $Launched = $null
    if ($Verdict.api_success) {
        $LaunchedProcess = Wait-EscapedFirefoxProcess -ProfileMarker $EscapedProfile -Deadline (Get-Date).AddSeconds(45)
        if ($null -ne $LaunchedProcess) {
            $Launched = Invoke-DriverJson -Arguments @("inspect", "--pid", $LaunchedProcess.ProcessId.ToString()) -EvidenceName "launched.json"
            $Verdict.controlled_arguments_observed = [bool]($Launched.command_line -like "*$EscapedProfile*")
            $Verdict.full_trust_token_observed = [bool](
                $Launched.integrity_rid -ge 8192 -and
                -not $Launched.is_restricted -and
                $Launched.package_family -eq $InstalledPackage.PackageFamilyName
            )
        }
    }

    if (-not $Verdict.api_success -and $Verdict.application_activation_success) {
        $LaunchedProcess = Wait-EscapedFirefoxProcess -ProfileMarker $EscapedProfile -Deadline (Get-Date).AddSeconds(45)
        if ($null -ne $LaunchedProcess) {
            $Launched = Invoke-DriverJson -Arguments @("inspect", "--pid", $LaunchedProcess.ProcessId.ToString()) -EvidenceName "application-activated.json"
            $Verdict.controlled_arguments_observed = [bool]($Launched.command_line -like "*$EscapedProfile*")
            $Verdict.full_trust_token_observed = [bool](
                $Launched.integrity_rid -ge 8192 -and
                -not $Launched.is_restricted -and
                $Launched.package_family -eq $InstalledPackage.PackageFamilyName
            )
            $Verdict.application_activation_process_observed = [bool](
                $Verdict.controlled_arguments_observed -and $Verdict.full_trust_token_observed
            )
        }
    }

    if ($Verdict.notification_activation_success) {
        $NotificationProcess = Wait-EscapedFirefoxProcess -ProfileMarker $NotificationProfile -Deadline (Get-Date).AddSeconds(45)
        if ($null -ne $NotificationProcess) {
            $NotificationSnapshot = Invoke-DriverJson -Arguments @("inspect", "--pid", $NotificationProcess.ProcessId.ToString()) -EvidenceName "notification-launched.json"
            $NotificationMarkerObserved = [bool]($NotificationSnapshot.command_line -like "*$NotificationProfile*")
            $NotificationTokenObserved = [bool](
                $NotificationSnapshot.integrity_rid -ge 8192 -and
                -not $NotificationSnapshot.is_restricted -and
                $NotificationSnapshot.package_family -eq $InstalledPackage.PackageFamilyName
            )
            $Verdict.notification_activation_process_observed = [bool]($NotificationMarkerObserved -and $NotificationTokenObserved)
            $Verdict.controlled_arguments_observed = [bool]($Verdict.controlled_arguments_observed -or $NotificationMarkerObserved)
            $Verdict.full_trust_token_observed = [bool]($Verdict.full_trust_token_observed -or $NotificationTokenObserved)
        }
    }

    if ($Verdict.app_exec_alias_success) {
        $AppExecAliasProcess = Wait-EscapedFirefoxProcess -ProfileMarker $AppExecAliasProfile -Deadline (Get-Date).AddSeconds(45)
        if ($null -ne $AppExecAliasProcess) {
            $AppExecAliasSnapshot = Invoke-DriverJson -Arguments @("inspect", "--pid", $AppExecAliasProcess.ProcessId.ToString()) -EvidenceName "app-exec-alias-launched.json"
            $AppExecAliasMarkerObserved = [bool]($AppExecAliasSnapshot.command_line -like "*$AppExecAliasProfile*")
            $AppExecAliasTokenObserved = [bool](
                $AppExecAliasSnapshot.integrity_rid -ge 8192 -and
                -not $AppExecAliasSnapshot.is_restricted -and
                $AppExecAliasSnapshot.package_family -eq $InstalledPackage.PackageFamilyName
            )
            $Verdict.app_exec_alias_process_observed = [bool]($AppExecAliasMarkerObserved -and $AppExecAliasTokenObserved)
            $Verdict.controlled_arguments_observed = [bool]($Verdict.controlled_arguments_observed -or $AppExecAliasMarkerObserved)
            $Verdict.full_trust_token_observed = [bool]($Verdict.full_trust_token_observed -or $AppExecAliasTokenObserved)
        }
    }

    if (-not $Verdict.notification_activation_process_observed -and -not $Verdict.app_exec_alias_process_observed -and $Verdict.shell_execute_api_success) {
        $ShellExecuteProcess = Wait-EscapedFirefoxProcess -ProfileMarker $ShellExecuteProfile -Deadline (Get-Date).AddSeconds(45)
        if ($null -ne $ShellExecuteProcess) {
            $ShellExecuteSnapshot = Invoke-DriverJson -Arguments @("inspect", "--pid", $ShellExecuteProcess.ProcessId.ToString()) -EvidenceName "shell-execute-launched.json"
            $ShellExecuteMarkerObserved = [bool]($ShellExecuteSnapshot.command_line -like "*$ShellExecuteProfile*")
            $ShellExecuteTokenObserved = [bool](
                $ShellExecuteSnapshot.integrity_rid -ge 8192 -and
                -not $ShellExecuteSnapshot.is_restricted -and
                $ShellExecuteSnapshot.package_family -eq $InstalledPackage.PackageFamilyName
            )
            $Verdict.shell_execute_process_observed = [bool]($ShellExecuteMarkerObserved -and $ShellExecuteTokenObserved)
            $Verdict.controlled_arguments_observed = [bool]($Verdict.controlled_arguments_observed -or $ShellExecuteMarkerObserved)
            $Verdict.full_trust_token_observed = [bool]($Verdict.full_trust_token_observed -or $ShellExecuteTokenObserved)
        }
    }

    if (-not $Verdict.notification_activation_process_observed -and -not $Verdict.app_exec_alias_process_observed -and $Verdict.shell_dispatch_api_success) {
        $ShellDispatchProcess = Wait-EscapedFirefoxProcess -ProfileMarker $ShellDispatchProfile -Deadline (Get-Date).AddSeconds(45)
        if ($null -ne $ShellDispatchProcess) {
            $ShellDispatchSnapshot = Invoke-DriverJson -Arguments @("inspect", "--pid", $ShellDispatchProcess.ProcessId.ToString()) -EvidenceName "shell-dispatch-launched.json"
            $ShellDispatchMarkerObserved = [bool]($ShellDispatchSnapshot.command_line -like "*$ShellDispatchProfile*")
            $ShellDispatchTokenObserved = [bool](
                $ShellDispatchSnapshot.integrity_rid -ge 8192 -and
                -not $ShellDispatchSnapshot.is_restricted -and
                $ShellDispatchSnapshot.package_family -eq $InstalledPackage.PackageFamilyName
            )
            $Verdict.shell_dispatch_process_observed = [bool]($ShellDispatchMarkerObserved -and $ShellDispatchTokenObserved)
            $Verdict.controlled_arguments_observed = [bool]($Verdict.controlled_arguments_observed -or $ShellDispatchMarkerObserved)
            $Verdict.full_trust_token_observed = [bool]($Verdict.full_trust_token_observed -or $ShellDispatchTokenObserved)
        }
    }

    if (-not $Verdict.api_success -and -not $Verdict.application_activation_success -and $Verdict.background_task_registered) {
        $LaunchedProcess = Wait-EscapedFirefoxProcess -ProfileMarker $BackgroundMarker -Deadline (Get-Date).AddMinutes($BackgroundTaskWaitMinutes)
        if ($null -ne $LaunchedProcess) {
            $Launched = Invoke-DriverJson -Arguments @("inspect", "--pid", $LaunchedProcess.ProcessId.ToString()) -EvidenceName "background-launched.json"
            $Verdict.controlled_arguments_observed = [bool]($Launched.command_line -like "*$BackgroundMarker*")
            $Verdict.full_trust_token_observed = [bool](
                $Launched.integrity_rid -ge 8192 -and
                -not $Launched.is_restricted -and
                $Launched.package_family -eq $InstalledPackage.PackageFamilyName
            )
            $Verdict.background_proxy_process_observed = [bool](
                $Verdict.controlled_arguments_observed -and $Verdict.full_trust_token_observed
            )
        }
    }
    Write-JsonFile -Value (Get-FirefoxProcesses | Select-Object ProcessId, ParentProcessId, CommandLine) -Path (Join-Path $ArtifactRoot "processes-after.json")

    if ($Verdict.app_exec_alias_process_observed) {
        $Verdict.status = "CONFIRMED_APP_EXEC_ALIAS"
        $Verdict.reason = "A restricted untrusted-integrity Firefox content process invoked the package AppExecLink with controlled arguments. Windows launched a non-restricted packaged Firefox process carrying the unique profile marker."
    } elseif ($Verdict.notification_activation_process_observed) {
        $Verdict.status = "CONFIRMED_NOTIFICATION_COM_PROXY"
        $Verdict.reason = "A restricted untrusted-integrity Firefox content process invoked the package notification COM surrogate with a controlled profile path. The surrogate launched a non-restricted packaged Firefox process carrying that unique path."
    } elseif ($Verdict.shell_execute_process_observed) {
        $Verdict.status = "CONFIRMED_SHELL_EXECUTE_BROKER"
        $Verdict.reason = "A restricted untrusted-integrity Firefox content process asked the shell namespace to activate the package with controlled arguments. Windows launched a non-restricted packaged Firefox process carrying the unique profile marker."
    } elseif ($Verdict.shell_dispatch_process_observed) {
        $Verdict.status = "CONFIRMED_SHELL_AUTOMATION_BROKER"
        $Verdict.reason = "A restricted untrusted-integrity Firefox content process invoked the Shell.Application automation broker with controlled arguments. Windows launched a non-restricted packaged Firefox process carrying the unique profile marker."
    } elseif ($Verdict.application_activation_process_observed) {
        $Verdict.status = "CONFIRMED_APP_ACTIVATION_BROKER"
        $Verdict.reason = "A restricted untrusted-integrity Firefox content process invoked the packaged-app activation broker with the package AUMID and controlled arguments. Windows launched a non-restricted packaged Firefox process carrying the unique profile marker."
    } elseif ($Verdict.background_proxy_process_observed) {
        $Verdict.status = "CONFIRMED_BACKGROUND_TASK_PROXY"
        $Verdict.reason = "A restricted untrusted-integrity Firefox content process registered an attacker-named package timer. Windows activated Mozilla's declared background-task AppContainer, which launched a full-trust Firefox process carrying the controlled marker."
    } elseif ($Verdict.api_success -and $Verdict.controlled_arguments_observed -and $Verdict.full_trust_token_observed) {
        $Verdict.status = "CONFIRMED"
        $Verdict.reason = "A restricted low-integrity Firefox browser content process invoked FullTrustProcessLauncher successfully, and Windows created a non-restricted medium-integrity packaged Firefox process carrying the controlled profile argument."
    } elseif (-not $Verdict.api_success -and [string]::IsNullOrEmpty($Injection.caller_inside.package_family)) {
        $Verdict.status = "BLOCKED_NO_PACKAGE_IDENTITY"
        $Verdict.reason = "The sandboxed Firefox content process did not retain package identity, and the full-trust launch did not succeed on this runner."
    } elseif ($Verdict.background_task_registered) {
        $Verdict.status = "INCONCLUSIVE_BACKGROUND_TIMER"
        $Verdict.reason = "The compromised content process registered the package background timer, but no controlled full-trust launch was observed before the runner deadline."
    } elseif ($Injection.launch_result -eq 1 -or $Injection.call_hresult_hex -eq "0x80070005" -or $Injection.extended_error_hex -eq "0x80070005") {
        $Verdict.status = "BLOCKED_BY_WINDOWS"
        $Verdict.reason = "The call originated inside the sandboxed Firefox content process, but Windows returned access denied and no sandbox escape was demonstrated."
    } elseif ($Verdict.api_success) {
        $Verdict.status = "INCONCLUSIVE"
        $Verdict.reason = "The WinRT API reported success, but the harness did not observe both controlled arguments and the expected token transition in the launched process."
    } else {
        $Verdict.status = "INCONCLUSIVE"
        $Verdict.reason = "The call ran inside the sandboxed Firefox content process but returned a non-success result that was not the documented AccessDenied outcome."
    }
} catch {
    $Verdict.status = "HARNESS_ERROR"
    $Verdict.reason = $_.Exception.Message
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $ArtifactRoot "harness-error.txt") -Encoding utf8NoBOM
    $ExitCode = 1
} finally {
    Write-JsonFile -Value $Verdict -Path $VerdictPath
    Write-Summary -Result $Verdict
    Get-FirefoxProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    if ($null -ne $InstalledPackage) {
        $InstalledPackage | Remove-AppxPackage -ErrorAction SilentlyContinue
    }
    if ($null -ne $SigningCertificate) {
        Remove-Item -LiteralPath "Cert:\LocalMachine\TrustedPeople\$($SigningCertificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($SigningCertificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
}

Get-Content -LiteralPath $SummaryPath | Write-Host
exit $ExitCode
