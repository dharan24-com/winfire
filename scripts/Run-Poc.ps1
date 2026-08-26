[CmdletBinding()]
param(
    [string]$ArtifactRoot = (Join-Path $PSScriptRoot "..\artifacts"),
    [string]$MsixUrl = "https://firefox-ci-tc.services.mozilla.com/api/queue/v1/task/dX7_cQx7RHyrDTlnGpbFeA/artifacts/public/build/target.installer.msix",
    [string]$MsixSha256 = "a7d656acc321ed52cd547ede6f540cfb6dd7272fe89d405ab9ebce5daaba813c"
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
        "- Controlled profile argument observed: ``$($Result.controlled_arguments_observed)``",
        "- Restricted content token observed: ``$($Result.sandbox_token_observed)``",
        "- Full-trust token transition observed: ``$($Result.full_trust_token_observed)``"
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
cl.exe /nologo /W4 /EHsc /std:c++20 /MT /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I"$SourceRoot" /LD "$SourceRoot\payload.cpp" /link /OUT:"$Payload" windowsapp.lib runtimeobject.lib advapi32.lib
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
    New-Item -ItemType Directory -Path $InitialProfile, $EscapedProfile -Force | Out-Null
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
    $Injection = Invoke-DriverJson -Arguments @(
        "inject",
        "--pid", $ContentProcess.ProcessId.ToString(),
        "--dll", $LoadablePayload,
        "--local-dll", $Payload,
        "--expected-family", $InstalledPackage.PackageFamilyName,
        "--launch-args", $EscapedArguments
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
    Write-JsonFile -Value (Get-FirefoxProcesses | Select-Object ProcessId, ParentProcessId, CommandLine) -Path (Join-Path $ArtifactRoot "processes-after.json")

    if ($Verdict.api_success -and $Verdict.controlled_arguments_observed -and $Verdict.full_trust_token_observed) {
        $Verdict.status = "CONFIRMED"
        $Verdict.reason = "A restricted low-integrity Firefox browser content process invoked FullTrustProcessLauncher successfully, and Windows created a non-restricted medium-integrity packaged Firefox process carrying the controlled profile argument."
    } elseif (-not $Verdict.api_success -and [string]::IsNullOrEmpty($Injection.caller_inside.package_family)) {
        $Verdict.status = "BLOCKED_NO_PACKAGE_IDENTITY"
        $Verdict.reason = "The sandboxed Firefox content process did not retain package identity, and the full-trust launch did not succeed on this runner."
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
