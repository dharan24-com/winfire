# Firefox MSIX full-trust launcher PoC

This repository contains a narrowly scoped Windows CI harness for the suspected sandbox escape introduced at Firefox commit [`276bad1472c95b721d47f0829c571e6d5b5ef263`](https://github.com/dharan24-com/firefox_autoland/commit/276bad1472c95b721d47f0829c571e6d5b5ef263).

Autoland batched that commit in pushlog `276768`. Taskcluster indexed the Windows build for the introducing revision, while the actual artifact was produced at the push head, [`e852cbbdfb8baa2989b8d7db78d5ca929dcea9dd`](https://hg.mozilla.org/integration/autoland/rev/e852cbbdfb8baa2989b8d7db78d5ca929dcea9dd). The evidence records both revisions.

The report's unresolved question is whether native code already executing in a sandboxed Firefox content process can directly invoke `Windows.ApplicationModel.FullTrustProcessLauncher`. The harness tests that question on a GitHub-hosted Windows Server 2025 runner.

## Observed result

The completed [Windows proof run](https://github.com/dharan24-com/winfire/actions/runs/32958506804) returned **`BLOCKED_BY_WINDOWS`**. Its [evidence artifact](https://github.com/dharan24-com/winfire/actions/runs/32958506804/artifacts/9602956065) records all of the following:

- The tested content process retained package family `Mozilla.MozillaFirefoxNightly_5x4grbbqzn2q4`.
- The caller was a real `firefox.exe -contentproc -isForBrowser` process with a restricted, non-elevated, untrusted-integrity token (`integrity_rid: 0`).
- The same token and package identity were captured again from inside the injected payload immediately before the WinRT call.
- `LaunchFullTrustProcessForCurrentAppWithArgumentsAsync` failed with `0x80070005 (E_ACCESSDENIED)`.
- No process carrying the controlled profile argument was created, and no full-trust token transition occurred.

Therefore this run does **not** confirm the reported sandbox escape. It demonstrates that Windows denied the decisive direct-WinRT step on Windows Server 2025 24H2 (build 26100) for the autoland package under test. As with any single dynamic environment, this is scoped evidence rather than a claim about every supported Windows client configuration.

## What the proof does

1. Downloads Mozilla Taskcluster's `repackage-msix-win64/opt` artifact from the autoland push containing the introducing commit and verifies its chain-of-trust SHA-256.
2. Verifies that the package declares `runFullTrust` and registers its packaged `firefox.exe` as `windows.fullTrustProcess`.
3. Adds only the benign test payload beside the packaged Firefox binaries, repacks with a runner-local test signature, installs the package for the ephemeral runner user, and starts Firefox through its AUMID. The original Taskcluster artifact is hashed and its manifest is captured before this test-only modification.
4. Selects only an MSIX-packaged `firefox.exe -contentproc -isForBrowser` process and verifies that its token is restricted and below medium integrity.
5. Injects a DLL into that process to model the report's Stage 2 assumption of native content-process compromise.
6. Calls `LaunchFullTrustProcessForCurrentAppWithArgumentsAsync` inside the compromised content process with a unique, benign profile path.
7. Records the API result and compares the content-process token with any newly launched packaged Firefox process.

The payload does not enable remote debugging, request system access, establish persistence, contact an external controller, or execute an arbitrary child binary. The controlled profile path is sufficient to prove argument control, while the token comparison proves or disproves the claimed boundary crossing.

The packaged payload is only a transport for the report's explicit assumption that native code already executes in the renderer. It is placed in Firefox's binary directory because the real content sandbox grants that directory read access; the payload then runs after the harness has independently verified the target's restricted low-integrity token. Firefox's content-process policy at this revision does not apply CIG or ACG, so this does not disable a mitigation or relax the sandbox.

## Verdicts

- `CONFIRMED`: the API succeeds, the controlled argument reaches a new packaged Firefox process, and the new process has a non-restricted medium-or-higher integrity token.
- `BLOCKED_NO_PACKAGE_IDENTITY`: the Firefox sandbox strips package identity from the content process and the launch does not succeed.
- `BLOCKED_BY_WINDOWS`: the call runs inside the restricted Firefox content process but Windows returns the documented access-denied result.
- `INCONCLUSIVE`: the API result and observed process state do not establish either outcome.
- `HARNESS_ERROR`: setup, injection, or evidence collection failed before a valid test completed.

The workflow uploads the manifest, package provenance, caller and child token snapshots, process lists, API results, build logs, and `verdict.json` as a public run artifact.

A positive result proves the boundary crossing on the tested autoland package and Windows configuration. A blocked or inconclusive result is scoped to the GitHub-hosted Windows Server 2025 runner and is not, by itself, proof that every supported Windows client configuration is safe.

## Run

Use **Actions → Firefox MSIX full-trust sandbox PoC → Run workflow**. The workflow can also run automatically from a branch named `msix-fulltrust-ctf`.

The pinned MSIX artifact expires on 25 August 2027. The WinRT method used by the report requires Windows build 22000 or newer, so the workflow intentionally uses `windows-2025`.
