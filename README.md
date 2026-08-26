# Firefox MSIX full-trust launcher validation

This repository validates the suspected Windows Firefox MSIX sandbox escape introduced at Firefox commit [`276bad1472c95b721d47f0829c571e6d5b5ef263`](https://github.com/dharan24-com/firefox_autoland/commit/276bad1472c95b721d47f0829c571e6d5b5ef263).

The tested Mozilla Taskcluster artifact was produced from Autoland push head [`e852cbbdfb8baa2989b8d7db78d5ca929dcea9dd`](https://hg.mozilla.org/integration/autoland/rev/e852cbbdfb8baa2989b8d7db78d5ca929dcea9dd), pushlog `276768`, by task `dX7_cQx7RHyrDTlnGpbFeA`. Its original SHA-256 is:

```text
a7d656acc321ed52cd547ede6f540cfb6dd7272fe89d405ab9ebce5daaba813c
```

## Result

**Not confirmed — blocked by Windows.**

The final [Windows 11 client run](https://github.com/dharan24-com/winfire/actions/runs/32968099137) completed without a harness error. The public [evidence artifact](https://github.com/dharan24-com/winfire/actions/runs/32968099137/artifacts/9606529068) has digest `sha256:11ff4fdeac537b14ae6b77e8425b33e9d5a5297d0df2ac98869183e3d6968183`.

The decisive call executed inside Firefox content PID `8252`, not in the CI controller:

- Windows 11 Enterprise 25H2, build `26200`, ARM64 host running the exact x64 MSIX under Windows x64 emulation.
- Real browser content process: `firefox-real.exe -contentproc -isForBrowser`.
- Package family retained: `Mozilla.MozillaFirefoxNightly_5x4grbbqzn2q4`.
- Restricted, non-elevated, non-AppContainer token at low integrity (`integrity_rid: 4096`).
- The same PID, command line, package identity, restriction state, and integrity level were captured again from inside the payload immediately before the calls.
- `LaunchFullTrustProcessForCurrentAppWithArgumentsAsync` returned `0x80070005 (E_ACCESSDENIED)`.
- No process carried the unique controlled profile/task marker and no unrestricted token transition occurred.

The same boundary was independently blocked on [Windows Server 2025 build 26100](https://github.com/dharan24-com/winfire/actions/runs/32963515553), where the real Firefox content token was restricted at untrusted integrity (`integrity_rid: 0`).

No CTF flag was generated because no sandbox escape occurred. In particular, this repository does not invent or substitute a value for `/root/flag.txt`; claiming a flag without the verified token transition would be false.

## Renderer-originated probes

The Windows 11 run produced these results from the verified content token:

| Route | Result | Marked unrestricted process |
| --- | --- | --- |
| `FullTrustProcessLauncher` | `0x80070005` | No |
| `IApplicationActivationManager` | `0x80070005` | No |
| `ShellExecuteExW` | No successful marked activation | No |
| Package AppExecLink via `CreateProcessW` | Win32 error `31` | No |
| `Shell.Application` automation | `0x80070005` | No |
| Notification activation COM surrogate | `0x80070005` | No |
| Parent process, injection-grade access | Win32 error `5` | No |
| Sibling process, injection-grade access | No eligible handle; error `1168` | No |
| `BackgroundExecutionManager::RequestAccessAsync` | `0x80070005` | No |
| Attacker-named package timer registration | `0x80070005` | No |

The background host added by the Autoland change does call `FullTrustProcessLauncher` when Windows activates a registered package task. That fact alone is not renderer reachability. The compromised content token could neither obtain background access nor register the attacker-named timer, and the production Firefox task registrar is a main-process-only XPCOM component with fixed production callers.

## Method

The workflow:

1. Downloads and hashes the exact Taskcluster MSIX.
2. Captures the original manifest and verifies `runFullTrust`, `windows.fullTrustProcess`, and the background-task declarations.
3. Adds a benign test payload, repacks with an ephemeral runner-local certificate, and installs the package.
4. Uses a small test-only launcher at the manifest's original executable path to set Firefox's supported `MOZ_REPLACE_MALLOC_LIB` variable, then starts the untouched original Firefox binary as `firefox-real.exe`. This is required only to transport the report's assumed native renderer compromise across Windows-on-ARM emulation.
5. Selects an actual packaged `-contentproc -isForBrowser` PID and independently verifies its token before proceeding.
6. Confirms `renderer_payload.dll` is resident in that exact process by reading its PEB module list.
7. Starts the payload's pure-x64 `RunPoc` export in that process, records the caller token again from inside, and performs all probes there.
8. Accepts a positive result only if a unique marker reaches a package-identical Firefox process whose token is non-restricted and medium integrity or higher.

The launcher does not perform a broker call or create the claimed escaped process. It only ensures that the benign payload is already mapped before the content sandbox is measured. The controller cannot turn an API failure into a positive verdict.

## Verdict meanings

- `CONFIRMED*`: a renderer-originated route creates a marked, package-identical, non-restricted medium-or-higher integrity process.
- `BLOCKED_BY_WINDOWS`: the call executes in the verified restricted renderer, Windows denies it, and no token transition is observed.
- `INCONCLUSIVE*`: some prerequisite or API outcome is real, but the marker and token evidence do not prove a boundary crossing.
- `HARNESS_ERROR`: setup or evidence collection failed before a valid security result.

## Run it

Use **Actions → Firefox MSIX full-trust sandbox PoC → Run workflow**, or push to the `msix-fulltrust-ctf` branch. The workflow currently targets GitHub's public `windows-11-arm` client runner. The pinned Taskcluster artifact expires on 25 August 2027.

The result is scoped to the exact artifact and tested Windows configurations. It disproves the report's demonstrated reachability on those systems; it does not assert that every future Windows or Firefox build is universally free of unrelated sandbox escapes.
