# Cascade install honesty + typed SSH failure — implementation report

Branch `fix/installer-honesty-20261107`, base `4683f55c14ece88eb97c1389d8751a10bf87a5ee` (accepted R7 composition). Isolated worktree `work/agent-installer-honesty-20261107`. Not merged, not released, not executed on a device or server.

## Why

Two defects were confirmed in real source by two independent product audits and by direct parent reading, and both make the app lie to the owner:

1. `workspace_ui.dart` `_installCascade` downloaded `deploy/cascade/terminal-install.sh` from the mutable `main` branch into a fixed `/tmp/xio-cascade.sh`, interpolated the user-supplied exit host into a single-quoted shell string, never inspected the remote exit code, then saved the addresses and showed **«Каскад поднят»** regardless of outcome.
2. `core.dart` `executeInput` threw only when the remote exit was non-zero **and** stdout was empty, so a failing command that printed anything read as success.

## What changed

**Typed outcome (`app/lib/core.dart`).** New `SshCommandFailure(exitCode, stdoutBytes, stderrBytes)` and a pure `sshCommandOutcome(exitCode, stdout, stderr)` boundary. `executeInput` now folds stderr into bytes (it used to drain and discard) and returns through that boundary, so a non-zero exit is always a failure while the stdout body remains available to callers that deliberately decode a structured JSON error. A null exit code maps to `-1`.

**Deliberate per-caller handling.** Callers that decode a JSON error body read `failure.stdoutBytes`; callers that only log server-side convert to the previous generic `StateError`. Both helpers rethrow when the failed command printed nothing, so the earlier behaviour for silent commands is preserved rather than silently widened. `stderr` is never surfaced in UI or logs.

**Installer trust and success (`app/lib/workspace_ui.dart`).** `buildCascadeInstallCommand()` replaces the interpolated one-liner:

- the exit host is read from stdin (`IFS= read -r exit_host`) and passed as a double-quoted argv element, so it can never become shell code;
- the bootstrap is downloaded into a fresh `mktemp -d` directory (mode 700, removed by an `EXIT` trap) with `--proto '=https'`, `--proto-redir '=https'`, `--tlsv1.2`, a byte cap and a timeout;
- its SHA-256 is verified **before** execution and the run aborts on mismatch;
- the verified bootstrap is invoked with the pinned bundle URL and bundle digest, `--data-dir /var/lib/xio-cascade`, `--unattended`, and `-- --role bridge --exit-host "$exit_host"`.

`runCascadeInstall()` reports success only from positive evidence: exit code 0 **and** the installer's explicit marker `Configuration installed`. Addresses are persisted only after that; any other outcome throws `StateError` carrying the real exit code and installer tail, and the dialog shows the failure instead of «Каскад поднят».

The pins are not invented: `cascadeBootstrapSha256` equals the SHA-256 of `deploy/cascade/terminal-install.sh` in this tree (`e9db1d8e…3331`), and the bundle URL/digest come from `app/assets/xio-cascade-release.json` (`6ca4b316…2171`, size 26686), which also lists every payload file digest. The accepted CLI contract was checked against the installers: `terminal-install.sh` requires `--bundle-url`/`--sha256`/`--data-dir` and accepts `--unattended` plus `--` passthrough; `cascade-install.sh` validates `--role exit|bridge|both` and prints the success marker to stderr, which reaches stdout here because the wrapper redirects both streams into the log and then `tail`s it.

**Tests (`app/test/installer_honesty_test.dart`, 14 cases).** Non-zero exit with non-empty stdout is a failure; exit 0 returns bytes unchanged; a missing exit code is still a failure; a successful JSON response still decodes; a non-zero JSON error body is decoded deliberately; a checksum mismatch aborts before execution; the exit host travels over stdin and never into the shell; success is not claimed when the installer reports failure; exit 0 without the explicit marker is still a failure; and checksum, marker and exit 0 are required together. Four further cases were added after the first independent review flagged them as missing: the digest check is asserted to come **before** the `bash` invocation in the generated command, the verification line is asserted to end in `|| exit`, a non-zero exit with empty stdout is asserted to still throw, and `SshCommandFailure` is asserted to preserve the code and both raw streams without leaking stderr through `toString()`.

## Unverified

No Dart/Flutter compilation, analysis or test execution was performed: Windows blocks the toolchain and the Debian root filesystem was full at the time. So this change is **statically reviewed by its author only**; it requires an independent review and a real `flutter analyze` + `dart test` run on a host with a working SDK before it can be treated as accepted. The remote installer itself was not executed; the success path is exercised only through the test doubles.

## Risks left for review

- The marker is matched as a substring of the installer tail; if the installer ever prints it in a failure branch the gate weakens. The current installer prints it only after container start and explicitly labels it "NOT an egress acceptance test".
- The download still uses the mutable `main` URL; safety rests entirely on the digest check. A release build should prefer the versioned release asset URL.
- `--data-dir /var/lib/xio-cascade` and the log path `/var/log/xio-cascade-install.log` are hard-coded in the app and must match the terminal instructions the owner follows.
