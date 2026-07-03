# PAM Module: Password & Fingerprint Concurrent Authentication

A professional, high-performance Pluggable Authentication Module (PAM) written in Rust that allows **concurrent** password and fingerprint authentication. 

Unlike standard PAM stacks that process authentication sequentially (causing frustrating timeouts or delays while waiting for the fingerprint scanner before prompting for a password), this module runs both authentication checks in parallel.

### A Modern Alternative to `pam-fprint-grosshack`

This module serves as a modern, memory-safe, and robust Rust alternative to the legacy `pam-fprint-grosshack`. While `pam-fprint-grosshack` relied on complex C process forking, pipe redirection, and terminal hacking, this module uses structured Rust concurrency (`std::thread::scope`) and direct D-Bus communication with `fprintd` to achieve concurrent authentication safely and cleanly. It also offers advanced features such as:
* Dynamic, single-line in-place error warnings.
* Customizable attempt counters per method.
* Optional typing asterisk feedback (`show_stars`).

### Key Features
* **No Delay Fallback:** If you type your password first, it authenticates immediately without waiting for the fingerprint reader to time out.
* **Instant Fingerprint Login:** If you swipe your finger first, it completes the authentication instantly and cancels the pending password prompt.
* **Automatic Fallback:** If the fingerprint reader is unavailable, not configured, or has no enrolled fingers for the user, it gracefully falls back to standard password authentication.
* **Thread-Safe Architecture:** Uses POSIX signal interruption (`SIGUSR1`) to abort the blocking PAM conversation prompt the millisecond the fingerprint scanner reports a match.
* **D-Bus fprintd Integration:** Communicates with the standard system `fprintd` daemon via D-Bus, avoiding direct hardware access requirements and configuration conflicts.

---

## Architecture Overview

The module uses a multi-threaded design within the synchronous `pam_sm_authenticate` call:
1. **Initial Check:** It queries `fprintd` over the D-Bus system bus to verify if the user has enrolled fingerprints. If none are found, it skips fingerprinting entirely.
2. **Signal Handling:** Installs a temporary signal handler for `SIGUSR1` (with `SA_RESTART` disabled) on the thread calling the PAM conversation callback.
3. **Parallel Execution (`std::thread::scope`):**
   - **Fingerprint Thread:** Claims the reader and starts a verification session (`VerifyStart`). It blocks waiting for `VerifyStatus` D-Bus signals.
   - **Password Thread:** Invokes the host application's PAM conversation (`pam_conv`) to prompt the user. It verifies the entered password using the host's `crypt` implementation against `/etc/shadow`.
4. **Interruption & Resolution:**
   - If the **fingerprint** matches: The fingerprint thread sets the success flag and signals the password thread with `SIGUSR1`. The password thread's blocking read fails with `EINTR`, returning control. The module exits with `PAM_SUCCESS`.
   - If the **password** matches: The password thread sets the success flag, calls `VerifyStop` on the fingerprint device, and exits. The fingerprint thread receives the stop notification and exits. The module exits with `PAM_SUCCESS`.
   - If the password fails, or the fingerprint fails/times out, the module exits with `PAM_AUTH_ERR`.

---

## Requirements

To build and run this PAM module, you need:

1. **Rust Toolchain:** `cargo` and `rustc` (edition 2021+).
2. **System Dependencies:**
   - **PAM Developers Library:** `libpam0g-dev` (Ubuntu/Debian) or `pam-devel` (Fedora/RHEL/Arch).
   - **Crypt Developers Library:** `libcrypt-dev` (Ubuntu/Debian) or `libxcrypt-devel` (Fedora/RHEL/Arch).
   - **D-Bus & fprintd:** `fprintd` service must be running, and you must have enrolled fingerprints for your user (check using `fprintd-list $USER` or `fprintd-verify`).
3. **Testing Utility:** `pamtester` (to test the PAM stack safely without risking lockout).

---

## Compiling & Installing

The compilation and installation are managed via the included `Makefile`.

### 1. Build the Module
To compile the project in release mode:
```bash
make
```
This runs `cargo build --release` under the hood.

### 2. Install the Module
Install the compiled shared library to the system's PAM security directory:
```bash
sudo make install
```
This automatically detects your system's directory (typically `/lib/x86_64-linux-gnu/security/` or `/lib/security/`) and places `pam_password_fingerprint.so` inside it.

To clean build artifacts or uninstall:
```bash
make clean
sudo make uninstall
```

---

## Configuration

To use the module in your system, add it to your service configuration files (located in `/etc/pam.d/`).

For example, to require it for `sudo`, edit `/etc/pam.d/sudo` and add the following line at the top of the authentication section:
```pam
auth sufficient pam_password_fingerprint.so
```

### Configuration Options

* `show_stars`: Enables visual asterisk feedback (`*`) in the terminal when typing the password. By default, typing feedback is hidden (blank).
* `tries=X`: Configures the global default maximum number of attempts allowed for both password and fingerprint authentication (defaults to `3`).
* `password_tries=Y`: Overrides and configures the maximum attempts allowed for password authentication.
* `fingerprint_tries=Z`: Overrides and configures the maximum attempts allowed for fingerprint authentication.

Example configuration (using different attempts limit for each method):
```pam
auth sufficient pam_password_fingerprint.so show_stars password_tries=3 fingerprint_tries=5
```

### Recommended Sudoers Configuration

By default, `sudo` implements its own retry loop (typically retrying 3 times). When using this module, this can cause the attempts limit to multiply (e.g. 3 retries of 3 password attempts each).

To delegate all attempt limits and prompt cancellations (such as immediate exit on `Ctrl+C` or limit exhaustion) entirely to this module, it is recommended to configure `sudo` to only try once:

1. Open the sudoers configuration:
   ```bash
   sudo visudo
   ```
2. Add the following line:
   ```sudoers
   Defaults passwd_tries=1
   ```

---

## Advanced UX & Security Features

* **Combined Error Warnings:** Both fingerprint and password attempts share a single warning line directly above the prompt (e.g. `Password incorrect (attempt 3/4). - Fingerprint did not match (attempt 2/4).`). Warnings update in-place dynamically.
* **Smart Exit Logic:** The PAM module remains active as long as at least one authentication method has remaining attempts left.
* **Keystroke Swallowing & Waiting Prompt:** When password attempts are fully exhausted, the prompt automatically changes to `Waiting for fingerprint...` and subsequent keyboard keystrokes are swallowed and disabled on the terminal to avoid raw key leaks.
* **Busy Device Recovery:** If the fingerprint reader is busy/claimed, a red warning is shown immediately, and claims are retried every 100ms. Once claimed, the warning seamlessly converts to a green success message in-place.

---

## Testing

We provide both automated unit tests and integration tests to verify the module's behavior.

### 1. Rust Unit Tests
Unit tests verify internal module logic such as argument parsing and status string formatting. To execute unit tests:
```bash
make test
```
(Runs `cargo test` under the hood).

### 2. Automated Integration Tests
An automated test script `automated_tests.sh` runs integration tests validating tries configuration limits and expected PAM prompting behavior. Run this with sudo:
```bash
sudo ./automated_tests.sh
```

### 3. Interactive Testing
A safety-first interactive test script `test.sh` is provided in the repository root. It tests the module using `pamtester` without modifying your live login configurations, preventing you from locking yourself out of your system:
```bash
./test.sh [show_stars]
```
You can swipe a registered finger or type your password to verify the concurrent auth flow.

