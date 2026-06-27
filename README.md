# PAM Module: Password & Fingerprint Concurrent Authentication

A professional, high-performance Pluggable Authentication Module (PAM) written in Rust that allows **concurrent** password and fingerprint authentication. 

Unlike standard PAM stacks that process authentication sequentially (causing frustrating timeouts or delays while waiting for the fingerprint scanner before prompting for a password), this module runs both authentication checks in parallel.

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

---

## Testing

A safety-first test script `test.sh` is provided in the repository root. It tests the module using `pamtester` without modifying your live login configurations, preventing you from locking yourself out of your system.

### How to Run the Tests:
1. Ensure the module is compiled and installed (`make` and `sudo make install`).
2. Run the test script:
   ```bash
   ./test.sh
   ```
3. The script will:
   - Ask for sudo permissions (required to write a temporary test PAM service configuration in `/etc/pam.d/pam_test_password_fingerprint` and allow `/etc/shadow` reads).
   - Run `pamtester` to authenticate your current user.
   - Prompt you with `Password:`.
   - **Test Case A (Password First):** Immediately type your password and hit Enter. The authentication should succeed instantly.
   - **Test Case B (Fingerprint First):** Re-run the script. Swipe your finger on the fingerprint reader. The prompt should immediately terminate and report success.
   - **Test Case C (Failure):** Type an incorrect password or scan an unregistered finger. The authentication should fail.
   - Automatically clean up the test configuration file from `/etc/pam.d/` on completion.
