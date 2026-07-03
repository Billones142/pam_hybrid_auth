use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use zbus::proxy;
use zbus::Connection;
use futures_util::stream::StreamExt;

// --- PAM FFI Definitions ---

pub const PAM_SUCCESS: libc::c_int = 0;
pub const PAM_AUTH_ERR: libc::c_int = 7;
pub const PAM_USER_UNKNOWN: libc::c_int = 10;
pub const PAM_MAXTRIES: libc::c_int = 11;
pub const PAM_CONV_ERR: libc::c_int = 19;
pub const PAM_BUF_ERR: libc::c_int = 5;
pub const PAM_SYSTEM_ERR: libc::c_int = 4;

pub const PAM_USER: libc::c_int = 2;
pub const PAM_SERVICE: libc::c_int = 3;
pub const PAM_CONV: libc::c_int = 5;

pub const PAM_PROMPT_ECHO_OFF: libc::c_int = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pam_message {
    pub msg_style: libc::c_int,
    pub msg: *const libc::c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pam_response {
    pub resp: *mut libc::c_char,
    pub resp_retcode: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pam_conv {
    pub conv: Option<
        unsafe extern "C" fn(
            num_msg: libc::c_int,
            msg: *mut *const pam_message,
            resp: *mut *mut pam_response,
            appdata_ptr: *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub appdata_ptr: *mut libc::c_void,
}

#[repr(C)]
pub struct spwd {
    pub sp_namp: *mut libc::c_char,
    pub sp_pwdp: *mut libc::c_char,
    pub sp_lstchg: libc::c_long,
    pub sp_min: libc::c_long,
    pub sp_max: libc::c_long,
    pub sp_warn: libc::c_long,
    pub sp_inact: libc::c_long,
    pub sp_expire: libc::c_long,
    pub sp_flag: libc::c_ulong,
}

#[link(name = "crypt")]
extern "C" {
    fn pam_get_item(
        pamh: *const libc::c_void,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int;

    fn getspnam(name: *const libc::c_char) -> *mut spwd;

    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

// --- D-Bus fprintd Interfaces ---

#[proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
trait FprintManager {
    fn get_default_device(&self) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint"
)]
trait FprintDevice {
    fn claim(&self, username: &str) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
    fn verify_stop(&self) -> zbus::Result<()>;
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;

    #[zbus(signal)]
    fn verify_status(&self, result: String, done: bool) -> zbus::Result<()>;
}

// --- Syslog Logging Helper ---

fn syslog_log(priority: libc::c_int, message: &str) {
    if let Ok(c_msg) = CString::new(message) {
        unsafe {
            libc::openlog(
                b"pam_password_fingerprint\0".as_ptr() as *const libc::c_char,
                libc::LOG_PID,
                libc::LOG_AUTH,
            );
            libc::syslog(
                priority,
                b"%s\0".as_ptr() as *const libc::c_char,
                c_msg.as_ptr(),
            );
            libc::closelog();
        }
    }
}

// --- Signal Handler for Interrupting pam_conv ---

static mut ORIGINAL_SIGUSR1_HANDLER: libc::sigaction = unsafe { std::mem::zeroed() };

unsafe extern "C" fn sigusr1_handler(_sig: libc::c_int) {
    // Empty handler to catch the signal and interrupt blocking reads with EINTR
}

unsafe fn setup_sigusr1_handler() {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = sigusr1_handler as *const () as usize;
    sa.sa_flags = 0; // Ensure SA_RESTART is NOT set so we trigger EINTR
    libc::sigemptyset(&mut sa.sa_mask);

    let mut old_sa: libc::sigaction = std::mem::zeroed();
    libc::sigaction(libc::SIGUSR1, &sa, &mut old_sa);
    ORIGINAL_SIGUSR1_HANDLER = old_sa;
}

unsafe fn restore_sigusr1_handler() {
    libc::sigaction(
        libc::SIGUSR1,
        std::ptr::addr_of!(ORIGINAL_SIGUSR1_HANDLER),
        std::ptr::null_mut(),
    );
}

// --- PAM Conversation & Password Helpers ---

unsafe fn get_username(pamh: *const libc::c_void) -> Result<String, libc::c_int> {
    let mut user_ptr: *const libc::c_void = std::ptr::null();
    let res = pam_get_item(pamh, PAM_USER, &mut user_ptr);
    if res != PAM_SUCCESS || user_ptr.is_null() {
        return Err(PAM_USER_UNKNOWN);
    }
    let username = CStr::from_ptr(user_ptr as *const libc::c_char)
        .to_string_lossy()
        .into_owned();
    Ok(username)
}

unsafe fn read_password_from_tty(prompt_text: &str, show_stars: bool) -> Result<String, libc::c_int> {
    use std::io::{Write, stdout};
    print!("{}", prompt_text);
    let _ = stdout().flush();

    let fd = libc::STDIN_FILENO;
    if libc::isatty(fd) == 0 {
        return Err(PAM_CONV_ERR);
    }

    let mut termios = unsafe { std::mem::zeroed() };
    if libc::tcgetattr(fd, &mut termios) != 0 {
        return Err(PAM_CONV_ERR);
    }

    let original_termios = termios;

    // Disable canonical mode (ICANON), echo (ECHO), and signal generation (ISIG)
    termios.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
    if libc::tcsetattr(fd, libc::TCSANOW, &termios) != 0 {
        return Err(PAM_CONV_ERR);
    }

    let mut password = String::new();
    let mut buf = [0u8; 1];

    loop {
        let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1);
        if n <= 0 {
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &original_termios);
            return Err(PAM_CONV_ERR);
        }

        let ch = buf[0];
        if ch == b'\n' || ch == b'\r' {
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &original_termios);
            eprint!("\r{}\x1b[K", prompt_text);
            let _ = std::io::stderr().flush();
            break;
        } else if ch == 8 || ch == 127 {
            // Backspace
            if !password.is_empty() {
                password.pop();
                if show_stars {
                    print!("\x08 \x08");
                    let _ = stdout().flush();
                }
            }
        } else if ch == 3 {
            // Ctrl+C
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &original_termios);
            eprint!("\r{}\x1b[K\n", prompt_text);
            let _ = std::io::stderr().flush();
            return Err(PAM_CONV_ERR);
        } else if ch.is_ascii_graphic() || ch == b' ' {
            password.push(ch as char);
            if show_stars {
                print!("*");
                let _ = stdout().flush();
            }
        }
    }

    let _ = libc::tcsetattr(fd, libc::TCSANOW, &original_termios);
    Ok(password)
}

unsafe fn prompt_password(
    pamh: *const libc::c_void,
    prompt_text: &str,
) -> Result<String, libc::c_int> {
    let mut conv_ptr: *const libc::c_void = std::ptr::null();
    let res = pam_get_item(pamh, PAM_CONV, &mut conv_ptr);
    if res != PAM_SUCCESS || conv_ptr.is_null() {
        return Err(PAM_CONV_ERR);
    }

    let pam_conv = *(conv_ptr as *const pam_conv);
    let conv_fn = pam_conv.conv.ok_or(PAM_CONV_ERR)?;

    let prompt_c = CString::new(prompt_text).map_err(|_| PAM_BUF_ERR)?;
    let msg = pam_message {
        msg_style: PAM_PROMPT_ECHO_OFF,
        msg: prompt_c.as_ptr(),
    };

    let mut msg_ptr = &msg as *const pam_message;
    let mut resp_ptr: *mut pam_response = std::ptr::null_mut();

    let res = conv_fn(
        1,
        &mut msg_ptr as *mut *const pam_message,
        &mut resp_ptr as *mut *mut pam_response,
        pam_conv.appdata_ptr,
    );

    if res != PAM_SUCCESS {
        return Err(res);
    }

    if resp_ptr.is_null() {
        return Err(PAM_CONV_ERR);
    }

    let resp = *resp_ptr;
    if resp.resp.is_null() {
        libc::free(resp_ptr as *mut libc::c_void);
        return Err(PAM_CONV_ERR);
    }

    let password = CStr::from_ptr(resp.resp)
        .to_string_lossy()
        .into_owned();

    libc::free(resp.resp as *mut libc::c_void);
    libc::free(resp_ptr as *mut libc::c_void);

    Ok(password)
}

fn verify_password_hash(password: &str, hash: &str) -> bool {
    let password_c = match CString::new(password) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let hash_c = match CString::new(hash) {
        Ok(c) => c,
        Err(_) => return false,
    };

    unsafe {
        let res_ptr = crypt(password_c.as_ptr(), hash_c.as_ptr());
        if res_ptr.is_null() {
            return false;
        }
        let res_str = CStr::from_ptr(res_ptr).to_string_lossy();
        res_str == hash
    }
}

fn get_shadow_hash(username: &str) -> Result<String, String> {
    let username_c = CString::new(username).map_err(|e| e.to_string())?;
    unsafe {
        let sp = getspnam(username_c.as_ptr());
        if sp.is_null() {
            return Err("User not found in shadow database or permission denied".to_string());
        }
        let hash_ptr = (*sp).sp_pwdp;
        if hash_ptr.is_null() {
            return Err("No password hash found for user".to_string());
        }
        let hash = CStr::from_ptr(hash_ptr).to_string_lossy().into_owned();
        Ok(hash)
    }
}

struct SharedState {
    password_status: Option<String>,
    fingerprint_status: Option<String>,
    has_warning_line: bool,
}

fn format_combined_status(p_status: &Option<String>, f_status: &Option<String>) -> Option<String> {
    match (p_status, f_status) {
        (Some(p), Some(f)) => Some(format!("{} - {}", p, f)),
        (Some(p), None) => Some(p.clone()),
        (None, Some(f)) => Some(f.clone()),
        (None, None) => None,
    }
}

fn parse_args(args: &[String]) -> (bool, u32, u32) {
    let mut show_stars = false;
    let mut global_tries = 3;
    let mut password_tries = None;
    let mut fingerprint_tries = None;
    for arg in args {
        if arg == "show_stars" {
            show_stars = true;
        } else if arg.starts_with("tries=") {
            if let Ok(t) = arg["tries=".len()..].parse::<u32>() {
                global_tries = t;
            }
        } else if arg.starts_with("password_tries=") {
            if let Ok(t) = arg["password_tries=".len()..].parse::<u32>() {
                password_tries = Some(t);
            }
        } else if arg.starts_with("fingerprint_tries=") {
            if let Ok(t) = arg["fingerprint_tries=".len()..].parse::<u32>() {
                fingerprint_tries = Some(t);
            }
        }
    }
    let p_tries = password_tries.unwrap_or(global_tries);
    let f_tries = fingerprint_tries.unwrap_or(global_tries);
    (show_stars, p_tries, f_tries)
}

fn get_prompt_text(pamh: *const libc::c_void, username: &str) -> String {
    let mut service_ptr: *const libc::c_void = std::ptr::null();
    let service_name = if unsafe { pam_get_item(pamh, PAM_SERVICE, &mut service_ptr) } == PAM_SUCCESS && !service_ptr.is_null() {
        unsafe { CStr::from_ptr(service_ptr as *const libc::c_char).to_string_lossy().into_owned() }
    } else {
        "login".to_string()
    };

    if service_name == "sudo" {
        format!("[sudo] password for {}: ", username)
    } else {
        "Password: ".to_string()
    }
}

fn update_status_line(
    shared_state: &Mutex<SharedState>,
    is_password_thread: bool,
    new_status: Option<String>,
    pw_failed: &AtomicBool,
    prompt_text: &str,
) {
    if unsafe { libc::isatty(libc::STDERR_FILENO) } == 0 {
        return;
    }

    let mut state = shared_state.lock().unwrap();
    if is_password_thread {
        state.password_status = new_status;
    } else {
        state.fingerprint_status = new_status;
    }

    let combined = format_combined_status(&state.password_status, &state.fingerprint_status);

    let prompt = if pw_failed.load(Ordering::SeqCst) {
        "Waiting for fingerprint..."
    } else {
        prompt_text
    };

    if let Some(msg) = combined {
        use std::io::Write;
        if state.has_warning_line {
            eprint!("\r\x1b[2K\x1b[1A\r\x1b[2K{}\n{}", msg, prompt);
        } else {
            eprint!("\r\x1b[2K{}\n{}", msg, prompt);
            state.has_warning_line = true;
        }
        let _ = std::io::stderr().flush();
    }
}

// --- Verification Logic ---

async fn run_fingerprint_auth(
    pamh: *const libc::c_void,
    username: &str,
    auth_success: &AtomicBool,
    auth_finished: &AtomicBool,
    _auth_canceled: &AtomicBool,
    auth_method: &AtomicU32,
    pw_failed: &AtomicBool,
    _fp_failed: &AtomicBool,
    shared_state: &Mutex<SharedState>,
    pw_thread_id: &Mutex<Option<libc::pthread_t>>,
    max_tries: u32,
    start_time: std::time::Instant,
) -> Result<bool, Box<dyn std::error::Error>> {
    syslog_log(
        libc::LOG_DEBUG,
        &format!("[+{:?}] Fingerprint thread: starting DBus connection...", start_time.elapsed()),
    );

    if auth_finished.load(Ordering::SeqCst) {
        return Ok(false);
    }

    let conn = Connection::system().await?;

    if auth_finished.load(Ordering::SeqCst) {
        return Ok(false);
    }

    let manager = FprintManagerProxy::new(&conn).await?;

    if auth_finished.load(Ordering::SeqCst) {
        return Ok(false);
    }

    let device_path = manager.get_default_device().await?;

    if auth_finished.load(Ordering::SeqCst) {
        return Ok(false);
    }

    let device = FprintDeviceProxy::builder(&conn)
        .path(device_path)?
        .build()
        .await?;

    // Check if enrolled
    let enrolled = device.list_enrolled_fingers(username).await?;
    if enrolled.is_empty() {
        syslog_log(
            libc::LOG_INFO,
            &format!("[+{:?}] Fingerprint thread: no enrolled fingers, exiting.", start_time.elapsed()),
        );
        return Ok(false);
    }

    if auth_finished.load(Ordering::SeqCst) {
        return Ok(false);
    }

    let mut claimed = false;
    match device.claim(username).await {
        Ok(_) => {
            claimed = true;
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("AlreadyInUse") {
                // Print the RED warning message immediately to the user
                if unsafe { libc::isatty(libc::STDERR_FILENO) } != 0 {
                    let msg = "\x1b[31mFingerprint reader is busy.\x1b[0m".to_string();
                    let prompt_text = get_prompt_text(pamh, username);
                    update_status_line(shared_state, false, Some(msg), pw_failed, &prompt_text);
                }

                syslog_log(
                    libc::LOG_INFO,
                    &format!("[+{:?}] Fingerprint reader is busy, starting background claim retries...", start_time.elapsed()),
                );

                // Start retrying in the background every 100ms until we succeed or the password thread finishes
                let mut success = false;
                let mut attempt = 0;
                while !auth_finished.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    if auth_finished.load(Ordering::SeqCst) {
                        break;
                    }
                    attempt += 1;
                    match device.claim(username).await {
                        Ok(_) => {
                            claimed = true;
                            success = true;
                            syslog_log(
                                libc::LOG_INFO,
                                &format!("[+{:?}] Fingerprint reader successfully claimed on attempt {}.", start_time.elapsed(), attempt),
                            );
                            break;
                        }
                        Err(_) => {
                            // Log every 10 attempts (1 second) to avoid spamming syslog too much
                            if attempt % 10 == 0 {
                                syslog_log(
                                    libc::LOG_DEBUG,
                                    &format!("[+{:?}] Fingerprint reader claim retry {} still busy...", start_time.elapsed(), attempt),
                                );
                            }
                        }
                    }
                }

                if success {
                    // Success! Print the GREEN reconnected message, converting the warning in-place
                    if unsafe { libc::isatty(libc::STDERR_FILENO) } != 0 {
                        let msg = "\x1b[32mFingerprint scanner was reconnected.\x1b[0m".to_string();
                        let prompt_text = get_prompt_text(pamh, username);
                        update_status_line(shared_state, false, Some(msg), pw_failed, &prompt_text);
                    }
                } else {
                    return Ok(false);
                }
            } else {
                return Err(e.into());
            }
        }
    }

    let mut started = false;
    let mut result_ok = false;

    let res = async {
        let mut attempt_count = 0;
        if auth_finished.load(Ordering::SeqCst) {
            return Ok(false);
        }

        loop {
            if auth_finished.load(Ordering::SeqCst) {
                break;
            }

            syslog_log(
                libc::LOG_DEBUG,
                &format!("[+{:?}] Fingerprint thread: starting VerifyStart...", start_time.elapsed()),
            );
            
            if let Err(err) = device.verify_start("any").await {
                syslog_log(
                    libc::LOG_ERR,
                    &format!("[+{:?}] VerifyStart failed: {}", start_time.elapsed(), err),
                );
                break;
            }
            started = true;

            syslog_log(
                libc::LOG_DEBUG,
                &format!("[+{:?}] Fingerprint thread: VerifyStart completed. Waiting for signals...", start_time.elapsed()),
            );

            let mut stream = device.receive_verify_status().await?;
            let mut got_match = false;
            let mut got_no_match = false;

            // Wait for verification signal for this try
            loop {
                if auth_finished.load(Ordering::SeqCst) {
                    break;
                }

                // Check for signals with a 100ms timeout
                match tokio::time::timeout(tokio::time::Duration::from_millis(100), stream.next()).await {
                    Ok(Some(signal)) => {
                        let args = signal.args()?;
                        let result_str: &str = &args.result;
                        syslog_log(
                            libc::LOG_DEBUG,
                            &format!(
                                "[+{:?}] Fingerprint signal received: {}, done: {}",
                                start_time.elapsed(),
                                result_str,
                                args.done
                            ),
                        );

                        match result_str {
                            "verify-match" => {
                                auth_method.store(2, Ordering::SeqCst);
                                auth_success.store(true, Ordering::SeqCst);
                                auth_finished.store(true, Ordering::SeqCst);
                                let tid = loop {
                                    if let Some(id) = *pw_thread_id.lock().unwrap() {
                                        break id;
                                    }
                                    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                                };
                                unsafe {
                                    libc::pthread_kill(tid, libc::SIGUSR1);
                                }
                                result_ok = true;
                                got_match = true;
                                break;
                            }
                            "verify-no-match" => {
                                attempt_count += 1;
                                if unsafe { libc::isatty(libc::STDERR_FILENO) } != 0 {
                                    if max_tries > 1 {
                                        let msg = format!("\x1b[31mFingerprint did not match (attempt {}/{})\x1b[0m", attempt_count, max_tries);
                                        let prompt_text = get_prompt_text(pamh, username);
                                        update_status_line(shared_state, false, Some(msg), pw_failed, &prompt_text);
                                    }
                                }
                                got_no_match = true;
                                break;
                            }
                            _ => {
                                if args.done {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(_) => {
                        // Timeout (100ms elapsed without signal), loop again and check auth_finished
                    }
                }
            }

            if got_match || attempt_count >= max_tries {
                break;
            }

            if got_no_match {
                let _ = tokio::time::timeout(tokio::time::Duration::from_millis(50), device.verify_stop()).await;
                started = false;
            }
        }
        Ok::<bool, Box<dyn std::error::Error>>(result_ok)
    }.await;

    // Clean up
    if started {
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(10), device.verify_stop()).await;
    }
    if claimed {
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(10), device.release()).await;
    }

    res
}

fn run_password_auth(
    pamh: *const libc::c_void,
    username: &str,
    shadow_hash: &str,
    auth_success: &AtomicBool,
    auth_finished: &AtomicBool,
    auth_canceled: &AtomicBool,
    auth_method: &AtomicU32,
    pw_failed: &AtomicBool,
    fp_failed: &AtomicBool,
    shared_state: &Mutex<SharedState>,
    pw_thread_id: &Mutex<Option<libc::pthread_t>>,
    show_stars: bool,
    max_tries: u32,
    start_time: std::time::Instant,
) {
    let self_id = unsafe { libc::pthread_self() };
    *pw_thread_id.lock().unwrap() = Some(self_id);

    let mut attempt = 0;
    while attempt < max_tries {
        if auth_finished.load(Ordering::SeqCst) {
            break;
        }

        attempt += 1;

        syslog_log(
            libc::LOG_DEBUG,
            &format!(
                "[+{:?}] Password thread: prompt starting (attempt {}/{})...",
                start_time.elapsed(),
                attempt,
                max_tries
            ),
        );
        let prompt_text = get_prompt_text(pamh, username);
        let prompt_res = unsafe {
            if libc::isatty(libc::STDIN_FILENO) != 0 {
                read_password_from_tty(&prompt_text, show_stars)
            } else {
                prompt_password(pamh, &prompt_text)
            }
        };
        syslog_log(
            libc::LOG_DEBUG,
            &format!("[+{:?}] Password thread: prompt returned.", start_time.elapsed()),
        );

        if auth_finished.load(Ordering::SeqCst) {
            break;
        }

        match prompt_res {
            Ok(password) => {
                syslog_log(
                    libc::LOG_DEBUG,
                    &format!("[+{:?}] Password thread: crypt verification starting...", start_time.elapsed()),
                );
                if verify_password_hash(&password, shadow_hash) {
                    auth_method.store(1, Ordering::SeqCst);
                    auth_success.store(true, Ordering::SeqCst);
                    auth_finished.store(true, Ordering::SeqCst);
                    syslog_log(
                        libc::LOG_INFO,
                        &format!("[+{:?}] Password thread: verification successful.", start_time.elapsed()),
                    );
                    break;
                } else {
                    syslog_log(
                        libc::LOG_WARNING,
                        &format!(
                            "[+{:?}] Password thread: verification failed (attempt {}/{}).",
                            start_time.elapsed(),
                            attempt,
                            max_tries
                        ),
                    );
                    // Print password failure message to user
                    if unsafe { libc::isatty(libc::STDERR_FILENO) } != 0 {
                        if max_tries > 1 {
                            let msg = format!("\x1b[31mPassword incorrect (attempt {}/{})\x1b[0m", attempt, max_tries);
                            update_status_line(shared_state, true, Some(msg), pw_failed, &prompt_text);
                        } else {
                            use std::io::Write;
                            eprint!("\r{}\x1b[K", prompt_text);
                            let _ = std::io::stderr().flush();
                        }
                    }
                }
            }
            Err(err) => {
                syslog_log(
                    libc::LOG_DEBUG,
                    &format!(
                        "[+{:?}] Password thread: prompt interrupted or failed: {}",
                        start_time.elapsed(),
                        err
                    ),
                );
                // Trigger immediate auth exit
                auth_canceled.store(true, Ordering::SeqCst);
                auth_finished.store(true, Ordering::SeqCst);
                break;
            }
        }
    }

    if !auth_success.load(Ordering::SeqCst) {
        pw_failed.store(true, Ordering::SeqCst);

        // If password attempts are exhausted, but fingerprint scanner is still running:
        if !fp_failed.load(Ordering::SeqCst) {
            if unsafe { libc::isatty(libc::STDERR_FILENO) } != 0 {
                use std::io::Write;
                eprint!("\r\x1b[2KWaiting for fingerprint...");
                let _ = std::io::stderr().flush();
            }

            // Disable input echo, canonical mode, and signal generation
            let fd = libc::STDIN_FILENO;
            if unsafe { libc::isatty(fd) } != 0 {
                let mut termios = unsafe { std::mem::zeroed() };
                if unsafe { libc::tcgetattr(fd, &mut termios) } == 0 {
                    let original_termios = termios;
                    termios.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
                    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };

                    let mut buf = [0u8; 1];
                    while !auth_finished.load(Ordering::SeqCst) {
                        // We read character-by-character. If SIGUSR1 is sent, this returns -1 (EINTR).
                        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
                        if n <= 0 {
                            break;
                        }
                        if buf[0] == 3 {
                            // Ctrl+C was pressed! Abort everything!
                            auth_canceled.store(true, Ordering::SeqCst);
                            auth_finished.store(true, Ordering::SeqCst);
                            break;
                        }
                    }

                    let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original_termios) };
                }
            }
        }

        if fp_failed.load(Ordering::SeqCst) {
            auth_finished.store(true, Ordering::SeqCst);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *const libc::c_void,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    let username = match get_username(pamh) {
        Ok(user) => user,
        Err(err) => {
            syslog_log(libc::LOG_ERR, "Failed to retrieve username.");
            return err;
        }
    };

    let shadow_hash = match get_shadow_hash(&username) {
        Ok(hash) => hash,
        Err(e) => {
            syslog_log(
                libc::LOG_ERR,
                &format!("Failed to retrieve password hash for {}: {}", username, e),
            );
            return PAM_AUTH_ERR;
        }
    };

    let start_time = std::time::Instant::now();
    syslog_log(
        libc::LOG_INFO,
        &format!("[+0.0ms] pam_sm_authenticate started for user: {}", username),
    );

    setup_sigusr1_handler();

    let mut args = Vec::new();
    for i in 0.._argc as usize {
        let arg_str = CStr::from_ptr(*_argv.add(i)).to_string_lossy().into_owned();
        args.push(arg_str);
    }
    let (show_stars, pw_max_tries, fp_max_tries) = parse_args(&args);

    let auth_success = AtomicBool::new(false);
    let auth_finished = AtomicBool::new(false);
    let auth_canceled = AtomicBool::new(false);
    let auth_method = AtomicU32::new(0); // 1 = password, 2 = fingerprint
    let pw_failed = AtomicBool::new(false);
    let fp_failed = AtomicBool::new(false);
    let shared_state = Mutex::new(SharedState {
        password_status: None,
        fingerprint_status: None,
        has_warning_line: false,
    });
    let pw_thread_id = Mutex::new(None);
    let pamh_usize = pamh as usize;

    std::thread::scope(|s| {
        // Spawn fingerprint authentication thread
        s.spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let res = rt.block_on(async {
                run_fingerprint_auth(
                    pamh_usize as *const libc::c_void,
                    &username,
                    &auth_success,
                    &auth_finished,
                    &auth_canceled,
                    &auth_method,
                    &pw_failed,
                    &fp_failed,
                    &shared_state,
                    &pw_thread_id,
                    fp_max_tries,
                    start_time,
                ).await
            });

            // Fingerprint thread is done (either failed, errored, or no enrolled fingers)
            fp_failed.store(true, Ordering::SeqCst);
            if pw_failed.load(Ordering::SeqCst) {
                auth_finished.store(true, Ordering::SeqCst);
            }
            // Send SIGUSR1 to wake up password thread if it is blocked in prompt/swallower,
            // but only if fingerprint authentication succeeded or both failed.
            if auth_success.load(Ordering::SeqCst) || auth_finished.load(Ordering::SeqCst) {
                let tid = pw_thread_id.lock().unwrap().take();
                if let Some(id) = tid {
                    unsafe {
                        libc::pthread_kill(id, libc::SIGUSR1);
                    }
                }
            }

            if let Err(e) = res {
                let err_str = e.to_string();
                if !err_str.contains("AlreadyInUse") {
                    let user_msg = if err_str.contains("PermissionDenied") {
                        "Permission denied accessing fingerprint reader."
                    } else {
                        "Fingerprint reader initialization failed."
                    };

                    if libc::isatty(libc::STDERR_FILENO) != 0 {
                        use std::io::Write;
                        eprint!("\r\x1b[2K\x1b[31m[PAM] {}\x1b[0m\nPassword: ", user_msg);
                        let _ = std::io::stderr().flush();
                    }
                }

                if !auth_success.load(Ordering::SeqCst) {
                    syslog_log(
                        libc::LOG_ERR,
                        &format!(
                            "[+{:?}] Fingerprint thread error: {}",
                            start_time.elapsed(),
                            e
                        ),
                    );
                }
            }
        });

        // Spawn password authentication thread
        s.spawn(|| {
            run_password_auth(
                pamh_usize as *const libc::c_void,
                &username,
                &shadow_hash,
                &auth_success,
                &auth_finished,
                &auth_canceled,
                &auth_method,
                &pw_failed,
                &fp_failed,
                &shared_state,
                &pw_thread_id,
                show_stars,
                pw_max_tries,
                start_time,
            );
        });
    });

    restore_sigusr1_handler();
    syslog_log(
        libc::LOG_INFO,
        &format!(
            "[+{:?}] Thread scope joined.",
            start_time.elapsed()
        ),
    );

    if auth_success.load(Ordering::SeqCst) {
        let method_str = match auth_method.load(Ordering::SeqCst) {
            1 => "password",
            2 => "fingerprint",
            _ => "unknown",
        };
        if unsafe { libc::isatty(libc::STDERR_FILENO) } != 0 {
            use std::io::Write;
            eprint!("\r\x1b[2K\x1b[32mAuthentication successful with {}.\x1b[0m\n", method_str);
            let _ = std::io::stderr().flush();
        }
        syslog_log(
            libc::LOG_INFO,
            &format!(
                "[+{:?}] Authentication successful via {} for user {}.",
                start_time.elapsed(),
                method_str,
                username
            ),
        );
        PAM_SUCCESS
    } else if auth_canceled.load(Ordering::SeqCst) {
        syslog_log(
            libc::LOG_WARNING,
            &format!(
                "[+{:?}] Authentication canceled by user (Ctrl+C) for user {}.",
                start_time.elapsed(),
                username
            ),
        );
        PAM_MAXTRIES
    } else {
        syslog_log(
            libc::LOG_WARNING,
            &format!(
                "[+{:?}] Authentication failed/exhausted for user {}.",
                start_time.elapsed(),
                username
            ),
        );
        PAM_MAXTRIES
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *const libc::c_void,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_combined_status() {
        assert_eq!(format_combined_status(&None, &None), None);
        assert_eq!(
            format_combined_status(&Some("A".to_string()), &None),
            Some("A".to_string())
        );
        assert_eq!(
            format_combined_status(&None, &Some("B".to_string())),
            Some("B".to_string())
        );
        assert_eq!(
            format_combined_status(&Some("A".to_string()), &Some("B".to_string())),
            Some("A - B".to_string())
        );
    }

    #[test]
    fn test_parse_args() {
        let args = vec![
            "show_stars".to_string(),
            "tries=5".to_string(),
            "password_tries=6".to_string(),
            "fingerprint_tries=2".to_string(),
        ];
        let (show_stars, pw_tries, fp_tries) = parse_args(&args);
        assert!(show_stars);
        assert_eq!(pw_tries, 6);
        assert_eq!(fp_tries, 2);

        let args_global = vec!["tries=5".to_string()];
        let (_, pw_g, fp_g) = parse_args(&args_global);
        assert_eq!(pw_g, 5);
        assert_eq!(fp_g, 5);

        let args_default = vec![];
        let (show_stars_d, pw_d, fp_d) = parse_args(&args_default);
        assert!(!show_stars_d);
        assert_eq!(pw_d, 3);
        assert_eq!(fp_d, 3);

        let args_invalid_tries = vec![
            "tries=abc".to_string(),
            "password_tries=def".to_string(),
            "fingerprint_tries=ghi".to_string(),
        ];
        let (_, pw_inv, fp_inv) = parse_args(&args_invalid_tries);
        assert_eq!(pw_inv, 3);
        assert_eq!(fp_inv, 3);
    }
}
