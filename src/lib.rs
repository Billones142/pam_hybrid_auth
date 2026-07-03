use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use zbus::proxy;
use zbus::Connection;
use futures_util::stream::StreamExt;

// --- PAM FFI Definitions ---

pub const PAM_SUCCESS: libc::c_int = 0;
pub const PAM_AUTH_ERR: libc::c_int = 7;
pub const PAM_USER_UNKNOWN: libc::c_int = 10;
pub const PAM_CONV_ERR: libc::c_int = 19;
pub const PAM_BUF_ERR: libc::c_int = 5;
pub const PAM_SYSTEM_ERR: libc::c_int = 4;

pub const PAM_USER: libc::c_int = 2;
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

unsafe fn read_password_with_stars(prompt_text: &str) -> Result<String, libc::c_int> {
    use std::io::{Write, stdout};
    print!("{}", prompt_text);
    let _ = stdout().flush();

    let fd = libc::STDIN_FILENO;
    if libc::isatty(fd) == 0 {
        return Err(PAM_CONV_ERR);
    }

    let mut termios = std::mem::zeroed();
    if libc::tcgetattr(fd, &mut termios) != 0 {
        return Err(PAM_CONV_ERR);
    }

    let original_termios = termios;

    // Disable canonical mode (ICANON) and echo (ECHO)
    termios.c_lflag &= !(libc::ICANON | libc::ECHO);
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
            println!();
            break;
        } else if ch == 8 || ch == 127 {
            // Backspace
            if !password.is_empty() {
                password.pop();
                print!("\x08 \x08");
                let _ = stdout().flush();
            }
        } else if ch == 3 {
            // Ctrl+C
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &original_termios);
            println!();
            return Err(PAM_CONV_ERR);
        } else if ch.is_ascii_graphic() || ch == b' ' {
            password.push(ch as char);
            print!("*");
            let _ = stdout().flush();
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

// --- Verification Logic ---

async fn run_fingerprint_auth(
    username: &str,
    auth_success: &AtomicBool,
    pw_thread_id: &Mutex<Option<libc::pthread_t>>,
    start_time: std::time::Instant,
) -> Result<bool, Box<dyn std::error::Error>> {
    syslog_log(
        libc::LOG_DEBUG,
        &format!("[+{:?}] Fingerprint thread: starting DBus connection...", start_time.elapsed()),
    );

    if auth_success.load(Ordering::SeqCst) {
        return Ok(false);
    }

    let conn = Connection::system().await?;

    if auth_success.load(Ordering::SeqCst) {
        return Ok(false);
    }

    let manager = FprintManagerProxy::new(&conn).await?;

    if auth_success.load(Ordering::SeqCst) {
        return Ok(false);
    }

    let device_path = manager.get_default_device().await?;

    if auth_success.load(Ordering::SeqCst) {
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

    if auth_success.load(Ordering::SeqCst) {
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
                    use std::io::Write;
                    eprint!("\r\x1b[2K\x1b[31mFingerprint reader is busy.\x1b[0m\nPassword: ");
                    let _ = std::io::stderr().flush();
                }

                syslog_log(
                    libc::LOG_INFO,
                    &format!("[+{:?}] Fingerprint reader is busy, starting background claim retries...", start_time.elapsed()),
                );

                // Start retrying in the background every 100ms until we succeed or the password thread succeeds
                let mut success = false;
                let mut attempt = 0;
                while !auth_success.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    if auth_success.load(Ordering::SeqCst) {
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
                        use std::io::Write;
                        eprint!("\r\x1b[2K\x1b[1A\r\x1b[2K\x1b[32mFingerprint scanner was reconnected.\x1b[0m\nPassword: ");
                        let _ = std::io::stderr().flush();
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
        if auth_success.load(Ordering::SeqCst) {
            return Ok(false);
        }

        syslog_log(
            libc::LOG_DEBUG,
            &format!("[+{:?}] Fingerprint thread: starting VerifyStart...", start_time.elapsed()),
        );
        device.verify_start("any").await?;
        started = true;
        syslog_log(
            libc::LOG_DEBUG,
            &format!("[+{:?}] Fingerprint thread: VerifyStart completed. Waiting for signals...", start_time.elapsed()),
        );

        let mut stream = device.receive_verify_status().await?;
        loop {
            if auth_success.load(Ordering::SeqCst) {
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
                            auth_success.store(true, Ordering::SeqCst);
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
                            break;
                        }
                        "verify-no-match" => {
                            if args.done {
                                break;
                            }
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
                    // Timeout (100ms elapsed without signal), loop again and check auth_success
                }
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
    shadow_hash: &str,
    auth_success: &AtomicBool,
    pw_thread_id: &Mutex<Option<libc::pthread_t>>,
    show_stars: bool,
    start_time: std::time::Instant,
) {
    let self_id = unsafe { libc::pthread_self() };
    *pw_thread_id.lock().unwrap() = Some(self_id);

    syslog_log(
        libc::LOG_DEBUG,
        &format!("[+{:?}] Password thread: prompt starting...", start_time.elapsed()),
    );
    let prompt_res = unsafe {
        if show_stars && libc::isatty(libc::STDIN_FILENO) != 0 {
            read_password_with_stars("Password: ")
        } else {
            prompt_password(pamh, "Password: ")
        }
    };
    syslog_log(
        libc::LOG_DEBUG,
        &format!("[+{:?}] Password thread: prompt returned.", start_time.elapsed()),
    );

    match prompt_res {
        Ok(password) => {
            syslog_log(
                libc::LOG_DEBUG,
                &format!("[+{:?}] Password thread: crypt verification starting...", start_time.elapsed()),
            );
            if verify_password_hash(&password, shadow_hash) {
                auth_success.store(true, Ordering::SeqCst);
                syslog_log(
                    libc::LOG_INFO,
                    &format!("[+{:?}] Password thread: verification successful.", start_time.elapsed()),
                );
            } else {
                syslog_log(
                    libc::LOG_WARNING,
                    &format!("[+{:?}] Password thread: verification failed.", start_time.elapsed()),
                );
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

    let mut show_stars = false;
    for i in 0.._argc as usize {
        let arg_str = CStr::from_ptr(*_argv.add(i)).to_string_lossy();
        if arg_str == "show_stars" {
            show_stars = true;
        }
    }

    let auth_success = AtomicBool::new(false);
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
                    &username,
                    &auth_success,
                    &pw_thread_id,
                    start_time,
                ).await
            });

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
                &shadow_hash,
                &auth_success,
                &pw_thread_id,
                show_stars,
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
        syslog_log(
            libc::LOG_INFO,
            &format!(
                "[+{:?}] Authentication successful for user {}.",
                start_time.elapsed(),
                username
            ),
        );
        PAM_SUCCESS
    } else {
        syslog_log(
            libc::LOG_WARNING,
            &format!(
                "[+{:?}] Authentication failed for user {}.",
                start_time.elapsed(),
                username
            ),
        );
        PAM_AUTH_ERR
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
