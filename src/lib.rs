use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use zbus::blocking::Connection;
use zbus::proxy;

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
    sa.sa_sigaction = sigusr1_handler as usize;
    sa.sa_flags = 0; // Ensure SA_RESTART is NOT set so we trigger EINTR
    libc::sigemptyset(&mut sa.sa_mask);

    let mut old_sa: libc::sigaction = std::mem::zeroed();
    libc::sigaction(libc::SIGUSR1, &sa, &mut old_sa);
    ORIGINAL_SIGUSR1_HANDLER = old_sa;
}

unsafe fn restore_sigusr1_handler() {
    libc::sigaction(
        libc::SIGUSR1,
        &ORIGINAL_SIGUSR1_HANDLER,
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

fn check_fingerprint_enrolled(username: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let conn = Connection::system()?;
    let manager = FprintManagerProxyBlocking::new(&conn)?;
    let device_path = manager.get_default_device()?;
    let device = FprintDeviceProxyBlocking::builder(&conn)
        .path(device_path)?
        .build()?;
    let enrolled = device.list_enrolled_fingers(username)?;
    Ok(!enrolled.is_empty())
}

fn run_fingerprint_auth(
    device: &FprintDeviceProxyBlocking,
    auth_success: &AtomicBool,
    pw_thread_id: &Mutex<Option<libc::pthread_t>>,
) -> Result<bool, Box<dyn std::error::Error>> {
    device.verify_start("any")?;

    let iter = device.receive_verify_status()?;
    for msg_res in iter {
        if auth_success.load(Ordering::SeqCst) {
            break;
        }

        let msg = msg_res?;
        let args: VerifyStatusArgs = msg.args()?;

        match args.result.as_str() {
            "verify-match" => {
                auth_success.store(true, Ordering::SeqCst);
                // Busy wait briefly if the password thread ID is not written yet
                let tid = loop {
                    if let Some(id) = *pw_thread_id.lock().unwrap() {
                        break id;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                };
                unsafe {
                    libc::pthread_kill(tid, libc::SIGUSR1);
                }
                return Ok(true);
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
    Ok(false)
}

fn run_password_auth(
    pamh: *const libc::c_void,
    shadow_hash: &str,
    auth_success: &AtomicBool,
    pw_thread_id: &Mutex<Option<libc::pthread_t>>,
    device: Option<&FprintDeviceProxyBlocking>,
) {
    let self_id = unsafe { libc::pthread_self() };
    *pw_thread_id.lock().unwrap() = Some(self_id);

    let prompt_res = unsafe { prompt_password(pamh, "Password: ") };

    match prompt_res {
        Ok(password) => {
            if verify_password_hash(&password, shadow_hash) {
                auth_success.store(true, Ordering::SeqCst);
                syslog_log(libc::LOG_INFO, "Password verification successful.");
            } else {
                syslog_log(libc::LOG_WARNING, "Password verification failed.");
            }
            // Stop fingerprint scanner if it was running
            if let Some(dev) = device {
                let _ = dev.verify_stop();
            }
        }
        Err(err) => {
            syslog_log(
                libc::LOG_DEBUG,
                &format!("Password prompt interrupted or failed: {}", err),
            );
            if let Some(dev) = device {
                let _ = dev.verify_stop();
            }
        }
    }
}

// --- Main PAM Sm Entrypoints ---

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

    // Check if fingerprint scanner is available and has enrolled fingers
    let fp_available = match check_fingerprint_enrolled(&username) {
        Ok(available) => available,
        Err(e) => {
            syslog_log(
                libc::LOG_DEBUG,
                &format!("Fingerprint reader check failed: {}", e),
            );
            false
        }
    };

    if !fp_available {
        syslog_log(
            libc::LOG_INFO,
            "Fingerprint authentication not available; falling back to password.",
        );
        let prompt_res = prompt_password(pamh, "Password: ");
        return match prompt_res {
            Ok(password) => {
                if verify_password_hash(&password, &shadow_hash) {
                    PAM_SUCCESS
                } else {
                    PAM_AUTH_ERR
                }
            }
            Err(err) => err,
        };
    }

    // Initialize DBus connection for fprintd
    let conn = match Connection::system() {
        Ok(c) => c,
        Err(e) => {
            syslog_log(
                libc::LOG_ERR,
                &format!("Failed to connect to system bus: {}", e),
            );
            return PAM_SYSTEM_ERR;
        }
    };

    let manager = match FprintManagerProxyBlocking::new(&conn) {
        Ok(m) => m,
        Err(e) => {
            syslog_log(
                libc::LOG_ERR,
                &format!("Failed to instantiate Fprint Manager proxy: {}", e),
            );
            return PAM_SYSTEM_ERR;
        }
    };

    let device_path = match manager.get_default_device() {
        Ok(path) => path,
        Err(e) => {
            syslog_log(
                libc::LOG_ERR,
                &format!("Failed to get default fprint device: {}", e),
            );
            return PAM_SYSTEM_ERR;
        }
    };

    let device = match FprintDeviceProxyBlocking::builder(&conn)
        .path(device_path)
        .unwrap()
        .build()
    {
        Ok(dev) => dev,
        Err(e) => {
            syslog_log(
                libc::LOG_ERR,
                &format!("Failed to build Fprint Device proxy: {}", e),
            );
            return PAM_SYSTEM_ERR;
        }
    };

    if let Err(e) = device.claim(&username) {
        syslog_log(
            libc::LOG_ERR,
            &format!("Failed to claim fprint device: {}", e),
        );
        return PAM_SYSTEM_ERR;
    }

    setup_sigusr1_handler();

    let auth_success = AtomicBool::new(false);
    let pw_thread_id = Mutex::new(None);

    std::thread::scope(|s| {
        // Spawn fingerprint authentication thread
        s.spawn(|| {
            if let Err(e) = run_fingerprint_auth(&device, &auth_success, &pw_thread_id) {
                syslog_log(
                    libc::LOG_ERR,
                    &format!("Fingerprint thread error: {}", e),
                );
            }
        });

        // Spawn password authentication thread
        s.spawn(|| {
            run_password_auth(
                pamh,
                &shadow_hash,
                &auth_success,
                &pw_thread_id,
                Some(&device),
            );
        });
    });

    restore_sigusr1_handler();
    let _ = device.release();

    if auth_success.load(Ordering::SeqCst) {
        syslog_log(
            libc::LOG_INFO,
            &format!("Authentication successful for user {}.", username),
        );
        PAM_SUCCESS
    } else {
        syslog_log(
            libc::LOG_WARNING,
            &format!("Authentication failed for user {}.", username),
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
