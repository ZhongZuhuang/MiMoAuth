//! Minimal hand-rolled PAM client FFI (pam_start/pam_authenticate/pam_end).
//!
//! Only what we need: verify a password against the system PAM stack.
//! The password stays inside the conversation callback and is never logged.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::os::raw::c_uint;

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn = extern "C" fn(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: ConvFn,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        conversation: *const PamConv,
        pamh: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut c_void, pam_status: c_int) -> c_int;
}

struct ConvData {
    password: Vec<u8>,
    answered: bool,
    log: Vec<String>,
}

extern "C" fn conversation(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata_ptr.is_null() {
        return PAM_SUCCESS;
    }
    let data = unsafe { &mut *(appdata_ptr as *mut ConvData) };

    let responses = unsafe { libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>()) }
        as *mut PamResponse;
    if responses.is_null() {
        return 1; // PAM_BUF_ERR
    }

    for i in 0..num_msg as usize {
        let m = unsafe { &**msg.add(i) };
        let out = unsafe { &mut *responses.add(i) };
        match m.msg_style {
            PAM_PROMPT_ECHO_OFF => {
                let bytes: &[u8] = if !data.answered {
                    data.answered = true;
                    &data.password
                } else {
                    b""
                };
                let mut with_nul = bytes.to_vec();
                with_nul.push(0);
                // PAM takes ownership of resp strings: hand over a copy.
                out.resp = unsafe { libc::strdup(with_nul.as_ptr() as *const c_char) };
                with_nul.zeroize_local();
            }
            PAM_PROMPT_ECHO_ON => {
                out.resp = unsafe { libc::strdup(b"\0".as_ptr() as *const c_char) };
            }
            PAM_ERROR_MSG | PAM_TEXT_INFO => {
                if !m.msg.is_null() {
                    let s = unsafe { CStr::from_ptr(m.msg) }.to_string_lossy();
                    data.log.push(s.to_string());
                }
                out.resp = std::ptr::null_mut();
            }
            _ => {
                out.resp = std::ptr::null_mut();
            }
        }
    }
    unsafe { *resp = responses };
    PAM_SUCCESS
}

/// Zeroize helper without an extra crate.
trait ZeroizeLocal {
    fn zeroize_local(&mut self);
}
impl ZeroizeLocal for Vec<u8> {
    fn zeroize_local(&mut self) {
        for b in self.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        self.clear();
    }
}

pub struct VerifyError {
    pub code: i32,
    pub messages: Vec<String>,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pam_authenticate failed with code {}", self.code)
    }
}

/// Verify `password` for `user` through the PAM service `service`.
///
/// Blocking (runs FFI); callers should use a worker thread.
pub fn verify_password(user: &str, password: &[u8], service: &str) -> Result<(), VerifyError> {
    if password.contains(&0) {
        return Err(VerifyError {
            code: -1,
            messages: vec!["password contains NUL".into()],
        });
    }
    let c_user = CString::new(user).map_err(|_| VerifyError {
        code: -2,
        messages: vec!["user contains NUL".into()],
    })?;
    let c_service = CString::new(service).map_err(|_| VerifyError {
        code: -2,
        messages: vec!["service contains NUL".into()],
    })?;

    let mut data = ConvData {
        password: password.to_vec(),
        answered: false,
        log: Vec::new(),
    };
    let conv = PamConv {
        conv: conversation,
        appdata_ptr: &mut data as *mut ConvData as *mut c_void,
    };

    let mut pamh: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { pam_start(c_service.as_ptr(), c_user.as_ptr(), &conv, &mut pamh) };
    if rc != PAM_SUCCESS || pamh.is_null() {
        return Err(VerifyError {
            code: rc,
            messages: data.log,
        });
    }

    let rc = unsafe { pam_authenticate(pamh, 0) };
    unsafe { pam_end(pamh, rc) };

    data.password.zeroize_local();

    if rc == PAM_SUCCESS {
        Ok(())
    } else {
        Err(VerifyError {
            code: rc,
            messages: data.log,
        })
    }
}

/// Resolve the login name for a uid.
pub fn username_for_uid(uid: u32) -> Option<String> {
    unsafe {
        let pw = libc::getpwuid(uid as c_uint);
        if pw.is_null() || (*pw).pw_name.is_null() {
            return None;
        }
        Some(CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}
