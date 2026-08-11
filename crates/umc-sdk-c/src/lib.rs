//! Small stable C ABI over the Rust SDK (sdk.md §31).
//!
//! The ABI deliberately exposes only byte-oriented request/response calls;
//! typed protobuf payloads remain versioned by the Control API schema. Handles
//! carry a generation so a stale pointer cannot be reused after close.
#![allow(unsafe_code)]

use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use umc_sdk::client::{Client, ClientError};

const ABI_VERSION: &[u8] = b"umc-sdk-c/0.1.0\0";
const MAX_C_ABI_PAYLOAD: usize = 1024 * 1024;

#[derive(Debug)]
#[repr(C)]
pub struct umc_status {
    pub code: i32,
    pub message: *mut c_char,
}

#[derive(Debug)]
#[repr(C)]
pub struct umc_bytes {
    pub data: *mut u8,
    pub len: usize,
}

struct ClientState {
    runtime: tokio::runtime::Runtime,
    client: Option<Client>,
    generation: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct umc_handle_t {
    ptr: *mut c_void,
    generation: u64,
}

fn message(text: impl Into<String>) -> *mut c_char {
    CString::new(text.into())
        .unwrap_or_else(|_| CString::new("invalid error message").expect("literal"))
        .into_raw()
}

fn ok_status() -> umc_status {
    umc_status {
        code: 0,
        message: ptr::null_mut(),
    }
}

fn error_status(code: i32, text: impl Into<String>) -> umc_status {
    umc_status {
        code,
        message: message(text),
    }
}

fn map_error(error: &ClientError) -> umc_status {
    let code = match error {
        ClientError::InvalidArgument => 3,
        ClientError::NotFound => 5,
        ClientError::PermissionDenied | ClientError::Denied => 7,
        ClientError::Unauthenticated | ClientError::Authentication => 8,
        ClientError::ResourceExhausted => 9,
        ClientError::Unimplemented(_) => 13,
        ClientError::Unavailable | ClientError::Io(_) | ClientError::Transport(_) => 15,
        ClientError::DataLoss => 16,
        ClientError::Conflict => 17,
        _ => 14,
    };
    error_status(code, format!("{error:?}"))
}

unsafe fn state<'a>(handle: *mut umc_handle_t) -> Result<&'a mut ClientState, umc_status> {
    if handle.is_null() {
        return Err(error_status(3, "null UMC handle"));
    }
    let handle_ref = &mut *handle;
    if handle_ref.ptr.is_null() {
        return Err(error_status(3, "closed UMC handle"));
    }
    let state = &mut *handle_ref.ptr.cast::<ClientState>();
    if state.generation != handle_ref.generation {
        return Err(error_status(9, "stale UMC handle generation"));
    }
    Ok(state)
}

unsafe fn string_arg(value: *const c_char, name: &str) -> Result<String, umc_status> {
    if value.is_null() {
        return Err(error_status(3, format!("null {name}")));
    }
    CStr::from_ptr(value)
        .to_str()
        .map(str::to_owned)
        .map_err(|_| error_status(3, format!("{name} is not UTF-8")))
}

/// Returns the ABI version string owned by the library.
#[no_mangle]
pub extern "C" fn umc_sdk_version() -> *const c_char {
    ABI_VERSION.as_ptr().cast()
}

/// Allocates an unopened client handle.
#[no_mangle]
pub extern "C" fn umc_client_new() -> *mut umc_handle_t {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ptr::null_mut();
    };
    let state = Box::new(ClientState {
        runtime,
        client: None,
        generation: 1,
    });
    let state_ptr = Box::into_raw(state);
    Box::into_raw(Box::new(umc_handle_t {
        ptr: state_ptr.cast(),
        generation: 1,
    }))
}

/// Connects a handle to a daemon control socket.
///
/// # Safety
///
/// `handle` must come from [`umc_client_new`], remain valid for the call, and
/// the two string pointers must reference NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn umc_client_connect(
    handle: *mut umc_handle_t,
    socket: *const c_char,
    client_name: *const c_char,
) -> umc_status {
    let socket = match string_arg(socket, "socket") {
        Ok(value) => value,
        Err(status) => return status,
    };
    let client_name = match string_arg(client_name, "client_name") {
        Ok(value) => value,
        Err(status) => return status,
    };
    let state = match state(handle) {
        Ok(state) => state,
        Err(status) => return status,
    };
    match state
        .runtime
        .block_on(Client::connect(&socket, &client_name))
    {
        Ok(client) => {
            state.client = Some(client);
            ok_status()
        }
        Err(error) => map_error(&error),
    }
}

/// Sends one raw Control API request and transfers the response payload to C.
///
/// # Safety
///
/// `handle` and `out_response` must be valid mutable pointers. `service` and
/// `method` must be NUL-terminated UTF-8 strings. `payload` must reference at
/// least `payload_len` readable bytes (or be null when the length is zero).
#[no_mangle]
pub unsafe extern "C" fn umc_client_request(
    handle: *mut umc_handle_t,
    service: *const c_char,
    method: *const c_char,
    payload: *const u8,
    payload_len: usize,
    out_response: *mut umc_bytes,
) -> umc_status {
    if out_response.is_null() {
        return error_status(3, "null response buffer");
    }
    (*out_response).data = ptr::null_mut();
    (*out_response).len = 0;
    let service = match string_arg(service, "service") {
        Ok(value) => value,
        Err(status) => return status,
    };
    let method = match string_arg(method, "method") {
        Ok(value) => value,
        Err(status) => return status,
    };
    if payload_len > MAX_C_ABI_PAYLOAD {
        return error_status(9, "payload exceeds the 1 MiB C ABI limit");
    }
    if payload_len > 0 && payload.is_null() {
        return error_status(3, "null payload");
    }
    let bytes = if payload_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(payload, payload_len).to_vec()
    };
    let state = match state(handle) {
        Ok(state) => state,
        Err(status) => return status,
    };
    let Some(client) = state.client.as_mut() else {
        return error_status(8, "client is not connected");
    };
    let result = state
        .runtime
        .block_on(client.request(&service, &method, bytes));
    let response = match result {
        Ok(response) => response,
        Err(error) => return map_error(&error),
    };
    let response_payload = response.payload;
    let mut boxed = response_payload.into_boxed_slice();
    (*out_response).data = boxed.as_mut_ptr();
    (*out_response).len = boxed.len();
    std::mem::forget(boxed);
    let code = response.status.map_or(0, |status| status.code);
    if code == 0 {
        ok_status()
    } else {
        error_status(code, "Control API request returned a non-OK status")
    }
}

/// Closes and frees a client handle. Passing NULL is harmless.
///
/// # Safety
///
/// `handle` must be null or a live pointer returned by [`umc_client_new`].
#[no_mangle]
pub unsafe extern "C" fn umc_client_close(handle: *mut umc_handle_t) -> umc_status {
    if handle.is_null() {
        return ok_status();
    }
    let handle_box = Box::from_raw(handle);
    if !handle_box.ptr.is_null() {
        drop(Box::from_raw(handle_box.ptr.cast::<ClientState>()));
    }
    ok_status()
}

/// Frees a payload returned by [`umc_client_request`].
///
/// # Safety
///
/// `bytes` must be a value previously returned through `umc_client_request`
/// and not already freed.
#[no_mangle]
pub unsafe extern "C" fn umc_bytes_free(bytes: umc_bytes) {
    if !bytes.data.is_null() {
        let raw = std::ptr::slice_from_raw_parts_mut(bytes.data, bytes.len);
        drop(Box::<[u8]>::from_raw(raw));
    }
}

/// Frees the optional message in a status value.
///
/// # Safety
///
/// `status` must be a status returned by this library and not already freed.
#[no_mangle]
pub unsafe extern "C" fn umc_status_free(status: umc_status) {
    if !status.message.is_null() {
        drop(CString::from_raw(status.message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_handle_lifecycle() {
        assert_eq!(
            unsafe { CStr::from_ptr(umc_sdk_version()) }.to_bytes_with_nul(),
            b"umc-sdk-c/0.1.0\0"
        );
        let handle = umc_client_new();
        assert!(!handle.is_null());
        unsafe { umc_client_close(handle) };
    }

    #[test]
    fn request_rejects_oversized_payload_before_dereference() {
        let handle = umc_client_new();
        assert!(!handle.is_null());
        let mut response = umc_bytes {
            data: ptr::null_mut(),
            len: 0,
        };
        let status = unsafe {
            umc_client_request(
                handle,
                c"service".as_ptr(),
                c"method".as_ptr(),
                ptr::null(),
                MAX_C_ABI_PAYLOAD + 1,
                &mut response,
            )
        };
        assert_eq!(status.code, 9);
        assert!(response.data.is_null());
        assert_eq!(response.len, 0);
        unsafe {
            umc_status_free(status);
            umc_client_close(handle);
        }
    }
}
