use std::any::Any;
use std::cell::RefCell;
use std::ffi::{CString};
use std::panic::AssertUnwindSafe;

enum LastError {
    None,
    Message(CString),
    // Only used when there was a memory panic happens
    // when trying to store the last panic message into the CString above
    NoMemory,
}

std::thread_local! {
   pub static LAST_LOCAL_ERROR: RefCell<LastError> = const { RefCell::new(LastError::None) };
}

pub fn replace_last_error_with_panic_payload(payload: &Box<dyn Any + Send>) {
    LAST_LOCAL_ERROR.with(|local_error| {
        let _previous_error = local_error.replace(panic_payload_to_error(payload));
    });
}

fn panic_payload_to_error(payload: &Box<dyn Any + Send>) -> LastError {
    // Add a catch panic as technically the to_vec could fail
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // Rust doc says:
        // An invocation of the panic!() macro in Rust 2021 or later
        // will always result in a panic payload of type &'static str or String.
        payload
            .downcast_ref::<&str>()
            .map_or_else(|| b"panic occurred".to_vec(), |s| s.as_bytes().to_vec())
    }));

    result.map_or_else(
        |_| LastError::NoMemory,
        |bytes| LastError::Message(CString::new(bytes).unwrap()),
    )
}
