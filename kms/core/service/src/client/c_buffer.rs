//! This module provides a [`DynamicBuffer`] struct that allows to easily share a pointer to u8 with
//! C APIs and free that pointer properly by carrying a `destructor_callback`. In that regard it is
//! carrying a very barebone vtable so that freeing the memory pointed to by the [`DynamicBuffer`]
//! is easy either on the C or Rust side.
//!
//! A `From` implementation is provided to convert a `Vec` of `u8` into a [`DynamicBuffer`] easily,
//! the destructor being populated automatically.
//!
//! A [`DynamicBufferView`] is also provided to indicate that the struct does not own the data and
//! is merely used to share data in a read-only way.

use crate::client::c_utils::get_mut_checked;
use std::ffi::c_int;

#[repr(C)]
pub struct DynamicBufferView {
    pub pointer: *const u8,
    pub length: usize,
}

impl DynamicBufferView {
    /// Returns a view to the memory borrowed by the [`DynamicBufferView`].
    ///
    /// # Safety
    ///
    /// This is safe to call as long as the pointer is valid and the length corresponds to the
    /// length of the underlying buffer.
    pub unsafe fn as_slice(&self) -> &[u8] {
        std::slice::from_raw_parts(self.pointer, self.length)
    }
}

impl From<&[u8]> for DynamicBufferView {
    fn from(a: &[u8]) -> Self {
        Self {
            pointer: a.as_ptr(),
            length: a.len(),
        }
    }
}

#[repr(C)]
pub struct DynamicBuffer {
    pub pointer: *mut u8,
    pub length: usize,
    pub destructor: Option<unsafe extern "C" fn(*mut u8, usize) -> c_int>,
}

impl DynamicBuffer {
    /// Destroy the [`DynamicBuffer`] freeing the underlying memory using the provided
    /// `destructor_callback` and clearing or zeroing all the members.
    ///
    /// If the `pointer` stored in [`DynamicBuffer`] is NULL, then `length` is zeroed out and the
    /// `destructor_callback` is set to `None`. It is similar to how free ignores NULL in C, we just
    /// do some additional housekeeping to signal the [`DynamicBuffer`] is an empty shell.
    ///
    /// # Safety
    ///
    /// Destroy is safe to call only if the `destructor_callback` is the method that needs to be
    /// called to free the stored pointer. For example in C++, memory allocated with `new` must be
    /// freed with `delete`, memory allocated with `new[]` must be freed with `delete[]`.
    ///
    /// Length must indicate how many `u8` are present in the allocation and can be used by the
    /// `destructor_callback` to free memory. For example in the case of a `Vec` being turned into a
    /// [`DynamicBuffer`] the length is obtained by first calling the `len` function on the `Vec`.
    pub unsafe fn destroy(&mut self) -> Result<(), &str> {
        if self.pointer.is_null() {
            // Finish emptying stuff
            self.length = 0;
            self.destructor = None;
            return Ok(());
        }

        match self.destructor {
            Some(destructor_callback) => {
                let res = destructor_callback(self.pointer, self.length);
                if res == 0 {
                    // If the deallocation is successful then we empty the buffer
                    self.pointer = std::ptr::null_mut();
                    self.length = 0;
                    self.destructor = None;
                    return Ok(());
                }
                Err("destructor returned a non 0 error code")
            }
            // We could not free because of a missing destructor, return an error
            None => Err("destructor is NULL, could not destroy DynamicBuffer"),
        }
    }
}

unsafe extern "C" fn free_u8_ptr_built_from_vec_u8(pointer: *mut u8, length: usize) -> c_int {
    if pointer.is_null() {
        return 0;
    }

    let slice = std::slice::from_raw_parts_mut(pointer, length);

    drop(Box::from_raw(slice));

    0
}

impl From<Vec<u8>> for DynamicBuffer {
    fn from(value: Vec<u8>) -> Self {
        // into_boxed_slice shrinks the allocation to fit the content of the vec
        let boxed_slice = value.into_boxed_slice();
        let length = boxed_slice.len();
        let pointer = Box::leak(boxed_slice);

        Self {
            pointer: pointer.as_mut_ptr(),
            length,
            destructor: Some(free_u8_ptr_built_from_vec_u8),
        }
    }
}

/// C API to destroy a [`DynamicBuffer`].
///
/// # Safety
///
/// This function is safe to call if `dynamic_buffer` is not aliased to avoid double frees.
#[no_mangle]
pub unsafe extern "C" fn destroy_dynamic_buffer(dynamic_buffer: *mut DynamicBuffer) -> c_int {
    // Mimics C for calls of free on NULL, nothing occurs
    if dynamic_buffer.is_null() {
        return 0;
    }

    let Ok(dynamic_buffer) = get_mut_checked(dynamic_buffer) else {
        return 1;
    };

    match dynamic_buffer.destroy() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
