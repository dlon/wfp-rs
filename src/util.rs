use std::{ffi::OsStr, iter, os::windows::ffi::OsStrExt};

/// Convert `s` to a null-terminated UTF-16 string
pub fn string_to_null_terminated_utf16<T: FromIterator<u16>>(s: impl AsRef<OsStr>) -> T {
    s.as_ref().encode_wide().chain(iter::once(0u16)).collect()
}
