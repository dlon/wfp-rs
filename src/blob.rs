use std::{ffi::OsStr, io};

use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    NetworkManagement::WindowsFilteringPlatform::{
        FWP_BYTE_BLOB, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    },
};

use crate::util::string_to_null_terminated_utf16;

/// An owned byte blob that is freed using `FwpmFreeMemory0`.
pub struct OwnedByteBlob {
    inner: InnerBlob,
}
enum InnerBlob {
    Pointer {
        blob: *mut FWP_BYTE_BLOB,
    },
    Vec {
        blob: FWP_BYTE_BLOB,
        _buf: Box<[u8]>,
    },
}

impl OwnedByteBlob {
    /// Take ownership of a pointer that must be freed using `FwpmFreeMemory0`.
    ///
    /// # Safety
    ///
    /// This must be a pointer that should be freed using `FwpmFreeMemory`,
    /// such as one returned by `FwpmGetAppIdFromFileName0`.
    pub unsafe fn from_raw(blob: *mut FWP_BYTE_BLOB) -> Self {
        Self {
            inner: InnerBlob::Pointer { blob },
        }
    }

    /// Return pointer to the underlying byte blob
    pub fn as_ptr(&self) -> *const FWP_BYTE_BLOB {
        match &self.inner {
            InnerBlob::Pointer { blob } => *blob,
            InnerBlob::Vec { blob, .. } => blob,
        }
    }
}

impl<T: AsRef<[u8]>> From<T> for OwnedByteBlob {
    fn from(value: T) -> Self {
        let value: Box<[u8]> = Box::from(value.as_ref());
        let blob = FWP_BYTE_BLOB {
            data: value.as_ptr() as _,
            size: u32::try_from(value.len()).expect("blob too large"),
        };
        OwnedByteBlob {
            inner: InnerBlob::Vec { blob, _buf: value },
        }
    }
}

impl Drop for OwnedByteBlob {
    fn drop(&mut self) {
        if let InnerBlob::Pointer { mut blob } = self.inner {
            // SAFETY: This was created using a value that must be freed with this function
            unsafe { FwpmFreeMemory0(&mut blob as *mut _ as *mut _) };
        }
    }
}

/// Return a byte blob representing the app ID of a filename.
///
/// The underlying function is [`FwpmGetAppIdFromFileName0`].
///
/// [`FwpmGetAppIdFromFileName0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
pub fn app_id_from_filename(app_path: impl AsRef<OsStr>) -> io::Result<OwnedByteBlob> {
    let path: Vec<u16> = string_to_null_terminated_utf16(app_path);
    let mut blob = std::ptr::null_mut();

    // SAFETY: We are passing a valid pointer to a pointer and null-terminated string
    let status = unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    // SAFETY: `blob` is a valid pointer returned by `FwpmGetAppIdFromFileName0`
    Ok(unsafe { OwnedByteBlob::from_raw(blob) })
}
