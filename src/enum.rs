//! Enumeration functionality for iterating over WFP objects.

use crate::engine::FilterEngine;

use std::io;
use std::marker::PhantomData;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FWPM_FILTER0, FWPM_FILTER_ENUM_TEMPLATE0, FWP_EMPTY
};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, ERROR_NO_MORE_ITEMS, HANDLE};

/// An iterator over filters.
///
/// This struct wraps the [`FwpmFilterEnum0`] API.
///
/// [`FwpmFilterEnum0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
///
/// # Example
///
/// ```no_run
/// use wfp::{FilterEngineBuilder, FilterEnumerator};
/// use std::io;
///
/// fn main() -> io::Result<()> {
///     let engine = FilterEngineBuilder::default().dynamic().open()?;
///     
///     let filter_enum = FilterEnumerator::new(&engine)?;
///     
///     for filter in filter_enum {
///         let filter = filter?;
///         println!("Filter found with weight: {}", filter.weight);
///     }
///     
///     Ok(())
/// }
/// ```
pub struct FilterEnumerator<'a> {
    engine: &'a FilterEngine,
    enum_handle: HANDLE,
    current_entries: *mut *mut FWPM_FILTER0,
    num_entries: u32,
    entries_idx: u32,
}

impl<'a> FilterEnumerator<'a> {
    /// Creates a new filter enumerator for the given filter engine.
    ///
    /// This calls `FwpmFilterCreateEnumHandle0` to create an enumeration handle
    /// that can be used to iterate over all filters.
    ///
    /// # Arguments
    ///
    /// * `engine` - The filter engine to enumerate filters from
    ///
    /// # Returns
    ///
    /// Returns a new `FilterEnumerator` on success, or an `io::Error` if the
    /// enumeration handle could not be created.
    pub fn new(engine: &'a FilterEngine) -> io::Result<Self> {
        let mut enum_handle = HANDLE::default();

        // SAFETY:
        // - engine.as_raw_handle() returns a valid engine handle
        // - enum_template is a valid FWPM_FILTER_ENUM_TEMPLATE0 struct
        // - enum_handle is a valid pointer to receive the handle
        let status = unsafe {
            FwpmFilterCreateEnumHandle0(
                engine.as_raw_handle(),
                ptr::null_mut(),
                &mut enum_handle,
            )
        };
        
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        
        Ok(Self {
            engine,
            enum_handle,
            current_entries: ptr::null_mut(),
            num_entries: 0,
            entries_idx: 0,
        })
    }

    fn free_current_entries(&mut self) {
        if self.current_entries.is_null() {
            return;
        }

        // FIXME: am I supposed to give a pointer
        unsafe { FwpmFreeMemory0((&mut self.current_entries) as *mut _ as *mut _); }

        self.current_entries = ptr::null_mut();
        self.num_entries = 0;
        self.entries_idx = 0;
    }
}

impl<'a> Iterator for FilterEnumerator<'a> {
    type Item = io::Result<FilterInfo>;
    
    fn next(&mut self) -> Option<Self::Item> {
        const ENTRIES_PER_CALL: u32 = 20;

        loop {
            if self.current_entries.is_null() {
                // SAFETY:
                // - self.engine.as_raw_handle() returns a valid engine handle
                // - self.enum_handle is a valid enumeration handle
                // - entries and num_entries_returned are valid pointers
                let status = unsafe {
                    FwpmFilterEnum0(
                        self.engine.as_raw_handle(),
                        self.enum_handle,
                        ENTRIES_PER_CALL,
                        &mut self.current_entries,
                        &mut self.num_entries,
                    )
                };

                match status {
                    ERROR_SUCCESS => (),
                    // Not sure if this is reachable
                    ERROR_NO_MORE_ITEMS => return None,
                    _ => return Some(Err(io::Error::from_raw_os_error(status as i32))),
                }

                self.entries_idx = 0;

                if self.num_entries == 0 {
                    return None;
                }
            } else {
                self.entries_idx += 1;
            }

            if self.entries_idx < self.num_entries {
                break;
            }

            // Retrieve new list, unless we have exhausted all entries
            let previous_num = self.num_entries;
            self.free_current_entries();
            if previous_num < ENTRIES_PER_CALL {
                return None;
            }
        }

        // SAFETY:
        // - entries is valid and points to an array of FWPM_FILTER0 pointers
        // - `entries_idx` is less than the number of entries
        let filter_ptr = unsafe { *self.current_entries.offset(self.entries_idx as isize) };

        // SAFETY: `filter_ptr` is a valid pointer to an FWPM_FILTER0
        unsafe { FilterInfo::from_raw(filter_ptr) }.map(Some).transpose()
    }
}

impl<'a> Drop for FilterEnumerator<'a> {
    fn drop(&mut self) {
        self.free_current_entries();

        // SAFETY:
        // - self.engine.as_raw_handle() returns a valid engine handle
        // - self.enum_handle is a valid enumeration handle created by FwpmFilterCreateEnumHandle0
        // - This is called exactly once during drop
        unsafe {
            FwpmFilterDestroyEnumHandle0(self.engine.as_raw_handle(), self.enum_handle);
        }
    }
}

struct FilterEntries<'a, 'b> {
    entries: *mut *mut FWPM_FILTER0,
    num_entries: u32,
    entries_idx: u32,
    _phantom: PhantomData<&'a FilterEnumerator<'b>>,
}

impl<'a, 'b> FilterEntries<'a, 'b> {
    unsafe fn new(
        enumerator: &'a FilterEnumerator<'b>,
    ) -> io::Result<Self> {
        const ENTRIES_PER_CALL: u32 = 20;

        let mut entries = ptr::null_mut();
        let mut num_entries = 0;

        // SAFETY:
        // - self.engine.as_raw_handle() returns a valid engine handle
        // - self.enum_handle is a valid enumeration handle
        // - entries and num_entries_returned are valid pointers
        let status = unsafe {
            FwpmFilterEnum0(
                enumerator.engine.as_raw_handle(),
                enumerator.enum_handle,
                ENTRIES_PER_CALL,
                &mut entries,
                &mut num_entries,
            )
        };

        match status {
            ERROR_SUCCESS => (),
            _ => return Err(io::Error::from_raw_os_error(status as i32)),
        }

        Ok(FilterEntries {
            entries,
            num_entries,
            entries_idx: 0,
            _phantom: PhantomData,
        })
    }
}

impl Drop for FilterEntries<'_, '_> {
    fn drop(&mut self) {
        // FIXME: am I supposed to give a pointer
        unsafe { FwpmFreeMemory0((&mut self.entries) as *mut _ as *mut _); }
    }
}

/// Information about a filter retrieved from the Windows Filtering Platform.
///
/// This struct provides a safe wrapper around the `FWPM_FILTER0` structure
/// returned by the enumeration APIs.
pub struct FilterInfo {
    /// The display name of the filter, if available.
    pub display_name: Option<String>,
    /// The description of the filter, if available.
    pub description: Option<String>,
}

impl FilterInfo {
    /// Creates a `FilterInfo` from a raw `FWPM_FILTER0` pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `filter_ptr` points to a valid `FWPM_FILTER0`
    /// structure that remains valid for the duration of this function call.
    unsafe fn from_raw(filter_ptr: *const FWPM_FILTER0) -> io::Result<Self> {
        // SAFETY: Caller promises that it's a valid pointer
        let filter = unsafe { &*filter_ptr };
        
        let display_name = if filter.displayData.name.is_null() {
            None
        } else {
            let wide_str = unsafe {
                std::slice::from_raw_parts(
                    filter.displayData.name,
                    wcslen(filter.displayData.name),
                )
            };
            Some(String::from_utf16(wide_str).map_err(|_err| io::Error::other("invalid filter name"))?)
        };
        
        let description = if filter.displayData.description.is_null() {
            None
        } else {
            let wide_str = unsafe {
                std::slice::from_raw_parts(
                filter.displayData.description,
                wcslen(filter.displayData.description),
                )
            };
            Some(String::from_utf16(wide_str).map_err(|_err| io::Error::other("invalid filter description"))?)
        };
        
        Ok(Self {
            display_name,
            description,
        })
    }
}

/// Calculate the length of a null-terminated wide string.
///
/// # Safety
///
/// The caller must ensure that `ptr` points to a valid null-terminated wide string.
unsafe fn wcslen(ptr: *const u16) -> usize {
    let mut len = 0;
    // SAFETY: `ptr` is null-terminated
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FilterEngineBuilder;

    #[test]
    #[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
    fn test_filter_enumerator_creation() {
        // This test requires Windows and appropriate permissions
        if let Ok(engine) = FilterEngineBuilder::default().dynamic().open() {
            let result = FilterEnumerator::new(&engine);
            assert!(result.is_ok());
        }
    }
}
