//! Enumeration over WFP objects.

use crate::Transaction;

use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_FILTER0, FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0,
    FwpmFreeMemory0,
};

/// An iterator over filters.
///
/// This struct wraps the [`FwpmFilterEnum0`] API.
///
/// [`FwpmFilterEnum0`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
///
/// # Example
///
/// ```no_run
/// use wfp::{FilterEngineBuilder, FilterEnumerator, Transaction};
/// use std::io;
///
/// fn main() -> io::Result<()> {
///     let mut engine = FilterEngineBuilder::default().dynamic().open()?;
///     let t = Transaction::new(&mut engine)?;
///
///     let mut filter_enum = FilterEnumerator::new(&t)?;
///
///     while let Some(filter) = filter_enum.next() {
///         let filter = filter?;
///         let id = filter.id();
///         println!("Name: {id}");
///     }
///
///     Ok(())
/// }
/// ```
pub struct FilterEnumerator<'a, 'b: 'a> {
    transaction: &'a Transaction<'b>,
    enum_handle: HANDLE,
    exhausted: bool,
    current_entries: *mut *mut FWPM_FILTER0,
    current_num_entries: u32,
    current_index: u32,
}

impl<'a, 'b> FilterEnumerator<'a, 'b> {
    /// Creates a new filter enumerator for the given filter engine.
    ///
    /// This calls `FwpmFilterCreateEnumHandle0` to create an enumeration handle
    /// that can be used to iterate over WFP filters.
    ///
    /// # Arguments
    ///
    /// * `transaction` - A transaction
    ///
    /// # Returns
    ///
    /// Returns a new `FilterEnumerator` on success, or an `io::Error` if the
    /// enumeration handle could not be created.
    pub fn new(transaction: &'a Transaction<'b>) -> io::Result<Self> {
        let mut enum_handle = HANDLE::default();

        // SAFETY:
        // - engine.as_raw_handle() returns a valid engine handle
        // - enum_template is null (enumerate all filters)
        // - enum_handle is a valid pointer to receive the handle
        let status = unsafe {
            FwpmFilterCreateEnumHandle0(
                transaction.engine.as_raw_handle(),
                ptr::null_mut(),
                &mut enum_handle,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(Self {
            transaction,
            enum_handle,
            exhausted: false,
            current_entries: ptr::null_mut(),
            current_num_entries: 0,
            current_index: 0,
        })
    }
}

impl<'a, 'b> FilterEnumerator<'a, 'b> {
    /// Gets the next filter from the enumeration, or `None` if iteration is complete.
    ///
    /// This method returns a `FilterEnumItem` that borrows from the enumerator,
    /// preventing further calls to `next()` until the returned `FilterEnumItem` is dropped.
    ///
    /// If an error occurs, an error is returned, and future calls to `next` return `None`.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<io::Result<FilterEnumItem<'a, 'b, '_>>> {
        const NUM_ENTRIES: u32 = 50;

        if self.exhausted {
            return None;
        }

        // If we have filters in the current batch, return the next one
        if self.current_index < self.current_num_entries {
            // SAFETY: The entries are valid and `current_index` is less than the total number of entries.
            //         Since `FilterEnumItem` borrows `self`, and `next()` borrows self mutably, the
            //         pointer will not be freed until the `FilterEnumItem` has been dropped.
            let idx = usize::try_from(self.current_index).unwrap();
            let filter = unsafe { &**self.current_entries.add(idx) };
            self.current_index += 1;

            return Some(Ok(FilterEnumItem {
                filter,
                _enumerator: self,
            }));
        }

        let prev_num_entries = self.current_num_entries;

        self.free_current_entries();

        // If the previous entries were fewer than requested num, we are done
        if prev_num_entries != 0 && prev_num_entries < NUM_ENTRIES {
            self.exhausted = true;
            return None;
        }

        // SAFETY:
        // - self.engine.as_raw_handle() returns a valid engine handle
        // - self.enum_handle is a valid enumeration handle
        // - entries and num_entries are valid pointers
        let status = unsafe {
            FwpmFilterEnum0(
                self.transaction.engine.as_raw_handle(),
                self.enum_handle,
                NUM_ENTRIES,
                &mut self.current_entries,
                &mut self.current_num_entries,
            )
        };
        self.current_index = 0;

        match status {
            ERROR_SUCCESS => {
                if self.current_num_entries == 0 {
                    self.exhausted = true;
                    return None;
                }

                // SAFETY: Entries contain at least one filter
                //         Since `FilterEnumItem` borrows `self`, and `next()` borrows self mutably, the
                //         pointer will not be freed until the `FilterEnumItem` has been dropped.
                let filter = unsafe { &**self.current_entries };

                self.current_index = 1;

                Some(Ok(FilterEnumItem {
                    filter,
                    _enumerator: self,
                }))
            }
            ERROR_NO_MORE_ITEMS => {
                self.exhausted = true;
                None
            }
            _ => {
                self.exhausted = true;
                Some(Err(io::Error::from_raw_os_error(status as i32)))
            }
        }
    }

    /// Frees the current entries if they exist.
    fn free_current_entries(&mut self) {
        if !self.current_entries.is_null() {
            // SAFETY: current_entries was allocated by FwpmFilterEnum0
            unsafe { FwpmFreeMemory0((&mut self.current_entries) as *mut _ as *mut _) };
            self.current_entries = ptr::null_mut();
            self.current_num_entries = 0;
            self.current_index = 0;
        }
    }
}

impl<'a, 'b> Drop for FilterEnumerator<'a, 'b> {
    fn drop(&mut self) {
        // Free any current entries before destroying the handle
        self.free_current_entries();

        // SAFETY:
        // - self.engine.as_raw_handle() returns a valid engine handle
        // - self.enum_handle is a valid enumeration handle created by FwpmFilterCreateEnumHandle0
        // - This is called exactly once during drop
        unsafe {
            FwpmFilterDestroyEnumHandle0(self.transaction.engine.as_raw_handle(), self.enum_handle);
        }
    }
}

/// A WFP filter
pub struct FilterEnumItem<'a, 'b, 'c> {
    filter: &'c FWPM_FILTER0,
    _enumerator: &'c FilterEnumerator<'a, 'b>,
}

impl<'a, 'b, 'c> FilterEnumItem<'a, 'b, 'c> {
    /// Return the filter ID.
    ///
    /// This corresponds to the `filterId` field in the underlying `FWPM_FILTER0` structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn id(&self) -> u64 {
        self.filter.filterId
    }

    /// Return the filter GUID.
    ///
    /// This corresponds to the `filterKey` field in the underlying `FWPM_FILTER0` structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn guid(&self) -> windows_sys::core::GUID {
        self.filter.filterKey
    }

    /// Return the filter provider, if set.
    ///
    /// This corresponds to the `providerKey` field in the underlying `FWPM_FILTER0` structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn provider(&self) -> Option<windows_sys::core::GUID> {
        if self.filter.providerKey.is_null() {
            None
        } else {
            // SAFETY: The provider contains no pointers, and is non-null.
            Some(unsafe { *self.filter.providerKey })
        }
    }

    /// Return the filter name, if set.
    ///
    /// This corresponds to `displayName.name` in the underlying `FWPM_FILTER0` structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn name(&self) -> io::Result<Option<String>> {
        if !self.filter.displayData.name.is_null() {
            let len = unsafe { wcslen(self.filter.displayData.name) };
            let slice = unsafe { std::slice::from_raw_parts(self.filter.displayData.name, len) };
            String::from_utf16(slice)
                .map_err(|_err| io::Error::other("invalid filter name"))
                .map(Some)
        } else {
            Ok(None)
        }
    }

    /// Return the filter description, if set.
    ///
    /// This corresponds to `displayName.description` in the underlying `FWPM_FILTER0` structure.
    ///
    /// [`FWPM_FILTER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/
    pub fn description(&self) -> io::Result<Option<String>> {
        if !self.filter.displayData.description.is_null() {
            let len = unsafe { wcslen(self.filter.displayData.description) };
            let slice =
                unsafe { std::slice::from_raw_parts(self.filter.displayData.description, len) };
            String::from_utf16(slice)
                .map_err(|_err| io::Error::other("invalid filter description"))
                .map(Some)
        } else {
            Ok(None)
        }
    }
}

/// Retrieve the length of `s`, a null-terminated UTF-16 string.
///
/// # Safety
///
/// `s` must be null-terminated.
unsafe fn wcslen(s: *const u16) -> usize {
    let mut current = s;
    while unsafe { std::ptr::read_unaligned(current) } != 0 {
        current = unsafe { current.add(1) };
    }
    usize::try_from(unsafe { current.offset_from(s) }).unwrap()
}
