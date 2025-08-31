//! Sublayer creation and management

use std::ffi::OsStr;
use std::io;
use std::iter;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerAdd0;
use windows_sys::core::GUID;

use crate::transaction::Transaction;

/// Builder for creating Windows Filtering Platform sublayers.
///
/// Sublayers provide a way to organize and prioritize filters within the same layer.
/// This builder uses the type system to ensure that all required fields
/// (name and description) are provided before a sublayer can be created.
/// The underlying sublayer is represented by the [`FWPM_SUBLAYER0`] structure.
///
/// Sublayers are essential for controlling filter evaluation order through their weight values.
/// For more information about how filters are prioritized and evaluated, see the
/// [Filter Arbitration] documentation.
///
/// # Type Parameters
///
/// The type parameters track which required fields have been set:
/// - `Name`: Tracks whether a name has been provided
///
/// # Example
///
/// ```no_run
/// use wfp::{SubLayerBuilder, Transaction};
/// use std::io;
///
/// fn create_sublayer(transaction: &Transaction) -> io::Result<()> {
///     SubLayerBuilder::default()
///         .name("My SubLayer")
///         .description("Custom sublayer for application filters")
///         .weight(100)
///         .add(transaction)?;
///     Ok(())
/// }
/// ```
///
/// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
/// [Filter Arbitration]: https://docs.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
#[derive(Clone)]
pub struct SubLayerBuilder<Name> {
    sublayer: FWPM_SUBLAYER0,

    display_data_name_buffer: Arc<[u16]>,
    display_data_desc_buffer: Arc<[u16]>,

    _pd: std::marker::PhantomData<Name>,
}

/// Type-level marker indicating that a sublayer name has not been set.
#[doc(hidden)]
pub struct SubLayerBuilderMissingName;

/// Type-level marker indicating that a sublayer name has been set.
#[doc(hidden)]
pub struct SubLayerBuilderHasName;

impl Default for SubLayerBuilder<SubLayerBuilderMissingName> {
    /// Creates a new sublayer builder with no fields set.
    ///
    /// You must call `name()` and `description()` before the sublayer
    /// can be added to a transaction.
    ///
    /// This corresponds to the type [`FWPM_SUBLAYER0`].
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
    fn default() -> SubLayerBuilder<SubLayerBuilderMissingName> {
        SubLayerBuilder {
            sublayer: Default::default(),
            display_data_name_buffer: Default::default(),
            display_data_desc_buffer: Default::default(),
            _pd: Default::default(),
        }
    }
}

impl<Name> SubLayerBuilder<Name> {
    /// Sets the display name for the sublayer.
    ///
    /// The name should be descriptive of the sublayer's purpose.
    ///
    /// This sets the `displayData.name` field in the underlying [`FWPM_SUBLAYER0`] structure.
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
    pub fn name(mut self, name: impl AsRef<OsStr>) -> SubLayerBuilder<SubLayerBuilderHasName> {
        self.display_data_name_buffer = name
            .as_ref()
            .encode_wide()
            .chain(iter::once(0u16))
            .collect();
        // SAFETY: The data is never mutated
        self.sublayer.displayData.name = self.display_data_name_buffer.as_ptr() as *mut _;
        SubLayerBuilder {
            sublayer: self.sublayer,
            display_data_name_buffer: self.display_data_name_buffer,
            display_data_desc_buffer: self.display_data_desc_buffer,

            _pd: std::marker::PhantomData,
        }
    }

    /// Sets the description for the sublayer.
    ///
    /// The description provides additional details about the sublayer's purpose.
    ///
    /// This sets the `displayData.description` field in the underlying [`FWPM_SUBLAYER0`] structure.
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
    pub fn description(mut self, desc: impl AsRef<OsStr>) -> SubLayerBuilder<Name> {
        self.display_data_desc_buffer = desc
            .as_ref()
            .encode_wide()
            .chain(iter::once(0u16))
            .collect();
        // SAFETY: The data is never mutated
        self.sublayer.displayData.description = self.display_data_desc_buffer.as_ptr() as *mut _;
        SubLayerBuilder {
            sublayer: self.sublayer,
            display_data_name_buffer: self.display_data_name_buffer,
            display_data_desc_buffer: self.display_data_desc_buffer,

            _pd: std::marker::PhantomData,
        }
    }

    /// Sets the weight (priority) of the sublayer.
    ///
    /// Higher weight values indicate higher priority. Filters in higher-weight
    /// sublayers are evaluated before filters in lower-weight sublayers.
    ///
    /// This sets the `weight` field in the underlying [`FWPM_SUBLAYER0`] structure.
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
    pub fn weight(mut self, weight: u16) -> SubLayerBuilder<Name> {
        self.sublayer.weight = weight;
        self
    }

    /// Sets a custom GUID for the sublayer.
    ///
    /// If not set, Windows will automatically generate a GUID for the sublayer.
    /// Setting a custom GUID allows you to reference the sublayer later.
    ///
    /// This sets the `subLayerKey` field in the underlying [`FWPM_SUBLAYER0`] structure.
    ///
    /// [`FWPM_SUBLAYER0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
    pub fn guid(mut self, guid: GUID) -> SubLayerBuilder<Name> {
        self.sublayer.subLayerKey = guid;
        self
    }
}

impl SubLayerBuilder<SubLayerBuilderHasName> {
    /// Adds the configured sublayer to a transaction.
    ///
    /// This method is only available when all required fields (name and description)
    /// have been set on the builder.
    ///
    /// It calls [`FwpmSubLayerAdd0`] to add the sublayer to the engine.
    ///
    /// [`FwpmSubLayerAdd0`]: https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayeradd0
    pub fn add<'a>(&self, transaction: &Transaction<'a>) -> io::Result<()> {
        // SAFETY:
        // - transaction.engine.as_raw_handle() returns a valid engine handle
        // - &self.sublayer is a valid pointer to a properly initialized FWPM_SUBLAYER0 structure
        // - All required fields (name, description) have been set by the type system
        // - The display data buffers are kept alive by self, ensuring string pointers remain valid
        // - NULL security descriptor pointer is acceptable (uses default security)
        let status = unsafe {
            FwpmSubLayerAdd0(
                transaction.engine.as_raw_handle(),
                &self.sublayer,
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        Ok(())
    }
}
