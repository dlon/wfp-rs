//! Filter condition creation and management.

use std::ffi::OsStr;
use std::io;
use std::sync::Arc;

use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_MATCH_GREATER, FWP_MATCH_GREATER_OR_EQUAL,
    FWP_MATCH_LESS, FWP_MATCH_LESS_OR_EQUAL, FWP_MATCH_RANGE, FWP_UINT8, FWP_UINT16, FWP_UINT32,
    FWP_UNICODE_STRING_TYPE, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_LOCAL_ADDRESS,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
};
use windows_sys::core::GUID;

use crate::blob::{OwnedByteBlob, app_id_from_filename};
use crate::util::string_to_null_terminated_utf16;

/// Typed builder for port-based conditions.
///
/// This builder enforces that only valid port numbers (u16) can be used as values,
/// providing compile-time type safety for port-related filtering.
///
/// # Example
///
/// ```no_run
/// use wfp::{PortConditionBuilder, ConditionField, MatchType};
///
/// // Block traffic to port 80
/// let condition = PortConditionBuilder::remote()
///     .equal(80)
///     .build();
/// ```
#[derive(Clone)]
pub struct PortConditionBuilder<Value> {
    builder: ConditionBuilder,
    _pd: std::marker::PhantomData<Value>,
}

/// Type-state marker indicating the port value has not been set.
#[doc(hidden)]
pub struct PortConditionBuilderMissingValue;

/// Type-state marker indicating the port value has been set.
#[doc(hidden)]
pub struct PortConditionBuilderHasValue;

impl PortConditionBuilder<PortConditionBuilderMissingValue> {
    /// Creates a remote port condition.
    pub fn remote() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::RemotePort),
            _pd: std::marker::PhantomData,
        }
    }

    /// Creates a local port condition.
    pub fn local() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::LocalPort),
            _pd: std::marker::PhantomData,
        }
    }
}

impl<Value> PortConditionBuilder<Value> {
    /// Creates a condition that matches the exact port number.
    pub fn equal(self, port: u16) -> PortConditionBuilder<PortConditionBuilderHasValue> {
        PortConditionBuilder {
            builder: self.builder.match_type(MatchType::Equal).value_u16(port),
            _pd: std::marker::PhantomData,
        }
    }
}

impl PortConditionBuilder<PortConditionBuilderHasValue> {
    /// Builds the condition.
    ///
    /// This method is only available when a port value has been set with `equal()`.
    pub fn build(self) -> Condition {
        self.builder.build().expect("condition should be valid")
    }
}

/// Typed builder for protocol-based conditions.
///
/// This builder enforces that only valid protocol numbers (u32) can be used as values,
/// providing compile-time type safety for protocol-related filtering.
///
/// # Example
///
/// ```no_run
/// use wfp::{ProtocolConditionBuilder, MatchType};
///
/// // Block TCP traffic (protocol 6)
/// let tcp_condition = ProtocolConditionBuilder::tcp().build();
///
/// // Block UDP traffic (protocol 17)
/// let udp_condition = ProtocolConditionBuilder::udp().build();
/// ```
#[derive(Clone)]
pub struct ProtocolConditionBuilder {
    builder: ConditionBuilder,
}

impl ProtocolConditionBuilder {
    /// Creates a condition that matches TCP traffic (protocol 6).
    pub fn tcp() -> Self {
        Self::new().equal(6)
    }

    /// Creates a condition that matches UDP traffic (protocol 17).
    pub fn udp() -> Self {
        Self::new().equal(17)
    }

    /// Creates a condition that matches ICMP traffic (protocol 1).
    pub fn icmp() -> Self {
        Self::new().equal(1)
    }

    /// Creates a new protocol condition builder.
    fn new() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::Protocol),
        }
    }

    /// Creates a condition that matches the exact protocol number.
    fn equal(self, protocol: u8) -> Self {
        Self {
            builder: self.builder.match_type(MatchType::Equal).value_u8(protocol),
        }
    }

    /// Builds the condition.
    pub fn build(self) -> Condition {
        self.builder.build().expect("all values are set")
    }
}

impl Default for ProtocolConditionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed builder for application ID conditions.
///
/// These are used for application-based filtering.
///
/// # Example
///
/// ```ignore
/// use wfp::AppIdConditionBuilder;
///
/// // Block traffic from a specific application
/// let app_condition = AppIdConditionBuilder::default()
///     .equal(r"C:\Program Files\MyApp\app.exe")?
///     .build();
/// ```
pub struct AppIdConditionBuilder<Value> {
    builder: ConditionBuilder,
    _pd: std::marker::PhantomData<Value>,
}

/// Type-state marker indicating the app ID value has not been set.
#[doc(hidden)]
pub struct AppIdConditionBuilderMissingValue;

/// Type-state marker indicating the app ID value has been set.
#[doc(hidden)]
pub struct AppIdConditionBuilderHasValue;

impl AppIdConditionBuilder<AppIdConditionBuilderMissingValue> {
    /// Creates a new application ID condition builder.
    pub fn new() -> Self {
        Self {
            builder: ConditionBuilder::default().field(ConditionField::AppId),
            _pd: std::marker::PhantomData,
        }
    }
}

impl<Value> AppIdConditionBuilder<Value> {
    /// Creates a condition that matches the exact application path.
    pub fn equal(
        self,
        app_path: impl AsRef<OsStr>,
    ) -> io::Result<AppIdConditionBuilder<AppIdConditionBuilderHasValue>> {
        let byte_blob = app_id_from_filename(app_path)?;

        Ok(AppIdConditionBuilder {
            builder: self
                .builder
                .match_type(MatchType::Equal)
                .value_byte_blob(byte_blob),
            _pd: std::marker::PhantomData,
        })
    }
}

impl AppIdConditionBuilder<AppIdConditionBuilderHasValue> {
    /// Builds the condition.
    ///
    /// This method is only available when an application path has been set with `equal()`.
    pub fn build(self) -> Condition {
        self.builder.build().expect("condition should be valid")
    }
}

impl Default for AppIdConditionBuilder<AppIdConditionBuilderMissingValue> {
    fn default() -> Self {
        Self::new()
    }
}

/// Specifies how a condition value should be matched against network traffic.
///
/// These correspond to the [`FWP_MATCH_TYPE`] enumeration values.
///
/// [`FWP_MATCH_TYPE`]: https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_match_type
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchType {
    /// The condition value must exactly match the network data.
    Equal = FWP_MATCH_EQUAL,
    /// The network data must be greater than the condition value.
    Greater = FWP_MATCH_GREATER,
    /// The network data must be less than the condition value.
    Less = FWP_MATCH_LESS,
    /// The network data must be greater than or equal to the condition value.
    GreaterOrEqual = FWP_MATCH_GREATER_OR_EQUAL,
    /// The network data must be less than or equal to the condition value.
    LessOrEqual = FWP_MATCH_LESS_OR_EQUAL,
    /// The network data must fall within a specified range.
    Range = FWP_MATCH_RANGE,
}

/// Represents different types of filter conditions that can be applied to network traffic.
///
/// Each condition type corresponds to a specific field in the network packet or connection
/// that can be inspected and matched against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionField {
    /// Remote IP address of the connection.
    RemoteAddress,
    /// Local IP address of the connection.
    LocalAddress,
    /// Remote port number of the connection.
    RemotePort,
    /// Local port number of the connection.
    LocalPort,
    /// IP protocol (TCP, UDP, etc.).
    Protocol,
    /// Application ID (executable path).
    ///
    /// The lower-case fully qualified device path of the application.
    /// (For example, "\device\hardiskvolume1\program files\application.exe".)
    AppId,
}

impl ConditionField {
    /// Returns the Windows GUID identifier for this condition field.
    pub fn guid(&self) -> &GUID {
        match self {
            Self::RemoteAddress => &FWPM_CONDITION_IP_REMOTE_ADDRESS,
            Self::LocalAddress => &FWPM_CONDITION_IP_LOCAL_ADDRESS,
            Self::RemotePort => &FWPM_CONDITION_IP_REMOTE_PORT,
            Self::LocalPort => &FWPM_CONDITION_IP_LOCAL_PORT,
            Self::Protocol => &FWPM_CONDITION_IP_PROTOCOL,
            Self::AppId => &FWPM_CONDITION_ALE_APP_ID,
        }
    }
}

/// Builder for creating filter conditions.
///
/// Conditions specify criteria that network traffic must match for a filter to apply.
/// This builder provides a flexible way to construct conditions with appropriate
/// data types and match operations.
///
/// For type-safe alternatives, consider using the specialized builders:
/// - [`PortConditionBuilder`] for port-based conditions
/// - [`ProtocolConditionBuilder`] for protocol-based conditions
/// - [`AppIdConditionBuilder`] for application-based conditions
///
/// # Example
///
/// ```ignore
/// // Block traffic to port 80 (untyped approach)
/// let condition = ConditionBuilder::default()
///     .field(ConditionField::RemotePort)
///     .match_type(MatchType::Equal)
///     .value_u16(80)
///     .build()?;
/// ```
#[derive(Default, Clone)]
struct ConditionBuilder {
    field: Option<ConditionField>,
    match_type: Option<MatchType>,
    value: Option<Arc<ConditionValue>>,
}

/// Internal representation of condition values with their associated buffers.
enum ConditionValue {
    UInt32(u32),
    UInt16(u16),
    UInt8(u8),
    String(Vec<u16>),
    ByteBlob { blob: OwnedByteBlob },
}

impl ConditionBuilder {
    /// Sets the field that this condition will match against.
    pub fn field(mut self, field: ConditionField) -> Self {
        self.field = Some(field);
        self
    }

    /// Sets how the condition value should be matched.
    pub fn match_type(mut self, match_type: MatchType) -> Self {
        self.match_type = Some(match_type);
        self
    }

    /// Sets a 32-bit unsigned integer value for the condition.
    #[allow(dead_code)]
    pub fn value_u32(mut self, value: u32) -> Self {
        self.value = Some(ConditionValue::UInt32(value).into());
        self
    }

    /// Sets a 16-bit unsigned integer value for the condition.
    pub fn value_u16(mut self, value: u16) -> Self {
        self.value = Some(ConditionValue::UInt16(value).into());
        self
    }

    /// Sets a 8-bit unsigned integer value for the condition.
    pub fn value_u8(mut self, value: u8) -> Self {
        self.value = Some(ConditionValue::UInt8(value).into());
        self
    }

    /// Sets a string value for the condition.
    #[allow(dead_code)]
    pub fn value_string(mut self, value: impl AsRef<OsStr>) -> Self {
        let wide_string = string_to_null_terminated_utf16(value);
        self.value = Some(ConditionValue::String(wide_string).into());
        self
    }

    /// Sets a byte blob value for the condition.
    ///
    /// This is typically used for application IDs and other binary data that
    /// needs to be matched exactly. The data is copied into an internal buffer.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let app_id_data = b"\x01\x02\x03\x04"; // Example binary data
    /// let condition = ConditionBuilder::default()
    ///     .field(ConditionField::AppId)
    ///     .match_type(MatchType::Equal)
    ///     .value_byte_blob(app_id_data)
    ///     .build()?;
    /// ```
    pub fn value_byte_blob(mut self, blob: impl Into<OwnedByteBlob>) -> Self {
        self.value = Some(ConditionValue::ByteBlob { blob: blob.into() }.into());
        self
    }

    /// Builds the condition into the internal representation used by FilterBuilder.
    pub fn build(self) -> Option<Condition> {
        let field = self.field?;
        let match_type = self.match_type?;
        let value = self.value?;

        // SAFETY: This is a C struct
        let mut raw_condition: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };

        raw_condition.fieldKey = *field.guid();
        raw_condition.matchType = match_type as i32;

        match &*value {
            ConditionValue::UInt32(val) => {
                raw_condition.conditionValue.r#type = FWP_UINT32;
                raw_condition.conditionValue.Anonymous.uint32 = *val;
            }
            ConditionValue::UInt16(val) => {
                raw_condition.conditionValue.r#type = FWP_UINT16;
                raw_condition.conditionValue.Anonymous.uint16 = *val;
            }
            ConditionValue::UInt8(val) => {
                raw_condition.conditionValue.r#type = FWP_UINT8;
                raw_condition.conditionValue.Anonymous.uint8 = *val;
            }
            ConditionValue::String(wide_str) => {
                raw_condition.conditionValue.r#type = FWP_UNICODE_STRING_TYPE;
                // SAFETY: The data is never mutated, and is tied to the lifetime of Condition
                raw_condition.conditionValue.Anonymous.unicodeString = wide_str.as_ptr() as *mut _;
            }
            ConditionValue::ByteBlob { blob } => {
                raw_condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                // SAFETY: The data is never mutated, and is tied to the lifetime of Condition
                raw_condition.conditionValue.Anonymous.byteBlob = blob.as_ptr() as _;
            }
        }

        Some(Condition {
            raw_condition,
            _value: value,
        })
    }
}

/// Internal representation of a built condition.
///
/// This can be added to a [`FilterBuilder`](crate::FilterBuilder).
#[derive(Clone)]
pub struct Condition {
    raw_condition: FWPM_FILTER_CONDITION0,
    // This keeps underlying pointers and data valid
    _value: Arc<ConditionValue>,
}

impl Condition {
    /// Return the underlying FWPM_FILTER_CONDITION0 structure.
    pub(crate) fn raw_condition(&self) -> &FWPM_FILTER_CONDITION0 {
        &self.raw_condition
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_condition_port_remote() {
        let condition = PortConditionBuilder::remote().equal(80).build();

        assert_eq!(
            condition.raw_condition.fieldKey.data1,
            FWPM_CONDITION_IP_REMOTE_PORT.data1
        );
        assert_eq!(
            condition.raw_condition.fieldKey.data2,
            FWPM_CONDITION_IP_REMOTE_PORT.data2
        );
        assert_eq!(
            condition.raw_condition.fieldKey.data3,
            FWPM_CONDITION_IP_REMOTE_PORT.data3
        );
        assert_eq!(
            condition.raw_condition.fieldKey.data4,
            FWPM_CONDITION_IP_REMOTE_PORT.data4
        );

        assert_eq!(condition.raw_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(
            unsafe { condition.raw_condition.conditionValue.Anonymous.uint16 },
            80
        );
    }
}
