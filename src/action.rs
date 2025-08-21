//! Core types and enums for the Windows Filtering Platform wrapper.

use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_BLOCK;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_PERMIT;

/// Specifies the action to take when a filter matches network traffic.
///
/// These correspond to the [`FWP_ACTION_TYPE`] enumeration values.
///
/// # Example
///
/// ```
/// use wfp::ActionType;
///
/// let block_action = ActionType::Block;
/// let permit_action = ActionType::Permit;
/// ```
///
/// [`FWP_ACTION_TYPE`]: https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_action_type
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionType {
    /// Block the network traffic that matches the filter.
    Block = FWP_ACTION_BLOCK,
    /// Allow the network traffic that matches the filter to proceed.
    Permit = FWP_ACTION_PERMIT,
}
