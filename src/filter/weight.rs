//! Filter weight types for controlling evaluation order within a sublayer.

use std::fmt;

/// Weight controlling filter evaluation order within a sublayer.
///
/// Higher weight means the filter is evaluated first. See the
/// [Filter Arbitration](https://docs.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)
/// documentation for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterWeight {
    /// Let BFE generate a weight in the range [0, 2^60).
    ///
    /// This corresponds to [`FWP_EMPTY`].
    ///
    /// [`FWP_EMPTY`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    Auto,
    /// Specify a weight in [0, 15). The low-order 60 bits are automatically generated but the
    /// high-order 4 bits are specified here.
    ///
    /// This corresponds to [`FWP_UINT8`].
    ///
    /// [`FWP_UINT8`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    Range(WeightRange),
    /// Specify an exact weight.
    ///
    /// This corresponds to [`FWP_UINT64`].
    ///
    /// [`FWP_UINT64`]: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
    Exact(u64),
}

/// A weight in the range 0-15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WeightRange(u8);

impl WeightRange {
    /// Returns the inner value.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for WeightRange {
    type Error = WeightRangeError;

    /// A value between 0 and 15 (inclusive).
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        if val > 15 {
            Err(WeightRangeError(val))
        } else {
            Ok(Self(val))
        }
    }
}

/// Error returned when a value exceeds the valid weight range (0-15).
#[derive(Debug, Clone, Copy)]
pub struct WeightRangeError(u8);

impl fmt::Display for WeightRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "weight range value {} is out of bounds (must be 0..=15)",
            self.0
        )
    }
}

impl std::error::Error for WeightRangeError {}

impl From<WeightRange> for FilterWeight {
    fn from(range: WeightRange) -> Self {
        FilterWeight::Range(range)
    }
}
