//! Layers

use windows_sys::{Win32::NetworkManagement::WindowsFilteringPlatform::*, core::GUID};

/// Specifies the network layer at which a filter operates.
///
/// Different layers provide different types of network information and
/// allow filtering at various points in the network stack. These correspond
/// to predefined layer GUIDs in the Windows Filtering Platform.
///
/// For more information about filtering layers, see the [WFP Layer Reference].
///
/// [WFP Layer Reference]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// IPv4 inbound connections at the Application Layer Enforcement (ALE) layer.
    /// Filters at this layer can inspect and control incoming IPv4 connection attempts.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`].
    ///
    /// [`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    AcceptV4,
    /// IPv6 inbound connections at the Application Layer Enforcement (ALE) layer.
    /// Filters at this layer can inspect and control incoming IPv6 connection attempts.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`].
    ///
    /// [`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    AcceptV6,
    /// IPv4 outbound connections at the Application Layer Enforcement (ALE) layer.
    /// Filters at this layer can inspect and control outgoing IPv4 connection attempts.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_AUTH_CONNECT_V4`].
    ///
    /// [`FWPM_LAYER_ALE_AUTH_CONNECT_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    ConnectV4,
    /// IPv6 outbound connections at the Application Layer Enforcement (ALE) layer.
    /// Filters at this layer can inspect and control outgoing IPv6 connection attempts.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_AUTH_CONNECT_V6`].
    ///
    /// [`FWPM_LAYER_ALE_AUTH_CONNECT_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    ConnectV6,
    /// IPv4 established flows at the Application Layer Enforcement (ALE) layer.
    /// Filters at this layer can inspect and control established IPv4 connections.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4`].
    ///
    /// [`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    FlowEstablishedV4,
    /// IPv6 established flows at the Application Layer Enforcement (ALE) layer.
    /// Filters at this layer can inspect and control established IPv6 connections.
    ///
    /// Corresponds to [`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6`].
    ///
    /// [`FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    FlowEstablishedV6,
    /// IPv4 inbound IP packets at the network layer.
    /// Filters at this layer can inspect and control incoming IPv4 packets before routing.
    ///
    /// Corresponds to [`FWPM_LAYER_INBOUND_IPPACKET_V4`].
    ///
    /// [`FWPM_LAYER_INBOUND_IPPACKET_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    InboundIpPacketV4,
    /// IPv6 inbound IP packets at the network layer.
    /// Filters at this layer can inspect and control incoming IPv6 packets before routing.
    ///
    /// Corresponds to [`FWPM_LAYER_INBOUND_IPPACKET_V6`].
    ///
    /// [`FWPM_LAYER_INBOUND_IPPACKET_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    InboundIpPacketV6,
    /// IPv4 outbound IP packets at the network layer.
    /// Filters at this layer can inspect and control outgoing IPv4 packets after routing.
    ///
    /// Corresponds to [`FWPM_LAYER_OUTBOUND_IPPACKET_V4`].
    ///
    /// [`FWPM_LAYER_OUTBOUND_IPPACKET_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    OutboundIpPacketV4,
    /// IPv6 outbound IP packets at the network layer.
    /// Filters at this layer can inspect and control outgoing IPv6 packets after routing.
    ///
    /// Corresponds to [`FWPM_LAYER_OUTBOUND_IPPACKET_V6`].
    ///
    /// [`FWPM_LAYER_OUTBOUND_IPPACKET_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    OutboundIpPacketV6,
    /// IPv4 inbound transport layer packets.
    /// Filters at this layer can inspect and control incoming IPv4 transport layer data.
    ///
    /// Corresponds to [`FWPM_LAYER_INBOUND_TRANSPORT_V4`].
    ///
    /// [`FWPM_LAYER_INBOUND_TRANSPORT_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    InboundTransportV4,
    /// IPv6 inbound transport layer packets.
    /// Filters at this layer can inspect and control incoming IPv6 transport layer data.
    ///
    /// Corresponds to [`FWPM_LAYER_INBOUND_TRANSPORT_V6`].
    ///
    /// [`FWPM_LAYER_INBOUND_TRANSPORT_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    InboundTransportV6,
    /// IPv4 outbound transport layer packets.
    /// Filters at this layer can inspect and control outgoing IPv4 transport layer data.
    ///
    /// Corresponds to [`FWPM_LAYER_OUTBOUND_TRANSPORT_V4`].
    ///
    /// [`FWPM_LAYER_OUTBOUND_TRANSPORT_V4`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    OutboundTransportV4,
    /// IPv6 outbound transport layer packets.
    /// Filters at this layer can inspect and control outgoing IPv6 transport layer data.
    ///
    /// Corresponds to [`FWPM_LAYER_OUTBOUND_TRANSPORT_V6`].
    ///
    /// [`FWPM_LAYER_OUTBOUND_TRANSPORT_V6`]: https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    OutboundTransportV6,
}

impl Layer {
    /// Returns the Windows GUID identifier for this layer.
    ///
    /// This is used internally when communicating with the Windows Filtering Platform API.
    pub fn guid(&self) -> &GUID {
        match self {
            Self::AcceptV4 => &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            Self::AcceptV6 => &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            Self::ConnectV4 => &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::ConnectV6 => &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            Self::FlowEstablishedV4 => &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            Self::FlowEstablishedV6 => &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
            Self::InboundIpPacketV4 => &FWPM_LAYER_INBOUND_IPPACKET_V4,
            Self::InboundIpPacketV6 => &FWPM_LAYER_INBOUND_IPPACKET_V6,
            Self::OutboundIpPacketV4 => &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
            Self::OutboundIpPacketV6 => &FWPM_LAYER_OUTBOUND_IPPACKET_V6,
            Self::InboundTransportV4 => &FWPM_LAYER_INBOUND_TRANSPORT_V4,
            Self::InboundTransportV6 => &FWPM_LAYER_INBOUND_TRANSPORT_V6,
            Self::OutboundTransportV4 => &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            Self::OutboundTransportV6 => &FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        }
    }
}
