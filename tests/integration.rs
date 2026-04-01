//! Integration tests for the Windows Filtering Platform library.

use windows_sys::core::GUID;

// Import the library modules we want to test
use wfp::*;

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_add_filters_and_sublayer() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    // Create a test sublayer
    let test_guid = GUID::from_u128(0x12345678_1234_5678_9abc_def012345678);

    SubLayerBuilder::default()
        .name("Test Sublayer")
        .description("Test sublayer for integration tests")
        .weight(100)
        .guid(test_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    // Create multiple filters in the same transaction
    let http_condition = PortConditionBuilder::remote().equal(80).build();
    let https_condition = PortConditionBuilder::remote().equal(443).build();
    let tcp_condition = ProtocolConditionBuilder::tcp().build();

    // HTTP block filter
    FilterBuilder::default()
        .name("HTTP Block Filter")
        .description("Blocks HTTP traffic")
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .condition(http_condition)
        .condition(tcp_condition.clone())
        .sublayer(test_guid)
        .add(&transaction)
        .expect("Should be able to add HTTP filter");

    // HTTPS permit filter
    FilterBuilder::default()
        .name("HTTPS Permit Filter")
        .description("Permits HTTPS traffic")
        .action(ActionType::Permit)
        .layer(Layer::ConnectV4)
        .condition(https_condition)
        .condition(tcp_condition)
        .sublayer(test_guid)
        .weight(FilterWeight::Exact(12345))
        .add(&transaction)
        .expect("Should be able to add HTTPS filter");

    transaction
        .commit()
        .expect("Should be able to commit multiple filters");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_app_id_condition() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let test_guid = windows_sys::core::GUID::from_u128(0xaabbccdd_1234_5678_9abc_def012345678);

    SubLayerBuilder::default()
        .name("Test AppId Sublayer")
        .description("Test sublayer for app ID integration tests")
        .weight(100)
        .guid(test_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    // get_app_id_from_filename returns Err for non-existent paths
    let bad_result = AppIdConditionBuilder::default().equal(r"C:\nonexistent\fake.exe");
    assert!(
        bad_result.is_err(),
        "Should return Err for a nonexistent executable path"
    );

    // get_app_id_from_filename returns Ok for a real executable
    let app_condition = AppIdConditionBuilder::default()
        .equal(r"C:\Windows\System32\ping.exe")
        .expect("Should be able to get app ID from ping.exe");

    FilterBuilder::default()
        .name("Ping Block Filter")
        .description("Blocks ping.exe outbound traffic")
        .action(ActionType::Block)
        .layer(Layer::ConnectV4)
        .condition(app_condition.build())
        .sublayer(test_guid)
        .weight(WeightRange::try_from(15).unwrap())
        .add(&transaction)
        .expect("Should be able to add app ID filter");

    transaction
        .commit()
        .expect("Should be able to commit app ID filter transaction");
}

#[test]
#[cfg_attr(not(feature = "wfp-integration-tests"), ignore)]
fn test_ndp_filter() {
    let mut engine = FilterEngineBuilder::default()
        .dynamic()
        .open()
        .expect("Should be able to open filter engine");

    let transaction = Transaction::new(&mut engine).expect("Should be able to create transaction");

    let test_guid = GUID::from_u128(0xfeed1234_5678_9abc_def0_123456789abc);

    SubLayerBuilder::default()
        .name("Test NDP Sublayer")
        .description("Test sublayer for NDP integration test")
        .weight(100)
        .guid(test_guid)
        .add(&transaction)
        .expect("Should be able to add sublayer");

    // ICMPv6 NDP messages.
    //
    // Outbound: Router Solicitation (133), Neighbor Solicitation (135),
    //           Neighbor Advertisement (136).
    // Inbound:  Router Advertisement (134), Neighbor Solicitation (135),
    //           Neighbor Advertisement (136), Redirect (137).
    let outbound_types = [133u8, 135, 136];
    let inbound_types = [134u8, 135, 136, 137];

    for t in outbound_types {
        FilterBuilder::default()
            .name("NDP (outbound)")
            .description("Permits outbound ICMPv6 NDP traffic")
            .action(ActionType::Permit)
            .layer(Layer::ConnectV6)
            .condition(ProtocolConditionBuilder::icmpv6().build())
            .condition(IcmpConditionBuilder::r#type().equal(t).build())
            .condition(IcmpConditionBuilder::code().equal(0).build())
            .sublayer(test_guid)
            .add(&transaction)
            .expect("Should be able to add outbound NDP filter");
    }

    for t in inbound_types {
        FilterBuilder::default()
            .name("NDP (inbound)")
            .description("Permits inbound ICMPv6 NDP traffic")
            .action(ActionType::Permit)
            .layer(Layer::AcceptV6)
            .condition(ProtocolConditionBuilder::icmpv6().build())
            .condition(IcmpConditionBuilder::r#type().equal(t).build())
            .condition(IcmpConditionBuilder::code().equal(0).build())
            .sublayer(test_guid)
            .add(&transaction)
            .expect("Should be able to add inbound NDP filter");
    }

    transaction
        .commit()
        .expect("Should be able to commit NDP filter transaction");
}
