use super::*;

#[test]
fn https_replies_merge_with_outbound_packets() {
    let outgoing = [
        0x45, 0, 0, 24, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0xc0, 0x00, 0x01, 0xbb,
    ];
    let mut incoming = outgoing;
    incoming[12..24].copy_from_slice(&[192, 0, 2, 2, 192, 0, 2, 1, 0x01, 0xbb, 0xc0, 0x00]);
    let log = rc_flow_log_new();
    unsafe {
        rc_flow_log_record(log, outgoing.as_ptr(), outgoing.len(), false);
        rc_flow_log_record(log, incoming.as_ptr(), incoming.len(), true);
        let mut row = std::mem::MaybeUninit::uninit();
        assert_eq!(rc_flow_log_snapshot(log, row.as_mut_ptr(), 1), 1);
        let row = row.assume_init();
        assert_eq!(&row.address[..4], &[192, 0, 2, 2]);
        assert_eq!((row.family, row.port, row.protocol), (4, 443, 6));
        assert_eq!(row.bytes, [24, 24]);
        assert_eq!(row.packets, [1, 1]);
        assert!(row.age_first >= row.age_last);
        assert_eq!(rc_flow_log_snapshot(log, std::ptr::null_mut(), 0), 1);
        rc_flow_log_free(log);
    }
}

#[test]
fn ipv6_extension_chain_exposes_ports_only_in_first_fragment() {
    let mut packet = [0; 60];
    packet[0] = 0x60;
    packet[5] = 20;
    packet[6] = 60; // destination options
    packet[39] = 1;
    packet[40] = 44; // fragment header
    packet[48] = 17;
    packet[58..60].copy_from_slice(&443u16.to_be_bytes());
    let endpoint = Endpoint::parse(&packet, false).unwrap();
    assert_eq!(endpoint.address[15], 1);
    assert_eq!(
        (endpoint.family, endpoint.port, endpoint.protocol),
        (6, 443, 17)
    );
    packet[51] = 8; // Fragment offset is one eight-byte unit.
    assert_eq!(Endpoint::parse(&packet, false).unwrap().port, 0);
    assert!(Endpoint::parse(&packet[..59], false).is_none());
}

#[test]
fn saturation_reuses_the_least_recent_endpoint() {
    let mut log = RCFlowLog::default();
    let key = |port| Endpoint {
        address: [0; 16],
        port,
        protocol: 6,
        family: 4,
    };
    let now = Instant::now();
    for port in 0..CAPACITY as u16 {
        log.record(key(port), 48, false, now);
    }
    log.record(key(0), 16, true, now);
    log.record(key(CAPACITY as u16), 48, false, now);
    assert_eq!(log.indices.len(), CAPACITY);
    assert_eq!(log.entries.len(), CAPACITY);
    assert!(!log.indices.contains_key(&key(1)));
    let retained = &log.entries[log.indices[&key(0)]];
    assert_eq!(retained.bytes, [48, 16]);
}
