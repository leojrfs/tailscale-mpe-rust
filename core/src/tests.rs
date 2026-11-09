use crate::{filter, noise, platform::ByteStream, transport};
use alloc::{boxed::Box, vec, vec::Vec};

struct Memory {
    input: Vec<u8>,
}
impl ByteStream for Memory {
    fn read(&mut self, out: &mut [u8]) -> Result<usize, ()> {
        let n = out.len().min(self.input.len());
        out[..n].copy_from_slice(&self.input[..n]);
        self.input.drain(..n);
        Ok(n)
    }
    fn write_all(&mut self, _: &[u8]) -> Result<(), ()> {
        Ok(())
    }
}
#[test]
fn record_headers_reject_oversized_and_short_frames_without_a_body() {
    for (header, reason) in [
        (vec![4, 255, 255], "4096"),
        (vec![4, 0, 0], "authentication tag"),
        (vec![4, 0, 15], "authentication tag"),
    ] {
        let mut input = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        input.extend(header);
        let mut conn =
            transport::connect_and_upgrade(Box::new(Memory { input }), "test", "").unwrap();
        assert!(alloc::format!("{}", conn.read_frame().unwrap_err()).contains(reason));
    }
}
#[test]
fn noise_handshake_uses_requested_capability_version_and_limits_records() {
    let a = [1; 32];
    let b = [2; 32];
    let pub_b = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(b));
    let (initiator, first) = noise::start_with_version(&a, pub_b.as_bytes(), 130).unwrap();
    assert_eq!(&first[..2], &130u16.to_be_bytes());
    let mut responder = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
        .local_private_key(&b)
        .unwrap()
        .prologue(b"Tailscale Control Protocol v130")
        .unwrap()
        .build_responder()
        .unwrap();
    let mut buf = [0; 256];
    responder.read_message(&first[5..], &mut buf).unwrap();
    let n = responder.write_message(&[], &mut buf).unwrap();
    let mut transport = initiator.complete(&buf[..n]).unwrap();
    assert!(transport.seal_record(&vec![0; 4077]).is_ok());
    assert!(transport.seal_record(&vec![0; 4078]).is_err());
    assert!(transport.open_record(&[0; 15]).is_err());
    assert!(transport.open_record(&vec![0; 4094]).is_err());
}
#[test]
fn named_filters_replace_and_revoke_rules() {
    use serde_json::json;
    let mut state = filter::Filters::default();
    assert_eq!(
        state
            .update(&json!({"PacketFilter":[1],"PacketFilters":{"extra":[2]}}))
            .unwrap(),
        json!([1, 2])
    );
    assert_eq!(
        state
            .update(&json!({"PacketFilters":{"extra":null}}))
            .unwrap(),
        json!([1])
    );
    assert_eq!(
        state
            .update(&json!({"PacketFilter":[3],"PacketFilters":{"*":null,"new":[4]}}))
            .unwrap(),
        json!([4])
    );
    assert_eq!(
        state.update(&json!({"PacketFilters":{"new":[]}})).unwrap(),
        json!([])
    );
}
#[test]
fn packet_filter_enforces_ports_protocol_fragments_and_node_source() {
    let filter = serde_json::json!([{"SrcIPs":["100.64.0.1/32"],"DstPorts":[{"IP":"100.64.0.2/32","Ports":{"First":80,"Last":80}}]}]);
    let mut p = vec![0; 40];
    p[0] = 0x45;
    p[3] = 40;
    p[9] = 6;
    p[12..16].copy_from_slice(&[100, 64, 0, 1]);
    p[16..20].copy_from_slice(&[100, 64, 0, 2]);
    p[23] = 80;
    let addresses = vec!["100.64.0.1/32".into()];
    let our = "100.64.0.2".parse().unwrap();
    assert!(filter::allowed(&filter, &addresses, our, &p));
    p[23] = 81;
    assert!(!filter::allowed(&filter, &addresses, our, &p));
    p[23] = 80;
    assert!(!filter::allowed(
        &filter,
        &["100.64.0.3/32".into()],
        our,
        &p
    ));
    p[6] = 32;
    assert!(!filter::allowed(&filter, &addresses, our, &p));
    p[6] = 0;
    p[9] = 17;
    assert!(!filter::allowed(&filter, &addresses, our, &p));
}

#[cfg(feature = "wireguard")]
mod complete_wg {
    use super::*;
    use crate::wireguard::{x25519, RateLimiter, Tunn, TunnResult};
    use std::{net::IpAddr, sync::Arc};
    fn keys(n: u8) -> (x25519::StaticSecret, x25519::PublicKey) {
        let key = x25519::StaticSecret::from([n; 32]);
        let public = x25519::PublicKey::from(&key);
        (key, public)
    }
    fn network(r: TunnResult<'_>) -> Vec<u8> {
        match r {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            r => panic!("expected network packet: {r:?}"),
        }
    }
    fn ip() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }
    #[test]
    fn mac_timestamp_transport_replay_and_forged_counters_are_rejected() {
        let (a_key, a_pub) = keys(1);
        let (b_key, b_pub) = keys(2);
        let mut a = Tunn::new(a_key, b_pub, None, None, 1, None);
        let mut b = Tunn::new(b_key, a_pub, None, None, 2, None);
        let mut buf = [0; 2048];
        let init = network(a.format_handshake_initiation(&mut buf, false));
        let mut bad = init.clone();
        bad[116] ^= 1;
        assert!(matches!(
            b.decapsulate(Some(ip()), &bad, &mut buf),
            TunnResult::Err(_)
        ));
        let response = network(b.decapsulate(Some(ip()), &init, &mut buf));
        let keepalive = network(a.decapsulate(Some(ip()), &response, &mut buf));
        assert!(matches!(
            b.decapsulate(Some(ip()), &keepalive, &mut buf),
            TunnResult::Done
        ));
        assert!(matches!(
            b.decapsulate(Some(ip()), &init, &mut buf),
            TunnResult::Err(_)
        ));
        let mut plain = vec![0; 20];
        plain[0] = 0x45;
        plain[3] = 20;
        plain[12..16].copy_from_slice(&[100, 64, 0, 1]);
        let packet = network(a.encapsulate(&plain, &mut buf));
        let mut forged = packet.clone();
        forged[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            b.decapsulate(Some(ip()), &forged, &mut buf),
            TunnResult::Err(_)
        ));
        match b.decapsulate(Some(ip()), &packet, &mut buf) {
            TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, &plain),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            b.decapsulate(Some(ip()), &packet, &mut buf),
            TunnResult::Err(_)
        ));
    }
    #[test]
    fn cookie_challenge_and_retry_complete_the_handshake() {
        let (a_key, a_pub) = keys(1);
        let (b_key, b_pub) = keys(2);
        let limiter = Arc::new(RateLimiter::new(&b_pub, 0));
        let mut a = Tunn::new(a_key, b_pub, None, None, 1, None);
        let mut b = Tunn::new(b_key, a_pub, None, None, 2, Some(limiter));
        let mut buf = [0; 2048];
        let init = network(a.format_handshake_initiation(&mut buf, false));
        let cookie = network(b.decapsulate(Some(ip()), &init, &mut buf));
        assert_eq!(cookie[0], 3);
        assert!(matches!(
            a.decapsulate(Some(ip()), &cookie, &mut buf),
            TunnResult::Done
        ));
        let retry = network(a.format_handshake_initiation(&mut buf, true));
        let response = network(b.decapsulate(Some(ip()), &retry, &mut buf));
        assert_eq!(response[0], 2);
    }
}

#[test]
fn stun_declared_length_cannot_hide_a_truncated_response() {
    let (_, id) = crate::stun::binding_request();
    let mut response = vec![0; 32];
    response[..2].copy_from_slice(&0x0101u16.to_be_bytes());
    response[2..4].copy_from_slice(&12u16.to_be_bytes());
    response[4..8].copy_from_slice(&crate::stun::MAGIC_COOKIE.to_be_bytes());
    response[8..20].copy_from_slice(&id);
    response[21] = 1;
    response[23] = 8;
    response[25] = 1;
    response[26..28].copy_from_slice(&1234u16.to_be_bytes());
    response[28..32].copy_from_slice(&[192, 0, 2, 1]);
    assert!(crate::stun::parse_response(&response, &id).is_ok());
    response[3] = 16;
    assert!(crate::stun::parse_response(&response, &id).is_err());
}
#[test]
fn h2_rejects_oversized_payload_from_header_without_waiting_for_body() {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
    let a = [1; 32];
    let b = [2; 32];
    let pub_b = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(b));
    let (initiator, first) = noise::start(&a, pub_b.as_bytes()).unwrap();
    let mut responder = snow::Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
        .local_private_key(&b)
        .unwrap()
        .prologue(b"Tailscale Control Protocol v130")
        .unwrap()
        .build_responder()
        .unwrap();
    let mut buf = [0; 256];
    responder.read_message(&first[5..], &mut buf).unwrap();
    let n = responder.write_message(&[], &mut buf).unwrap();
    let transport = initiator.complete(&buf[..n]).unwrap();
    let (_, server_key) = responder.dangerously_get_raw_split();
    let cipher = ChaCha20Poly1305::new_from_slice(&server_key).unwrap();
    let mut plain = b"\xff\xff\xffTS\0\0\0\0".to_vec();
    plain.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // SETTINGS
    plain.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1]); // Oversized DATA; no body.
    let ct = cipher
        .encrypt((&[0u8; 12]).into(), plain.as_slice())
        .unwrap();
    let mut input = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
    input.push(4);
    input.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    input.extend(ct);
    let conn = transport::connect_and_upgrade(Box::new(Memory { input }), "test", "").unwrap();
    let (mut session, _) = crate::h2::H2::start(conn, transport, "test".into()).unwrap();
    assert!(alloc::format!("{}", session.read_data(1).unwrap_err()).contains("negotiated limit"));
}

#[test]
fn discovery_round_trips_native_ipv6_endpoints() {
    let a = [1; 32];
    let b = [2; 32];
    let public = |k: [u8; 32]| {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(k)).to_bytes()
    };
    let endpoint = "[2001:db8::1234]:4321".parse().unwrap();
    let sealed = crate::disco::seal(
        &a,
        &public(a),
        &public(b),
        &crate::disco::call_me_maybe_plaintext(&[endpoint]),
    )
    .unwrap();
    assert_eq!(
        crate::disco::open(&b, &sealed).unwrap().endpoints,
        vec![endpoint]
    );
    let (_, id) = crate::stun::binding_request();
    let mut response = vec![0; 44];
    response[..2].copy_from_slice(&0x0101u16.to_be_bytes());
    response[2..4].copy_from_slice(&24u16.to_be_bytes());
    response[4..8].copy_from_slice(&crate::stun::MAGIC_COOKIE.to_be_bytes());
    response[8..20].copy_from_slice(&id);
    response[21] = 0x20;
    response[23] = 20;
    response[25] = 2;
    response[26..28].copy_from_slice(&(4321u16 ^ 0x2112).to_be_bytes());
    let ip: core::net::Ipv6Addr = "2001:db8::1234".parse().unwrap();
    let mut bytes = ip.octets();
    let mut mask = [0; 16];
    mask[..4].copy_from_slice(&crate::stun::MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(&id);
    for (b, m) in bytes.iter_mut().zip(mask) {
        *b ^= m;
    }
    response[28..].copy_from_slice(&bytes);
    assert_eq!(
        crate::stun::parse_response_addr(&response, &id).unwrap(),
        endpoint
    );
}
