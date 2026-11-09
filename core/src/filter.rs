use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::net::Ipv4Addr;
use serde_json::Value;

#[derive(Default)]
pub struct Filters(BTreeMap<String, Vec<Value>>);
impl Filters {
    pub fn update(&mut self, map: &Value) -> anyhow::Result<Value> {
        if !map["PacketFilter"].is_null() {
            self.0.insert(
                "base".into(),
                map["PacketFilter"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("invalid PacketFilter"))?
                    .clone(),
            );
        }
        if let Some(updates) = map["PacketFilters"].as_object() {
            if updates.get("*").is_some_and(Value::is_null) {
                self.0.clear();
            }
            for (name, rules) in updates {
                if rules.is_null() {
                    self.0.remove(name);
                } else {
                    self.0.insert(
                        name.clone(),
                        rules
                            .as_array()
                            .ok_or_else(|| anyhow::anyhow!("invalid PacketFilters ruleset"))?
                            .clone(),
                    );
                }
            }
        }
        Ok(Value::Array(self.0.values().flatten().cloned().collect()))
    }
}

pub fn contains(cidr: &str, ip: Ipv4Addr) -> bool {
    if cidr == "*" {
        return true;
    }
    if let Some((start, end)) = cidr.split_once('-') {
        return start
            .parse::<Ipv4Addr>()
            .ok()
            .zip(end.parse::<Ipv4Addr>().ok())
            .is_some_and(|(start, end)| start <= ip && ip <= end);
    }
    let (address, bits) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let (Ok(address), Ok(bits)) = (address.parse::<Ipv4Addr>(), bits.parse::<u32>()) else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(address) & mask == u32::from(ip) & mask
}

/// Reject fragments and unsupported protocols, bind inner source to the authenticated
/// node, and enforce the complete source/destination/protocol/port filter rule.
pub fn allowed(filter: &Value, addresses: &[String], our: Ipv4Addr, p: &[u8]) -> bool {
    allowed_with_caps(filter, addresses, &[], our, p)
}

pub fn allowed_with_caps(
    filter: &Value,
    addresses: &[String],
    capabilities: &[String],
    our: Ipv4Addr,
    p: &[u8],
) -> bool {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return false;
    }
    let header = (p[0] & 15) as usize * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    if header < 20 || total < header || total > p.len() || p[6] & 0x3f != 0 || p[7] != 0 {
        return false;
    }
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    if dst != our || !addresses.iter().any(|a| contains(a, src)) {
        return false;
    }
    let port = match p[9] {
        6 if total >= header + 20 => u16::from_be_bytes([p[header + 2], p[header + 3]]) as u64,
        1 if total >= header + 8 && p[header] == 8 => 0,
        _ => return false,
    };
    filter.as_array().into_iter().flatten().any(|rule| {
        let proto_ok = rule["IPProto"].as_array().map_or(true, |v| {
            v.is_empty() || v.iter().any(|n| n.as_u64() == Some(p[9] as u64))
        });
        let src_ok = rule["SrcIPs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|s| {
                contains(s, src)
                    || s.strip_prefix("cap:")
                        .is_some_and(|cap| capabilities.iter().any(|c| c == cap))
            })
            || rule["SrcCaps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|cap| capabilities.iter().any(|c| c == cap));
        proto_ok
            && src_ok
            && rule["DstPorts"].as_array().into_iter().flatten().any(|d| {
                let first = d["Ports"]["First"].as_u64();
                let last = d["Ports"]["Last"].as_u64();
                d["IP"].as_str().is_some_and(|s| contains(s, dst))
                    && first
                        .zip(last)
                        .is_some_and(|(first, last)| first <= port && port <= last)
            })
    })
}
