use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::BOOL;
use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_CLASS};

const AF_INET_FAMILY: u32 = 2;
const AF_INET6_FAMILY: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL_CLASS: i32 = 5;
const IPV4_ROW_BYTES: usize = 24;
const IPV6_ROW_BYTES: usize = 56;

pub const MIB_TCP_STATE_LISTEN: u32 = 2;
pub const MIB_TCP_STATE_ESTABLISHED: u32 = 5;

pub struct TcpRow {
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub state: u32,
    pub pid: u32,
}

pub fn tcp_rows() -> Vec<TcpRow> {
    let mut rows = table_rows(AF_INET_FAMILY, IPV4_ROW_BYTES, parse_v4_row);
    rows.extend(table_rows(AF_INET6_FAMILY, IPV6_ROW_BYTES, parse_v6_row));
    rows
}

fn table_rows(family: u32, row_bytes: usize, parse: fn(&[u8]) -> Option<TcpRow>) -> Vec<TcpRow> {
    let Some(bytes) = owner_pid_table(family) else {
        return Vec::new();
    };
    let count = native_u32(&bytes, 0).unwrap_or(0) as usize;
    (0..count)
        .filter_map(|index| {
            let start = 4 + index * row_bytes;
            bytes.get(start..start + row_bytes).and_then(parse)
        })
        .collect()
}

fn owner_pid_table(family: u32) -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            BOOL(0),
            family,
            TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL_CLASS),
            0,
        );
    }
    if size == 0 {
        return None;
    }
    let mut words = vec![0u32; (size as usize).div_ceil(4)];
    let status = unsafe {
        GetExtendedTcpTable(
            Some(words.as_mut_ptr().cast()),
            &mut size,
            BOOL(0),
            family,
            TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL_CLASS),
            0,
        )
    };
    if status != 0 {
        return None;
    }
    let byte_len = words.len() * 4;
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), byte_len) };
    Some(bytes.to_vec())
}

fn native_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(raw))
}

fn network_port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

fn parse_v4_row(row: &[u8]) -> Option<TcpRow> {
    let remote_bytes: [u8; 4] = row.get(12..16)?.try_into().ok()?;
    let local_bytes: [u8; 4] = row.get(4..8)?.try_into().ok()?;
    Some(TcpRow {
        local: IpAddr::V4(Ipv4Addr::from(local_bytes)),
        local_port: network_port(native_u32(row, 8)?),
        remote: IpAddr::V4(Ipv4Addr::from(remote_bytes)),
        remote_port: network_port(native_u32(row, 16)?),
        state: native_u32(row, 0)?,
        pid: native_u32(row, 20)?,
    })
}

fn parse_v6_row(row: &[u8]) -> Option<TcpRow> {
    let local_bytes: [u8; 16] = row.get(0..16)?.try_into().ok()?;
    let remote_bytes: [u8; 16] = row.get(24..40)?.try_into().ok()?;
    Some(TcpRow {
        local: IpAddr::V6(Ipv6Addr::from(local_bytes)),
        local_port: network_port(native_u32(row, 20)?),
        remote: IpAddr::V6(Ipv6Addr::from(remote_bytes)),
        remote_port: network_port(native_u32(row, 44)?),
        state: native_u32(row, 48)?,
        pid: native_u32(row, 52)?,
    })
}
