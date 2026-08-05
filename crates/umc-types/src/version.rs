pub const PROTOCOL_VERSION: u32 = 0x0000_0001;
pub const MAGIC_UMP1: u32 = 0x554D_5031;
pub const MAX_PACKET_SIZE: usize = 65_535;
pub const MAX_CONNECTION_ID_LEN: usize = 20;
pub const MAX_TOKEN_LEN: usize = 1_024;
pub const MAX_GENERIC_BYTE_STRING: usize = 16 * 1024 * 1024;
pub const MIN_INITIAL_UDP: usize = 1_200;
pub const DEFAULT_UDP_MTU: usize = 1_200;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_wire_format_spec() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAGIC_UMP1, u32::from_be_bytes(*b"UMP1"));
        assert_eq!(MAX_PACKET_SIZE, 65_535);
        assert_eq!(MAX_CONNECTION_ID_LEN, 20);
        assert_eq!(MAX_TOKEN_LEN, 1_024);
        assert_eq!(MAX_GENERIC_BYTE_STRING, 16 * 1024 * 1024);
        assert_eq!(MIN_INITIAL_UDP, 1_200);
        assert_eq!(DEFAULT_UDP_MTU, 1_200);
    }
}
