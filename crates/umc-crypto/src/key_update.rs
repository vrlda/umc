/// Next traffic secret on key update (handshake.md §41).
///
/// # Panics
/// Panics if the 32-byte label expansion fails; impossible for in-range
/// lengths, but the [`Result`] from `expand_label` must still be unwrapped.
#[must_use]
pub fn next_traffic_secret(current: &[u8; 32]) -> [u8; 32] {
    let out = crate::label::expand_label(current, b"traffic update", b"", 32)
        .expect("32-byte expansion cannot fail");
    let mut next = [0u8; 32];
    next.copy_from_slice(&out);
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_changes_secret() {
        let s0 = [1u8; 32];
        let s1 = next_traffic_secret(&s0);
        let s2 = next_traffic_secret(&s1);
        assert_ne!(s0, s1);
        assert_ne!(s1, s2);
    }

    #[test]
    fn update_is_deterministic() {
        let s0 = [1u8; 32];
        assert_eq!(next_traffic_secret(&s0), next_traffic_secret(&s0));
    }
}
