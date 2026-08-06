use std::collections::BTreeMap;

pub const MAX_OUT_OF_ORDER_BYTES: usize = 1_048_576;
pub const MAX_OUT_OF_ORDER_RANGES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    Ready,
    Send,
    DataSent,
    ResetSent,
    DataAcked,
    ResetAcked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    Recv,
    SizeKnown,
    DataRecvd,
    ResetRecvd,
    DataRead,
    ResetRead,
}

#[derive(Debug, Clone)]
pub struct Stream {
    pub stream_id: u64,
    pub protocol_id: Vec<u8>,
    pub send_state: SendState,
    pub recv_state: RecvState,
    pub next_send_offset: u64,
    pub final_size: Option<u64>,
    pub buffered: BTreeMap<u64, Vec<u8>>,
    pub buffered_bytes: usize,
    pub next_deliver_offset: u64,
    pub max_stream_data_local: u64,
    pub max_stream_data_remote: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    AlreadyClosed,
    FinalSizeConflict,
    DataBeyondFinalSize,
    OverlappingDataConflict,
    OutOfOrderBudgetExceeded,
    OffsetsOutOfOrder,
}

impl Stream {
    #[must_use]
    pub fn new(stream_id: u64, protocol_id: Vec<u8>, max_stream_data: u64) -> Self {
        Self {
            stream_id,
            protocol_id,
            send_state: SendState::Ready,
            recv_state: RecvState::Recv,
            next_send_offset: 0,
            final_size: None,
            buffered: BTreeMap::new(),
            buffered_bytes: 0,
            next_deliver_offset: 0,
            max_stream_data_local: max_stream_data,
            max_stream_data_remote: max_stream_data,
        }
    }

    /// Buffer a received segment at `offset`. Returns the number of new bytes
    /// buffered (0 for a fully duplicated segment, which is dropped silently).
    ///
    /// # Errors
    ///
    /// Returns `StreamError` when the segment conflicts with the final size,
    /// partially overlaps buffered or delivered data, exceeds flow-control or
    /// out-of-order budgets, or arrives with offsets out of order.
    pub fn receive(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<usize, StreamError> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(StreamError::DataBeyondFinalSize)?;
        if fin {
            if let Some(fs) = self.final_size {
                if fs != end {
                    return Err(StreamError::FinalSizeConflict);
                }
            } else {
                self.final_size = Some(end);
            }
        }
        if let Some(fs) = self.final_size {
            if end > fs {
                return Err(StreamError::DataBeyondFinalSize);
            }
        }
        if offset > self.max_stream_data_local {
            return Err(StreamError::OffsetsOutOfOrder);
        }
        // Idempotent dedup (QUIC-style): a segment fully inside already-
        // delivered bytes, or inside an existing buffered range, carries no
        // new data — a delayed original arriving after its retransmit was
        // delivered must not error the whole packet. Partial conflicts (the
        // segment straddles the boundary of existing data) still error below.
        if end <= self.next_deliver_offset {
            return Ok(0);
        }
        if let Some((&key, value)) = self.buffered.range(..=offset).next_back() {
            let range_end = key.saturating_add(value.len() as u64);
            if key <= offset && end <= range_end {
                return Ok(0);
            }
        }
        if offset < self.next_deliver_offset {
            return Err(StreamError::OffsetsOutOfOrder);
        }
        // Overlap conflict check and insert.
        if let Some((&key, value)) = self.buffered.range(..offset).next_back() {
            let overlap_end = key.saturating_add(value.len() as u64);
            if overlap_end > offset {
                return Err(StreamError::OverlappingDataConflict);
            }
        }
        self.buffered_bytes = self.buffered_bytes.saturating_add(data.len());
        if self.buffered_bytes > MAX_OUT_OF_ORDER_BYTES
            || self.buffered.len() >= MAX_OUT_OF_ORDER_RANGES
        {
            // Rejected input must not mutate state: roll back the tentative
            // byte count so the budget reflects only buffered ranges.
            self.buffered_bytes = self.buffered_bytes.saturating_sub(data.len());
            return Err(StreamError::OutOfOrderBudgetExceeded);
        }
        self.buffered.insert(offset, data.to_vec());
        Ok(data.len())
    }

    /// Deliver contiguous bytes from `next_deliver_offset`.
    pub fn read_available(&mut self) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut eof = false;
        while let Some((&offset, data)) = self.buffered.first_key_value() {
            if offset != self.next_deliver_offset {
                break;
            }
            out.extend_from_slice(data);
            self.buffered_bytes = self.buffered_bytes.saturating_sub(data.len());
            self.next_deliver_offset = offset.saturating_add(data.len() as u64);
            self.buffered.remove(&offset);
        }
        if let Some(fs) = self.final_size {
            if self.next_deliver_offset == fs {
                eof = true;
                self.recv_state = RecvState::DataRead;
            }
        }
        (out, eof)
    }

    /// Take up to `max_stream_data_remote` bytes for transmission.
    ///
    /// # Errors
    ///
    /// Returns `StreamError::AlreadyClosed` when the send side is fully acked
    /// or reset.
    pub fn send_ready(&mut self, data: &[u8]) -> Result<(u64, Vec<u8>), StreamError> {
        if self.send_state == SendState::DataAcked || self.send_state == SendState::ResetAcked {
            return Err(StreamError::AlreadyClosed);
        }
        let offset = self.next_send_offset;
        #[allow(clippy::cast_possible_truncation)]
        let allowed = self.max_stream_data_remote.saturating_sub(offset) as usize;
        let take = data.len().min(allowed);
        self.next_send_offset += take as u64;
        if self.send_state == SendState::Ready {
            self.send_state = SendState::Send;
        }
        Ok((offset, data[..take].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_delivery() {
        let mut s = Stream::new(0, b"org.example.echo/1".to_vec(), 1_000_000);
        s.receive(0, b"hel", false).unwrap();
        s.receive(3, b"lo", true).unwrap();
        let (data, eof) = s.read_available();
        assert_eq!(data, b"hello");
        assert!(eof);
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut s = Stream::new(0, Vec::new(), 1_000_000);
        s.receive(3, b"lo", true).unwrap();
        let (data, eof) = s.read_available();
        assert!(data.is_empty());
        assert!(!eof);
        s.receive(0, b"hel", false).unwrap();
        let (data, eof) = s.read_available();
        assert_eq!(data, b"hello");
        assert!(eof);
    }

    #[test]
    fn final_size_conflict_rejected() {
        let mut s = Stream::new(0, Vec::new(), 1_000_000);
        s.receive(0, b"abc", true).unwrap();
        assert_eq!(
            s.receive(0, b"abcd", true),
            Err(StreamError::FinalSizeConflict)
        );
    }

    #[test]
    fn overlapping_conflict_rejected() {
        let mut s = Stream::new(0, Vec::new(), 1_000_000);
        s.receive(0, b"abc", false).unwrap();
        // A segment that straddles the boundary of buffered data — new bytes
        // beyond the existing range — is a partial conflict, not a duplicate.
        assert_eq!(
            s.receive(2, b"xyz", false),
            Err(StreamError::OverlappingDataConflict)
        );
    }

    #[test]
    fn partial_overlap_of_delivered_region_rejected() {
        let mut s = Stream::new(0, Vec::new(), 1_000_000);
        s.receive(0, b"abc", false).unwrap();
        let (data, _eof) = s.read_available();
        assert_eq!(data, b"abc");
        // Starts inside the delivered region but carries new bytes past it:
        // a partial conflict, not a silent duplicate.
        assert_eq!(
            s.receive(2, b"xyz", false),
            Err(StreamError::OffsetsOutOfOrder)
        );
    }

    #[test]
    fn duplicate_segment_after_delivery_is_idempotent() {
        let mut s = Stream::new(0, Vec::new(), 1_000_000);
        s.receive(0, b"hel", false).unwrap();
        s.receive(3, b"lo", true).unwrap();
        let (data, eof) = s.read_available();
        assert_eq!(data, b"hello");
        assert!(eof);
        // A delayed original arriving after the retransmit was delivered must
        // not error (QUIC-style silent dedup): it carries no new bytes.
        assert!(s.receive(0, b"hel", false).is_ok());
        let (data, _eof) = s.read_available();
        assert!(data.is_empty(), "duplicate must not be delivered again");
    }

    #[test]
    fn duplicate_of_buffered_range_is_idempotent() {
        let mut s = Stream::new(0, Vec::new(), 1_000_000);
        s.receive(3, b"lo", false).unwrap();
        assert_eq!(s.buffered.len(), 1);
        assert!(s.receive(3, b"lo", false).is_ok());
        assert_eq!(s.buffered.len(), 1, "duplicate must not be re-buffered");
    }

    #[test]
    fn send_respects_remote_credit() {
        let mut s = Stream::new(0, Vec::new(), 10);
        let (offset, data) = s.send_ready(b"hello world").unwrap();
        assert_eq!(offset, 0);
        assert_eq!(data, b"hello worl");
    }

    #[test]
    fn out_of_order_budget_bounded() {
        let mut s = Stream::new(0, Vec::new(), u64::MAX);
        // Sparse offsets must not create unbounded state.
        for i in 0..MAX_OUT_OF_ORDER_RANGES as u64 {
            s.receive(i * 10_000, &[0xAA], false).unwrap();
        }
        assert_eq!(
            s.receive(MAX_OUT_OF_ORDER_RANGES as u64 * 10_000, &[0xBB], false),
            Err(StreamError::OutOfOrderBudgetExceeded)
        );
    }
}
