use std::collections::VecDeque;

pub const MAX_QUEUED_DATAGRAMS: usize = 256;
pub const MAX_QUEUED_DATAGRAM_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub context_id: u64,
    pub data: Vec<u8>,
    pub expires_at_ms: Option<u64>,
    pub ack_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramError {
    QueueFull,
    BytesFull,
    Oversize,
}

#[derive(Debug, Clone)]
pub struct DatagramQueue {
    outbound: VecDeque<Datagram>,
    inbound: VecDeque<Datagram>,
    outbound_bytes: usize,
    inbound_bytes: usize,
}

impl DatagramQueue {
    #[must_use]
    pub fn new() -> Self {
        Self {
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
            outbound_bytes: 0,
            inbound_bytes: 0,
        }
    }

    /// Queue a datagram for sending.
    ///
    /// # Errors
    ///
    /// Returns [`DatagramError::Oversize`] if `d.data` exceeds `max_size`,
    /// [`DatagramError::QueueFull`] if the queue holds `MAX_QUEUED_DATAGRAMS`
    /// items, or [`DatagramError::BytesFull`] if the queued byte count would
    /// exceed `MAX_QUEUED_DATAGRAM_BYTES`.
    pub fn enqueue_outbound(&mut self, d: Datagram, max_size: usize) -> Result<(), DatagramError> {
        if d.data.len() > max_size {
            return Err(DatagramError::Oversize);
        }
        if self.outbound.len() >= MAX_QUEUED_DATAGRAMS {
            return Err(DatagramError::QueueFull);
        }
        if self.outbound_bytes + d.data.len() > MAX_QUEUED_DATAGRAM_BYTES {
            return Err(DatagramError::BytesFull);
        }
        self.outbound_bytes += d.data.len();
        self.outbound.push_back(d);
        Ok(())
    }

    /// Pop the next sendable datagram, dropping expired ones first.
    ///
    /// # Panics
    ///
    /// Panics only on an internal invariant violation while draining
    /// expired datagrams.
    pub fn pop_outbound(&mut self, now_ms: u64) -> Option<Datagram> {
        while let Some(front) = self.outbound.front() {
            if let Some(exp) = front.expires_at_ms {
                if exp <= now_ms {
                    let d = self.outbound.pop_front().expect("front");
                    self.outbound_bytes = self.outbound_bytes.saturating_sub(d.data.len());
                    continue;
                }
            }
            break;
        }
        let d = self.outbound.pop_front()?;
        self.outbound_bytes = self.outbound_bytes.saturating_sub(d.data.len());
        Some(d)
    }

    /// Queue a received datagram.
    ///
    /// # Errors
    ///
    /// Returns [`DatagramError::QueueFull`] if the queue holds
    /// `MAX_QUEUED_DATAGRAMS` items, or [`DatagramError::BytesFull`] if the
    /// queued byte count would exceed `MAX_QUEUED_DATAGRAM_BYTES`.
    pub fn enqueue_inbound(&mut self, d: Datagram) -> Result<(), DatagramError> {
        if self.inbound.len() >= MAX_QUEUED_DATAGRAMS {
            return Err(DatagramError::QueueFull);
        }
        if self.inbound_bytes + d.data.len() > MAX_QUEUED_DATAGRAM_BYTES {
            return Err(DatagramError::BytesFull);
        }
        self.inbound_bytes += d.data.len();
        self.inbound.push_back(d);
        Ok(())
    }

    pub fn pop_inbound(&mut self) -> Option<Datagram> {
        let d = self.inbound.pop_front()?;
        self.inbound_bytes = self.inbound_bytes.saturating_sub(d.data.len());
        Some(d)
    }
}

impl Default for DatagramQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_bounds_enforced() {
        let mut q = DatagramQueue::new();
        for _ in 0..MAX_QUEUED_DATAGRAMS {
            q.enqueue_outbound(
                Datagram {
                    context_id: 0,
                    data: vec![0u8; 8],
                    expires_at_ms: None,
                    ack_requested: false,
                },
                1200,
            )
            .unwrap();
        }
        assert_eq!(
            q.enqueue_outbound(
                Datagram {
                    context_id: 0,
                    data: vec![0u8; 8],
                    expires_at_ms: None,
                    ack_requested: false
                },
                1200
            ),
            Err(DatagramError::QueueFull)
        );
    }

    #[test]
    fn expired_datagrams_dropped_on_pop() {
        let mut q = DatagramQueue::new();
        q.enqueue_outbound(
            Datagram {
                context_id: 0,
                data: vec![1],
                expires_at_ms: Some(100),
                ack_requested: false,
            },
            1200,
        )
        .unwrap();
        q.enqueue_outbound(
            Datagram {
                context_id: 0,
                data: vec![2],
                expires_at_ms: None,
                ack_requested: false,
            },
            1200,
        )
        .unwrap();
        let d = q.pop_outbound(200).unwrap();
        assert_eq!(d.data, vec![2]);
    }

    #[test]
    fn oversize_rejected() {
        let mut q = DatagramQueue::new();
        assert_eq!(
            q.enqueue_outbound(
                Datagram {
                    context_id: 0,
                    data: vec![0u8; 1201],
                    expires_at_ms: None,
                    ack_requested: false
                },
                1200
            ),
            Err(DatagramError::Oversize)
        );
    }
}
