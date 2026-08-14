/// Storage abstraction (core.md §21). Namespaces group records by state category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    Config,
    Identity,
    Trust,
    Peer,
    Route,
    Bundle,
    Relay,
    Api,
    Abuse,
}

impl Namespace {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Namespace::Config => "config",
            Namespace::Identity => "identity",
            Namespace::Trust => "trust",
            Namespace::Peer => "peer",
            Namespace::Route => "route",
            Namespace::Bundle => "bundle",
            Namespace::Relay => "relay",
            Namespace::Api => "api",
            Namespace::Abuse => "abuse",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    Serialization,
    Transaction,
    Corrupt(String),
    QuotaExceeded,
}

pub trait Store: Send + Sync {
    /// Reads the value stored under `key` in `namespace`.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    fn get(&self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;
    /// Writes `value` under `key` in `namespace`, overwriting any prior value.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] or [`StoreError::QuotaExceeded`] on
    /// backend failure.
    fn put(&self, namespace: Namespace, key: &[u8], value: &[u8]) -> Result<(), StoreError>;
    /// Removes `key` from `namespace`; missing keys are a no-op.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    fn delete(&self, namespace: Namespace, key: &[u8]) -> Result<(), StoreError>;
    /// Returns all entries in `namespace` ordered by key.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    fn scan(&self, namespace: Namespace) -> Result<Vec<Entry>, StoreError>;
    /// Writes `entries` atomically as a single transaction.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] or [`StoreError::Transaction`] on
    /// backend failure.
    fn put_batch(
        &self,
        namespace: Namespace,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_are_stable_strings() {
        assert_eq!(Namespace::Config.as_str(), "config");
        assert_eq!(Namespace::Abuse.as_str(), "abuse");
    }
}
