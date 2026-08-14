pub mod umc {
    pub mod plugin {
        #[allow(clippy::doc_markdown, clippy::must_use_candidate)]
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/umc.plugin.v1.rs"));
        }
    }
}
