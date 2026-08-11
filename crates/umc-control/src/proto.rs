//! Generated protobuf types from api/umc.proto (build.rs).
#[allow(clippy::all, clippy::pedantic, missing_debug_implementations)]
pub mod umc {
    pub mod api {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/umc.api.v1.rs"));
        }
    }
}
