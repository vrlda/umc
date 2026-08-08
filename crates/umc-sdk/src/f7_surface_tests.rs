use super::*;
use prost::Message;
use umc_control::proto::umc::api::v1;

#[test]
fn handles_are_type_and_generation_bound() {
    let session = SessionHandle::with_generation(b"session", 7);
    assert_eq!(session.as_bytes(), b"session");
    assert_eq!(session.generation(), 7);
    assert!(session.validate_generation(7).is_ok());
    assert!(matches!(
        session.validate_generation(8),
        Err(ClientError::HandleGenerationMismatch { .. })
    ));
    let stream = StreamHandle::with_generation(b"session", 7);
    assert_ne!(session.kind(), stream.kind());
}

#[test]
fn status_mapping_covers_the_sdk_categories() {
    assert_eq!(
        ClientError::from_status(v1::StatusCode::PermissionDenied as i32),
        ClientError::PermissionDenied
    );
    assert_eq!(
        ClientError::from_status(v1::StatusCode::DeadlineExceeded as i32),
        ClientError::DeadlineExceeded
    );
    assert_eq!(
        ClientError::from_status(v1::StatusCode::Unauthenticated as i32),
        ClientError::Authentication
    );
    assert_eq!(
        SdkError::from_status(v1::StatusCode::ResourceExhausted as i32),
        SdkError::ResourceExhausted
    );
}

#[test]
fn policy_serializes_constraints_without_strategy_code() {
    let policy = Policy {
        require_end_to_end_encryption: true,
        allow_relay: false,
        path_strategy: PathStrategy::LocalFirst,
        ..Policy::default()
    };
    let route = policy.to_route_policy();
    assert!(!route.allow_relay);
    assert_eq!(
        route.maximum_hops,
        u32::try_from(policy.maximum_hops).expect("test policy fits")
    );
    assert_eq!(route.scope, v1::RouteScope::LocalMesh as i32);
}

#[test]
fn protocol_registry_validates_and_deduplicates_ids() {
    let mut registry = ServiceRegistry::new();
    registry
        .register("org.example.echo/1")
        .expect("valid protocol");
    assert!(matches!(
        registry.register("org.example.echo/1"),
        Err(ClientError::AlreadyExists)
    ));
    assert!(matches!(
        registry.register("Bad Protocol"),
        Err(ClientError::InvalidArgument)
    ));
    assert_eq!(registry.protocols(), &["org.example.echo/1".to_string()]);
}

#[test]
fn bounded_send_queue_reports_would_block() {
    let mut queue = BoundedSendQueue::new(3);
    queue.try_enqueue(b"ab").expect("first chunk");
    assert!(matches!(
        queue.try_enqueue(b"cd"),
        Err(ClientError::WouldBlock)
    ));
    assert_eq!(queue.pop().as_deref(), Some(b"ab".as_slice()));
    queue.try_enqueue(b"cd").expect("space released");
}

#[test]
fn delivery_events_do_not_claim_peer_application_receipt() {
    let event = DeliveryEvent::Acknowledged {
        stream_id: 3,
        offset: 10,
    };
    assert_eq!(event.stream_id(), Some(3));
    assert!(!event.is_application_receipt());
}

#[test]
fn endpoint_metadata_is_non_secret() {
    let summary = v1::IdentitySummary {
        identity_handle: Some(v1::OpaqueHandle {
            value: b"identity".to_vec(),
        }),
        endpoint_id: vec![4; 32],
        label: "default".into(),
        secret_available: true,
        ..Default::default()
    };
    let endpoint = Endpoint::from_summary(&summary).expect("summary");
    assert_eq!(endpoint.label(), "default");
    assert_eq!(endpoint.endpoint_id(), &[4; 32]);
    assert!(!endpoint.exposes_private_key());
}

#[test]
fn request_shape_carries_deadline_without_unbounded_waiting() {
    let bytes = crate::daemon::encode_request_with_deadline(
        1,
        2,
        "ApplicationService",
        "Connect",
        Vec::new(),
        Some(123),
    )
    .expect("encode request");
    let envelope = v1::Envelope::decode(bytes.as_slice()).expect("decode request");
    let v1::envelope::Body::Request(request) = envelope.body.expect("request body") else {
        panic!("expected request body");
    };
    assert_eq!(request.deadline_unix_ms, 123);
}
