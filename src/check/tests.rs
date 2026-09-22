//! Unit tests for the listener probe's request frame and reply check.

use super::{FRAME_HEADER_LEN, build_req_pq_multi, reply_is_res_pq};

/// The frame a peer reads: a 4-byte length prefix, 8 zero bytes where a session
/// would carry `auth_key_id`, the message id, the body length, and the body
/// padded to a multiple of 4.
#[test]
fn req_pq_multi_is_a_padded_intermediate_frame() {
    let frame = build_req_pq_multi();

    assert_eq!(frame.len() % 4, 0, "padded to a multiple of 4");

    let declared = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
    assert_eq!(
        declared + 4,
        frame.len(),
        "the length prefix covers the frame"
    );

    assert_eq!(
        &frame[4..12],
        &[0u8; 8],
        "no session yet: auth_key_id is zero"
    );

    let body_len = u32::from_le_bytes(frame[20..24].try_into().unwrap()) as usize;
    assert_eq!(
        body_len,
        4 + 16,
        "the body is the constructor and its nonce"
    );
    assert_eq!(&frame[24..28], &0xbe7e_8ef1u32.to_le_bytes());
    assert!(
        frame[28..44].iter().any(|byte| *byte != 0),
        "the nonce is random, not zeroed"
    );
}

/// `resPQ` with a zero `auth_key_id` is the answer we want; another
/// constructor, a session key or a short read is not.
#[test]
fn only_a_zero_key_res_pq_reply_passes() {
    let mut reply = vec![0u8; FRAME_HEADER_LEN];
    reply[24..28].copy_from_slice(&0x0516_2463u32.to_le_bytes());
    assert!(reply_is_res_pq(&reply));

    reply[24..28].copy_from_slice(&0xbe7e_8ef1u32.to_le_bytes());
    assert!(!reply_is_res_pq(&reply), "another constructor is not resPQ");

    let mut reply = vec![0u8; FRAME_HEADER_LEN];
    reply[24..28].copy_from_slice(&0x0516_2463u32.to_le_bytes());
    reply[4] = 1;
    assert!(
        !reply_is_res_pq(&reply),
        "a session key means it is not a resPQ"
    );

    assert!(
        !reply_is_res_pq(&reply[..FRAME_HEADER_LEN - 1]),
        "short read"
    );
    assert!(!reply_is_res_pq(&[]));
}
