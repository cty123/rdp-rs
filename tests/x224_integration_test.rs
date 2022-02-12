use bytes::{Buf, BufMut, BytesMut};
use rdp::core::x224::base::{NegotiationType, Protocols, RdpNegRequest, X224ConnectionPDU};
use rdp::model::data::{Message, U32};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_x224_request() {
    let (mut server, mut client) = tokio::io::duplex(128);
    let request = RdpNegRequest::new(
        Some(NegotiationType::TypeRDPNegReq),
        None,
        Some(Protocols::ProtocolSSL as u32),
    );
    request.write_to(&mut client).await.unwrap();

    let mut buf = [0; 8];
    server.read(&mut buf).await.unwrap();

    assert_eq!(buf, [1, 0, 8, 0, 1, 0, 0, 0]);
}

// #[tokio::test]
// async fn test_tpkt_client_response() {
//     // let (mut server, mut client) = tokio::io::duplex(128);
//     let mut buffer = BytesMut::with_capacity(32);
//     buffer.put_slice(&[1, 0, 8, 0, 1, 0, 0, 0]);

//     let mut pdu = X224ConnectionPDU::new();
//     pdu.read_from_buffer(&mut buffer).unwrap();

//     assert_eq!(
//         Protocols::try_from(pdu.negotiation.protocols.inner()).unwrap() as u8,
//         Protocols::ProtocolSSL as u8
//     );
// }
