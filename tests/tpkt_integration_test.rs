use rdp::core::tpkt::base::Payload;
use rdp::core::tpkt::client::TpktClient;
use rdp::model::data::U32;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_tpkt_client_write() {
    let (mut server, client) = tokio::io::duplex(128);
    let mut client = TpktClient::new(client);

    let x = U32::BE(1);
    let mut buf = [0; 8];

    client.write(x).await.unwrap();
    server.read(&mut buf).await.unwrap();

    assert_eq!(buf, [3, 0, 0, 8, 0, 0, 0, 1]);
}

#[tokio::test]
async fn test_tpkt_client_read() {
    let (mut server, client) = tokio::io::duplex(128);
    let mut client = TpktClient::new(client);

    server.write(&[3, 0, 0, 8, 0, 0, 0, 1]).await.unwrap();
    let payload = client.read().await.unwrap();

    match payload {
        Payload::Raw(data) => {
            assert_eq!(data.to_vec(), vec![0, 0, 0, 1])
        }
        _ => assert!(false),
    }
}
