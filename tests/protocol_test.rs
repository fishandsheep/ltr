use ltr_cli::shared::{ClientMessage, Delimited};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn bore_v1_wire_shape_remains_null_delimited_json() {
    let (mut raw, framed_stream) = duplex(256);
    let mut framed = Delimited::new(framed_stream);

    raw.write_all(b"{\"Hello\":9000}\0")
        .await
        .expect("fixture should write");
    let message = framed
        .recv::<ClientMessage>()
        .await
        .expect("frame should parse")
        .expect("message should exist");
    assert!(matches!(message, ClientMessage::Hello(9000)));
}

#[tokio::test]
async fn bore_v1_outgoing_frame_is_stable() {
    let (framed_stream, mut raw) = duplex(256);
    let mut framed = Delimited::new(framed_stream);
    framed
        .send(ClientMessage::Hello(9000))
        .await
        .expect("frame should send");

    let mut bytes = vec![0u8; b"{\"Hello\":9000}\0".len()];
    raw.read_exact(&mut bytes)
        .await
        .expect("frame should be readable");
    assert_eq!(bytes, b"{\"Hello\":9000}\0");
}
