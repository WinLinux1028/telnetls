use std::{env, marker, sync::Arc};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::rustls;

#[tokio::main]
async fn main() {
    // コマンドライン引数から通信先を取得する
    let mut options = env::args();
    options.next().unwrap();
    let host = options
        .next()
        .expect("1つ目の引数には接続先のサーバーを設定してください");
    let port = options.next().unwrap_or_else(|| "443".to_string());
    let host_port = format!("{}:{}", host, port);

    // ユーザーの入力を処理する
    let host_port = host_port.trim();
    let host = host_port.split(':').next().unwrap();

    // TLS接続の設定
    let mut certs = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().unwrap() {
        certs.add(&rustls::Certificate(cert.0)).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(certs)
        .with_no_client_auth();
    let config = tokio_rustls::TlsConnector::from(Arc::new(config));

    // 接続を行う
    let connection = TcpStream::connect(host_port).await.unwrap();
    let connection = config
        .connect(host.try_into().unwrap(), connection)
        .await
        .unwrap();
    let (recv, send) = tokio::io::split(connection);

    let receiver = tokio::spawn(receiver(BufReader::new(recv)));
    let sender = tokio::spawn(sender(send));

    let _ = receiver.await;
    sender.abort();

    std::process::exit(0);
}

// 受信したメッセージをリアルタイムに出力
async fn receiver<R: AsyncBufReadExt + std::marker::Unpin>(mut recv: R) {
    let mut stdout = tokio::io::stdout();

    let mut buf = [0];
    let buf = buf.as_mut_slice();
    loop {
        if recv.read_exact(buf).await.is_err() {
            stdout
                .write_all("connection closed\n".as_bytes())
                .await
                .unwrap();
            stdout.flush().await.unwrap();
            return;
        }

        stdout.write_all(buf).await.unwrap();
        stdout.flush().await.unwrap();
    }
}

// txtファイルに指定されたデータを送信してからtelnetのように動作する
async fn sender<W: AsyncWriteExt + marker::Unpin>(mut send: W) {
    let mut stdin = BufReader::new(tokio::io::stdin());

    // 送信するデータを読み取る
    let mut msg = Vec::new();
    if let Ok(mut file) = File::open("./telnetls.txt").await {
        file.read_to_end(&mut msg).await.unwrap();
    }

    loop {
        if send.write_all(&msg).await.is_err() || send.flush().await.is_err() {
            return;
        }
        msg.clear();

        stdin.read_until(0xA, &mut msg).await.unwrap();
        // 改行を\r\nに置き換える
        msg.pop();
        msg.push(0xD);
        msg.push(0xA);
    }
}
