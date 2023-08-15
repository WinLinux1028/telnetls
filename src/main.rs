#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::{env, future::Future, marker, pin::Pin, sync::Arc};
use tokio::{
    fs::{self, File},
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
    // ファイルから証明書を読み込む
    if let Ok(mut dir) = fs::read_dir("./certs").await {
        while let Ok(Some(file)) = dir.next_entry().await {
            let file_type = match file.file_type().await {
                Ok(o) => o,
                Err(_) => continue,
            };
            if !file_type.is_file() {
                continue;
            }

            let file_path = file.path();
            let file_path = file_path.to_str().unwrap();

            let convert: Box<
                dyn FnOnce(Vec<u8>) -> Pin<Box<dyn Future<Output = Vec<rustls::Certificate>>>>,
            >;
            if file_path.ends_with(".pem") {
                convert = Box::new(|file_buf| {
                    Box::pin(async move {
                        let certs = match rustls_pemfile::certs(&mut file_buf.as_slice()) {
                            Ok(o) => o,
                            Err(_) => return Vec::new(),
                        };
                        certs
                            .into_iter()
                            .map(|cert| rustls::Certificate(cert))
                            .collect()
                    })
                });
            } else if file_path.ends_with(".der") {
                convert = Box::new(|file_buf| {
                    Box::pin(async move { vec![rustls::Certificate(file_buf)] })
                });
            } else {
                continue;
            }

            let mut file = match fs::File::open(file.path()).await {
                Ok(o) => o,
                Err(_) => continue,
            };
            let mut file_buf = Vec::new();
            if file.read_to_end(&mut file_buf).await.is_err() {
                continue;
            }

            let certs_from_file = convert(file_buf).await;
            for cert in certs_from_file {
                let _ = certs.add(&cert);
            }
        }
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
    eprintln!("Connected to {}.", host);
    let (recv, send) = tokio::io::split(connection);

    let receiver = tokio::spawn(receiver(BufReader::new(recv)));
    let sender = tokio::spawn(sender(send));

    let _ = receiver.await;
    sender.abort();

    std::process::exit(0);
}

// 受信したメッセージを出力
async fn receiver<R: AsyncBufReadExt + std::marker::Unpin>(mut recv: R) {
    let mut stdout = tokio::io::stdout();

    while let Ok(buf) = recv.fill_buf().await {
        if buf.is_empty() {
            break;
        }

        stdout.write_all(buf).await.unwrap();
        stdout.flush().await.unwrap();

        // 後始末
        let buf_len = buf.len();
        recv.consume(buf_len);
    }

    eprintln!("Connection closed by foreign host.");
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

        // 改行コードが\r\nでなければ\r\nに置き換える
        if msg.len() < 2 {
            msg.insert(0, 0xD);
        } else if msg[msg.len() - 2] != 0xD {
            msg.insert(msg.len() - 1, 0xD);
        }
    }
}
