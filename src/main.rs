#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::{env, future::Future, marker, pin::pin, pin::Pin, sync::Arc};
use tokio::{
    fs::{self, File},
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        BufStream,
    },
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
    let connection = BufStream::new(TcpStream::connect(host_port).await.unwrap());
    let connection = config
        .connect(host.as_str().try_into().unwrap(), connection)
        .await
        .unwrap();
    eprintln!("Connected to {}.", host);
    let (recv, send) = tokio::io::split(connection);

    tokio::select! {
        _ = sender(send) => (),
        _ = receiver(recv) => (),
    }
    eprintln!("Connection closed by foreign host.");

    std::process::exit(0);
}

// 受信したメッセージを出力
async fn receiver<R>(recv: R)
where
    R: AsyncReadExt + Unpin,
{
    let mut stdout = tokio::io::stdout();

    let _ = copy_low_latency(BufReader::new(recv), &mut stdout).await;
}

// txtファイルに指定されたデータを送信してからtelnetのように動作する
async fn sender<W: AsyncWriteExt + marker::Unpin>(send: W) {
    let mut send = ConvertCRLFWriter::new(send);
    let stdin = tokio::io::stdin();

    // 事前に送信するデータを読み取り送信する
    if let Ok(file) = File::open("./telnetls.txt").await {
        let _ = copy_low_latency(BufReader::new(file), &mut send).await;
    }

    let _ = copy_low_latency(BufReader::new(stdin), &mut send).await;
}

struct ConvertCRLFWriter<W>
where
    W: AsyncWrite + Unpin,
{
    inner: W,
    #[cfg(windows)]
    is_before_cr: bool,
}

impl<W> ConvertCRLFWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(inner: W) -> Self {
        Self {
            inner,
            #[cfg(windows)]
            is_before_cr: false,
        }
    }
}

impl<W> AsyncWrite for ConvertCRLFWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        #[cfg(not(windows))]
        let task = pin!(async {
            let mut start_index = 0;
            for (index, byte) in buf.iter().enumerate() {
                if *byte == 0x0D {
                    self.inner.write_all(&buf[start_index..index]).await?;
                    self.inner.write_all(&[0x0D, 0x00]).await?;
                    start_index = index + 1;
                } else if *byte == 0x0A {
                    self.inner.write_all(&buf[start_index..index]).await?;
                    self.inner.write_all(&[0x0D, 0x0A]).await?;
                    start_index = index + 1;
                }
            }

            if start_index != buf.len() {
                self.inner.write_all(&buf[start_index..buf.len()]).await?;
            }
            Ok(buf.len())
        });

        #[cfg(windows)]
        let task = pin!(async {
            let mut start_index = 0;
            for (index, byte) in buf.iter().enumerate() {
                if self.is_before_cr && *byte != 0x0A {
                    if index != 0 {
                        self.inner.write_all(&buf[start_index..index - 1]).await?;
                    }
                    self.inner.write_all(&[0x0D, 0x00]).await?;
                    start_index = index;
                }
                if !self.is_before_cr && *byte == 0x0A {
                    self.inner.write_all(&buf[start_index..index]).await?;
                    self.inner.write_all(&[0x0D, 0x0A]).await?;
                    start_index = index + 1;
                }

                self.is_before_cr = *byte == 0x0D;
            }

            if start_index != buf.len() {
                let range = if self.is_before_cr {
                    start_index..buf.len() - 1
                } else {
                    start_index..buf.len()
                };
                self.inner.write_all(&buf[range]).await?;
            }
            Ok(buf.len())
        });

        Future::poll(task, cx)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}

async fn copy_low_latency<R, W>(mut reader: R, writer: &mut W)
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while let Ok(buf) = reader.fill_buf().await {
        if buf.is_empty() {
            break;
        }

        let _ = writer.write_all(buf).await;
        let _ = writer.flush().await;

        let buf_len = buf.len();
        reader.consume(buf_len);
    }
}
