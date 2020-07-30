#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod whois {
    tonic::include_proto!("whois");
}

lazy_static! {
    static ref NOTICE: Vec<u8> = {
        let txt_file = include_str!("notice.txt")
            .replace("\\cBB", "\x1b[38;5;81m")
            .replace("\\cBM", "\x1b[38;5;218m")
            .replace("\\cBW", "\x1b[38;5;231m")
            .replace("\\cRS", "\x1b[0m");
        txt_file.as_bytes().to_owned()
    };
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let mut listener = tokio::net::TcpListener::bind("[::]:43").await.expect("Unable to bind to socket");
    let client = whois::whois_client::WhoisClient::connect(
        std::env::var("GRPC_SERVER").unwrap_or("http://[::1]:50051".to_string())
    ).await.expect("Unable to connect to gRPC server");

    loop {
        let (socket, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("Error accepting connection: {}", e);
                return
            }
        };
        process_socket(socket, client.clone()).await;
    }
}

async fn process_socket<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin>(mut socket: T, mut client: whois::whois_client::WhoisClient<tonic::transport::Channel>) {
    let mut buf: Vec<u8> = vec![];
    loop {
        let byte = match socket.read_u8().await {
            Ok(b) => b,
            Err(_) => {
                return;
            }
        };
        if char::from(byte) != '\r' {
            buf.push(byte);
        } else {
            break;
        }
    }
    let byte = match socket.read_u8().await {
        Ok(b) => b,
        Err(_) => {
            return;
        }
    };
    if char::from(byte) != '\n' {
        return;
    }
    let query_str = match String::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => {
            return;
        }
    };

    let request = tonic::Request::new(whois::WhoisRequest {
        query: query_str
    });

     match client.whois_query(request).await {
        Ok(r) => {
            let response = r.into_inner();
            for object in response.objects {
                for element in object.elements {
                    match socket.write(format!("{}: {}\r\n", element.key, element.value).as_bytes()).await {
                        Ok(_) => {}
                        Err(_) => {
                            return;
                        }
                    };
                }
                match socket.write(b"\r\n").await {
                    Ok(_) => {}
                    Err(_) => {
                        return;
                    }
                };
            }
        },
        Err(e) => {
            match socket.write(format!(">>> Error: {:?}, {}\r\n\r\n", e.code(), e.message()).as_bytes()).await {
                Ok(_) => {}
                Err(_) => {
                    return;
                }
            };
        }
    };

    match socket.write(&NOTICE).await {
        Ok(_) => {}
        Err(_) => {}
    };
}