//! A probably not standard compliant SOCKS5 implementation

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_byteorder::BigEndian;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum SocksRequest {
    Fqdn { fqdn: String, port: u16 },
    Ip(SocketAddr),
}

#[derive(Debug)]
pub enum SocksError {
    UnsupportedDestination,
    IoError(tokio::io::Error),
    ProtocolError(&'static str),
    ConnectionDropped,
}

async fn authenticate(socket: &mut TcpStream) -> Result<(), SocksError> {
    if socket.read_u8().await? != 5 {
        return Err(SocksError::ProtocolError("Wrong version"));
    }

    let methods_len = socket.read_u8().await?;
    let mut methods = Vec::with_capacity(methods_len as usize);
    for _ in 0..methods_len {
        methods.push(socket.read_u8().await?);
    }

    if !methods.contains(&0) {
        return Err(SocksError::ProtocolError(
            "NO AUTHENTICATION REQUIRED not supported",
        ));
    }

    // respond with version 5
    socket.write_u8(5).await?;
    // choose no authentication
    socket.write_u8(0).await?;

    Ok(())
}

/// Read the SOCKS request sent in the beginning. It contains instructions where to connect to.
/// This implementation is probably not standard compliant.
pub async fn receive_request(socket: &mut TcpStream) -> Result<SocksRequest, SocksError> {
    authenticate(socket).await?;

    if socket.read_u8().await? != 5 {
        return Err(SocksError::ProtocolError("Wrong version"));
    }

    if socket.read_u8().await? != 1 {
        return Err(SocksError::ProtocolError(
            "Only connect requests are supported",
        ));
    }

    if socket.read_u8().await? != 0 {
        return Err(SocksError::ProtocolError("RSV!=0"));
    }

    let addr_type = socket.read_u8().await?;
    let socks_req = match addr_type {
        // parse FQDN and port
        0x03 => {
            let len = socket.read_u8().await?;
            let mut addr_bytes = vec![0u8; len as usize];
            socket.read_exact(&mut addr_bytes).await?;
            let fqdn = String::from_utf8(addr_bytes)
                .map_err(|_| SocksError::ProtocolError("Invalid unicode as fqdn"))?;
            let port = tokio_byteorder::AsyncReadBytesExt::read_u16::<BigEndian>(socket).await?;

            SocksRequest::Fqdn { fqdn, port }
        }
        // parse IPv4 and port
        0x01 => {
            let mut ip_bytes = [0u8; 4];
            socket.read_exact(&mut ip_bytes).await?;
            let port = tokio_byteorder::AsyncReadBytesExt::read_u16::<BigEndian>(socket).await?;

            SocksRequest::Ip(SocketAddr::from((ip_bytes, port)))
        }
        // parse IPv6 and port
        0x04 => {
            let mut ip_bytes = [0u8; 16];
            socket.read_exact(&mut ip_bytes).await?;
            let port = tokio_byteorder::AsyncReadBytesExt::read_u16::<BigEndian>(socket).await?;

            SocksRequest::Ip(SocketAddr::from((ip_bytes, port)))
        }
        _ => {
            return Err(SocksError::ProtocolError("Unsupported address format"));
        }
    };

    // Our response is kinda bs except that it says it was successful (which might actually be the case)
    socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(socks_req)
}

impl From<tokio::io::Error> for SocksError {
    fn from(e: tokio::io::Error) -> Self {
        SocksError::IoError(e)
    }
}
