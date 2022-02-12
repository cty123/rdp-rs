use bytes::BytesMut;
use std::io::{self, Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::core::tpkt::base::{Action, Payload, TpktHeader};
use crate::model::data::{Message, U16};
// use crate::nla::cssp::cssp_connect;
// use crate::nla::sspi::AuthenticationProtocol;

/// TPKT must implement this two kind of payload

/// Client Context of TPKT layer
pub struct TpktClient<S> {
    transport: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TpktClient<S> {
    /// Create a new Client based on a low level connection instance
    pub fn new(transport: S) -> Self {
        TpktClient { transport }
    }

    /// Send a message to the link layer
    /// with appropriate header
    /// Move to avoid copy
    pub async fn write<T: 'static>(&mut self, message: T) -> Result<()>
    where
        T: Message,
    {
        let header = TpktHeader {
            action: Action::FastPathActionX224 as u8,
            flag: 0,
            size: (message.length() + 4) as u16,
        };

        return header.write_to(&mut self.transport).await;
    }

    /// Read a payload from the underlying layer
    /// Check the tpkt header and provide a well
    /// formed payload
    pub async fn read(&mut self) -> io::Result<Payload> {
        let action = match Action::try_from(self.transport.read_u8().await?) {
            Ok(a) => a,
            Err(_) => return Err(Error::new(ErrorKind::InvalidData, "Invalid action code")),
        };

        match action {
            Action::FastPathActionX224 => {
                let padding = self.transport.read_u8().await?;
                let size = self.transport.read_u16().await?;

                if size < 4 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid minimal size for TPKT",
                    ));
                }

                let mut buffer = BytesMut::with_capacity(size as usize - 4);
                return match self.transport.read_buf(&mut buffer).await {
                    Ok(_) => Ok(Payload::Raw(buffer)),
                    Err(e) => Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid minimal size for TPKT",
                    )),
                };
            }
            _ => {
                let sec_flag = (action as u8 >> 6) & 0x3;
                let short_length = self.transport.read_u8().await?;

                match short_length & 0x80 {
                    0 => {
                        if short_length < 2 {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "Invalid minimal size for TPKT",
                            ));
                        }

                        let mut buffer = BytesMut::with_capacity(short_length as usize - 2);
                        return match self.transport.read_buf(&mut buffer).await {
                            Ok(_) => Ok(Payload::FastPath(sec_flag, buffer)),
                            Err(e) => Err(Error::new(
                                ErrorKind::InvalidData,
                                "Invalid minimal size for TPKT",
                            )),
                        };
                    }
                    _ => {
                        let hi_length = self.transport.read_u8().await?;
                        let length: u16 = ((short_length & !0x80) as u16) << 8;
                        let length = length | hi_length as u16;

                        if length < 3 {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "Invalid minimal size for TPKT",
                            ));
                        }

                        let mut buffer = BytesMut::with_capacity(length as usize - 3);
                        return match self.transport.read_buf(&mut buffer).await {
                            Ok(_) => Ok(Payload::FastPath(sec_flag, buffer)),
                            Err(e) => Err(Error::new(
                                ErrorKind::InvalidData,
                                "Invalid minimal size for TPKT",
                            )),
                        };
                    }
                };
            }
        };
    }

    // /// This function transform the link layer with
    // /// raw data stream into a SSL data stream
    // ///
    // /// # Example
    // /// ```no_run
    // /// use std::net::{SocketAddr, TcpStream};
    // /// use rdp::core::tpkt;
    // /// use rdp::model::link;
    // /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    // /// let mut tcp = TcpStream::connect(&addr).unwrap();
    // /// let mut tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(tcp)));
    // /// let mut tpkt_ssl = tpkt.start_ssl(false).unwrap();
    // /// ```
    // pub fn start_ssl(self, check_certificate: bool) -> RdpResult<Client<S>> {
    //     Ok(Client::new(self.transport.start_ssl(check_certificate)?))
    // }

    /// This function is used when NLA (Network Level Authentication)
    /// Authentication is negotiated
    ///
    /// # Example
    /// ```no_run
    /// use std::net::{SocketAddr, TcpStream};
    /// use rdp::core::tpkt;
    /// use rdp::nla::ntlm::Ntlm;
    /// use rdp::model::link;
    /// let addr = "127.0.0.1:3389".parse::<SocketAddr>().unwrap();
    /// let mut tcp = TcpStream::connect(&addr).unwrap();
    /// let mut tpkt = tpkt::Client::new(link::Link::new(link::Stream::Raw(tcp)));
    /// let mut tpkt_nla = tpkt.start_nla(false, &mut Ntlm::new("domain".to_string(), "username".to_string(), "password".to_string()), false);
    /// ```
    // pub fn start_nla(
    //     self,
    //     check_certificate: bool,
    //     authentication_protocol: &mut dyn AuthenticationProtocol,
    //     restricted_admin_mode: bool,
    // ) -> RdpResult<Client<S>> {
    //     let mut link = self.transport.start_ssl(check_certificate)?;
    //     cssp_connect(&mut link, authentication_protocol, restricted_admin_mode)?;
    //     Ok(Client::new(link))
    // }

    /// Shutdown current connection
    pub async fn shutdown(&mut self) -> Result<()> {
        self.transport.shutdown().await
    }
}

#[cfg(test)]
mod test {
    // /// Test the tpkt header type in write context
    // #[test]
    // fn test_write_tpkt_header() {
    //     let x = U32::BE(1);
    //     let message = trame![tpkt_header(x.length() as u16), x];
    //     let mut buffer = Cursor::new(Vec::new());
    //     message.write(&mut buffer).unwrap();
    //     assert_eq!(buffer.get_ref().as_slice(), [3, 0, 0, 8, 0, 0, 0, 1]);
    // }

    // /// Test read of TPKT header
    // #[test]
    // fn test_read_tpkt_header() {
    //     let mut message = tpkt_header(0);
    //     let mut buffer = Cursor::new([3, 0, 0, 8, 0, 0, 0, 1]);
    //     message.read(&mut buffer).unwrap();
    //     assert_eq!(cast!(DataType::U16, message["size"]).unwrap(), 8);
    //     assert_eq!(
    //         cast!(DataType::U8, message["action"]).unwrap(),
    //         Action::FastPathActionX224 as u8
    //     );
    // }

    // fn process(data: &[u8]) {
    //     let cur = Cursor::new(data.to_vec());
    //     let link = Link::new(Stream::Raw(cur));
    //     let mut client = Client::new(link);
    //     let _ = client.read();
    // }

    // #[test]
    // fn test_tpkt_size_overflow_case_1() {
    //     let buf = b"\x00\x00\x03\x00\x00\x00";
    //     process(buf);
    // }

    // #[test]
    // fn test_tpkt_size_overflow_case_2() {
    //     let buf = b"\x00\x80\x00\x00\x00\x00";
    //     process(buf);
    // }

    // #[test]
    // fn test_tpkt_size_overflow_case_3() {
    //     let buf = b"\x03\xe8\x00\x00\x80\x00";
    //     process(buf);
    // }
}
