use crate::core::tpkt;
use crate::core::tpkt::base::Payload;
use crate::core::tpkt::client::TpktClient;
use crate::core::x224::base::{
    MessageType, NegotiationType, Protocols, RdpNegRequest, RequestMode, X224ConnectionPDU,
    X224Header, X224CRQ,
};
use crate::model::data::{Message, U16, U32};
// use crate::model::error::{Error, RdpError, RdpErrorKind, RdpResult};
use crate::nla::sspi::AuthenticationProtocol;

use bytes::Buf;
use native_tls::Protocol;
use std::convert::TryFrom;
use std::io::{Error, ErrorKind, Result};
use std::option::Option;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_stream::{self as stream, StreamExt};

/// RDP Negotiation Request
/// Use to inform server about supported
/// Security protocol
///
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
// fn rdp_neg_req(
//     neg_type: Option<NegotiationType>,
//     result: Option<u32>,
//     flag: Option<u8>,
// ) -> Component {
//     component! [
//         "type" => neg_type.unwrap_or(NegotiationType::TypeRDPNegReq) as u8,
//         "flag" => flag.unwrap_or(0),
//         "length" => Check::new(U16::LE(0x0008)),
//         "result" => U32::LE(result.unwrap_or(0))
//     ]
// }

/// X224 request header
// fn x224_crq(len: u8, code: MessageType) -> Component {
//     component! [
//         "len" => (len + 6) as u8,
//         "code" => code as u8,
//         "padding" => trame! [U16::LE(0), U16::LE(0), 0 as u8]
//     ]
// }

/// Connection PDU
/// Include nego for security protocols
/// And restricted administration mode
// fn x224_connection_pdu(
//     neg_type: Option<NegotiationType>,
//     mode: Option<u8>,
//     protocols: Option<u32>,
// ) -> Component {
//     let negotiation = rdp_neg_req(neg_type, protocols, mode);

//     component![
//         "header" => x224_crq(negotiation.length() as u8, MessageType::X224TPDUConnectionRequest),
//         "negotiation" => negotiation
//     ]
// }

/// X224 header
// fn x224_header() -> Component {
//     component![
//         "header" => 2 as u8,
//         "messageType" => MessageType::X224TPDUData as u8,
//         "separator" => Check::new(0x80 as u8)
//     ]
// }

/// x224 client
pub struct X224Client<S> {
    /// Transport layer, x224 use a tpkt
    transport: TpktClient<S>,
    /// Security selected protocol by the connector
    selected_protocol: Protocols,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> X224Client<S> {
    /// Constructor use by the connector
    fn new(transport: TpktClient<S>, selected_protocol: Protocols) -> Self {
        Self {
            transport,
            selected_protocol,
        }
    }

    /// Send a new x224 formated message
    /// using the underlying layer
    pub async fn write<T: 'static>(&mut self, message: T) -> Result<()>
    where
        T: Message,
    {
        let header = X224Header::new();
        self.transport.write(header).await?;
        self.transport.write(message).await?;
        Ok(())
        // self.transport.write(trame![x224_header(), message])
    }

    /// Start reading an entire X224 paylaod
    /// This function act to return a valid x224 payload
    /// or a fastpath payload coming from directly underlying layer
    pub async fn read(&mut self) -> Result<Payload> {
        let s = self.transport.read().await?;
        match s {
            Payload::Raw(mut payload) => {
                // Skip 4 bytes for X224Header
                payload.get_u32();
                Ok(Payload::Raw(payload))
            }
            Payload::FastPath(flag, payload) => Ok(Payload::FastPath(flag, payload)),
        }
    }

    /// Launch the connection sequence of the x224 stack
    /// It will start security protocol negotiation
    /// At the end it will produce a valid x224 layer
    ///
    /// security_protocols is a valid mix of Protocols
    /// RDP -> Protocols::ProtocolRDP as u32 NOT implemented
    /// SSL -> Protocols::ProtocolSSL as u32
    /// NLA -> Protocols::ProtocolSSL as u32 Protocols::Hybrid as u32
    ///
    /// If NLA we need to provide an authentication protocol
    ///
    /// # Example
    /// ```rust, ignore
    /// // SSL Security layer
    /// x224::Connector::connect(
    ///     tpkt,
    ///     Protocols::ProtocolSSL as u32,
    ///     None,
    ///     false
    /// ).unwrap();
    ///
    /// // NLA security Layer
    /// x224::Client::connect(
    ///     tpkt,
    ///     Protocols::ProtocolSSL as u32 Protocols::Hybrid as u32,
    ///     Some(&mut Ntlm::new("domain".to_string(), "username".to_string(), "password".to_string()),
    ///     false
    /// ).unwrap()
    /// ```
    pub async fn connect(
        mut client: TpktClient<S>,
        security_protocols: u32,
        check_certificate: bool,
        authentication_protocol: Option<&mut dyn AuthenticationProtocol>,
        restricted_admin_mode: bool,
        blank_creds: bool,
    ) -> Result<X224Client<S>> {
        Self::write_connection_request(
            &mut client,
            security_protocols,
            Some(if restricted_admin_mode {
                RequestMode::RestrictedAdminModeRequired as u8
            } else {
                0
            }),
        )
        .await?;

        match Self::read_connection_confirm(&mut client).await? {
            // Protocols::ProtocolHybrid => Ok(Client::new(
            //     tpkt.start_nla(
            //         check_certificate,
            //         authentication_protocol.unwrap(),
            //         restricted_admin_mode || blank_creds,
            //     )?,
            //     Protocols::ProtocolHybrid,
            // )),
            // Protocols::ProtocolSSL => Ok(Client::new(
            //     tpkt.start_ssl(check_certificate)?,
            //     Protocols::ProtocolSSL,
            // )),
            Protocols::ProtocolRDP => Ok(X224Client::new(client, Protocols::ProtocolRDP)),
            _ => Err(Error::new(
                ErrorKind::PermissionDenied,
                "Security protocol not handled",
            )),
        }
    }

    /// Send connection request
    async fn write_connection_request(
        client: &mut TpktClient<S>,
        security_protocols: u32,
        mode: Option<u8>,
    ) -> std::io::Result<()> {
        let body = RdpNegRequest::new(
            Some(NegotiationType::TypeRDPNegReq),
            mode,
            Some(security_protocols),
        );
        let header = X224CRQ::new(body.length() as u8, MessageType::X224TPDUConnectionRequest);
        let pdu = X224ConnectionPDU {
            header,
            negotiation: body,
        };
        client.write(pdu).await
    }

    /// Expect a connection confirm payload
    async fn read_connection_confirm(client: &mut TpktClient<S>) -> std::io::Result<Protocols> {
        let mut buffer = match client.read().await? {
            Payload::Raw(p) => p,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Expecting raw payload from TpktClient",
                ))
            }
        };

        let mut pdu = X224ConnectionPDU::new();
        match pdu.read_from_buffer(&mut buffer) {
            Ok(()) => (),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Failed to read request confirmation, {}", e),
                ))
            }
        }

        return match NegotiationType::try_from(pdu.negotiation.tpe).unwrap() {
            NegotiationType::TypeRDPNegFailure => Err(Error::new(
                ErrorKind::ConnectionReset,
                "Error during negotiation step",
            )),
            NegotiationType::TypeRDPNegReq => Err(Error::new(
                ErrorKind::ConnectionRefused,
                "Server reject security protocols",
            )),
            NegotiationType::TypeRDPNegRsp => Ok(
                match Protocols::try_from(pdu.negotiation.protocols.inner()) {
                    Ok(p) => p,
                    Err(_) => {
                        return Err(Error::new(
                            ErrorKind::ConnectionRefused,
                            "Server reject security protocols",
                        ))
                    }
                },
            ),
        };
    }

    /// Getter for selected protocols
    pub fn get_selected_protocols(&self) -> Protocols {
        self.selected_protocol
    }

    #[inline]
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.transport.shutdown().await
    }
}

#[cfg(test)]
mod test {
    // use super::*;
    // use std::io::Cursor;

    // /// test the negotiation request
    // #[test]
    // fn test_rdp_neg_req() {
    //     let mut s = Cursor::new(vec![]);
    //     rdp_neg_req(Some(NegotiationType::TypeRDPNegRsp), Some(1), Some(0))
    //         .write(&mut s)
    //         .unwrap();
    //     assert_eq!(s.into_inner(), vec![2, 0, 8, 0, 1, 0, 0, 0])
    // }

    // /// test of the x224 header format
    // #[test]
    // fn test_x224_crq() {
    //     let mut s = Cursor::new(vec![]);
    //     x224_crq(20, MessageType::X224TPDUData)
    //         .write(&mut s)
    //         .unwrap();
    //     assert_eq!(s.into_inner(), vec![26, 240, 0, 0, 0, 0, 0])
    // }

    // /// test of X224 data header
    // #[test]
    // fn test_x224_header() {
    //     let mut s = Cursor::new(vec![]);
    //     x224_header().write(&mut s).unwrap();
    //     assert_eq!(s.into_inner(), vec![2, 240, 128])
    // }

    // /// test of X224 client connection payload
    // #[test]
    // fn test_x224_connection_pdu() {
    //     let mut s = Cursor::new(vec![]);
    //     x224_connection_pdu(Some(NegotiationType::TypeRDPNegReq), Some(0), Some(3))
    //         .write(&mut s)
    //         .unwrap();
    //     assert_eq!(
    //         s.into_inner(),
    //         vec![14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0]
    //     )
    // }
}
