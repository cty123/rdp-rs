use std::io::Read;

use crate::model::data::{Message, U16, U32};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use num_enum::TryFromPrimitive;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[repr(u8)]
#[derive(Copy, Clone, TryFromPrimitive)]
pub enum NegotiationType {
    /// Negotiation Request
    /// Send from client to server
    TypeRDPNegReq = 0x01,
    /// Negotiation Response
    /// Send from Server to client
    TypeRDPNegRsp = 0x02,
    /// Negotiation failure
    /// Send when security level are not expected
    /// Server ask for NLA and client doesn't support it
    TypeRDPNegFailure = 0x03,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, TryFromPrimitive)]
pub enum Protocols {
    /// Basic RDP security
    /// Not supported by rdp-rs
    ProtocolRDP = 0x00,
    /// Secure Socket Layer
    ProtocolSSL = 0x01,
    /// Network Level Authentication over SSL
    ProtocolHybrid = 0x02,
    /// NLA + SSL + Quick respond
    ProtocolHybridEx = 0x08,
}

#[derive(Copy, Clone)]
pub enum MessageType {
    X224TPDUConnectionRequest = 0xE0,
    X224TPDUConnectionConfirm = 0xD0,
    X224TPDUDisconnectRequest = 0x80,
    X224TPDUData = 0xF0,
    X224TPDUError = 0x70,
}

/// Credential mode
#[repr(u8)]
pub enum RequestMode {
    /// Restricted admin mode
    /// Use to auth only with NLA mode
    /// Protect against crendential forward
    RestrictedAdminModeRequired = 0x01,
    /// New feature present in lastest windows 10
    /// Can't support acctually
    RedirectedAuthenticationModeRequired = 0x02,
    CorrelationInfoPresent = 0x08,
}

pub struct X224Header {
    header: u8,
    messageType: u8,
    separator: u8,
}

impl X224Header {
    pub fn new() -> Self {
        X224Header {
            header: 2,
            messageType: MessageType::X224TPDUData as u8,
            separator: 0x80,
        }
    }
}

#[async_trait]
impl Message for X224Header {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> std::io::Result<()> {
        writer.write_u8(self.header).await?;
        writer.write_u8(self.messageType).await?;
        writer.write_u8(self.separator).await?;
        Ok(())
    }

    async fn read_from(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin + Send),
    ) -> std::io::Result<()> {
        self.header = reader.read_u8().await?;
        self.messageType = reader.read_u8().await?;
        self.separator = reader.read_u8().await?;
        Ok(())
    }

    #[inline]
    fn length(&self) -> usize {
        4
    }
}

pub struct X224CRQ {
    len: u8,
    code: u8,
    padding: [u8; 5],
}

impl X224CRQ {
    pub fn new(len: u8, code: MessageType) -> Self {
        X224CRQ {
            len: len + 6,
            code: code as u8,
            padding: [0u8; 5],
        }
    }

    pub fn read_from_buffer(&mut self, buffer: &mut BytesMut) -> std::io::Result<()> {
        self.len = buffer.get_u8();
        self.code = buffer.get_u8();
        buffer.reader().read_exact(&mut self.padding)?;
        Ok(())
    }
}

#[async_trait]
impl Message for X224CRQ {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> std::io::Result<()> {
        writer.write_u8(self.len).await?;
        writer.write_u8(self.code).await?;
        writer.write_all(&self.padding).await?;
        Ok(())
    }

    async fn read_from(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin + Send),
    ) -> std::io::Result<()> {
        self.len = reader.read_u8().await?;
        self.code = reader.read_u8().await?;
        reader.read_exact(&mut self.padding).await?;
        Ok(())
    }

    #[inline]
    fn length(&self) -> usize {
        7
    }
}

pub struct RdpNegRequest {
    pub tpe: u8,
    pub flags: u8,
    pub length: U16,
    pub protocols: U32,
}

impl RdpNegRequest {
    pub fn new(tpe: Option<NegotiationType>, flags: Option<u8>, protocols: Option<u32>) -> Self {
        Self {
            tpe: tpe.unwrap_or(NegotiationType::TypeRDPNegReq) as u8,
            flags: flags.unwrap_or(0),
            length: U16::LE(0x0008),
            protocols: U32::LE(protocols.unwrap_or(0)),
        }
    }

    pub fn read_from_buffer(&mut self, buffer: &mut BytesMut) -> std::io::Result<()> {
        self.tpe = buffer.get_u8();
        self.flags = buffer.get_u8();
        self.length = U16::LE(buffer.get_u16_le());
        self.protocols = U32::LE(buffer.get_u32_le());
        Ok(())
    }
}

#[async_trait]
impl Message for RdpNegRequest {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> std::io::Result<()> {
        writer.write_u8(self.tpe).await?;
        writer.write_u8(self.flags).await?;
        self.length.write_to(writer).await?;
        self.protocols.write_to(writer).await?;
        Ok(())
    }

    async fn read_from(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin + Send),
    ) -> std::io::Result<()> {
        self.tpe = reader.read_u8().await?;
        self.flags = reader.read_u8().await?;
        self.length.read_from(reader).await?;
        self.protocols.read_from(reader).await?;
        Ok(())
    }

    #[inline]
    fn length(&self) -> usize {
        8
    }
}

/// Connection PDU
/// Include nego for security protocols
/// And restricted administration mode
// fn x224_connection_pdu(
//     neg_type: Option<NegotiationType>,
//     mode: Option<u8>,
//     protocols: Option<u32>,
// ) -> Component {
//     let negotiation = RdpNegRequest::new(neg_type, mode, protocols);

//     component![
//         "header" => x224_crq(negotiation.length() as u8, MessageType::X224TPDUConnectionRequest),
//         "negotiation" => negotiation
//     ]
// }
pub struct X224ConnectionPDU {
    pub header: X224CRQ,
    pub negotiation: RdpNegRequest,
}

impl X224ConnectionPDU {
    pub fn new() -> Self {
        Self {
            header: X224CRQ::new(0, MessageType::X224TPDUConnectionConfirm),
            negotiation: RdpNegRequest::new(None, None, None),
        }
    }

    pub fn read_from_buffer(&mut self, buffer: &mut BytesMut) -> std::io::Result<()> {
        self.header.read_from_buffer(buffer)?;
        self.negotiation.read_from_buffer(buffer)?;
        Ok(())
    }
}

#[async_trait]
impl Message for X224ConnectionPDU {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> std::io::Result<()> {
        self.header.write_to(writer).await?;
        self.negotiation.write_to(writer).await?;
        Ok(())
    }

    async fn read_from(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin + Send),
    ) -> std::io::Result<()> {
        self.header.read_from(reader).await?;
        self.negotiation.read_from(reader).await?;
        Ok(())
    }

    #[inline]
    fn length(&self) -> usize {
        self.header.length() + self.negotiation.length()
    }
}
