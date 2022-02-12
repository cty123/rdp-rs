use crate::model::data::Message;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub enum Payload {
    Raw(BytesMut),
    FastPath(u8, BytesMut),
}

/// TPKT action header
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133
/// # see : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597
#[derive(Copy, Clone)]
pub enum Action {
    FastPathActionFastPath = 0x0,
    FastPathActionX224 = 0x3,
}

impl TryFrom<u8> for Action {
    type Error = ();

    fn try_from(val: u8) -> Result<Action, ()> {
        match val {
            0 => Ok(Action::FastPathActionFastPath),
            0x3 => Ok(Action::FastPathActionX224),
            _ => Err(()),
        }
    }
}

pub struct TpktHeader {
    pub action: u8,
    pub flag: u8,
    pub size: u16,
}

#[async_trait]
impl Message for TpktHeader {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> std::io::Result<()> {
        writer.write_u8(self.action).await?;
        writer.write_u8(self.flag).await?;
        writer.write_u16(self.size).await?;
        Ok(())
    }

    async fn read_from(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin + Send),
    ) -> std::io::Result<()> {
        self.action = reader.read_u8().await?;
        self.flag = reader.read_u8().await?;
        self.size = reader.read_u16().await?;
        Ok(())
    }

    #[inline]
    fn length(&self) -> usize {
        4
    }
}
