use async_trait::async_trait;
use std::io::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// All data type used
///
/// Allow us to retrieve correct data
/// Into the message tree via cast! or cast_optional! macro
///
/// # Examples
/// ```
/// # #[macro_use]
/// # extern crate rdp;
/// # use rdp::model::data::{DataType, Component, U32};
/// # fn main() {
/// let message = component!(
///     "header" => U32::LE(1234)
/// );
/// if let DataType::U32(header) = message["header"].visit() {
///     assert_eq!(header, 1234)
/// }
/// else {
///     panic!("Invalid cast")
/// }
/// # }
/// ```
pub enum DataType<'a> {
    /// Unsigned 32 bits integer
    U32(u32),
    /// Unsigned 16 bits integer
    U16(u16),
    /// 8 bits integer
    U8(u8),
    /// A slice is just a raw u8 of vector
    Slice(&'a [u8]),
    /// Optional value can be absent
    None,
}

/// Allow to a son to inform parent of something special
///
/// IN tree type a son can control parser of a parent node
/// by providing some type depend fields
///
/// This is control by the options function of Message Trait
pub enum MessageOption {
    /// You ask to skip a field
    /// during reading operation
    SkipField(String),
    /// You ask to limit the size of reading buffer
    /// for a particular field
    Size(String, usize),
    /// Non option
    None,
}

/// All is a message
///
/// A message can be Read or Write from a Stream
///
#[async_trait]
pub trait Message: Send {
    /// Write node to the Stream
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> Result<()>;

    /// Read node from stream
    async fn read_from(&mut self, reader: &mut (impl AsyncRead + Unpin + Send)) -> Result<()>;

    /// Length in bytes of current element
    fn length(&self) -> usize;
}

/// u8 message
#[async_trait]
impl Message for u8 {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> Result<()> {
        writer.write_u8(*self).await
    }

    async fn read_from(&mut self, reader: &mut (impl AsyncRead + Unpin + Send)) -> Result<()> {
        *self = reader.read_u8().await?;
        Ok(())
    }

    #[inline]
    fn length(&self) -> usize {
        1
    }
}

/// Trame is just a list of boxed Message
/// # Example
///
/// ```
/// # #[macro_use]
/// # extern crate rdp;
/// # use rdp::model::data::{Trame, U32};
/// # fn main() {
///     let t = trame! [0 as u8, U32::BE(4)];
/// # }
/// ```
// pub type Trame = Vec<Box<dyn Message>>;

#[derive(Copy, Clone)]
pub enum Value<Type> {
    /// Big Endianness
    BE(Type),
    /// Little Endianness
    LE(Type),
}

impl<Type: Copy + PartialEq> Value<Type> {
    /// Return the inner value
    ///
    /// # Example
    /// ```
    /// use rdp::model::data::U32;
    /// let x = U32::LE(4);
    /// assert_eq!(x.inner(), 4);
    /// ```
    pub fn inner(&self) -> Type {
        match self {
            Value::<Type>::BE(e) | Value::<Type>::LE(e) => *e,
        }
    }
}

impl<Type: Copy + PartialEq> PartialEq for Value<Type> {
    /// Equality between all type
    fn eq(&self, other: &Self) -> bool {
        return self.inner() == other.inner();
    }
}

/// Unsigned 16 bits message
pub type U16 = Value<u16>;

#[async_trait]
impl Message for U16 {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> Result<()> {
        match self {
            U16::BE(value) => writer.write_u16(*value).await,
            U16::LE(value) => writer.write_u16_le(*value).await,
        }
    }

    async fn read_from(&mut self, reader: &mut (impl AsyncRead + Unpin + Send)) -> Result<()> {
        match self {
            U16::BE(value) => *value = reader.read_u16().await?,
            U16::LE(value) => *value = reader.read_u16_le().await?,
        }
        Ok(())
    }

    /// Length of U16 is 2
    fn length(&self) -> usize {
        2
    }
}

/// Unsigned 32 bits message
pub type U32 = Value<u32>;

#[async_trait]
impl Message for U32 {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> Result<()> {
        match self {
            U32::BE(value) => writer.write_u32(*value).await,
            U32::LE(value) => writer.write_u32_le(*value).await,
        }
    }

    async fn read_from(&mut self, reader: &mut (impl AsyncRead + Unpin + Send)) -> Result<()> {
        match self {
            U32::BE(value) => *value = reader.read_u32().await?,
            U32::LE(value) => *value = reader.read_u32_le().await?,
        }
        Ok(())
    }

    /// Length of the 32 bits is four
    fn length(&self) -> usize {
        4
    }
}

#[async_trait]
impl Message for Vec<u8> {
    async fn write_to(&self, writer: &mut (impl AsyncWrite + Unpin + Send)) -> Result<()> {
        writer.write_all(self).await
    }

    async fn read_from(&mut self, reader: &mut (impl AsyncRead + Unpin + Send)) -> Result<()> {
        reader.read_exact(self).await?;
        Ok(())
    }

    fn length(&self) -> usize {
        self.len()
    }
}

// /// Add dynamic filtering capability for parent Node
// ///
// /// Use by component node to create a filtering relationship
// /// between two or more fields
// ///
// /// # Example
// /// ```
// /// # #[macro_use]
// /// # extern crate rdp;
// /// # use rdp::model::data::{Message, DynOption, Component, U32, DataType, MessageOption};
// /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
// /// # use std::io::Cursor;
// /// # fn main() {
// ///     let mut node = component![
// ///         "flag" => DynOption::new(U32::LE(0), |flag| {
// ///             if flag.inner() == 1 {
// ///                 return MessageOption::SkipField("depend".to_string());
// ///             }
// ///             return MessageOption::None;
// ///         }),
// ///         "depend" => U32::LE(0)
// ///     ];
// ///     let mut stream = Cursor::new(vec![0,0,0,0,1,0,0,0]);
// ///     node.read(&mut stream).unwrap();
// ///     assert_eq!(cast!(DataType::U32, node["depend"]).unwrap(), 1);
// ///
// ///     let mut stream = Cursor::new(vec![1,0,0,0,2,0,0,0]);
// ///     node.read(&mut stream).unwrap();
// ///     assert_ne!(cast!(DataType::U32, node["depend"]).unwrap(), 2);
// /// }
// /// ```
// pub type DynOptionFnSend<T> = dyn Fn(&T) -> MessageOption + Send;
// pub struct DynOption<T> {
//     inner: T,
//     filter: Box<DynOptionFnSend<T>>,
// }

// /// The filter impl
// /// A filter work like a proxy pattern for an inner object
// impl<T> DynOption<T> {
//     /// Create a new filter from a callback
//     /// Callback may return a list of field name taht will be skip
//     /// by the component reader
//     ///
//     /// The following example add a dynamic skip option
//     /// # Example
//     /// ```
//     /// #[macro_use]
//     /// # extern crate rdp;
//     /// # use rdp::model::data::{Message, Component, DynOption, U32, MessageOption};
//     /// # fn main() {
//     ///     let message = component![
//     ///         "flag" => DynOption::new(U32::LE(1), |flag| {
//     ///             if flag.inner() == 1 {
//     ///                 return MessageOption::SkipField("depend".to_string());
//     ///             }
//     ///             else {
//     ///                 return MessageOption::None;
//     ///             }
//     ///         }),
//     ///         "depend" => U32::LE(0)
//     ///     ];
//     ///     assert_eq!(message.length(), 4);
//     /// # }
//     /// ```
//     ///
//     /// The next example use dynamic option to set a size to a value
//     ///
//     /// # Example
//     /// ```
//     /// #[macro_use]
//     /// # extern crate rdp;
//     /// # use rdp::model::data::{Message, Component, DynOption, U32, MessageOption, DataType};
//     /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
//     /// # use std::io::Cursor;
//     /// # fn main() {
//     ///     let mut message = component![
//     ///         "Type" => DynOption::new(U32::LE(0), |flag| {
//     ///             MessageOption::Size("Value".to_string(), flag.inner() as usize)
//     ///         }),
//     ///         "Value" => Vec::<u8>::new()
//     ///     ];
//     ///     let mut stream = Cursor::new(vec![1,0,0,0,1]);
//     ///     message.read(&mut stream).unwrap();
//     ///     assert_eq!(cast!(DataType::Slice, message["Value"]).unwrap().len(), 1);
//     /// # }
//     /// ```
//     pub fn new<F: 'static>(current: T, filter: F) -> Self
//     where
//         F: Fn(&T) -> MessageOption,
//         F: Send,
//     {
//         DynOption {
//             inner: current,
//             filter: Box::new(filter),
//         }
//     }
// }

// /// Dynamic option
// /// is a transparent object for the inner
// impl<T: Message> Message for DynOption<T> {
//     /// Transparent
//     fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
//         self.inner.write(writer)
//     }

//     /// Transparent
//     fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
//         self.inner.read(reader)
//     }

//     /// Transparent
//     fn length(&self) -> u64 {
//         self.inner.length()
//     }
// }

// /// This is an optional fields
// /// Actually always write but read if and only if the reader
// /// buffer could read the size of inner Message
// impl<T: Message> Message for Option<T> {
//     /// Write an optional message
//     /// Actually always try to write
//     ///
//     /// # Example
//     /// ```
//     /// use std::io::Cursor;
//     /// use rdp::model::data::Message;
//     /// let mut s1 = Cursor::new(vec![]);
//     /// Some(4).write(&mut s1);
//     /// assert_eq!(s1.into_inner(), [4]);
//     /// let mut s2 = Cursor::new(vec![]);
//     /// Option::<u8>::None.write(&mut s2);
//     /// assert_eq!(s2.into_inner(), [])
//     /// ```
//     fn write(&self, writer: &mut dyn Write) -> RdpResult<()> {
//         Ok(if let Some(value) = self {
//             value.write(writer)?
//         })
//     }

//     /// Read an optional field
//     /// Read the value if and only if there is enough space in the
//     /// reader
//     ///
//     /// # Example
//     /// ```
//     /// #[macro_use]
//     /// # extern crate rdp;
//     /// # use std::io::Cursor;
//     /// # use rdp::model::error::{Error, RdpError, RdpResult, RdpErrorKind};
//     /// # use rdp::model::data::{U32, Message, DataType, Component};
//     /// # fn main() {
//     ///     let mut s1 = Cursor::new(vec![1, 0, 0, 0]);
//     ///     let mut x = Some(U32::LE(0));
//     ///     x.read(&mut s1);
//     ///     assert_eq!(1, cast!(DataType::U32, x).unwrap());
//     ///
//     ///     let mut s2 = Cursor::new(vec![1, 0, 0]);
//     ///     let mut y = Some(U32::LE(0));
//     ///     y.read(&mut s2);
//     ///     assert!(y == None);
//     ///
//     ///     let mut s3 = Cursor::new(vec![1, 0, 0]);
//     ///     // case in component
//     ///     let mut z = component![
//     ///         "optional" => Some(U32::LE(0))
//     ///     ];
//     ///     z.read(&mut s3);
//     ///     assert!(is_none!(z["optional"]))
//     /// # }
//     /// ```
//     fn read(&mut self, reader: &mut dyn Read) -> RdpResult<()> {
//         if let Some(value) = self {
//             if value.read(reader).is_err() {
//                 *self = None
//             }
//         }
//         Ok(())
//     }

//     /// This compute the length of the optionaln field
//     /// # Example
//     /// ```
//     /// use rdp::model::data::{U32, Message};
//     /// assert_eq!(Some(U32::LE(4)).length(), 4);
//     /// assert_eq!(Option::<U32>::None.length(), 0);
//     /// ```
//     fn length(&self) -> u64 {
//         if let Some(value) = self {
//             value.length()
//         } else {
//             0
//         }
//     }
// }

#[cfg(test)]
mod test {
    #[test]
    fn test_data_u8_write() {
        // let mut stream = Cursor::new(Vec::<u8>::new());
        // let x = 1 as u8;
        // x.write(&mut stream).unwrap();
        // assert_eq!(stream.get_ref().as_slice(), [1])
    }
}
