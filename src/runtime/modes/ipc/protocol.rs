use std::io::{Read, Write};

use lz4::block::{compress, decompress};

use crate::runtime::error::ProcessorError;

pub const MAGIC: [u8; 4] = *b"BLEX";
pub const VERSION: u16 = 2;

pub const FLAG_COMPRESSED: u16 = 0x1;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Hello = 1,
    HelloAck = 2,
    Request = 3,
    Response = 4,
    Error = 5,
    Shutdown = 6,
    ShutdownAck = 7,
}

impl MessageKind {
    pub fn from_u16(value: u16) -> Result<Self, ProcessorError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::Request),
            4 => Ok(Self::Response),
            5 => Ok(Self::Error),
            6 => Ok(Self::Shutdown),
            7 => Ok(Self::ShutdownAck),
            _ => Err(ProcessorError::Protocol(format!(
                "unknown processor message kind: {}",
                value
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FrameHeader {
    pub kind: MessageKind,
    pub id: u16,
    pub flags: u16,
    pub request_id: u64,
    pub payload_len: u32,
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct HelloProcessor {
    pub id: u16,
    pub name: String,
    pub os: Vec<crate::processor::ProcessorOs>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Hello {
    pub protocol_version: u16,
    pub backend_name: String,
    pub host_os: crate::processor::ProcessorOs,
    pub processor_name: String,
    pub supported_ids: Vec<u16>,
    pub processors: Vec<HelloProcessor>,
    pub pid: u32,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ProcessorFailure {
    pub message: String,
}

pub fn write_frame<W: Write>(
    writer: &mut W,
    kind: MessageKind,
    id: u16,
    request_id: u64,
    payload: &[u8],
    compression_enabled: bool,
) -> Result<(), ProcessorError> {
    let (flags, framed_payload) = if compression_enabled && !payload.is_empty() {
        let compressed = compress(payload, None, false)
            .map_err(|error| ProcessorError::Compression(error.to_string()))?;
        let mut framed = Vec::with_capacity(4 + compressed.len());
        framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(&compressed);
        (FLAG_COMPRESSED, framed)
    } else {
        (0, payload.to_vec())
    };

    let payload_len = u32::try_from(framed_payload.len())
        .map_err(|_| ProcessorError::Protocol("payload too large for frame".to_string()))?;

    writer.write_all(&MAGIC)?;
    writer.write_all(&VERSION.to_le_bytes())?;
    writer.write_all(&(kind as u16).to_le_bytes())?;
    writer.write_all(&id.to_le_bytes())?;
    writer.write_all(&flags.to_le_bytes())?;
    writer.write_all(&request_id.to_le_bytes())?;
    writer.write_all(&payload_len.to_le_bytes())?;
    writer.write_all(&0u32.to_le_bytes())?;
    writer.write_all(&framed_payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Frame, ProcessorError> {
    let mut header_buf = [0u8; 28];
    reader.read_exact(&mut header_buf)?;

    if header_buf[0..4] != MAGIC {
        return Err(ProcessorError::Protocol(
            "invalid processor frame magic".to_string(),
        ));
    }

    let version = u16::from_le_bytes([header_buf[4], header_buf[5]]);
    if version != VERSION {
        return Err(ProcessorError::Protocol(format!(
            "unsupported processor protocol version: {}",
            version
        )));
    }

    let kind = MessageKind::from_u16(u16::from_le_bytes([header_buf[6], header_buf[7]]))?;
    let id = u16::from_le_bytes([header_buf[8], header_buf[9]]);
    let flags = u16::from_le_bytes([header_buf[10], header_buf[11]]);
    let request_id = u64::from_le_bytes([
        header_buf[12],
        header_buf[13],
        header_buf[14],
        header_buf[15],
        header_buf[16],
        header_buf[17],
        header_buf[18],
        header_buf[19],
    ]);
    let payload_len = u32::from_le_bytes([
        header_buf[20],
        header_buf[21],
        header_buf[22],
        header_buf[23],
    ]);

    let mut payload = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload)?;

    if flags & FLAG_COMPRESSED != 0 {
        if payload.len() < 4 {
            return Err(ProcessorError::Protocol(
                "compressed worker frame missing size prefix".to_string(),
            ));
        }
        let uncompressed_len =
            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as i32;
        payload = decompress(&payload[4..], Some(uncompressed_len))
            .map_err(|error| ProcessorError::Compression(error.to_string()))?;
    }

    Ok(Frame {
        header: FrameHeader {
            kind,
            id,
            flags,
            request_id,
            payload_len,
        },
        payload,
    })
}
