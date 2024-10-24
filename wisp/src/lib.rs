#![deny(missing_docs, clippy::todo)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! A library for easily creating [Wisp] clients and servers.
//!
//! [Wisp]: https://github.com/MercuryWorkshop/wisp-protocol

pub mod extensions;
#[cfg(feature = "fastwebsockets")]
#[cfg_attr(docsrs, doc(cfg(feature = "fastwebsockets")))]
mod fastwebsockets;
#[cfg(feature = "generic_stream")]
#[cfg_attr(docsrs, doc(cfg(feature = "generic_stream")))]
pub mod generic;
mod inner;
mod mux;
mod packet;
mod sink_unfold;
mod stream;
pub mod ws;

pub use crate::{mux::*, packet::*, stream::*};

use thiserror::Error;

/// Wisp version supported by this crate.
pub const WISP_VERSION: WispVersion = WispVersion { major: 2, minor: 0 };

/// The role of the multiplexor.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Role {
	/// Client side, can create new channels to proxy.
	Client,
	/// Server side, can listen for channels to proxy.
	Server,
}

/// Errors the Wisp implementation can return.
#[derive(Error, Debug)]
pub enum WispError {
	/// The packet received did not have enough data.
	#[error("Packet too small")]
	PacketTooSmall,
	/// The packet received had an invalid type.
	#[error("Invalid packet type")]
	InvalidPacketType,
	/// The stream had an invalid ID.
	#[error("Invalid steam ID")]
	InvalidStreamId,
	/// The close packet had an invalid reason.
	#[error("Invalid close reason")]
	InvalidCloseReason,
	/// The max stream count was reached.
	#[error("Maximum stream count reached")]
	MaxStreamCountReached,
	/// The Wisp protocol version was incompatible.
	#[error("Incompatible Wisp protocol version: found {0} but needed {1}")]
	IncompatibleProtocolVersion(WispVersion, WispVersion),
	/// The stream had already been closed.
	#[error("Stream already closed")]
	StreamAlreadyClosed,

	/// The websocket frame received had an invalid type.
	#[error("Invalid websocket frame type: {0:?}")]
	WsFrameInvalidType(ws::OpCode),
	/// The websocket frame received was not finished.
	#[error("Unfinished websocket frame")]
	WsFrameNotFinished,
	/// Error specific to the websocket implementation.
	#[error("Websocket implementation error:")]
	WsImplError(Box<dyn std::error::Error + Sync + Send>),
	/// The websocket implementation socket closed.
	#[error("Websocket implementation error: socket closed")]
	WsImplSocketClosed,
	/// The websocket implementation did not support the action.
	#[error("Websocket implementation error: not supported")]
	WsImplNotSupported,

	/// The string was invalid UTF-8.
	#[error("UTF-8 error: {0}")]
	Utf8Error(#[from] std::str::Utf8Error),
	/// The integer failed to convert.
	#[error("Integer conversion error: {0}")]
	TryFromIntError(#[from] std::num::TryFromIntError),
	/// Other error.
	#[error("Other: {0:?}")]
	Other(Box<dyn std::error::Error + Sync + Send>),

	/// Failed to send message to multiplexor task.
	#[error("Failed to send multiplexor message")]
	MuxMessageFailedToSend,
	/// Failed to receive message from multiplexor task.
	#[error("Failed to receive multiplexor message")]
	MuxMessageFailedToRecv,
	/// Multiplexor task ended.
	#[error("Multiplexor task ended")]
	MuxTaskEnded,
	/// Multiplexor task already started.
	#[error("Multiplexor task already started")]
	MuxTaskStarted,

	/// Error specific to the protocol extension implementation.
	#[error("Protocol extension implementation error: {0:?}")]
	ExtensionImplError(Box<dyn std::error::Error + Sync + Send>),
	/// The protocol extension implementation did not support the action.
	#[error("Protocol extension implementation error: unsupported feature")]
	ExtensionImplNotSupported,
	/// The specified protocol extensions are not supported by the other side.
	#[error("Protocol extensions {0:?} not supported")]
	ExtensionsNotSupported(Vec<u8>),
	/// The password authentication username/password was invalid.
	#[error("Password protocol extension: Invalid username/password")]
	PasswordExtensionCredsInvalid,
	/// The certificate authentication signature was invalid.
	#[error("Certificate authentication protocol extension: Invalid signature")]
	CertAuthExtensionSigInvalid,
}
