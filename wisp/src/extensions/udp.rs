//! UDP protocol extension.
//!
//! See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x01---udp)
use async_trait::async_trait;
use bytes::Bytes;

use crate::{
	ws::{DynWebSocketRead, LockingWebSocketWrite},
	WispError,
};

use super::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder};

#[derive(Debug)]
/// UDP protocol extension.
pub struct UdpProtocolExtension;

impl UdpProtocolExtension {
	/// UDP protocol extension ID.
	pub const ID: u8 = 0x01;
}

#[async_trait]
impl ProtocolExtension for UdpProtocolExtension {
	fn get_id(&self) -> u8 {
		Self::ID
	}

	fn get_supported_packets(&self) -> &'static [u8] {
		&[]
	}

	fn get_congestion_stream_types(&self) -> &'static [u8] {
		&[]
	}

	fn encode(&self) -> Bytes {
		Bytes::new()
	}

	async fn handle_handshake(
		&mut self,
		_: &mut DynWebSocketRead,
		_: &dyn LockingWebSocketWrite,
	) -> Result<(), WispError> {
		Ok(())
	}

	async fn handle_packet(
		&mut self,
		_: u8,
		_: Bytes,
		_: &mut DynWebSocketRead,
		_: &dyn LockingWebSocketWrite,
	) -> Result<(), WispError> {
		Ok(())
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(Self)
	}
}

/// UDP protocol extension builder.
pub struct UdpProtocolExtensionBuilder;

impl ProtocolExtensionBuilder for UdpProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		UdpProtocolExtension::ID
	}

	fn build_from_bytes(
		&mut self,
		_: Bytes,
		_: crate::Role,
	) -> Result<AnyProtocolExtension, WispError> {
		Ok(UdpProtocolExtension.into())
	}

	fn build_to_extension(&mut self, _: crate::Role) -> Result<AnyProtocolExtension, WispError> {
		Ok(UdpProtocolExtension.into())
	}
}
