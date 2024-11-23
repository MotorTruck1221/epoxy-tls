mod client;
pub(crate) mod inner;
mod server;
use std::{future::Future, pin::Pin};

pub use client::ClientMux;
pub use server::ServerMux;

use crate::{
	extensions::{udp::UdpProtocolExtension, AnyProtocolExtension, AnyProtocolExtensionBuilder},
	ws::{LockedWebSocketWrite, WebSocketWrite},
	CloseReason, Packet, PacketType, Role, WispError,
};

struct WispHandshakeResult {
	kind: WispHandshakeResultKind,
	downgraded: bool,
}

enum WispHandshakeResultKind {
	V2 {
		extensions: Vec<AnyProtocolExtension>,
	},
	V1 {
		frame: Option<Packet<'static>>,
	},
}

impl WispHandshakeResultKind {
	pub fn into_parts(self) -> (Vec<AnyProtocolExtension>, Option<Packet<'static>>) {
		match self {
			Self::V2 { extensions } => (extensions, None),
			Self::V1 { frame } => (vec![UdpProtocolExtension.into()], frame),
		}
	}
}

async fn send_info_packet<W: WebSocketWrite>(
	write: &LockedWebSocketWrite<W>,
	builders: &mut [AnyProtocolExtensionBuilder],
) -> Result<(), WispError> {
	write
		.write_frame(
			Packet::new_info(
				builders
					.iter_mut()
					.map(|x| x.build_to_extension(Role::Server))
					.collect::<Result<Vec<_>, _>>()?,
			)
			.into(),
		)
		.await
}

fn validate_continue_packet(packet: Packet<'_>) -> Result<u32, WispError> {
	if packet.stream_id != 0 {
		return Err(WispError::InvalidStreamId);
	}

	let PacketType::Continue(continue_packet) = packet.packet_type else {
		return Err(WispError::InvalidPacketType);
	};

	Ok(continue_packet.buffer_remaining)
}

fn get_supported_extensions(
	extensions: Vec<AnyProtocolExtension>,
	builders: &mut [AnyProtocolExtensionBuilder],
) -> Vec<AnyProtocolExtension> {
	let extension_ids: Vec<_> = builders.iter().map(|x| x.get_id()).collect();
	extensions
		.into_iter()
		.filter(|x| extension_ids.contains(&x.get_id()))
		.collect()
}

trait Multiplexor {
	fn has_extension(&self, extension_id: u8) -> bool;
	async fn exit(&self, reason: CloseReason) -> Result<(), WispError>;
}

/// Result of creating a multiplexor. Helps require protocol extensions.
#[expect(private_bounds)]
pub struct MuxResult<M, F>(M, F)
where
	M: Multiplexor,
	F: Future<Output = Result<(), WispError>> + Send;

#[expect(private_bounds)]
impl<M, F> MuxResult<M, F>
where
	M: Multiplexor,
	F: Future<Output = Result<(), WispError>> + Send,
{
	/// Require no protocol extensions.
	pub fn with_no_required_extensions(self) -> (M, F) {
		(self.0, self.1)
	}

	/// Require protocol extensions by their ID. Will close the multiplexor connection if
	/// extensions are not supported.
	pub async fn with_required_extensions(self, extensions: &[u8]) -> Result<(M, F), WispError> {
		let mut unsupported_extensions = Vec::new();
		for extension in extensions {
			if !self.0.has_extension(*extension) {
				unsupported_extensions.push(*extension);
			}
		}

		if unsupported_extensions.is_empty() {
			Ok((self.0, self.1))
		} else {
			self.0.exit(CloseReason::ExtensionsIncompatible).await?;
			self.1.await?;
			Err(WispError::ExtensionsNotSupported(unsupported_extensions))
		}
	}

	/// Shorthand for `with_required_extensions(&[UdpProtocolExtension::ID])`
	pub async fn with_udp_extension_required(self) -> Result<(M, F), WispError> {
		self.with_required_extensions(&[UdpProtocolExtension::ID])
			.await
	}
}

/// Wisp V2 middleware closure.
pub type WispV2Middleware = dyn for<'a> Fn(
		&'a mut Vec<AnyProtocolExtensionBuilder>,
	) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Sync + Send + 'a>>
	+ Send;
/// Wisp V2 handshake and protocol extension settings wrapper struct.
pub struct WispV2Handshake {
	builders: Vec<AnyProtocolExtensionBuilder>,
	closure: Box<WispV2Middleware>,
}

impl WispV2Handshake {
	/// Create a Wisp V2 settings struct with no middleware.
	pub fn new(builders: Vec<AnyProtocolExtensionBuilder>) -> Self {
		Self {
			builders,
			closure: Box::new(|_| Box::pin(async { Ok(()) })),
		}
	}

	/// Create a Wisp V2 settings struct with some middleware.
	pub fn new_with_middleware(
		builders: Vec<AnyProtocolExtensionBuilder>,
		closure: Box<WispV2Middleware>,
	) -> Self {
		Self { builders, closure }
	}

	/// Add a Wisp V2 extension builder to the settings struct.
	pub fn add_extension(&mut self, extension: AnyProtocolExtensionBuilder) {
		self.builders.push(extension);
	}
}
