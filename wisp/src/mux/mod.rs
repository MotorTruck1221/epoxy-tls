mod client;
mod server;
use std::{future::Future, pin::Pin, time::Duration};

pub use client::ClientMux;
use futures::{select, FutureExt};
use futures_timer::Delay;
pub use server::ServerMux;

use crate::{
	extensions::{udp::UdpProtocolExtension, AnyProtocolExtension, AnyProtocolExtensionBuilder},
	ws::{Frame, LockedWebSocketWrite, WebSocketRead},
	CloseReason, Packet, PacketType, Role, WispError,
};

async fn maybe_wisp_v2<R>(
	read: &mut R,
	write: &LockedWebSocketWrite,
	role: Role,
	builders: &mut [AnyProtocolExtensionBuilder],
) -> Result<(Vec<AnyProtocolExtension>, Option<Frame<'static>>, bool), WispError>
where
	R: WebSocketRead + Send,
{
	let mut supported_extensions = Vec::new();
	let mut extra_packet: Option<Frame<'static>> = None;
	let mut downgraded = true;

	let extension_ids: Vec<_> = builders.iter().map(|x| x.get_id()).collect();
	if let Some(frame) = select! {
		x = read.wisp_read_frame(write).fuse() => Some(x?),
		_ = Delay::new(Duration::from_secs(5)).fuse() => None
	} {
		let packet = Packet::maybe_parse_info(frame, role, builders)?;
		if let PacketType::Info(info) = packet.packet_type {
			supported_extensions = info
				.extensions
				.into_iter()
				.filter(|x| extension_ids.contains(&x.get_id()))
				.collect();
			downgraded = false;
		} else {
			extra_packet.replace(Frame::from(packet).clone());
		}
	}

	for extension in supported_extensions.iter_mut() {
		extension.handle_handshake(read, write).await?;
	}
	Ok((supported_extensions, extra_packet, downgraded))
}

async fn send_info_packet(
	write: &LockedWebSocketWrite,
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

trait Multiplexor {
	fn has_extension(&self, extension_id: u8) -> bool;
	async fn exit(&self, reason: CloseReason) -> Result<(), WispError>;
}

/// Result of creating a multiplexor. Helps require protocol extensions.
#[allow(private_bounds)]
pub struct MuxResult<M, F>(M, F)
where
	M: Multiplexor,
	F: Future<Output = Result<(), WispError>> + Send;

#[allow(private_bounds)]
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

type WispV2ClosureResult = Pin<Box<dyn Future<Output = Result<(), WispError>> + Sync + Send>>;
type WispV2ClosureBuilders<'a> = &'a mut [AnyProtocolExtensionBuilder];
/// Wisp V2 handshake and protocol extension settings wrapper struct.
pub struct WispV2Extensions {
	builders: Vec<AnyProtocolExtensionBuilder>,
	closure: Box<dyn Fn(WispV2ClosureBuilders) -> WispV2ClosureResult + Send>,
}

impl WispV2Extensions {
	/// Create a Wisp V2 settings struct with no middleware.
	pub fn new(builders: Vec<AnyProtocolExtensionBuilder>) -> Self {
		Self {
			builders,
			closure: Box::new(|_| Box::pin(async { Ok(()) })),
		}
	}

	/// Create a Wisp V2 settings struct with some middleware.
	pub fn new_with_middleware<C>(builders: Vec<AnyProtocolExtensionBuilder>, closure: C) -> Self
	where
		C: Fn(WispV2ClosureBuilders) -> WispV2ClosureResult + Send + 'static,
	{
		Self {
			builders,
			closure: Box::new(closure),
		}
	}

	/// Add a Wisp V2 extension builder to the settings struct.
	pub fn add_extension(&mut self, extension: AnyProtocolExtensionBuilder) {
		self.builders.push(extension);
	}
}
