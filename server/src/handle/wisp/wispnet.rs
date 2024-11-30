use std::{
	collections::HashMap,
	sync::atomic::{AtomicU32, Ordering},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use lazy_static::lazy_static;
use log::debug;
use tokio::{select, sync::Mutex};
use uuid::Uuid;
use wisp_mux::{
	extensions::{
		AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder, ProtocolExtensionVecExt,
	},
	ws::{DynWebSocketRead, Frame, LockingWebSocketWrite, Payload},
	ClientMux, CloseReason, ConnectPacket, MuxStream, MuxStreamRead, MuxStreamWrite, Role,
	WispError, WispV2Handshake,
};

use crate::{
	route::{WispResult, WispStreamWrite},
	stream::ClientStream,
	CLIENTS,
};

struct WispnetClient {
	mux: ClientMux<WispStreamWrite>,
	id: String,
	private: bool,
}

lazy_static! {
	static ref WISPNET_SERVERS: Mutex<HashMap<u32, WispnetClient>> = Mutex::new(HashMap::new());
	static ref WISPNET_IDS: AtomicU32 = AtomicU32::new(0);
}

// payload:
// client (acting like wisp server) sends a bool saying if it wants to be private or not
// server (acting like wisp client) sends a u32 client id
//
// packets:
// client sends a 0xF1 on stream id 0 with no body to probe
// server sends back a 0xF1 on stream id 0 with a body of a bunch of u32s for each public client

struct WispnetServerProtocolExtensionBuilder(u32);
impl WispnetServerProtocolExtensionBuilder {
	const ID: u8 = 0xF1;
}

#[async_trait]
impl ProtocolExtensionBuilder for WispnetServerProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		Self::ID
	}

	fn build_from_bytes(
		&mut self,
		mut bytes: Bytes,
		_: Role,
	) -> Result<AnyProtocolExtension, WispError> {
		if bytes.remaining() < 1 {
			return Err(WispError::PacketTooSmall);
		};
		Ok(WispnetServerProtocolExtension(self.0, bytes.get_u8() != 0).into())
	}

	fn build_to_extension(&mut self, _: Role) -> Result<AnyProtocolExtension, WispError> {
		Ok(WispnetServerProtocolExtension(self.0, false).into())
	}
}

#[derive(Debug, Copy, Clone)]
struct WispnetServerProtocolExtension(u32, pub bool);
impl WispnetServerProtocolExtension {
	const ID: u8 = 0xF1;
}

#[async_trait]
impl ProtocolExtension for WispnetServerProtocolExtension {
	fn get_id(&self) -> u8 {
		Self::ID
	}
	fn get_supported_packets(&self) -> &'static [u8] {
		&[Self::ID]
	}
	fn get_congestion_stream_types(&self) -> &'static [u8] {
		&[]
	}
	fn encode(&self) -> Bytes {
		let mut out = BytesMut::new();
		out.put_u32_le(self.0);
		out.freeze()
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
		packet_type: u8,
		mut packet: Bytes,
		_: &mut DynWebSocketRead,
		write: &dyn LockingWebSocketWrite,
	) -> Result<(), WispError> {
		if packet_type == Self::ID {
			if packet.remaining() < 4 {
				return Err(WispError::PacketTooSmall);
			}
			if packet.get_u32_le() != 0 {
				return Err(WispError::InvalidStreamId);
			}

			let mut out = BytesMut::new();
			out.put_u8(Self::ID);
			out.put_u32_le(0);

			let locked = WISPNET_SERVERS.lock().await;
			for client in locked.iter() {
				if !client.1.private {
					out.put_u32_le(*client.0);
				}
			}
			drop(locked);

			write
				.wisp_write_frame(Frame::binary(Payload::Bytes(out)))
				.await?;
		}
		Ok(())
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(*self)
	}
}

pub async fn route_wispnet(server: u32, packet: ConnectPacket) -> Result<ClientStream> {
	if let Some(server) = WISPNET_SERVERS.lock().await.get(&server) {
		let stream = server
			.mux
			.client_new_stream(
				packet.stream_type,
				packet.destination_hostname,
				packet.destination_port,
			)
			.await
			.context("failed to connect to wispnet server")?;
		Ok(ClientStream::Wispnet(stream, server.id.clone()))
	} else {
		Ok(ClientStream::NoResolvedAddrs)
	}
}

async fn copy_wisp(
	rx: MuxStreamRead<WispStreamWrite>,
	tx: MuxStreamWrite<WispStreamWrite>,
	#[cfg(feature = "speed-limit")] limiter: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
) -> Result<()> {
	while let Some(data) = rx.read().await? {
		#[cfg(feature = "speed-limit")]
		limiter.consume(data.len()).await;
		tx.write_payload(Payload::Borrowed(data.as_ref())).await?;
	}
	Ok(())
}

pub async fn handle_stream(
	mux: MuxStream<WispStreamWrite>,
	wisp: MuxStream<WispStreamWrite>,
	mux_id: String,
	uuid: Uuid,
	resolved_stream: ConnectPacket,
	#[cfg(feature = "speed-limit")] read_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
	#[cfg(feature = "speed-limit")] write_limit: async_speed_limit::Limiter<
		async_speed_limit::clock::StandardClock,
	>,
) {
	if let Some(client) = CLIENTS.lock().await.get(&mux_id) {
		client
			.0
			.lock()
			.await
			.insert(uuid, (resolved_stream.clone(), resolved_stream));
	}

	let closer = mux.get_close_handle();

	let (muxread, muxwrite) = mux.into_split();
	let (wispread, wispwrite) = wisp.into_split();
	let _ = select! {
		x = copy_wisp(muxread, wispwrite, #[cfg(feature = "speed-limit")] write_limit) => x,
		x = copy_wisp(wispread, muxwrite, #[cfg(feature = "speed-limit")] read_limit) => x,
	};

	let _ = closer
		.close(closer.get_close_reason().unwrap_or(CloseReason::Unknown))
		.await;

	if let Some(client) = CLIENTS.lock().await.get(&mux_id) {
		client.0.lock().await.remove(&uuid);
	}
}

pub async fn handle_wispnet(stream: WispResult, id: String) -> Result<()> {
	let (read, write) = stream;
	let net_id = WISPNET_IDS.fetch_add(1, Ordering::SeqCst);

	let extensions = vec![WispnetServerProtocolExtensionBuilder(net_id).into()];

	let (mux, fut) = Box::pin(
		ClientMux::create(read, write, Some(WispV2Handshake::new(extensions)))
			.await
			.context("failed to create client multiplexor")?
			.with_required_extensions(&[WispnetServerProtocolExtension::ID]),
	)
	.await
	.context("wispnet client did not have wispnet extension")?;

	let is_private = mux
		.supported_extensions
		.find_extension::<WispnetServerProtocolExtension>()
		.context("failed to find wispnet extension")?
		.1;

	WISPNET_SERVERS.lock().await.insert(
		net_id,
		WispnetClient {
			mux,
			id: id.clone(),
			private: is_private,
		},
	);

	// probably the only time someone would do this
	let ret = fut.await;
	debug!("wispnet client id {:?} multiplexor result {:?}", id, ret);

	WISPNET_SERVERS.lock().await.remove(&net_id);

	Ok(())
}
