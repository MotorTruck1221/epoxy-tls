use std::{
	future::Future,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
};

use flume as mpsc;
use futures::channel::oneshot;

use crate::{
	extensions::{udp::UdpProtocolExtension, AnyProtocolExtension},
	inner::{MuxInner, WsEvent},
	mux::send_info_packet,
	ws::{AppendingWebSocketRead, LockedWebSocketWrite, Payload, WebSocketRead, WebSocketWrite},
	CloseReason, MuxProtocolExtensionStream, MuxStream, Packet, PacketType, Role, StreamType,
	WispError,
};

use super::{
	get_supported_extensions, validate_continue_packet, Multiplexor, MuxResult,
	WispHandshakeResult, WispHandshakeResultKind, WispV2Extensions,
};

async fn handshake<R: WebSocketRead>(
	rx: &mut R,
	tx: &LockedWebSocketWrite,
	v2_info: Option<WispV2Extensions>,
) -> Result<(WispHandshakeResult, u32), WispError> {
	if let Some(WispV2Extensions {
		mut builders,
		closure,
	}) = v2_info
	{
		let packet =
			Packet::maybe_parse_info(rx.wisp_read_frame(tx).await?, Role::Client, &mut builders)?;

		if let PacketType::Info(info) = packet.packet_type {
			// v2 server
			let buffer_size = validate_continue_packet(rx.wisp_read_frame(tx).await?.try_into()?)?;

			(closure)(&mut builders).await?;
			send_info_packet(tx, &mut builders).await?;

			Ok((
				WispHandshakeResult {
					kind: WispHandshakeResultKind::V2 {
						extensions: get_supported_extensions(info.extensions, &mut builders),
					},
					downgraded: false,
				},
				buffer_size,
			))
		} else {
			// downgrade to v1
			let buffer_size = validate_continue_packet(packet)?;

			Ok((
				WispHandshakeResult {
					kind: WispHandshakeResultKind::V1 { frame: None },
					downgraded: true,
				},
				buffer_size,
			))
		}
	} else {
		// user asked for a v1 client
		let buffer_size = validate_continue_packet(rx.wisp_read_frame(tx).await?.try_into()?)?;

		Ok((
			WispHandshakeResult {
				kind: WispHandshakeResultKind::V1 { frame: None },
				downgraded: false,
			},
			buffer_size,
		))
	}
}

/// Client side multiplexor.
pub struct ClientMux {
	/// Whether the connection was downgraded to Wisp v1.
	///
	/// If this variable is true you must assume no extensions are supported.
	pub downgraded: bool,
	/// Extensions that are supported by both sides.
	pub supported_extensions: Vec<AnyProtocolExtension>,
	actor_tx: mpsc::Sender<WsEvent>,
	tx: LockedWebSocketWrite,
	actor_exited: Arc<AtomicBool>,
}

impl ClientMux {
	/// Create a new client side multiplexor.
	///
	/// If `wisp_v2` is None a Wisp v1 connection is created otherwise a Wisp v2 connection is created.
	/// **It is not guaranteed that all extensions you specify are available.** You must manually check
	/// if the extensions you need are available after the multiplexor has been created.
	pub async fn create<R, W>(
		mut rx: R,
		tx: W,
		wisp_v2: Option<WispV2Extensions>,
	) -> Result<MuxResult<ClientMux, impl Future<Output = Result<(), WispError>> + Send>, WispError>
	where
		R: WebSocketRead + Send,
		W: WebSocketWrite + Send + 'static,
	{
		let tx = LockedWebSocketWrite::new(Box::new(tx));

		let (handshake_result, buffer_size) = handshake(&mut rx, &tx, wisp_v2).await?;
		let (extensions, frame) = handshake_result.kind.into_parts();

		let mux_inner = MuxInner::new_client(
			AppendingWebSocketRead(frame, rx),
			tx.clone(),
			extensions.clone(),
			buffer_size,
		);

		Ok(MuxResult(
			Self {
				actor_tx: mux_inner.actor_tx,
				actor_exited: mux_inner.actor_exited,

				tx,

				downgraded: handshake_result.downgraded,
				supported_extensions: extensions,
			},
			mux_inner.mux.into_future(),
		))
	}

	/// Create a new stream, multiplexed through Wisp.
	pub async fn client_new_stream(
		&self,
		stream_type: StreamType,
		host: String,
		port: u16,
	) -> Result<MuxStream, WispError> {
		if self.actor_exited.load(Ordering::Acquire) {
			return Err(WispError::MuxTaskEnded);
		}
		if stream_type == StreamType::Udp
			&& !self
				.supported_extensions
				.iter()
				.any(|x| x.get_id() == UdpProtocolExtension::ID)
		{
			return Err(WispError::ExtensionsNotSupported(vec![
				UdpProtocolExtension::ID,
			]));
		}
		let (tx, rx) = oneshot::channel();
		self.actor_tx
			.send_async(WsEvent::CreateStream(stream_type, host, port, tx))
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)?;
		rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)?
	}

	/// Send a ping to the server.
	pub async fn send_ping(&self, payload: Payload<'static>) -> Result<(), WispError> {
		if self.actor_exited.load(Ordering::Acquire) {
			return Err(WispError::MuxTaskEnded);
		}
		let (tx, rx) = oneshot::channel();
		self.actor_tx
			.send_async(WsEvent::SendPing(payload, tx))
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)?;
		rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)?
	}

	async fn close_internal(&self, reason: Option<CloseReason>) -> Result<(), WispError> {
		if self.actor_exited.load(Ordering::Acquire) {
			return Err(WispError::MuxTaskEnded);
		}
		self.actor_tx
			.send_async(WsEvent::EndFut(reason))
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)
	}

	/// Close all streams.
	///
	/// Also terminates the multiplexor future.
	pub async fn close(&self) -> Result<(), WispError> {
		self.close_internal(None).await
	}

	/// Close all streams and send a close reason on stream ID 0.
	///
	/// Also terminates the multiplexor future.
	pub async fn close_with_reason(&self, reason: CloseReason) -> Result<(), WispError> {
		self.close_internal(Some(reason)).await
	}

	/// Get a protocol extension stream for sending packets with stream id 0.
	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream {
		MuxProtocolExtensionStream {
			stream_id: 0,
			tx: self.tx.clone(),
			is_closed: self.actor_exited.clone(),
		}
	}
}

impl Drop for ClientMux {
	fn drop(&mut self) {
		let _ = self.actor_tx.send(WsEvent::EndFut(None));
	}
}

impl Multiplexor for ClientMux {
	fn has_extension(&self, extension_id: u8) -> bool {
		self.supported_extensions
			.iter()
			.any(|x| x.get_id() == extension_id)
	}
	async fn exit(&self, reason: CloseReason) -> Result<(), WispError> {
		self.close_with_reason(reason).await
	}
}
