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
	ws::{AppendingWebSocketRead, LockedWebSocketWrite, WebSocketRead, WebSocketWrite, Payload},
	CloseReason, MuxProtocolExtensionStream, MuxStream, Packet, PacketType, Role, StreamType,
	WispError,
};

use super::{maybe_wisp_v2, send_info_packet, WispV2Extensions};

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
	) -> Result<ClientMuxResult<impl Future<Output = Result<(), WispError>> + Send>, WispError>
	where
		R: WebSocketRead + Send,
		W: WebSocketWrite + Send + 'static,
	{
		let tx = LockedWebSocketWrite::new(Box::new(tx));
		let first_packet = Packet::try_from(rx.wisp_read_frame(&tx).await?)?;

		if first_packet.stream_id != 0 {
			return Err(WispError::InvalidStreamId);
		}

		if let PacketType::Continue(packet) = first_packet.packet_type {
			let (supported_extensions, extra_packet, downgraded) = if let Some(WispV2Extensions {
				mut builders,
				closure,
			}) = wisp_v2
			{
				let res = maybe_wisp_v2(&mut rx, &tx, Role::Client, &mut builders).await?;
				// if not downgraded
				if !res.2 {
					(closure)(&mut builders).await?;
					send_info_packet(&tx, &mut builders).await?;
				}
				res
			} else {
				(Vec::new(), None, true)
			};

			let mux_result = MuxInner::new_client(
				AppendingWebSocketRead(extra_packet, rx),
				tx.clone(),
				supported_extensions.clone(),
				packet.buffer_remaining,
			);

			Ok(ClientMuxResult(
				Self {
					actor_tx: mux_result.actor_tx,
					downgraded,
					supported_extensions,
					tx,
					actor_exited: mux_result.actor_exited,
				},
				mux_result.mux.into_future(),
			))
		} else {
			Err(WispError::InvalidPacketType)
		}
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

/// Result of `ClientMux::new`.
pub struct ClientMuxResult<F>(ClientMux, F)
where
	F: Future<Output = Result<(), WispError>> + Send;

impl<F> ClientMuxResult<F>
where
	F: Future<Output = Result<(), WispError>> + Send,
{
	/// Require no protocol extensions.
	pub fn with_no_required_extensions(self) -> (ClientMux, F) {
		(self.0, self.1)
	}

	/// Require protocol extensions by their ID.
	pub async fn with_required_extensions(
		self,
		extensions: &[u8],
	) -> Result<(ClientMux, F), WispError> {
		let mut unsupported_extensions = Vec::new();
		for extension in extensions {
			if !self
				.0
				.supported_extensions
				.iter()
				.any(|x| x.get_id() == *extension)
			{
				unsupported_extensions.push(*extension);
			}
		}
		if unsupported_extensions.is_empty() {
			Ok((self.0, self.1))
		} else {
			self.0
				.close_with_reason(CloseReason::ExtensionsIncompatible)
				.await?;
			self.1.await?;
			Err(WispError::ExtensionsNotSupported(unsupported_extensions))
		}
	}

	/// Shorthand for `with_required_extensions(&[UdpProtocolExtension::ID])`
	pub async fn with_udp_extension_required(self) -> Result<(ClientMux, F), WispError> {
		self.with_required_extensions(&[UdpProtocolExtension::ID])
			.await
	}
}
