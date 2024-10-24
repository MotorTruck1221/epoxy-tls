use std::{
	future::Future,
	ops::DerefMut,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
};

use flume as mpsc;
use futures::channel::oneshot;

use crate::{
	extensions::AnyProtocolExtension,
	inner::{MuxInner, WsEvent},
	ws::{AppendingWebSocketRead, LockedWebSocketWrite, Payload, WebSocketRead, WebSocketWrite},
	CloseReason, ConnectPacket, MuxProtocolExtensionStream, MuxStream, Packet, Role, WispError,
};

use super::{maybe_wisp_v2, send_info_packet, Multiplexor, MuxResult, WispV2Extensions};

/// Server-side multiplexor.
pub struct ServerMux {
	/// Whether the connection was downgraded to Wisp v1.
	///
	/// If this variable is true you must assume no extensions are supported.
	pub downgraded: bool,
	/// Extensions that are supported by both sides.
	pub supported_extensions: Vec<AnyProtocolExtension>,
	actor_tx: mpsc::Sender<WsEvent>,
	muxstream_recv: mpsc::Receiver<(ConnectPacket, MuxStream)>,
	tx: LockedWebSocketWrite,
	actor_exited: Arc<AtomicBool>,
}

impl ServerMux {
	/// Create a new server-side multiplexor.
	///
	/// If `wisp_v2` is None a Wisp v1 connection is created otherwise a Wisp v2 connection is created.
	/// **It is not guaranteed that all extensions you specify are available.** You must manually check
	/// if the extensions you need are available after the multiplexor has been created.
	pub async fn create<R, W>(
		mut rx: R,
		tx: W,
		buffer_size: u32,
		wisp_v2: Option<WispV2Extensions>,
	) -> Result<MuxResult<ServerMux, impl Future<Output = Result<(), WispError>> + Send>, WispError>
	where
		R: WebSocketRead + Send,
		W: WebSocketWrite + Send + 'static,
	{
		let tx = LockedWebSocketWrite::new(Box::new(tx));
		let ret_tx = tx.clone();
		let ret = async {
			tx.write_frame(Packet::new_continue(0, buffer_size).into())
				.await?;

			let (supported_extensions, extra_packet, downgraded) = if let Some(WispV2Extensions {
				mut builders,
				closure,
			}) = wisp_v2
			{
				send_info_packet(&tx, builders.deref_mut()).await?;
				(closure)(builders.deref_mut()).await?;
				maybe_wisp_v2(&mut rx, &tx, Role::Server, &mut builders).await?
			} else {
				(Vec::new(), None, true)
			};

			let (mux_result, muxstream_recv) = MuxInner::new_server(
				AppendingWebSocketRead(extra_packet, rx),
				tx.clone(),
				supported_extensions.clone(),
				buffer_size,
			);

			Ok(MuxResult(
				Self {
					muxstream_recv,
					actor_tx: mux_result.actor_tx,
					downgraded,
					supported_extensions,
					tx,
					actor_exited: mux_result.actor_exited,
				},
				mux_result.mux.into_future(),
			))
		}
		.await;

		match ret {
			Ok(x) => Ok(x),
			Err(x) => match x {
				WispError::PasswordExtensionCredsInvalid => {
					ret_tx
						.write_frame(
							Packet::new_close(0, CloseReason::ExtensionsPasswordAuthFailed).into(),
						)
						.await?;
					ret_tx.close().await?;
					Err(x)
				}
				WispError::CertAuthExtensionSigInvalid => {
					ret_tx
						.write_frame(
							Packet::new_close(0, CloseReason::ExtensionsCertAuthFailed).into(),
						)
						.await?;
					ret_tx.close().await?;
					Err(x)
				}
				x => Err(x),
			},
		}
	}

	/// Wait for a stream to be created.
	pub async fn server_new_stream(&self) -> Option<(ConnectPacket, MuxStream)> {
		if self.actor_exited.load(Ordering::Acquire) {
			return None;
		}
		self.muxstream_recv.recv_async().await.ok()
	}

	/// Send a ping to the client.
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

impl Drop for ServerMux {
	fn drop(&mut self) {
		let _ = self.actor_tx.send(WsEvent::EndFut(None));
	}
}

impl Multiplexor for ServerMux {
	fn has_extension(&self, extension_id: u8) -> bool {
		self.supported_extensions
			.iter()
			.any(|x| x.get_id() == extension_id)
	}
	async fn exit(&self, reason: CloseReason) -> Result<(), WispError> {
		self.close_with_reason(reason).await
	}
}
