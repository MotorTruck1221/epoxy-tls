mod compat;
mod sink_unfold;
pub use compat::*;

use crate::{
	inner::WsEvent,
	ws::{Frame, LockedWebSocketWrite, Payload, WebSocketWrite},
	AtomicCloseReason, CloseReason, Packet, Role, StreamType, WispError,
};

use bytes::{BufMut, Bytes, BytesMut};
use event_listener::Event;
use flume as mpsc;
use futures::{channel::oneshot, select, stream, FutureExt, Sink, Stream};
use std::{
	pin::Pin,
	sync::{
		atomic::{AtomicBool, AtomicU32, Ordering},
		Arc,
	},
};

/// Read side of a multiplexor stream.
pub struct MuxStreamRead<W: WebSocketWrite + 'static> {
	/// ID of the stream.
	pub stream_id: u32,
	/// Type of the stream.
	pub stream_type: StreamType,

	role: Role,

	tx: LockedWebSocketWrite<W>,
	rx: mpsc::Receiver<Bytes>,

	is_closed: Arc<AtomicBool>,
	is_closed_event: Arc<Event>,
	close_reason: Arc<AtomicCloseReason>,

	should_flow_control: bool,
	flow_control: Arc<AtomicU32>,
	flow_control_read: AtomicU32,
	target_flow_control: u32,
}

impl<W: WebSocketWrite + 'static> MuxStreamRead<W> {
	/// Read an event from the stream.
	pub async fn read(&self) -> Result<Option<Bytes>, WispError> {
		if self.rx.is_empty() && self.is_closed.load(Ordering::Acquire) {
			return Ok(None);
		}
		let bytes = select! {
			x = self.rx.recv_async() => x.map_err(|_| WispError::MuxMessageFailedToRecv)?,
			_ = self.is_closed_event.listen().fuse() => return Ok(None)
		};
		if self.role == Role::Server && self.should_flow_control {
			let val = self.flow_control_read.fetch_add(1, Ordering::AcqRel) + 1;
			if val > self.target_flow_control && !self.is_closed.load(Ordering::Acquire) {
				self.tx
					.write_frame(
						Packet::new_continue(
							self.stream_id,
							self.flow_control.fetch_add(val, Ordering::AcqRel) + val,
						)
						.into(),
					)
					.await?;
				self.flow_control_read.store(0, Ordering::Release);
			}
		}
		Ok(Some(bytes))
	}

	pub(crate) fn into_inner_stream(
		self,
	) -> Pin<Box<dyn Stream<Item = Result<Bytes, WispError>> + Send>> {
		Box::pin(stream::unfold(self, |rx| async move {
			Some((rx.read().await.transpose()?, rx))
		}))
	}

	/// Turn the read half into one that implements futures `Stream`, consuming it.
	pub fn into_stream(self) -> MuxStreamIoStream {
		MuxStreamIoStream {
			close_reason: self.close_reason.clone(),
			is_closed: self.is_closed.clone(),
			rx: self.into_inner_stream(),
		}
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		if self.is_closed.load(Ordering::Acquire) {
			Some(self.close_reason.load(Ordering::Acquire))
		} else {
			None
		}
	}
}

/// Write side of a multiplexor stream.
pub struct MuxStreamWrite<W: WebSocketWrite + 'static> {
	/// ID of the stream.
	pub stream_id: u32,
	/// Type of the stream.
	pub stream_type: StreamType,

	role: Role,
	mux_tx: mpsc::Sender<WsEvent<W>>,
	tx: LockedWebSocketWrite<W>,

	is_closed: Arc<AtomicBool>,
	close_reason: Arc<AtomicCloseReason>,

	continue_recieved: Arc<Event>,
	should_flow_control: bool,
	flow_control: Arc<AtomicU32>,
}

impl<W: WebSocketWrite + 'static> MuxStreamWrite<W> {
	pub(crate) async fn write_payload_internal<'a>(
		&self,
		header: Frame<'static>,
		body: Frame<'a>,
	) -> Result<(), WispError> {
		if self.role == Role::Client
			&& self.should_flow_control
			&& self.flow_control.load(Ordering::Acquire) == 0
		{
			self.continue_recieved.listen().await;
		}
		if self.is_closed.load(Ordering::Acquire) {
			return Err(WispError::StreamAlreadyClosed);
		}

		self.tx.write_split(header, body).await?;

		if self.role == Role::Client && self.stream_type == StreamType::Tcp {
			self.flow_control.store(
				self.flow_control.load(Ordering::Acquire).saturating_sub(1),
				Ordering::Release,
			);
		}
		Ok(())
	}

	/// Write a payload to the stream.
	pub async fn write_payload(&self, data: Payload<'_>) -> Result<(), WispError> {
		let frame: Frame<'static> = Frame::from(Packet::new_data(
			self.stream_id,
			Payload::Bytes(BytesMut::new()),
		));
		self.write_payload_internal(frame, Frame::binary(data))
			.await
	}

	/// Write data to the stream.
	pub async fn write<D: AsRef<[u8]>>(&self, data: D) -> Result<(), WispError> {
		self.write_payload(Payload::Borrowed(data.as_ref())).await
	}

	/// Get a handle to close the connection.
	///
	/// Useful to close the connection without having access to the stream.
	///
	/// # Example
	/// ```
	/// let handle = stream.get_close_handle();
	/// if let Err(error) = handle_stream(stream) {
	///     handle.close(0x01);
	/// }
	/// ```
	pub fn get_close_handle(&self) -> MuxStreamCloser<W> {
		MuxStreamCloser {
			stream_id: self.stream_id,
			close_channel: self.mux_tx.clone(),
			is_closed: self.is_closed.clone(),
			close_reason: self.close_reason.clone(),
		}
	}

	/// Get a protocol extension stream to send protocol extension packets.
	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream<W> {
		MuxProtocolExtensionStream {
			stream_id: self.stream_id,
			tx: self.tx.clone(),
			is_closed: self.is_closed.clone(),
		}
	}

	/// Close the stream. You will no longer be able to write or read after this has been called.
	pub async fn close(&self, reason: CloseReason) -> Result<(), WispError> {
		if self.is_closed.load(Ordering::Acquire) {
			return Err(WispError::StreamAlreadyClosed);
		}
		self.is_closed.store(true, Ordering::Release);

		let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
		self.mux_tx
			.send_async(WsEvent::Close(
				Packet::new_close(self.stream_id, reason),
				tx,
			))
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)?;
		rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)??;

		Ok(())
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		if self.is_closed.load(Ordering::Acquire) {
			Some(self.close_reason.load(Ordering::Acquire))
		} else {
			None
		}
	}

	pub(crate) fn into_inner_sink(
		self,
	) -> Pin<Box<dyn Sink<Payload<'static>, Error = WispError> + Send>> {
		let handle = self.get_close_handle();
		Box::pin(sink_unfold::unfold(
			self,
			|tx, data| async move {
				tx.write_payload(data).await?;
				Ok(tx)
			},
			handle,
			|handle| async move {
				handle.close(CloseReason::Unknown).await?;
				Ok(handle)
			},
		))
	}

	/// Turn the write half into one that implements futures `Sink`, consuming it.
	pub fn into_sink(self) -> MuxStreamIoSink {
		MuxStreamIoSink {
			close_reason: self.close_reason.clone(),
			is_closed: self.is_closed.clone(),
			tx: self.into_inner_sink(),
		}
	}
}

impl<W: WebSocketWrite + 'static> Drop for MuxStreamWrite<W> {
	fn drop(&mut self) {
		if !self.is_closed.load(Ordering::Acquire) {
			self.is_closed.store(true, Ordering::Release);
			let (tx, _) = oneshot::channel();
			let _ = self.mux_tx.send(WsEvent::Close(
				Packet::new_close(self.stream_id, CloseReason::Unknown),
				tx,
			));
		}
	}
}

/// Multiplexor stream.
pub struct MuxStream<W: WebSocketWrite + 'static> {
	/// ID of the stream.
	pub stream_id: u32,
	rx: MuxStreamRead<W>,
	tx: MuxStreamWrite<W>,
}

impl<W: WebSocketWrite + 'static> MuxStream<W> {
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new(
		stream_id: u32,
		role: Role,
		stream_type: StreamType,
		rx: mpsc::Receiver<Bytes>,
		mux_tx: mpsc::Sender<WsEvent<W>>,
		tx: LockedWebSocketWrite<W>,
		is_closed: Arc<AtomicBool>,
		is_closed_event: Arc<Event>,
		close_reason: Arc<AtomicCloseReason>,
		should_flow_control: bool,
		flow_control: Arc<AtomicU32>,
		continue_recieved: Arc<Event>,
		target_flow_control: u32,
	) -> Self {
		Self {
			stream_id,
			rx: MuxStreamRead {
				stream_id,
				stream_type,
				role,
				tx: tx.clone(),
				rx,
				is_closed: is_closed.clone(),
				is_closed_event: is_closed_event.clone(),
				close_reason: close_reason.clone(),
				should_flow_control,
				flow_control: flow_control.clone(),
				flow_control_read: AtomicU32::new(0),
				target_flow_control,
			},
			tx: MuxStreamWrite {
				stream_id,
				stream_type,
				role,
				mux_tx,
				tx,
				is_closed: is_closed.clone(),
				close_reason: close_reason.clone(),
				should_flow_control,
				flow_control: flow_control.clone(),
				continue_recieved: continue_recieved.clone(),
			},
		}
	}

	/// Read an event from the stream.
	pub async fn read(&self) -> Result<Option<Bytes>, WispError> {
		self.rx.read().await
	}

	/// Write a payload to the stream.
	pub async fn write_payload(&self, data: Payload<'_>) -> Result<(), WispError> {
		self.tx.write_payload(data).await
	}

	/// Write data to the stream.
	pub async fn write<D: AsRef<[u8]>>(&self, data: D) -> Result<(), WispError> {
		self.tx.write(data).await
	}

	/// Get a handle to close the connection.
	///
	/// Useful to close the connection without having access to the stream.
	///
	/// # Example
	/// ```
	/// let handle = stream.get_close_handle();
	/// if let Err(error) = handle_stream(stream) {
	///     handle.close(0x01);
	/// }
	/// ```
	pub fn get_close_handle(&self) -> MuxStreamCloser<W> {
		self.tx.get_close_handle()
	}

	/// Get a protocol extension stream to send protocol extension packets.
	pub fn get_protocol_extension_stream(&self) -> MuxProtocolExtensionStream<W> {
		self.tx.get_protocol_extension_stream()
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.rx.get_close_reason()
	}

	/// Close the stream. You will no longer be able to write or read after this has been called.
	pub async fn close(&self, reason: CloseReason) -> Result<(), WispError> {
		self.tx.close(reason).await
	}

	/// Split the stream into read and write parts, consuming it.
	pub fn into_split(self) -> (MuxStreamRead<W>, MuxStreamWrite<W>) {
		(self.rx, self.tx)
	}

	/// Turn the stream into one that implements futures `Stream + Sink`, consuming it.
	pub fn into_io(self) -> MuxStreamIo {
		MuxStreamIo {
			rx: self.rx.into_stream(),
			tx: self.tx.into_sink(),
		}
	}
}

/// Close handle for a multiplexor stream.
#[derive(Clone)]
pub struct MuxStreamCloser<W: WebSocketWrite + 'static> {
	/// ID of the stream.
	pub stream_id: u32,
	close_channel: mpsc::Sender<WsEvent<W>>,
	is_closed: Arc<AtomicBool>,
	close_reason: Arc<AtomicCloseReason>,
}

impl<W: WebSocketWrite + 'static> MuxStreamCloser<W> {
	/// Close the stream. You will no longer be able to write or read after this has been called.
	pub async fn close(&self, reason: CloseReason) -> Result<(), WispError> {
		if self.is_closed.load(Ordering::Acquire) {
			return Err(WispError::StreamAlreadyClosed);
		}
		self.is_closed.store(true, Ordering::Release);

		let (tx, rx) = oneshot::channel::<Result<(), WispError>>();
		self.close_channel
			.send_async(WsEvent::Close(
				Packet::new_close(self.stream_id, reason),
				tx,
			))
			.await
			.map_err(|_| WispError::MuxMessageFailedToSend)?;
		rx.await.map_err(|_| WispError::MuxMessageFailedToRecv)??;

		Ok(())
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		if self.is_closed.load(Ordering::Acquire) {
			Some(self.close_reason.load(Ordering::Acquire))
		} else {
			None
		}
	}
}

/// Stream for sending arbitrary protocol extension packets.
pub struct MuxProtocolExtensionStream<W: WebSocketWrite + 'static> {
	/// ID of the stream.
	pub stream_id: u32,
	pub(crate) tx: LockedWebSocketWrite<W>,
	pub(crate) is_closed: Arc<AtomicBool>,
}

impl<W: WebSocketWrite + 'static> MuxProtocolExtensionStream<W> {
	/// Send a protocol extension packet with this stream's ID.
	pub async fn send(&self, packet_type: u8, data: Bytes) -> Result<(), WispError> {
		if self.is_closed.load(Ordering::Acquire) {
			return Err(WispError::StreamAlreadyClosed);
		}
		let mut encoded = BytesMut::with_capacity(1 + 4 + data.len());
		encoded.put_u8(packet_type);
		encoded.put_u32_le(self.stream_id);
		encoded.extend(data);
		self.tx
			.write_frame(Frame::binary(Payload::Bytes(encoded)))
			.await
	}
}
