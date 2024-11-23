use std::sync::{
	atomic::{AtomicBool, AtomicU32, Ordering},
	Arc,
};

use crate::{
	extensions::AnyProtocolExtension,
	ws::{Frame, LockedWebSocketWrite, OpCode, Payload, WebSocketRead, WebSocketWrite},
	AtomicCloseReason, ClosePacket, CloseReason, ConnectPacket, MuxStream, Packet, PacketType,
	Role, StreamType, WispError,
};
use bytes::{Bytes, BytesMut};
use event_listener::Event;
use flume as mpsc;
use futures::{channel::oneshot, select, stream::unfold, FutureExt, StreamExt};
use nohash_hasher::IntMap;

pub(crate) enum WsEvent<W: WebSocketWrite + 'static> {
	Close(Packet<'static>, oneshot::Sender<Result<(), WispError>>),
	CreateStream(
		StreamType,
		String,
		u16,
		oneshot::Sender<Result<MuxStream<W>, WispError>>,
	),
	SendPing(Payload<'static>, oneshot::Sender<Result<(), WispError>>),
	SendPong(Payload<'static>),
	WispMessage(Option<Packet<'static>>, Option<Frame<'static>>),
	EndFut(Option<CloseReason>),
	Noop,
}

struct MuxMapValue {
	stream: mpsc::Sender<Bytes>,
	stream_type: StreamType,

	should_flow_control: bool,
	flow_control: Arc<AtomicU32>,
	flow_control_event: Arc<Event>,

	is_closed: Arc<AtomicBool>,
	close_reason: Arc<AtomicCloseReason>,
	is_closed_event: Arc<Event>,
}

pub struct MuxInner<R: WebSocketRead + 'static, W: WebSocketWrite + 'static> {
	// gets taken by the mux task
	rx: Option<R>,
	// gets taken by the mux task
	maybe_downgrade_packet: Option<Packet<'static>>,

	tx: LockedWebSocketWrite<W>,
	// gets taken by the mux task
	extensions: Option<Vec<AnyProtocolExtension>>,
	tcp_extensions: Vec<u8>,
	role: Role,

	// gets taken by the mux task
	actor_rx: Option<mpsc::Receiver<WsEvent<W>>>,
	actor_tx: mpsc::Sender<WsEvent<W>>,
	fut_exited: Arc<AtomicBool>,

	stream_map: IntMap<u32, MuxMapValue>,

	buffer_size: u32,
	target_buffer_size: u32,

	server_tx: mpsc::Sender<(ConnectPacket, MuxStream<W>)>,
}

pub struct MuxInnerResult<R: WebSocketRead + 'static, W: WebSocketWrite + 'static> {
	pub mux: MuxInner<R, W>,
	pub actor_exited: Arc<AtomicBool>,
	pub actor_tx: mpsc::Sender<WsEvent<W>>,
}

impl<R: WebSocketRead + 'static, W: WebSocketWrite + 'static> MuxInner<R, W> {
	fn get_tcp_extensions(extensions: &[AnyProtocolExtension]) -> Vec<u8> {
		extensions
			.iter()
			.flat_map(|x| x.get_congestion_stream_types())
			.copied()
			.chain(std::iter::once(StreamType::Tcp.into()))
			.collect()
	}

	#[allow(clippy::type_complexity)]
	pub fn new_server(
		rx: R,
		maybe_downgrade_packet: Option<Packet<'static>>,
		tx: LockedWebSocketWrite<W>,
		extensions: Vec<AnyProtocolExtension>,
		buffer_size: u32,
	) -> (
		MuxInnerResult<R, W>,
		mpsc::Receiver<(ConnectPacket, MuxStream<W>)>,
	) {
		let (fut_tx, fut_rx) = mpsc::bounded::<WsEvent<W>>(256);
		let (server_tx, server_rx) = mpsc::unbounded::<(ConnectPacket, MuxStream<W>)>();
		let ret_fut_tx = fut_tx.clone();
		let fut_exited = Arc::new(AtomicBool::new(false));

		(
			MuxInnerResult {
				mux: Self {
					rx: Some(rx),
					maybe_downgrade_packet,
					tx,

					actor_rx: Some(fut_rx),
					actor_tx: fut_tx,
					fut_exited: fut_exited.clone(),

					tcp_extensions: Self::get_tcp_extensions(&extensions),
					extensions: Some(extensions),
					buffer_size,
					target_buffer_size: ((buffer_size as u64 * 90) / 100) as u32,

					role: Role::Server,

					stream_map: IntMap::default(),

					server_tx,
				},
				actor_exited: fut_exited,
				actor_tx: ret_fut_tx,
			},
			server_rx,
		)
	}

	pub fn new_client(
		rx: R,
		maybe_downgrade_packet: Option<Packet<'static>>,
		tx: LockedWebSocketWrite<W>,
		extensions: Vec<AnyProtocolExtension>,
		buffer_size: u32,
	) -> MuxInnerResult<R, W> {
		let (fut_tx, fut_rx) = mpsc::bounded::<WsEvent<W>>(256);
		let (server_tx, _) = mpsc::unbounded::<(ConnectPacket, MuxStream<W>)>();
		let ret_fut_tx = fut_tx.clone();
		let fut_exited = Arc::new(AtomicBool::new(false));

		MuxInnerResult {
			mux: Self {
				rx: Some(rx),
				maybe_downgrade_packet,
				tx,

				actor_rx: Some(fut_rx),
				actor_tx: fut_tx,
				fut_exited: fut_exited.clone(),

				tcp_extensions: Self::get_tcp_extensions(&extensions),
				extensions: Some(extensions),
				buffer_size,
				target_buffer_size: 0,

				role: Role::Client,

				stream_map: IntMap::default(),

				server_tx,
			},
			actor_exited: fut_exited,
			actor_tx: ret_fut_tx,
		}
	}

	pub async fn into_future(mut self) -> Result<(), WispError> {
		let ret = self.stream_loop().await;

		self.fut_exited.store(true, Ordering::Release);

		for (_, stream) in self.stream_map.iter() {
			self.close_stream(stream, ClosePacket::new(CloseReason::Unknown));
		}
		self.stream_map.clear();

		let _ = self.tx.close().await;
		ret
	}

	async fn create_new_stream(
		&mut self,
		stream_id: u32,
		stream_type: StreamType,
	) -> Result<(MuxMapValue, MuxStream<W>), WispError> {
		let (ch_tx, ch_rx) = mpsc::bounded(if self.role == Role::Server {
			self.buffer_size as usize
		} else {
			usize::MAX
		});

		let should_flow_control = self.tcp_extensions.contains(&stream_type.into());
		let flow_control_event: Arc<Event> = Event::new().into();
		let flow_control: Arc<AtomicU32> = AtomicU32::new(self.buffer_size).into();

		let is_closed: Arc<AtomicBool> = AtomicBool::new(false).into();
		let close_reason: Arc<AtomicCloseReason> =
			AtomicCloseReason::new(CloseReason::Unknown).into();
		let is_closed_event: Arc<Event> = Event::new().into();

		Ok((
			MuxMapValue {
				stream: ch_tx,
				stream_type,

				should_flow_control,
				flow_control: flow_control.clone(),
				flow_control_event: flow_control_event.clone(),

				is_closed: is_closed.clone(),
				close_reason: close_reason.clone(),
				is_closed_event: is_closed_event.clone(),
			},
			MuxStream::new(
				stream_id,
				self.role,
				stream_type,
				ch_rx,
				self.actor_tx.clone(),
				self.tx.clone(),
				is_closed,
				is_closed_event,
				close_reason,
				should_flow_control,
				flow_control,
				flow_control_event,
				self.target_buffer_size,
			),
		))
	}

	fn close_stream(&self, stream: &MuxMapValue, close_packet: ClosePacket) {
		stream
			.close_reason
			.store(close_packet.reason, Ordering::Release);
		stream.is_closed.store(true, Ordering::Release);
		stream.is_closed_event.notify(usize::MAX);
		stream.flow_control.store(u32::MAX, Ordering::Release);
		stream.flow_control_event.notify(usize::MAX);
	}

	async fn process_wisp_message(
		rx: &mut R,
		tx: &LockedWebSocketWrite<W>,
		extensions: &mut [AnyProtocolExtension],
		msg: (Frame<'static>, Option<Frame<'static>>),
	) -> Result<Option<WsEvent<W>>, WispError> {
		let (mut frame, optional_frame) = msg;
		if frame.opcode == OpCode::Close {
			return Ok(None);
		} else if frame.opcode == OpCode::Ping {
			return Ok(Some(WsEvent::SendPong(frame.payload)));
		} else if frame.opcode == OpCode::Pong {
			return Ok(Some(WsEvent::Noop));
		}

		if let Some(ref extra_frame) = optional_frame {
			if frame.payload[0] != PacketType::Data(Payload::Bytes(BytesMut::new())).as_u8() {
				let mut payload = BytesMut::from(frame.payload);
				payload.extend_from_slice(&extra_frame.payload);
				frame.payload = Payload::Bytes(payload);
			}
		}

		let packet = Packet::maybe_handle_extension(frame, extensions, rx, tx).await?;

		Ok(Some(WsEvent::WispMessage(packet, optional_frame)))
	}

	async fn stream_loop(&mut self) -> Result<(), WispError> {
		let mut next_free_stream_id: u32 = 1;

		let rx = self.rx.take().ok_or(WispError::MuxTaskStarted)?;
		let maybe_downgrade_packet = self.maybe_downgrade_packet.take();

		let tx = self.tx.clone();
		let fut_rx = self.actor_rx.take().ok_or(WispError::MuxTaskStarted)?;

		let extensions = self.extensions.take().ok_or(WispError::MuxTaskStarted)?;

		if let Some(downgrade_packet) = maybe_downgrade_packet {
			if self.handle_packet(downgrade_packet, None).await? {
				return Ok(());
			}
		}

		let mut read_stream = Box::pin(unfold(
			(rx, tx.clone(), extensions),
			|(mut rx, tx, mut extensions)| async {
				let ret = async {
					let msg = rx.wisp_read_split(&tx).await?;
					Self::process_wisp_message(&mut rx, &tx, &mut extensions, msg).await
				}
				.await;
				ret.transpose().map(|x| (x, (rx, tx, extensions)))
			},
		))
		.fuse();

		let mut recv_fut = fut_rx.recv_async().fuse();
		while let Some(msg) = select! {
			x = recv_fut => {
				drop(recv_fut);
				recv_fut = fut_rx.recv_async().fuse();
				Ok(x.ok())
			},
			x = read_stream.next() => {
				x.transpose()
			}
		}? {
			match msg {
				WsEvent::CreateStream(stream_type, host, port, channel) => {
					let ret: Result<MuxStream<W>, WispError> = async {
						let stream_id = next_free_stream_id;
						let next_stream_id = next_free_stream_id
							.checked_add(1)
							.ok_or(WispError::MaxStreamCountReached)?;

						let (map_value, stream) =
							self.create_new_stream(stream_id, stream_type).await?;

						self.tx
							.write_frame(
								Packet::new_connect(stream_id, stream_type, port, host).into(),
							)
							.await?;

						self.stream_map.insert(stream_id, map_value);

						next_free_stream_id = next_stream_id;

						Ok(stream)
					}
					.await;
					let _ = channel.send(ret);
				}
				WsEvent::Close(packet, channel) => {
					if let Some(stream) = self.stream_map.remove(&packet.stream_id) {
						if let PacketType::Close(close) = packet.packet_type {
							self.close_stream(&stream, close);
						}
						let _ = channel.send(self.tx.write_frame(packet.into()).await);
					} else {
						let _ = channel.send(Err(WispError::InvalidStreamId));
					}
				}
				WsEvent::SendPing(payload, channel) => {
					let _ = channel.send(
						self.tx
							.write_frame(Frame::new(OpCode::Ping, payload, true))
							.await,
					);
				}
				WsEvent::SendPong(payload) => {
					self.tx
						.write_frame(Frame::new(OpCode::Pong, payload, true))
						.await?;
				}
				WsEvent::EndFut(x) => {
					if let Some(reason) = x {
						let _ = self
							.tx
							.write_frame(Packet::new_close(0, reason).into())
							.await;
					}
					break;
				}
				WsEvent::WispMessage(packet, optional_frame) => {
					if let Some(packet) = packet {
						let should_break = self.handle_packet(packet, optional_frame).await?;
						if should_break {
							break;
						}
					}
				}
				WsEvent::Noop => {}
			}
		}

		Ok(())
	}

	fn handle_close_packet(
		&mut self,
		stream_id: u32,
		inner_packet: ClosePacket,
	) -> Result<bool, WispError> {
		if stream_id == 0 {
			return Ok(true);
		}

		if let Some(stream) = self.stream_map.remove(&stream_id) {
			self.close_stream(&stream, inner_packet);
		}

		Ok(false)
	}

	fn handle_data_packet(
		&mut self,
		stream_id: u32,
		optional_frame: Option<Frame<'static>>,
		data: Payload<'static>,
	) -> Result<bool, WispError> {
		let mut data = BytesMut::from(data);

		if let Some(stream) = self.stream_map.get(&stream_id) {
			if let Some(extra_frame) = optional_frame {
				if data.is_empty() {
					data = extra_frame.payload.into();
				} else {
					data.extend_from_slice(&extra_frame.payload);
				}
			}
			let _ = stream.stream.try_send(data.freeze());
			if self.role == Role::Server && stream.should_flow_control {
				stream.flow_control.store(
					stream
						.flow_control
						.load(Ordering::Acquire)
						.saturating_sub(1),
					Ordering::Release,
				);
			}
		}

		Ok(false)
	}

	async fn handle_packet(
		&mut self,
		packet: Packet<'static>,
		optional_frame: Option<Frame<'static>>,
	) -> Result<bool, WispError> {
		use PacketType as P;
		match packet.packet_type {
			P::Data(data) => self.handle_data_packet(packet.stream_id, optional_frame, data),
			P::Close(inner_packet) => self.handle_close_packet(packet.stream_id, inner_packet),

			_ => match self.role {
				Role::Server => self.server_handle_packet(packet, optional_frame).await,
				Role::Client => self.client_handle_packet(packet, optional_frame).await,
			},
		}
	}

	async fn server_handle_packet(
		&mut self,
		packet: Packet<'static>,
		_optional_frame: Option<Frame<'static>>,
	) -> Result<bool, WispError> {
		use PacketType as P;
		match packet.packet_type {
			P::Connect(inner_packet) => {
				let (map_value, stream) = self
					.create_new_stream(packet.stream_id, inner_packet.stream_type)
					.await?;
				self.server_tx
					.send_async((inner_packet, stream))
					.await
					.map_err(|_| WispError::MuxMessageFailedToSend)?;
				self.stream_map.insert(packet.stream_id, map_value);
				Ok(false)
			}

			// Continue | Info => invalid packet type
			// Data | Close => specialcased
			_ => Err(WispError::InvalidPacketType),
		}
	}

	async fn client_handle_packet(
		&mut self,
		packet: Packet<'static>,
		_optional_frame: Option<Frame<'static>>,
	) -> Result<bool, WispError> {
		use PacketType as P;
		match packet.packet_type {
			P::Continue(inner_packet) => {
				if let Some(stream) = self.stream_map.get(&packet.stream_id) {
					if stream.stream_type == StreamType::Tcp {
						stream
							.flow_control
							.store(inner_packet.buffer_remaining, Ordering::Release);
						let _ = stream.flow_control_event.notify(u32::MAX);
					}
				}
				Ok(false)
			}

			// Connect | Info => invalid packet type
			// Data | Close => specialcased
			_ => Err(WispError::InvalidPacketType),
		}
	}
}
