use std::str::FromStr;

use fastwebsockets::CloseCode;
use log::debug;
use tokio::{
	io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
	select,
};
use uuid::Uuid;
use wisp_mux::{ws::Payload, CloseReason, ConnectPacket, StreamType};

use crate::{
	handle::wisp::wispnet::route_wispnet,
	stream::{ClientStream, ResolvedPacket, WebSocketFrame, WebSocketStreamWrapper},
	CLIENTS, CONFIG,
};

// TODO rewrite this whole thing
//      isn't even cancel safe i think
#[allow(clippy::too_many_lines)]
pub async fn handle_wsproxy(
	mut ws: WebSocketStreamWrapper,
	id: String,
	path: String,
	udp: bool,
) -> anyhow::Result<()> {
	if udp && !CONFIG.stream.allow_wsproxy_udp {
		let _ = ws.close(CloseCode::Error.into(), b"udp is blocked").await;
		return Ok(());
	}

	let vec: Vec<&str> = path.split('/').last().unwrap().split(':').collect();
	let Ok(port) = FromStr::from_str(vec[1]) else {
		let _ = ws.close(CloseCode::Error.into(), b"invalid port").await;
		return Ok(());
	};
	let connect = ConnectPacket {
		stream_type: if udp {
			StreamType::Udp
		} else {
			StreamType::Tcp
		},
		destination_hostname: vec[0].to_string(),
		destination_port: port,
	};

	let requested_stream = connect.clone();

	let Ok(resolved) = ClientStream::resolve(connect).await else {
		let _ = ws
			.close(CloseCode::Error.into(), b"failed to resolve host")
			.await;
		return Ok(());
	};
	let (stream, resolved_stream) = match resolved {
		ResolvedPacket::Valid(connect) => {
			let resolved = connect.clone();
			let Ok(stream) = ClientStream::connect(connect).await else {
				let _ = ws
					.close(CloseCode::Error.into(), b"failed to connect to host")
					.await;
				return Ok(());
			};
			(stream, resolved)
		}
		ResolvedPacket::ValidWispnet(server, connect) => {
			let resolved = connect.clone();
			let Ok(stream) = route_wispnet(server, connect).await else {
				let _ = ws
					.close(CloseCode::Error.into(), b"failed to connect to host")
					.await;
				return Ok(());
			};
			(stream, resolved)
		}
		ResolvedPacket::NoResolvedAddrs => {
			let _ = ws
				.close(
					CloseCode::Error.into(),
					b"host did not resolve to any addrs",
				)
				.await;
			return Ok(());
		}
		ResolvedPacket::Blocked => {
			let _ = ws.close(CloseCode::Error.into(), b"host is blocked").await;
			return Ok(());
		}
		ResolvedPacket::Invalid => {
			let _ = ws
				.close(
					CloseCode::Error.into(),
					b"invalid host/port/type combination",
				)
				.await;
			return Ok(());
		}
	};

	let uuid = Uuid::new_v4();

	debug!(
		"new wsproxy client id {:?} connected: (stream uuid {:?}) {:?} {:?}",
		id, uuid, requested_stream, resolved_stream
	);

	if let Some(client) = CLIENTS.lock().await.get(&id) {
		client
			.0
			.lock()
			.await
			.insert(uuid, (requested_stream, resolved_stream.clone()));
	}

	match stream {
		ClientStream::Tcp(stream) => {
			let mut stream = BufReader::new(stream);
			let ret: anyhow::Result<()> = async {
				loop {
					select! {
						x = ws.read() => {
							match x? {
								WebSocketFrame::Data(data) => {
									stream.write_all(&data).await?;
								}
								WebSocketFrame::Close => {
									stream.shutdown().await?;
								}
								WebSocketFrame::Ignore => {}
							}
						}
						x = stream.fill_buf() => {
							let x = x?;
							ws.write(x).await?;
							let len = x.len();
							stream.consume(len);
						}
					}
				}
			}
			.await;
			match ret {
				Ok(()) => {
					let _ = ws.close(CloseCode::Normal.into(), b"").await;
				}
				Err(x) => {
					let _ = ws
						.close(CloseCode::Normal.into(), x.to_string().as_bytes())
						.await;
				}
			}
		}
		ClientStream::Udp(stream) => {
			let ret: anyhow::Result<()> = async {
				let mut data = vec![0u8; 65507];
				loop {
					select! {
						x = ws.read() => {
							match x? {
								WebSocketFrame::Data(data) => {
									stream.send(&data).await?;
								}
								WebSocketFrame::Close | WebSocketFrame::Ignore => {}
							}
						}
						size = stream.recv(&mut data) => {
							ws.write(&data[..size?]).await?;
						}
					}
				}
			}
			.await;
			match ret {
				Ok(()) => {
					let _ = ws.close(CloseCode::Normal.into(), b"").await;
				}
				Err(x) => {
					let _ = ws
						.close(CloseCode::Normal.into(), x.to_string().as_bytes())
						.await;
				}
			}
		}
		#[cfg(feature = "twisp")]
		ClientStream::Pty(_, _) => {
			let _ = ws
				.close(CloseCode::Error.into(), b"twisp is not supported")
				.await;
		}
		ClientStream::Wispnet(stream, mux_id) => {
			if let Some(client) = CLIENTS.lock().await.get(&mux_id) {
				client
					.0
					.lock()
					.await
					.insert(uuid, (resolved_stream.clone(), resolved_stream));
			}

			let ret: anyhow::Result<()> = async {
				loop {
					select! {
						x = ws.read() => {
							match x? {
								WebSocketFrame::Data(data) => {
									stream.write_payload(Payload::Bytes(data)).await?;
								}
								WebSocketFrame::Close => {
									stream.close(CloseReason::Voluntary).await?;
								}
								WebSocketFrame::Ignore => {}
							}
						}
						x = stream.read() => {
							let Some(x) = x? else {
								break;
							};
							ws.write(&x).await?;
						}
					}
				}
				Ok(())
			}
			.await;

			if let Some(client) = CLIENTS.lock().await.get(&mux_id) {
				client.0.lock().await.remove(&uuid);
			}

			match ret {
				Ok(()) => {
					let _ = ws.close(CloseCode::Normal.into(), b"").await;
				}
				Err(x) => {
					let _ = ws
						.close(CloseCode::Normal.into(), x.to_string().as_bytes())
						.await;
				}
			}
		}
		ClientStream::NoResolvedAddrs => {
			let _ = ws
				.close(
					CloseCode::Error.into(),
					b"host did not resolve to any addrs",
				)
				.await;
			return Ok(());
		}
		ClientStream::Blocked => {
			let _ = ws.close(CloseCode::Error.into(), b"host is blocked").await;
		}
		ClientStream::Invalid => {
			let _ = ws.close(CloseCode::Error.into(), b"host is invalid").await;
		}
	}

	debug!(
		"wsproxy client id {:?} disconnected (stream uuid {:?})",
		id, uuid
	);

	if let Some(client) = CLIENTS.lock().await.get(&id) {
		client.0.lock().await.remove(&uuid);
	}

	Ok(())
}
