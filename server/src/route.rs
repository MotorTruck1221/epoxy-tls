use std::{fmt::Display, future::Future, io::Cursor};

use anyhow::Context;
use bytes::Bytes;
use fastwebsockets::{FragmentCollector, Role, WebSocket, WebSocketRead, WebSocketWrite};
use http_body_util::Full;
use hyper::{
	body::Incoming, header::SEC_WEBSOCKET_PROTOCOL, server::conn::http1::Builder,
	service::service_fn, upgrade::OnUpgrade, HeaderMap, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use log::{debug, error, trace};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use wisp_mux::{
	generic::{GenericWebSocketRead, GenericWebSocketWrite},
	ws::{EitherWebSocketRead, EitherWebSocketWrite},
};

use crate::{
	config::SocketTransport,
	generate_stats,
	listener::{ServerStream, ServerStreamExt, ServerStreamRead, ServerStreamWrite},
	stream::WebSocketStreamWrapper,
	upgrade::{is_upgrade_request, upgrade},
	util_chain::{chain, Chain},
	CONFIG,
};

pub type WispStreamRead = EitherWebSocketRead<
	WebSocketRead<Chain<Cursor<Bytes>, ServerStreamRead>>,
	GenericWebSocketRead<FramedRead<ServerStreamRead, LengthDelimitedCodec>, std::io::Error>,
>;
pub type WispStreamWrite = EitherWebSocketWrite<
	WebSocketWrite<ServerStreamWrite>,
	GenericWebSocketWrite<FramedWrite<ServerStreamWrite, LengthDelimitedCodec>, std::io::Error>,
>;
pub type WispResult = (WispStreamRead, WispStreamWrite);

pub enum ServerRouteResult {
	Wisp {
		stream: WispResult,
		has_ws_protocol: bool,
	},
	Wispnet {
		stream: WispResult,
	},
	WsProxy {
		stream: WebSocketStreamWrapper,
		path: String,
		udp: bool,
	},
}

impl Display for ServerRouteResult {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Wisp { .. } => write!(f, "Wisp"),
			Self::Wispnet { .. } => write!(f, "Wispnet"),
			Self::WsProxy { path, udp, .. } => write!(f, "WsProxy path {path:?} udp {udp:?}"),
		}
	}
}

type Body = Full<Bytes>;
fn non_ws_resp() -> anyhow::Result<Response<Body>> {
	Ok(Response::builder()
		.status(StatusCode::OK)
		.body(Body::new(CONFIG.server.non_ws_response.as_bytes().into()))?)
}

async fn send_stats() -> anyhow::Result<Response<Body>> {
	match generate_stats().await {
		Ok(x) => {
			debug!("sent server stats to http client");
			Ok(Response::builder()
				.status(StatusCode::OK)
				.body(Body::new(x.into()))?)
		}
		Err(x) => {
			error!("failed to send stats to http client: {:?}", x);
			Ok(Response::builder()
				.status(StatusCode::INTERNAL_SERVER_ERROR)
				.body(Body::new(x.to_string().into()))?)
		}
	}
}

fn get_header(headers: &HeaderMap, header: &str) -> Option<String> {
	headers
		.get(header)
		.and_then(|x| x.to_str().ok())
		.map(ToString::to_string)
}

enum HttpUpgradeResult {
	Wisp {
		has_ws_protocol: bool,
		is_wispnet: bool,
	},
	WsProxy {
		path: String,
		udp: bool,
	},
}

async fn ws_upgrade<F, R>(
	mut req: Request<Incoming>,
	stats_endpoint: Option<String>,
	callback: F,
) -> anyhow::Result<Response<Body>>
where
	F: FnOnce(OnUpgrade, HttpUpgradeResult, Option<String>) -> R + Send + 'static,
	R: Future<Output = anyhow::Result<()>> + Send,
{
	let is_upgrade = is_upgrade_request(&req);

	if !is_upgrade {
		if let Some(stats_endpoint) = stats_endpoint {
			if req.uri().path() == stats_endpoint {
				return send_stats().await;
			}
		}

		debug!("sent non_ws_response to http client");
		return non_ws_resp();
	}

	trace!("recieved request {:?}", req);

	let (resp, fut) = upgrade(&mut req)?;
	// replace body of Empty<Bytes> with Full<Bytes>
	let mut resp = Response::from_parts(resp.into_parts().0, Body::new(Bytes::new()));

	let headers = req.headers();
	let ip_header = if CONFIG.server.use_real_ip_headers {
		get_header(headers, "x-real-ip").or_else(|| get_header(headers, "x-forwarded-for"))
	} else {
		None
	};

	let ws_protocol = headers.get(SEC_WEBSOCKET_PROTOCOL);
	let req_path = req.uri().path().to_string();

	if req_path.ends_with(&(CONFIG.wisp.prefix.clone() + "/")) {
		let has_ws_protocol = ws_protocol.is_some();
		let is_wispnet =
			CONFIG.wisp.has_wispnet() && req.uri().query().unwrap_or_default() == "net";
		tokio::spawn(async move {
			if let Err(err) = (callback)(
				fut,
				HttpUpgradeResult::Wisp {
					has_ws_protocol,
					is_wispnet,
				},
				ip_header,
			)
			.await
			{
				error!("error while serving client: {:?}", err);
			}
		});
		if let Some(protocol) = ws_protocol {
			resp.headers_mut()
				.append(SEC_WEBSOCKET_PROTOCOL, protocol.clone());
		}
	} else if CONFIG.wisp.allow_wsproxy {
		let udp = req.uri().query().unwrap_or_default() == "udp";
		tokio::spawn(async move {
			if let Err(err) = (callback)(
				fut,
				HttpUpgradeResult::WsProxy {
					path: req_path,
					udp,
				},
				ip_header,
			)
			.await
			{
				error!("error while serving client: {:?}", err);
			}
		});
	} else {
		debug!("sent non_ws_response to http client");
		return non_ws_resp();
	}

	Ok(resp)
}

pub async fn route_stats(stream: ServerStream) -> anyhow::Result<()> {
	let stream = TokioIo::new(stream);
	Builder::new()
		.serve_connection(stream, service_fn(move |_| async { send_stats().await }))
		.await?;
	Ok(())
}

pub async fn route(
	stream: ServerStream,
	stats_endpoint: Option<String>,
	callback: impl FnOnce(ServerRouteResult, Option<String>) + Clone + Send + 'static,
) -> anyhow::Result<()> {
	match CONFIG.server.transport {
		SocketTransport::WebSocket => {
			let stream = TokioIo::new(stream);

			Builder::new()
				.serve_connection(
					stream,
					service_fn(move |req| {
						let callback = callback.clone();

						ws_upgrade(
							req,
							stats_endpoint.clone(),
							|fut, res, maybe_ip| async move {
								let ws = fut.await.context("failed to await upgrade future")?;

								let mut ws =
									WebSocket::after_handshake(TokioIo::new(ws), Role::Server);
								ws.set_max_message_size(CONFIG.server.max_message_size);
								ws.set_auto_pong(false);

								match res {
									HttpUpgradeResult::Wisp {
										has_ws_protocol,
										is_wispnet,
									} => {
										let (read, write) = ws.split(|x| {
											let parts = x
												.into_inner()
												.downcast::<TokioIo<ServerStream>>()
												.unwrap();
											let (r, w) = parts.io.into_inner().split();
											(chain(Cursor::new(parts.read_buf), r), w)
										});

										let result = if is_wispnet {
											ServerRouteResult::Wispnet {
												stream: (
													EitherWebSocketRead::Left(read),
													EitherWebSocketWrite::Left(write),
												),
											}
										} else {
											ServerRouteResult::Wisp {
												stream: (
													EitherWebSocketRead::Left(read),
													EitherWebSocketWrite::Left(write),
												),
												has_ws_protocol,
											}
										};

										(callback)(result, maybe_ip);
									}
									HttpUpgradeResult::WsProxy { path, udp } => {
										let ws = WebSocketStreamWrapper(FragmentCollector::new(ws));
										(callback)(
											ServerRouteResult::WsProxy {
												stream: ws,
												path,
												udp,
											},
											maybe_ip,
										);
									}
								}

								Ok(())
							},
						)
					}),
				)
				.with_upgrades()
				.await?;
		}
		SocketTransport::LengthDelimitedLe => {
			let codec = LengthDelimitedCodec::builder()
				.little_endian()
				.max_frame_length(usize::MAX)
				.new_codec();

			let (read, write) = stream.split();
			let read = GenericWebSocketRead::new(FramedRead::new(read, codec.clone()));
			let write = GenericWebSocketWrite::new(FramedWrite::new(write, codec));

			(callback)(
				ServerRouteResult::Wisp {
					stream: (
						EitherWebSocketRead::Right(read),
						EitherWebSocketWrite::Right(write),
					),
					has_ws_protocol: true,
				},
				None,
			);
		}
	}
	Ok(())
}
