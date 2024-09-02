#![feature(ip)]

use std::{fmt::Write, fs::read_to_string};

use clap::Parser;
use config::{validate_config_cache, Cli, Config};
use dashmap::DashMap;
use handle::{handle_wisp, handle_wsproxy};
use lazy_static::lazy_static;
use listener::ServerListener;
use log::{error, info};
use route::ServerRouteResult;
use tokio::signal::unix::{signal, SignalKind};
use uuid::Uuid;
use wisp_mux::{ConnectPacket, StreamType};

mod config;
mod handle;
mod listener;
mod route;
mod stream;

type Client = (DashMap<Uuid, (ConnectPacket, ConnectPacket)>, bool);

lazy_static! {
	pub static ref CLI: Cli = Cli::parse();
	pub static ref CONFIG: Config = {
		if let Some(path) = &CLI.config {
			Config::de(read_to_string(path).unwrap()).unwrap()
		} else {
			Config::default()
		}
	};
	pub static ref CLIENTS: DashMap<String, Client> = DashMap::new();
}

fn format_stream_type(stream_type: StreamType) -> &'static str {
	match stream_type {
		StreamType::Tcp => "tcp",
		StreamType::Udp => "udp",
		StreamType::Unknown(_) => unreachable!(),
	}
}

fn generate_stats() -> anyhow::Result<String> {
	let mut out = String::new();
	let len = CLIENTS.len();

	use tikv_jemalloc_ctl::stats::{active, allocated, mapped, metadata, resident, retained};
	tikv_jemalloc_ctl::epoch::advance()?;

	writeln!(&mut out, "Memory usage:")?;
	writeln!(
		&mut out,
		"\tActive: {:?} MiB",
		active::read()? as f64 / (1024 * 1024) as f64
	)?;
	writeln!(
		&mut out,
		"\tAllocated: {:?} MiB",
		allocated::read()? as f64 / (1024 * 1024) as f64
	)?;
	writeln!(
		&mut out,
		"\tMapped: {:?} MiB",
		mapped::read()? as f64 / (1024 * 1024) as f64
	)?;
	writeln!(
		&mut out,
		"\tMetadata: {:?} MiB",
		metadata::read()? as f64 / (1024 * 1024) as f64
	)?;
	writeln!(
		&mut out,
		"\tResident: {:?} MiB",
		resident::read()? as f64 / (1024 * 1024) as f64
	)?;
	writeln!(
		&mut out,
		"\tRetained: {:?} MiB",
		retained::read()? as f64 / (1024 * 1024) as f64
	)?;

	writeln!(
		&mut out,
		"{} clients connected{}",
		len,
		if len != 0 { ":" } else { "" }
	)?;

	for client in CLIENTS.iter() {
		let len = client.value().0.len();

		writeln!(
			&mut out,
			"\tClient \"{}\"{}: {} streams connected{}",
			client.key(),
			if client.value().1 { " (wsproxy)" } else { "" },
			len,
			if len != 0 && CONFIG.server.verbose_stats {
				":"
			} else {
				""
			}
		)?;

		if CONFIG.server.verbose_stats {
			for stream in client.value().0.iter() {
				writeln!(
					&mut out,
					"\t\tStream \"{}\": {}",
					stream.key(),
					format_stream_type(stream.value().0.stream_type)
				)?;
				writeln!(
					&mut out,
					"\t\t\tRequested: {}:{}",
					stream.value().0.destination_hostname,
					stream.value().0.destination_port
				)?;
				writeln!(
					&mut out,
					"\t\t\tResolved: {}:{}",
					stream.value().1.destination_hostname,
					stream.value().1.destination_port
				)?;
			}
		}
	}
	Ok(out)
}

fn handle_stream(stream: ServerRouteResult, id: String) {
	tokio::spawn(async move {
		CLIENTS.insert(id.clone(), (DashMap::new(), false));
		let res = match stream {
			ServerRouteResult::Wisp(stream) => handle_wisp(stream, id.clone()).await,
			ServerRouteResult::WsProxy(ws, path, udp) => {
				handle_wsproxy(ws, id.clone(), path, udp).await
			}
		};
		if let Err(e) = res {
			error!("error while handling client: {:?}", e);
		}
		CLIENTS.remove(&id)
	});
}

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
	if CLI.default_config {
		println!("{}", Config::default().ser()?);
		return Ok(());
	}

	env_logger::builder()
		.filter_level(CONFIG.server.log_level)
		.parse_default_env()
		.init();

	validate_config_cache();

	info!(
		"listening on {:?} with socket type {:?} and socket transport {:?}",
		CONFIG.server.bind, CONFIG.server.socket, CONFIG.server.transport
	);

	tokio::spawn(async {
		let mut sig = signal(SignalKind::user_defined1()).unwrap();
		while sig.recv().await.is_some() {
			info!("{}", generate_stats().unwrap());
		}
	});

	let mut listener = ServerListener::new().await?;
	loop {
		let (stream, id) = listener.accept().await?;
		tokio::spawn(async move {
			let res = route::route(stream, move |stream| handle_stream(stream, id)).await;

			if let Err(e) = res {
				error!("error while routing client: {:?}", e);
			}
		});
	}
}
