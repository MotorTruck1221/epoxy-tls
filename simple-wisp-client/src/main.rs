use atomic_counter::{AtomicCounter, RelaxedCounter};
use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use fastwebsockets::{handshake, WebSocketWrite};
use futures::{future::select_all, FutureExt, TryFutureExt};
use http_body_util::Empty;
use humantime::format_duration;
use hyper::{
	header::{CONNECTION, UPGRADE},
	Request, Uri,
};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use simple_moving_average::{SingleSumSMA, SMA};
use std::{
	error::Error,
	future::Future,
	io::{stdout, Cursor, IsTerminal, Write},
	net::SocketAddr,
	path::PathBuf,
	pin::Pin,
	process::{abort, exit},
	sync::Arc,
	time::{Duration, Instant},
};
use tokio::{
	io::AsyncReadExt,
	net::{tcp::OwnedWriteHalf, TcpStream},
	select,
	signal::unix::{signal, SignalKind},
	time::{interval, sleep},
};
use wisp_mux::{
	extensions::{
		cert::{CertAuthProtocolExtension, CertAuthProtocolExtensionBuilder, SigningKey},
		motd::{MotdProtocolExtension, MotdProtocolExtensionBuilder},
		password::{PasswordProtocolExtension, PasswordProtocolExtensionBuilder},
		udp::{UdpProtocolExtension, UdpProtocolExtensionBuilder},
		AnyProtocolExtensionBuilder,
	},
	ClientMux, StreamType, WispError, WispV2Handshake,
};

#[global_allocator]
static JEMALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug)]
enum WispClientError {
	InvalidUriScheme,
	UriHasNoHost,
}

impl std::fmt::Display for WispClientError {
	fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		use WispClientError as E;
		match self {
			E::InvalidUriScheme => write!(fmt, "Invalid URI scheme"),
			E::UriHasNoHost => write!(fmt, "URI has no host"),
		}
	}
}

impl Error for WispClientError {}

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
	Fut: Future + Send + 'static,
	Fut::Output: Send + 'static,
{
	fn execute(&self, fut: Fut) {
		tokio::task::spawn(fut);
	}
}

#[derive(Parser)]
#[command(version = clap::crate_version!())]
struct Cli {
	/// Wisp server URL
	#[arg(short, long)]
	wisp: Uri,
	/// TCP server address
	#[arg(short, long)]
	tcp: SocketAddr,
	/// Number of streams
	#[arg(short, long, default_value_t = 10)]
	streams: usize,
	/// Size of packets sent, in KB
	#[arg(short, long, default_value_t = 1)]
	packet_size: usize,
	/// Duration to run the test for
	#[arg(short, long)]
	duration: Option<humantime::Duration>,
	/// Ask for UDP
	#[arg(short, long)]
	udp: bool,
	/// Enable auth: format is `username:password`
	///
	/// Usernames and passwords are sent in plaintext!!
	#[arg(long)]
	auth: Option<String>,
	/// Enable certauth
	#[arg(long)]
	certauth: Option<PathBuf>,
	/// Enable motd parsing
	#[arg(long)]
	motd: bool,
	/// Make a Wisp V2 connection
	#[arg(long)]
	wisp_v2: bool,
}

async fn get_cert(path: PathBuf) -> Result<SigningKey, Box<dyn Error + Sync + Send>> {
	let data = tokio::fs::read_to_string(path).await?;
	let signer = ed25519_dalek::SigningKey::from_pkcs8_pem(&data)?;
	let binary_key = signer.verifying_key().to_bytes();

	let mut hasher = Sha256::new();
	hasher.update(binary_key);
	let hash: [u8; 32] = hasher.finalize().into();
	Ok(SigningKey::new_ed25519(Arc::new(signer), hash))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
	tokio::spawn(real_main()).await?
}

async fn create_mux(
	opts: &Cli,
) -> Result<
	(
		ClientMux<WebSocketWrite<OwnedWriteHalf>>,
		impl Future<Output = Result<(), WispError>> + Send,
	),
	Box<dyn Error + Send + Sync>,
> {
	if opts.wisp.scheme_str().unwrap_or_default() != "ws" {
		Err(Box::new(WispClientError::InvalidUriScheme))?;
	}

	let addr = opts.wisp.host().ok_or(WispClientError::UriHasNoHost)?;
	let addr_port = opts.wisp.port_u16().unwrap_or(80);
	let addr_path = opts.wisp.path();

	let auth = opts.auth.as_ref().map(|auth| {
		let split: Vec<_> = auth.split(':').collect();
		let username = split[0].to_string();
		let password = split[1..].join(":");
		PasswordProtocolExtensionBuilder::new_client(Some((username, password)))
	});

	println!(
		"connecting to {} and sending &[0; 1024 * {}] to {} with threads {}",
		opts.wisp, opts.packet_size, opts.tcp, opts.streams,
	);

	let socket = TcpStream::connect(format!("{}:{}", &addr, addr_port)).await?;
	let req = Request::builder()
		.method("GET")
		.uri(addr_path)
		.header("Host", addr)
		.header(UPGRADE, "websocket")
		.header(CONNECTION, "upgrade")
		.header(
			"Sec-WebSocket-Key",
			fastwebsockets::handshake::generate_key(),
		)
		.header("Sec-WebSocket-Version", "13")
		.body(Empty::<Bytes>::new())?;

	let (ws, _) = handshake::client(&SpawnExecutor, req, socket).await?;

	let (rx, tx) = ws.split(|x| {
		let parts = x.into_inner().downcast::<TokioIo<TcpStream>>().unwrap();
		let (r, w) = parts.io.into_inner().into_split();
		(Cursor::new(parts.read_buf).chain(r), w)
	});

	let mut extensions: Vec<AnyProtocolExtensionBuilder> = Vec::new();
	let mut extension_ids: Vec<u8> = Vec::new();
	if opts.udp {
		extensions.push(AnyProtocolExtensionBuilder::new(
			UdpProtocolExtensionBuilder,
		));
		extension_ids.push(UdpProtocolExtension::ID);
	}
	if opts.motd {
		extensions.push(AnyProtocolExtensionBuilder::new(
			MotdProtocolExtensionBuilder::Client,
		));
	}
	if let Some(auth) = auth {
		extensions.push(AnyProtocolExtensionBuilder::new(auth));
		extension_ids.push(PasswordProtocolExtension::ID);
	}
	if let Some(certauth) = &opts.certauth {
		let key = get_cert(certauth.clone()).await?;
		let extension = CertAuthProtocolExtensionBuilder::new_client(Some(key));
		extensions.push(AnyProtocolExtensionBuilder::new(extension));
		extension_ids.push(CertAuthProtocolExtension::ID);
	}

	let (mux, fut) = if opts.wisp_v2 {
		ClientMux::create(rx, tx, Some(WispV2Handshake::new(extensions)))
			.await?
			.with_required_extensions(extension_ids.as_slice())
			.await?
	} else {
		ClientMux::create(rx, tx, None)
			.await?
			.with_no_required_extensions()
	};

	Ok((mux, fut))
}

#[allow(clippy::too_many_lines)]
async fn real_main() -> Result<(), Box<dyn Error + Send + Sync>> {
	#[cfg(feature = "tokio-console")]
	console_subscriber::init();
	let opts = Cli::parse();

	let addr_dest = opts.tcp.ip().to_string();
	let addr_dest_port = opts.tcp.port();
	let (mux, fut) = create_mux(&opts).await?;

	let motd_extension = mux
		.supported_extensions
		.iter()
		.find_map(|x| x.downcast_ref::<MotdProtocolExtension>());

	println!(
		"connected and created ClientMux, was downgraded {}, extensions supported {:?}, motd {:?}\n\n",
		mux.downgraded,
		mux.supported_extensions
			.iter()
			.map(|x| x.get_id())
			.collect::<Vec<_>>(),
		motd_extension.map(|x| x.motd.clone())
	);

	let mut threads = Vec::with_capacity((opts.streams * 2) + 3);

	threads.push(Box::pin(
		tokio::spawn(fut)
			.map_err(|x| WispError::Other(Box::new(x)))
			.map(|x| x.and_then(|x| x)),
	)
		as Pin<Box<dyn Future<Output = Result<(), WispError>> + Send>>);

	let payload = vec![0; 1024 * opts.packet_size];

	let cnt = Arc::new(RelaxedCounter::new(0));

	let start_time = Instant::now();
	for _ in 0..opts.streams {
		let (cr, cw) = mux
			.client_new_stream(StreamType::Tcp, addr_dest.clone(), addr_dest_port)
			.await?
			.into_split();
		let cnt = cnt.clone();
		let payload = payload.clone();
		threads.push(Box::pin(async move {
			while let Ok(()) = cw.write(&payload).await {
				cnt.inc();
			}
			#[allow(unreachable_code)]
			Ok::<(), WispError>(())
		}));
		threads.push(Box::pin(async move {
			loop {
				let _ = cr.read().await;
			}
		}));
	}

	let cnt_avg = cnt.clone();
	threads.push(Box::pin(async move {
        let mut interval = interval(Duration::from_millis(100));
        let mut avg: SingleSumSMA<usize, usize, 100> = SingleSumSMA::new();
        let mut last_time = 0;
        let is_term = stdout().is_terminal();
        loop {
            interval.tick().await;
            let now = cnt_avg.get();
            let stat = format!(
                "sent &[0; 1024 * {}] cnt: {:?} ({} KiB), +{:?} / 100ms ({} KiB / 1s), moving average (10 s): {:?} / 100ms ({} KiB / 1s)",
                opts.packet_size,
                now,
                now * opts.packet_size,
                now - last_time,
                (now - last_time) * opts.packet_size * 10,
                avg.get_average(),
                avg.get_average() * opts.packet_size * 10,
            );
            if is_term {
                println!("\x1b[1A\x1b[2K{}\r", stat);
            } else {
                println!("{}", stat);
            }
            stdout().flush().unwrap();
            avg.add_sample(now - last_time);
            last_time = now;
        }
    }));

	threads.push(Box::pin(async move {
		let mut interrupt =
			signal(SignalKind::interrupt()).map_err(|x| WispError::Other(Box::new(x)))?;
		let mut terminate =
			signal(SignalKind::terminate()).map_err(|x| WispError::Other(Box::new(x)))?;
		select! {
			_ = interrupt.recv() => (),
			_ = terminate.recv() => (),
		}
		Ok(())
	}));

	if let Some(duration) = opts.duration {
		threads.push(Box::pin(async move {
			sleep(duration.into()).await;
			Ok(())
		}));
	}

	let out = select_all(threads.into_iter().map(tokio::spawn)).await;

	let duration_since = Instant::now().duration_since(start_time);

	if let Err(err) = out.0? {
		println!("\n\nerr: {:?}", err);
		exit(1);
	}

	out.2.into_iter().for_each(|x| x.abort());

	mux.close().await?;

	if duration_since.as_secs() != 0 {
		println!(
			"\nresults: {} packets of &[0; 1024 * {}] ({} KiB) sent in {} ({} KiB/s)",
			cnt.get(),
			opts.packet_size,
			cnt.get() * opts.packet_size,
			format_duration(duration_since),
			(cnt.get() * opts.packet_size) as u64 / duration_since.as_secs(),
		);
	}

	// force everything to die
	abort()
}
