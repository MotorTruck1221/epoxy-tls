use std::{collections::HashMap, ops::RangeInclusive};

use lazy_static::lazy_static;
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use wisp_mux::extensions::{
	password::PasswordProtocolExtensionBuilder, udp::UdpProtocolExtensionBuilder,
	ProtocolExtensionBuilder,
};

use crate::CONFIG;

type AnyProtocolExtensionBuilder = Box<dyn ProtocolExtensionBuilder + Sync + Send>;

struct ConfigCache {
	pub blocked_ports: Vec<RangeInclusive<u16>>,
	pub allowed_ports: Vec<RangeInclusive<u16>>,

	pub allowed_hosts: RegexSet,
	pub blocked_hosts: RegexSet,

	pub wisp_config: (Option<Vec<AnyProtocolExtensionBuilder>>, u32),
}

lazy_static! {
	static ref CONFIG_CACHE: ConfigCache = {
		ConfigCache {
			allowed_ports: CONFIG
				.stream
				.allow_ports
				.iter()
				.map(|x| x[0]..=x[1])
				.collect(),
			blocked_ports: CONFIG
				.stream
				.block_ports
				.iter()
				.map(|x| x[0]..=x[1])
				.collect(),
			allowed_hosts: RegexSet::new(&CONFIG.stream.allow_hosts).unwrap(),
			blocked_hosts: RegexSet::new(&CONFIG.stream.block_hosts).unwrap(),
			wisp_config: CONFIG.wisp.to_opts_inner().unwrap(),
		}
	};
}

pub fn validate_config_cache() {
	let _ = CONFIG_CACHE.wisp_config;
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SocketType {
	#[default]
	Tcp,
	Unix,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
	pub bind: String,
	pub socket: SocketType,
	pub resolve_ipv6: bool,

	pub max_message_size: usize,
	// TODO
	// prefix: String,
}

impl Default for ServerConfig {
	fn default() -> Self {
		Self {
			bind: "127.0.0.1:4000".to_owned(),
			socket: SocketType::default(),
			resolve_ipv6: false,

			max_message_size: 64 * 1024,
		}
	}
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolExtension {
	Udp,
	Password,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct WispConfig {
	pub wisp_v2: bool,
	pub buffer_size: u32,

	pub extensions: Vec<ProtocolExtension>,
	pub password_extension_users: HashMap<String, String>,
	// TODO
	// enable_wsproxy: bool,
}

impl Default for WispConfig {
	fn default() -> Self {
		Self {
			buffer_size: 512,
			wisp_v2: false,

			extensions: Vec::new(),
			password_extension_users: HashMap::new(),
		}
	}
}

impl WispConfig {
	pub fn to_opts_inner(&self) -> anyhow::Result<(Option<Vec<AnyProtocolExtensionBuilder>>, u32)> {
		if self.wisp_v2 {
			let mut extensions: Vec<Box<dyn ProtocolExtensionBuilder + Sync + Send>> = Vec::new();

			if self.extensions.contains(&ProtocolExtension::Udp) {
				extensions.push(Box::new(UdpProtocolExtensionBuilder));
			}

			if self.extensions.contains(&ProtocolExtension::Password) {
				extensions.push(Box::new(PasswordProtocolExtensionBuilder::new_server(
					self.password_extension_users.clone(),
				)));
			}

			Ok((Some(extensions), self.buffer_size))
		} else {
			Ok((None, self.buffer_size))
		}
	}

	pub fn to_opts(&self) -> (Option<&'static [AnyProtocolExtensionBuilder]>, u32) {
		(
			CONFIG_CACHE.wisp_config.0.as_deref(),
			CONFIG_CACHE.wisp_config.1,
		)
	}
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct StreamConfig {
	pub allow_udp: bool,

	pub allow_direct_ip: bool,
	pub allow_loopback: bool,
	pub allow_multicast: bool,

	pub allow_global: bool,
	pub allow_non_global: bool,

	pub allow_hosts: Vec<String>,
	pub block_hosts: Vec<String>,

	pub allow_ports: Vec<Vec<u16>>,
	pub block_ports: Vec<Vec<u16>>,
}

impl Default for StreamConfig {
	fn default() -> Self {
		Self {
			allow_udp: true,

			allow_direct_ip: true,
			allow_loopback: true,
			allow_multicast: true,

			allow_global: true,
			allow_non_global: true,

			allow_hosts: Vec::new(),
			block_hosts: Vec::new(),

			allow_ports: Vec::new(),
			block_ports: Vec::new(),
		}
	}
}

impl StreamConfig {
	pub fn allowed_ports(&self) -> &'static [RangeInclusive<u16>] {
		&CONFIG_CACHE.allowed_ports
	}

	pub fn blocked_ports(&self) -> &'static [RangeInclusive<u16>] {
		&CONFIG_CACHE.blocked_ports
	}

	pub fn allowed_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.allowed_hosts
	}

	pub fn blocked_hosts(&self) -> &RegexSet {
		&CONFIG_CACHE.blocked_hosts
	}
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
	pub server: ServerConfig,
	pub wisp: WispConfig,
	pub stream: StreamConfig,
}
