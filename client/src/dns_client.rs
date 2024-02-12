use crate::*;

use doh_dns::{client::DnsClient, error::DnsError, status::RCode, Dns, DnsHttpsServer};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util_wasm::client::legacy::Error;
use std::{collections::HashMap, future::Future, pin::Pin, time::Duration};
use tokio::sync::RwLock;

struct HyperWasmDnsClient {
    hyper_client: Arc<Client<TlsWispService<SplitSink<WsStream, WsMessage>>, HttpBody>>,
}

impl DnsClient for HyperWasmDnsClient {
    fn get<'life0, 'async_trait>(
        &'life0 self,
        uri: Uri,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Incoming>, Error>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let mut req = Request::new(Full::new(Bytes::new()));
        *req.uri_mut() = uri;
        req.headers_mut()
            .insert("Accept", HeaderValue::from_static("application/dns-json"));
        Box::pin(self.hyper_client.request(req))
    }
}

pub struct EpxDnsClient {
    dns_client: Dns<HyperWasmDnsClient>,
    cache: RwLock<HashMap<String, String>>,
}

impl EpxDnsClient {
    pub fn new(
        hyper_client: Arc<Client<TlsWispService<SplitSink<WsStream, WsMessage>>, HttpBody>>,
        servers: Vec<String>,
    ) -> Result<Self, JsError> {
        Ok(Self {
            dns_client: Dns::with_servers(
                &servers
                    .iter()
                    .map(|x| DnsHttpsServer::new(x.to_string(), Duration::from_secs(2)))
                    .collect::<Vec<_>>(),
                HyperWasmDnsClient {
                    hyper_client: hyper_client.clone(),
                },
            )
            .replace_err("Failed to create DNS client")?,
            cache: RwLock::new(HashMap::new()),
        })
    }

    async fn get_from_cache(&self, uri: &str) -> Option<String> {
        self.cache.read().await.get(uri).map(|x| x.to_string())
    }

    pub async fn resolve(&self, uri: &str) -> Result<String, DnsError> {
        match self.get_from_cache(uri).await {
            Some(res) => Ok(res),
            None => {
                let res = self.dns_client.resolve_a(uri).await;
                let res = res.and_then(|x| {
                    Ok(x.first()
                        .ok_or(DnsError::Status(RCode::BADKEY))?
                        .data
                        .clone())
                })?;
                self.cache
                    .write()
                    .await
                    .insert(uri.to_string(), res.clone());
                Ok(res)
            }
        }
    }
}
