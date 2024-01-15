#![feature(let_chains)]
#[macro_use]
mod utils;
mod tokioio;
mod wrappers;

use base64::{engine::general_purpose::STANDARD, Engine};
use fastwebsockets::{Frame, OpCode, Payload, Role, WebSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokioio::TokioIo;
use utils::{ReplaceErr, UriExt};
use wrappers::{IncomingBody, WsStreamWrapper};

use std::{io::Read, ptr::null_mut, str::from_utf8, sync::Arc};

use async_compression::tokio::bufread as async_comp;
use bytes::Bytes;
use futures_util::StreamExt;
use http::{uri, HeaderName, HeaderValue, Request, Response};
use hyper::{
    body::Incoming,
    client::conn::http1::{handshake, Builder},
    Uri,
};
use js_sys::{Array, Function, Object, Reflect, Uint8Array};
use penguin_mux_wasm::{Multiplexor, MuxStream};
use tokio_rustls::{client::TlsStream, rustls, rustls::RootCertStore, TlsConnector};
use tokio_util::{
    either::Either,
    io::{ReaderStream, StreamReader},
};
use wasm_bindgen::prelude::*;
use web_sys::TextEncoder;

type HttpBody = http_body_util::Full<Bytes>;

#[derive(Debug)]
enum EpxResponse {
    Success(Response<Incoming>),
    Redirect((Response<Incoming>, http::Request<HttpBody>, Uri)),
}

enum EpxCompression {
    Brotli,
    Gzip,
}

type EpxTlsStream = TlsStream<MuxStream<WsStreamWrapper>>;
type EpxUnencryptedStream = MuxStream<WsStreamWrapper>;
type EpxStream = Either<WsTcpTlsStream, WsTcpUnencryptedStream>;

async fn send_req(
    req: http::Request<HttpBody>,
    should_redirect: bool,
    io: EpxStream,
) -> Result<EpxResponse, JsError> {
    let (mut req_sender, conn) = Builder::new()
        .title_case_headers(true)
        .preserve_header_case(true)
        .handshake(TokioIo::new(io))
        .await
        .replace_err("Failed to connect to host")?;

    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = conn.await {
            error!("wstcp: error in muxed hyper connection! {:?}", e);
        }
    });

    let new_req = if should_redirect {
        Some(req.clone())
    } else {
        None
    };

    let res = req_sender
        .send_request(req)
        .await
        .replace_err("Failed to send request");
    match res {
        Ok(res) => {
            if utils::is_redirect(res.status().as_u16())
                && let Some(mut new_req) = new_req
                && let Some(location) = res.headers().get("Location")
                && let Ok(redirect_url) = new_req.uri().get_redirect(location)
                && let Some(redirect_url_authority) = redirect_url
                    .clone()
                    .authority()
                    .replace_err("Redirect URL must have an authority")
                    .ok()
            {
                let should_strip = new_req.uri().is_same_host(&redirect_url);
                if should_strip {
                    new_req.headers_mut().remove("authorization");
                    new_req.headers_mut().remove("cookie");
                    new_req.headers_mut().remove("www-authenticate");
                }
                let new_url = redirect_url.clone();
                *new_req.uri_mut() = redirect_url;
                new_req.headers_mut().insert(
                    "Host",
                    HeaderValue::from_str(redirect_url_authority.as_str())?,
                );
                Ok(EpxResponse::Redirect((res, new_req, new_url)))
            } else {
                Ok(EpxResponse::Success(res))
            }
        }
        Err(err) => Err(err),
    }
}

#[wasm_bindgen(start)]
async fn start() {
    utils::set_panic_hook();
}

#[wasm_bindgen]
pub struct WsWebSocket {
    onopen: Function,
    onclose: Function,
    onerror: Function,
    onmessage: Function,
    ws: Option<WebSocket<EpxStream>>,
}

async fn wtf(iop: *mut EpxStream) {
    let mut t = false;
    unsafe {
        let io = &mut *iop;
        let mut v = vec![];
        loop {
            let r = io.read_u8().await;

            if let Ok(u) = r {
                v.push(u);
                if t && u as char == '\r' {
                    let r = io.read_u8().await;
                    break;
                }
                if u as char == '\n' {
                    t = true;
                } else {
                    t = false;
                }
            } else {
                break;
            }
        }
        log!("{}", &from_utf8(&v).unwrap().to_string());
    }
}

#[wasm_bindgen]
impl WsWebSocket {
    #[wasm_bindgen(constructor)]
    pub fn new(
        onopen: Function,
        onclose: Function,
        onmessage: Function,
        onerror: Function,
    ) -> Result<WsWebSocket, JsError> {
        Ok(Self {
            onopen,
            onclose,
            onerror,
            onmessage,
            ws: None,
        })
    }

    #[wasm_bindgen]
    pub async fn connect(
        &mut self,
        tcp: &mut EpoxyClient,
        url: String,
        protocols: Vec<String>,
        origin: String,
    ) -> Result<(), JsError> {
        self.onopen.call0(&Object::default());
        let uri = url.parse::<uri::Uri>().replace_err("Failed to parse URL")?;
        let mut io = tcp.get_http_io(&uri).await?;

        let r: [u8; 16] = rand::random();
        let key = STANDARD.encode(&r);

        let pathstr = if let Some(p) = uri.path_and_query() {
            p.to_string()
        } else {
            uri.path().to_string()
        };

        io.write(format!("GET {} HTTP/1.1\r\n", pathstr).as_bytes())
            .await;
        io.write(b"Sec-WebSocket-Version: 13\r\n").await;
        io.write(format!("Sec-WebSocket-Key: {}\r\n", key).as_bytes())
            .await;
        io.write(b"Connection: Upgrade\r\n").await;
        io.write(b"Upgrade: websocket\r\n").await;
        io.write(format!("Origin: {}\r\n", origin).as_bytes()).await;
        io.write(format!("Host: {}\r\n", uri.host().unwrap()).as_bytes())
            .await;
        io.write(b"\r\n").await;

        let iop: *mut EpxStream = &mut io;
        wtf(iop).await;

        let mut ws = WebSocket::after_handshake(io, fastwebsockets::Role::Client);
        ws.set_writev(false);
        ws.set_auto_close(true);
        ws.set_auto_pong(true);

        self.ws = Some(ws);

        Ok(())
    }

    #[wasm_bindgen]
    pub fn ptr(&mut self) -> *mut WsWebSocket {
        self
    }

    #[wasm_bindgen]
    pub async fn send(&mut self, payload: String) -> Result<(), JsError> {
        let Some(ws) = self.ws.as_mut() else {
            return Err(JsError::new("Tried to send() before handshake!"));
        };
        ws.write_frame(Frame::new(
            true,
            OpCode::Text,
            None,
            Payload::Owned(payload.as_bytes().to_vec()),
        ))
        .await
        .unwrap();
        // .replace_err("Failed to send WsWebSocket payload")?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn recv(&mut self) -> Result<(), JsError> {
        let Some(ws) = self.ws.as_mut() else {
            return Err(JsError::new("Tried to recv() before handshake!"));
        };
        loop {
            let Ok(frame) = ws.read_frame().await else {
                break;
            };

            match frame.opcode {
                OpCode::Text => {
                    if let Ok(str) = from_utf8(&frame.payload) {
                        self.onmessage
                            .call1(&JsValue::null(), &jval!(str))
                            .replace_err("missing onmessage handler")?;
                    }
                }
                OpCode::Binary => {
                    self.onmessage
                        .call1(
                            &JsValue::null(),
                            &jval!(Uint8Array::from(frame.payload.to_vec().as_slice())),
                        )
                        .replace_err("missing onmessage handler")?;
                }

                _ => panic!("unknown opcode {:?}", frame.opcode),
            }
        }
        self.onclose
            .call0(&JsValue::null())
            .replace_err("missing onclose handler")?;
        Ok(())
    }
}

#[wasm_bindgen]
pub async fn send(pointer: *mut WsWebSocket, payload: String) -> Result<(), JsError> {
    let tcp = unsafe { &mut *pointer };
    tcp.send(payload).await
}

#[wasm_bindgen]
pub struct EpoxyClient {
    rustls_config: Arc<rustls::ClientConfig>,
    mux: Multiplexor<WsStreamWrapper>,
    useragent: String,
    redirect_limit: usize,
}

#[wasm_bindgen]
impl EpoxyClient {
    #[wasm_bindgen(constructor)]
    pub async fn new(
        ws_url: String,
        useragent: String,
        redirect_limit: usize,
    ) -> Result<EpoxyClient, JsError> {
        let ws_uri = ws_url
            .parse::<uri::Uri>()
            .replace_err("Failed to parse websocket url")?;

        let ws_uri_scheme = ws_uri
            .scheme_str()
            .replace_err("Websocket URL must have a scheme")?;
        if ws_uri_scheme != "ws" && ws_uri_scheme != "wss" {
            return Err(JsError::new("Scheme must be either `ws` or `wss`"));
        }

        debug!("connecting to ws {:?}", ws_url);
        let ws = WsStreamWrapper::connect(ws_url, None)
            .await
            .replace_err("Failed to connect to websocket")?;
        debug!("connected!");
        let mux = Multiplexor::new(ws, penguin_mux_wasm::Role::Client, None, None);

        let mut certstore = RootCertStore::empty();
        certstore.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let rustls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(certstore)
                .with_no_client_auth(),
        );

        Ok(EpoxyClient {
            mux,
            rustls_config,
            useragent,
            redirect_limit,
        })
    }
    #[wasm_bindgen]
    pub fn ptr(&mut self) -> *mut EpoxyClient {
        self as *mut Self
    }

    async fn get_http_io(&self, url: &Uri) -> Result<EpxStream, JsError> {
        let url_host = url.host().replace_err("URL must have a host")?;
        let url_port = utils::get_url_port(url)?;
        let channel = self
            .mux
            .client_new_stream_channel(url_host.as_bytes(), url_port)
            .await
            .replace_err("Failed to create multiplexor channel")?;

        if *url.scheme().replace_err("URL must have a scheme")? == uri::Scheme::HTTPS {
            let cloned_uri = url_host.to_string().clone();
            let connector = TlsConnector::from(self.rustls_config.clone());
            let io = connector
                .connect(
                    cloned_uri
                        .try_into()
                        .replace_err("Failed to parse URL (rustls)")?,
                    channel,
                )
                .await
                .replace_err("Failed to perform TLS handshake")?;
            Ok(EpxStream::Left(io))
        } else {
            Ok(EpxStream::Right(channel))
        }
    }

    async fn send_req(
        &self,
        req: http::Request<HttpBody>,
        should_redirect: bool,
    ) -> Result<(hyper::Response<Incoming>, Uri, bool), JsError> {
        let mut redirected = false;
        let uri = req.uri().clone();
        let mut current_resp: EpxResponse =
            send_req(req, should_redirect, self.get_http_io(&uri).await?).await?;
        for _ in 0..self.redirect_limit - 1 {
            match current_resp {
                EpxResponse::Success(_) => break,
                EpxResponse::Redirect((_, req, new_url)) => {
                    redirected = true;
                    current_resp =
                        send_req(req, should_redirect, self.get_http_io(&new_url).await?).await?
                }
            }
        }

        match current_resp {
            EpxResponse::Success(resp) => Ok((resp, uri, redirected)),
            EpxResponse::Redirect((resp, _, new_url)) => Ok((resp, new_url, redirected)),
        }
    }

    pub async fn fetch(&self, url: String, options: Object) -> Result<web_sys::Response, JsError> {
        let uri = url.parse::<uri::Uri>().replace_err("Failed to parse URL")?;
        let uri_scheme = uri.scheme().replace_err("URL must have a scheme")?;
        if *uri_scheme != uri::Scheme::HTTP && *uri_scheme != uri::Scheme::HTTPS {
            return Err(jerr!("Scheme must be either `http` or `https`"));
        }
        let uri_host = uri.host().replace_err("URL must have a host")?;

        let req_method_string: String = match Reflect::get(&options, &jval!("method")) {
            Ok(val) => val.as_string().unwrap_or("GET".to_string()),
            Err(_) => "GET".to_string(),
        };
        let req_method: http::Method =
            http::Method::try_from(<String as AsRef<str>>::as_ref(&req_method_string))
                .replace_err("Invalid http method")?;

        let req_should_redirect = match Reflect::get(&options, &jval!("redirect")) {
            Ok(val) => !matches!(
                val.as_string().unwrap_or_default().as_str(),
                "error" | "manual"
            ),
            Err(_) => true,
        };

        let body_jsvalue: Option<JsValue> = Reflect::get(&options, &jval!("body")).ok();
        let body = if let Some(val) = body_jsvalue {
            if val.is_string() {
                let str = val
                    .as_string()
                    .replace_err("Failed to get string from body")?;
                let encoder =
                    TextEncoder::new().replace_err("Failed to create TextEncoder for body")?;
                let encoded = encoder.encode_with_input(str.as_ref());
                Some(encoded)
            } else {
                Some(Uint8Array::new(&val).to_vec())
            }
        } else {
            None
        };

        let body_bytes: Bytes = match body {
            Some(vec) => Bytes::from(vec),
            None => Bytes::new(),
        };

        let headers: Option<Vec<Vec<String>>> = Reflect::get(&options, &jval!("headers"))
            .map(|val| {
                if val.is_truthy() {
                    Some(utils::entries_of_object(&Object::from(val)))
                } else {
                    None
                }
            })
            .unwrap_or(None);

        let mut builder = Request::builder().uri(uri.clone()).method(req_method);

        let headers_map = builder.headers_mut().replace_err("Failed to get headers")?;
        headers_map.insert("Accept-Encoding", HeaderValue::from_str("gzip, br")?);
        headers_map.insert("Connection", HeaderValue::from_str("close")?);
        headers_map.insert("User-Agent", HeaderValue::from_str(&self.useragent)?);
        headers_map.insert("Host", HeaderValue::from_str(uri_host)?);
        if body_bytes.is_empty() {
            headers_map.insert("Content-Length", HeaderValue::from_str("0")?);
        }

        if let Some(headers) = headers {
            for hdr in headers {
                headers_map.insert(
                    HeaderName::from_bytes(hdr[0].as_bytes())
                        .replace_err("Failed to get hdr name")?,
                    HeaderValue::from_str(hdr[1].clone().as_ref())
                        .replace_err("Failed to get hdr value")?,
                );
            }
        }

        let request = builder
            .body(HttpBody::new(body_bytes))
            .replace_err("Failed to make request")?;

        let (resp, last_url, req_redirected) = self.send_req(request, req_should_redirect).await?;

        let resp_headers_raw = resp.headers().clone();

        let resp_headers_jsarray = resp
            .headers()
            .iter()
            .filter_map(|val| {
                Some(Array::of2(
                    &jval!(val.0.as_str()),
                    &jval!(val.1.to_str().ok()?),
                ))
            })
            .collect::<Array>();

        let resp_headers = Object::from_entries(&resp_headers_jsarray)
            .replace_err("Failed to create response headers object")?;

        let mut respinit = web_sys::ResponseInit::new();
        respinit
            .headers(&resp_headers)
            .status(resp.status().as_u16())
            .status_text(resp.status().canonical_reason().unwrap_or_default());

        let compression = match resp
            .headers()
            .get("Content-Encoding")
            .and_then(|val| val.to_str().ok())
            .unwrap_or_default()
        {
            "gzip" => Some(EpxCompression::Gzip),
            "br" => Some(EpxCompression::Brotli),
            _ => None,
        };

        let incoming_body = IncomingBody::new(resp.into_body());
        let decompressed_body = match compression {
            Some(alg) => match alg {
                EpxCompression::Gzip => Either::Left(Either::Left(ReaderStream::new(
                    async_comp::GzipDecoder::new(StreamReader::new(incoming_body)),
                ))),
                EpxCompression::Brotli => Either::Left(Either::Right(ReaderStream::new(
                    async_comp::BrotliDecoder::new(StreamReader::new(incoming_body)),
                ))),
            },
            None => Either::Right(incoming_body),
        };
        let stream = wasm_streams::ReadableStream::from_stream(decompressed_body.map(|x| {
            Ok(Uint8Array::from(
                x.replace_err_jv("Failed to get frame from response")?
                    .as_ref(),
            )
            .into())
        }));

        let resp = web_sys::Response::new_with_opt_readable_stream_and_init(
            Some(&stream.into_raw()),
            &respinit,
        )
        .replace_err("Failed to make response")?;

        Object::define_property(
            &resp,
            &jval!("url"),
            &utils::define_property_obj(jval!(last_url.to_string()), false)
                .replace_err("Failed to make define_property object for url")?,
        );

        Object::define_property(
            &resp,
            &jval!("redirected"),
            &utils::define_property_obj(jval!(req_redirected), false)
                .replace_err("Failed to make define_property object for redirected")?,
        );

        let raw_headers = Object::new();
        for (k, v) in resp_headers_raw.iter() {
            if let Ok(jv) = Reflect::get(&raw_headers, &jval!(k.to_string())) {
                if jv.is_array() {
                    let arr = Array::from(&jv);

                    arr.push(&jval!(v.to_str()?.to_string()));
                    let _ = Reflect::set(&raw_headers, &jval!(k.to_string()), &arr);
                } else if jv.is_truthy() {
                    let _ = Reflect::set(
                        &raw_headers,
                        &jval!(k.to_string()),
                        &Array::of2(&jv, &jval!(v.to_str()?.to_string())),
                    );
                } else {
                    let _ = Reflect::set(
                        &raw_headers,
                        &jval!(k.to_string()),
                        &jval!(v.to_str()?.to_string()),
                    );
                }
            }
        }
        Object::define_property(
            &resp,
            &jval!("rawHeaders"),
            &utils::define_property_obj(jval!(&raw_headers), false).replace_err("wjat!!")?,
        );

        Ok(resp)
    }
}
