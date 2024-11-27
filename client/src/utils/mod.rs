mod js;
mod rustls;
pub use js::*;
pub use rustls::*;

use std::{
	pin::Pin,
	task::{Context, Poll},
};

use bytes::{buf::UninitSlice, BufMut, Bytes, BytesMut};
use futures_util::{ready, AsyncRead, Future, Stream};
use http::{HeaderValue, Uri};
use hyper::rt::Executor;
use js_sys::Uint8Array;
use pin_project_lite::pin_project;
use send_wrapper::SendWrapper;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::WritableStreamDefaultWriter;
use wisp_mux::{
	ws::{Frame, WebSocketWrite},
	WispError,
};

use crate::EpoxyError;

#[wasm_bindgen]
extern "C" {
	#[wasm_bindgen(js_namespace = console, js_name = log)]
	pub fn js_console_log(s: &str);

	#[wasm_bindgen(js_namespace = console, js_name = warn)]
	pub fn js_console_warn(s: &str);

	#[wasm_bindgen(js_namespace = console, js_name = error)]
	pub fn js_console_error(s: &str);
}

#[macro_export]
macro_rules! console_log {
	($($expr:expr),*) => {
		$crate::utils::js_console_log(&format!($($expr),*))
	};
}
#[macro_export]
macro_rules! console_warn {
	($($expr:expr),*) => {
		$crate::utils::js_console_warn(&format!($($expr),*))
	};
}

#[macro_export]
macro_rules! console_error {
	($($expr:expr),*) => {
		$crate::utils::js_console_error(&format!($($expr),*))
	};
}

pub fn is_redirect(code: u16) -> bool {
	[301, 302, 303, 307, 308].contains(&code)
}

pub fn is_null_body(code: u16) -> bool {
	[101, 204, 205, 304].contains(&code)
}

pub trait UriExt {
	fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, EpoxyError>;
}

impl UriExt for Uri {
	fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, EpoxyError> {
		let new_uri = location.to_str()?.parse::<hyper::Uri>()?;
		let mut new_parts: http::uri::Parts = new_uri.into();
		if new_parts.scheme.is_none() {
			new_parts.scheme = self.scheme().cloned();
		}
		if new_parts.authority.is_none() {
			new_parts.authority = self.authority().cloned();
		}

		Ok(Uri::from_parts(new_parts)?)
	}
}

#[derive(Clone)]
pub struct WasmExecutor;

impl<F> Executor<F> for WasmExecutor
where
	F: Future + Send + 'static,
	F::Output: Send + 'static,
{
	fn execute(&self, future: F) {
		wasm_bindgen_futures::spawn_local(async move {
			let _ = future.await;
		});
	}
}

pin_project! {
	#[derive(Debug)]
	pub struct ReaderStream<R> {
		#[pin]
		reader: Option<R>,
		buf: BytesMut,
		capacity: usize,
	}
}

impl<R: AsyncRead> ReaderStream<R> {
	pub fn new(reader: R, capacity: usize) -> Self {
		ReaderStream {
			reader: Some(reader),
			buf: BytesMut::new(),
			capacity,
		}
	}
}

pub fn poll_read_buf<T: AsyncRead + ?Sized, B: BufMut>(
	io: Pin<&mut T>,
	cx: &mut Context<'_>,
	buf: &mut B,
) -> Poll<std::io::Result<usize>> {
	if !buf.has_remaining_mut() {
		return Poll::Ready(Ok(0));
	}

	let n = {
		let dst = buf.chunk_mut();

		let dst =
			unsafe { &mut *(std::ptr::from_mut::<UninitSlice>(dst) as *mut [u8]) };
		ready!(io.poll_read(cx, dst)?)
	};

	unsafe {
		buf.advance_mut(n);
	}

	Poll::Ready(Ok(n))
}

impl<R: AsyncRead> Stream for ReaderStream<R> {
	type Item = std::io::Result<Bytes>;
	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let mut this = self.as_mut().project();

		let Some(reader) = this.reader.as_pin_mut() else {
			return Poll::Ready(None);
		};

		if this.buf.capacity() == 0 {
			this.buf.reserve(*this.capacity);
		}

		match poll_read_buf(reader, cx, &mut this.buf) {
			Poll::Pending => Poll::Pending,
			Poll::Ready(Err(err)) => {
				self.project().reader.set(None);
				Poll::Ready(Some(Err(err)))
			}
			Poll::Ready(Ok(0)) => {
				self.project().reader.set(None);
				Poll::Ready(None)
			}
			Poll::Ready(Ok(_)) => {
				let chunk = this.buf.split();
				Poll::Ready(Some(Ok(chunk.freeze())))
			}
		}
	}
}

pub struct WispTransportWrite {
	pub inner: SendWrapper<WritableStreamDefaultWriter>,
}

impl WebSocketWrite for WispTransportWrite {
	async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError> {
		SendWrapper::new(async {
			let chunk = Uint8Array::from(frame.payload.as_ref()).into();
			JsFuture::from(self.inner.write_with_chunk(&chunk))
				.await
				.map(|_| ())
				.map_err(|x| WispError::WsImplError(Box::new(EpoxyError::wisp_transport(x))))
		})
		.await
	}

	async fn wisp_close(&mut self) -> Result<(), WispError> {
		SendWrapper::new(JsFuture::from(self.inner.abort()))
			.await
			.map(|_| ())
			.map_err(|x| WispError::WsImplError(Box::new(EpoxyError::wisp_transport(x))))
	}
}
