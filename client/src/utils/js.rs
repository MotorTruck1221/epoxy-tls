use std::{
	pin::Pin,
	task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::{AsyncRead, Stream, StreamExt, TryStreamExt};
use http_body_util::{Either, Full, StreamBody};
use js_sys::{Array, JsString, Object, Uint8Array};
use send_wrapper::SendWrapper;
use wasm_bindgen::{prelude::*, JsCast, JsValue};
use wasm_streams::ReadableStream;

use crate::{console_error, EpoxyError};

use super::ReaderStream;

#[wasm_bindgen(inline_js = r#"
export function ws_protocol() {
	return (
      [1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,
      c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    );
}

export function object_get(obj, k) { 
	try {
		return obj[k]
	} catch(x) {
		return undefined
	}
};
export function object_set(obj, k, v) {
	try { obj[k] = v } catch {}
};

export async function convert_body_inner(body) {
	let req = new Request("", { method: "POST", duplex: "half", body });
	let type = req.headers.get("content-type");
	return [new Uint8Array(await req.arrayBuffer()), type];
}

export async function convert_streaming_body_inner(body) {
	try {
		let req = new Request("", { method: "POST", body });
		let type = req.headers.get("content-type");
		return [false, new Uint8Array(await req.arrayBuffer()), type];
	} catch(x) {
		let req = new Request("", { method: "POST", duplex: "half", body });
		let type = req.headers.get("content-type");
		return [true, req.body, type];
	}
}

export function entries_of_object_inner(obj) {
	return Object.entries(obj).map(x => x.map(String));
}

export function define_property(obj, k, v) {
	Object.defineProperty(obj, k, { value: v, writable: false });
}

export function ws_key() {
	let key = new Uint8Array(16);
	crypto.getRandomValues(key);
	return btoa(String.fromCharCode.apply(null, key));
}

export function from_entries(entries){
    var ret = {};
    for(var i = 0; i < entries.length; i++) ret[entries[i][0]] = entries[i][1];
    return ret;
}
"#)]
extern "C" {
	pub fn object_get(obj: &Object, key: &str) -> JsValue;
	pub fn object_set(obj: &Object, key: &str, val: JsValue);

	#[wasm_bindgen(catch)]
	async fn convert_body_inner(val: JsValue) -> Result<JsValue, JsValue>;
	#[wasm_bindgen(catch)]
	async fn convert_streaming_body_inner(val: JsValue) -> Result<JsValue, JsValue>;

	fn entries_of_object_inner(obj: &Object) -> Vec<Array>;
	pub fn define_property(obj: &Object, key: &str, val: JsValue);
	pub fn ws_key() -> String;
	pub fn ws_protocol() -> String;

	#[wasm_bindgen(catch)]
	pub fn from_entries(iterable: &JsValue) -> Result<Object, JsValue>;
}

pub async fn convert_body(val: JsValue) -> Result<(Uint8Array, Option<String>), JsValue> {
	let req: Array = convert_body_inner(val).await?.unchecked_into();
	let content_type: Option<JsString> = object_truthy(req.at(1)).map(wasm_bindgen::JsCast::unchecked_into);
	Ok((req.at(0).unchecked_into(), content_type.map(Into::into)))
}

pub enum MaybeStreamingBody {
	Streaming(web_sys::ReadableStream),
	Static(Uint8Array),
}

pub struct StreamingInnerBody(
	Pin<Box<dyn Stream<Item = Result<http_body::Frame<Bytes>, std::io::Error>> + Send>>,
	SendWrapper<ReadableStream>,
);
impl StreamingInnerBody {
	pub fn from_teed(a: ReadableStream, b: ReadableStream) -> Result<Self, EpoxyError> {
		let reader = a
			.try_into_stream()
			.map_err(|x| EpoxyError::StreamingBodyConvertFailed(format!("{x:?}")))?;
		let reader = reader
			.then(|x| async {
				Ok::<Bytes, JsValue>(Bytes::from(convert_body(x?).await?.0.to_vec()))
			})
			.map_ok(http_body::Frame::data);
		let reader = reader.map_err(|x| std::io::Error::other(format!("{x:?}")));
		let reader = Box::pin(SendWrapper::new(reader));

		Ok(Self(reader, SendWrapper::new(b)))
	}
}
impl Stream for StreamingInnerBody {
	type Item = Result<http_body::Frame<Bytes>, std::io::Error>;
	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.0.poll_next_unpin(cx)
	}
	fn size_hint(&self) -> (usize, Option<usize>) {
		self.0.size_hint()
	}
}
impl Clone for StreamingInnerBody {
	fn clone(&self) -> Self {
		match ReadableStream::from_raw(self.1.as_raw().clone())
			.try_tee()
			.map_err(|x| EpoxyError::StreamingBodyTeeFailed(format!("{x:?}")))
			.and_then(|(a, b)| StreamingInnerBody::from_teed(a, b))
		{
			Ok(x) => x,
			Err(x) => {
				console_error!(
					"epoxy internal error: failed to clone streaming body: {:?}",
					x
				);
				unreachable!("failed to clone streaming body");
			}
		}
	}
}

pub type StreamingBody = Either<StreamBody<StreamingInnerBody>, Full<Bytes>>;

impl MaybeStreamingBody {
	pub fn into_httpbody(self) -> Result<StreamingBody, EpoxyError> {
		match self {
			Self::Streaming(x) => {
				let (a, b) = ReadableStream::from_raw(x)
					.try_tee()
					.map_err(|x| EpoxyError::StreamingBodyTeeFailed(format!("{x:?}")))?;

				Ok(Either::Left(StreamBody::new(
					StreamingInnerBody::from_teed(a, b)?,
				)))
			}
			Self::Static(x) => Ok(Either::Right(Full::new(Bytes::from(x.to_vec())))),
		}
	}
}

pub async fn convert_streaming_body(
	val: JsValue,
) -> Result<(MaybeStreamingBody, Option<String>), JsValue> {
	let req: Array = convert_streaming_body_inner(val).await?.unchecked_into();
	let content_type: Option<JsString> = object_truthy(req.at(2)).map(wasm_bindgen::JsCast::unchecked_into);

	let body = if req.at(0).is_truthy() {
		MaybeStreamingBody::Streaming(req.at(1).unchecked_into())
	} else {
		MaybeStreamingBody::Static(req.at(1).unchecked_into())
	};

	Ok((body, content_type.map(Into::into)))
}

pub fn entries_of_object(obj: &Object) -> Vec<Vec<String>> {
	entries_of_object_inner(obj)
		.into_iter()
		.map(|x| {
			x.iter()
				.map(|x| x.unchecked_into::<JsString>().into())
				.collect()
		})
		.collect()
}

pub fn asyncread_to_readablestream(
	read: Pin<Box<dyn AsyncRead>>,
	buffer_size: usize,
) -> web_sys::ReadableStream {
	ReadableStream::from_stream(
		ReaderStream::new(read, buffer_size)
			.map_ok(|x| Uint8Array::from(x.as_ref()).into())
			.map_err(|x| EpoxyError::from(x).into()),
	)
	.into_raw()
}

pub fn object_truthy(val: JsValue) -> Option<JsValue> {
	if val.is_truthy() {
		Some(val)
	} else {
		None
	}
}
