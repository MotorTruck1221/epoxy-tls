//! Abstraction over WebSocket implementations.
//!
//! Use the [`fastwebsockets`] implementation of these traits as an example for implementing them
//! for other WebSocket implementations.
//!
//! [`fastwebsockets`]: https://github.com/MercuryWorkshop/epoxy-tls/blob/multiplexed/wisp/src/fastwebsockets.rs
use std::{future::Future, ops::Deref, pin::Pin, sync::Arc};

use crate::WispError;
use bytes::{Buf, BytesMut};
use futures::{lock::Mutex, TryFutureExt};

/// Payload of the websocket frame.
#[derive(Debug)]
pub enum Payload<'a> {
	/// Borrowed payload. Currently used when writing data.
	Borrowed(&'a [u8]),
	/// BytesMut payload. Currently used when reading data.
	Bytes(BytesMut),
}

impl From<BytesMut> for Payload<'static> {
	fn from(value: BytesMut) -> Self {
		Self::Bytes(value)
	}
}

impl<'a> From<&'a [u8]> for Payload<'a> {
	fn from(value: &'a [u8]) -> Self {
		Self::Borrowed(value)
	}
}

impl Payload<'_> {
	/// Turn a Payload<'a> into a Payload<'static> by copying the data.
	pub fn into_owned(self) -> Self {
		match self {
			Self::Bytes(x) => Self::Bytes(x),
			Self::Borrowed(x) => Self::Bytes(BytesMut::from(x)),
		}
	}
}

impl From<Payload<'_>> for BytesMut {
	fn from(value: Payload<'_>) -> Self {
		match value {
			Payload::Bytes(x) => x,
			Payload::Borrowed(x) => x.into(),
		}
	}
}

impl Deref for Payload<'_> {
	type Target = [u8];
	fn deref(&self) -> &Self::Target {
		match self {
			Self::Bytes(x) => x.deref(),
			Self::Borrowed(x) => x,
		}
	}
}

impl Clone for Payload<'_> {
	fn clone(&self) -> Self {
		match self {
			Self::Bytes(x) => Self::Bytes(x.clone()),
			Self::Borrowed(x) => Self::Bytes(BytesMut::from(*x)),
		}
	}
}

impl Buf for Payload<'_> {
	fn remaining(&self) -> usize {
		match self {
			Self::Bytes(x) => x.remaining(),
			Self::Borrowed(x) => x.remaining(),
		}
	}

	fn chunk(&self) -> &[u8] {
		match self {
			Self::Bytes(x) => x.chunk(),
			Self::Borrowed(x) => x.chunk(),
		}
	}

	fn advance(&mut self, cnt: usize) {
		match self {
			Self::Bytes(x) => x.advance(cnt),
			Self::Borrowed(x) => x.advance(cnt),
		}
	}
}

/// Opcode of the WebSocket frame.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OpCode {
	/// Text frame.
	Text,
	/// Binary frame.
	Binary,
	/// Close frame.
	Close,
	/// Ping frame.
	Ping,
	/// Pong frame.
	Pong,
}

/// WebSocket frame.
#[derive(Debug, Clone)]
pub struct Frame<'a> {
	/// Whether the frame is finished or not.
	pub finished: bool,
	/// Opcode of the WebSocket frame.
	pub opcode: OpCode,
	/// Payload of the WebSocket frame.
	pub payload: Payload<'a>,
}

impl<'a> Frame<'a> {
	/// Create a new frame.
	pub fn new(opcode: OpCode, payload: Payload<'a>, finished: bool) -> Self {
		Self {
			finished,
			opcode,
			payload,
		}
	}

	/// Create a new text frame.
	pub fn text(payload: Payload<'a>) -> Self {
		Self {
			finished: true,
			opcode: OpCode::Text,
			payload,
		}
	}

	/// Create a new binary frame.
	pub fn binary(payload: Payload<'a>) -> Self {
		Self {
			finished: true,
			opcode: OpCode::Binary,
			payload,
		}
	}

	/// Create a new close frame.
	pub fn close(payload: Payload<'a>) -> Self {
		Self {
			finished: true,
			opcode: OpCode::Close,
			payload,
		}
	}
}

/// Generic WebSocket read trait.
pub trait WebSocketRead: Send {
	/// Read a frame from the socket.
	fn wisp_read_frame(
		&mut self,
		tx: &dyn LockingWebSocketWrite,
	) -> impl Future<Output = Result<Frame<'static>, WispError>> + Send;

	/// Read a split frame from the socket.
	fn wisp_read_split(
		&mut self,
		tx: &dyn LockingWebSocketWrite,
	) -> impl Future<Output = Result<(Frame<'static>, Option<Frame<'static>>), WispError>> + Send {
		self.wisp_read_frame(tx).map_ok(|x| (x, None))
	}
}

// similar to what dynosaur does
mod wsr_inner {
	use std::{future::Future, pin::Pin};

	use crate::WispError;

	use super::{Frame, LockingWebSocketWrite, WebSocketRead};

	trait ErasedWebSocketRead: Send {
		fn wisp_read_frame<'a>(
			&'a mut self,
			tx: &'a dyn LockingWebSocketWrite,
		) -> Pin<Box<dyn Future<Output = Result<Frame<'static>, WispError>> + Send + 'a>>;

		#[allow(clippy::type_complexity)]
		fn wisp_read_split<'a>(
			&'a mut self,
			tx: &'a dyn LockingWebSocketWrite,
		) -> Pin<
			Box<
				dyn Future<Output = Result<(Frame<'static>, Option<Frame<'static>>), WispError>>
					+ Send
					+ 'a,
			>,
		>;
	}

	impl<T: WebSocketRead> ErasedWebSocketRead for T {
		fn wisp_read_frame<'a>(
			&'a mut self,
			tx: &'a dyn LockingWebSocketWrite,
		) -> Pin<Box<dyn Future<Output = Result<Frame<'static>, WispError>> + Send + 'a>> {
			Box::pin(self.wisp_read_frame(tx))
		}

		fn wisp_read_split<'a>(
			&'a mut self,
			tx: &'a dyn LockingWebSocketWrite,
		) -> Pin<
			Box<
				dyn Future<Output = Result<(Frame<'static>, Option<Frame<'static>>), WispError>>
					+ Send
					+ 'a,
			>,
		> {
			Box::pin(self.wisp_read_split(tx))
		}
	}

	/// WebSocketRead trait object.
	#[repr(transparent)]
	pub struct DynWebSocketRead {
		ptr: dyn ErasedWebSocketRead + 'static,
	}
	impl WebSocketRead for DynWebSocketRead {
		async fn wisp_read_frame(
			&mut self,
			tx: &dyn LockingWebSocketWrite,
		) -> Result<Frame<'static>, WispError> {
			self.ptr.wisp_read_frame(tx).await
		}

		async fn wisp_read_split(
			&mut self,
			tx: &dyn LockingWebSocketWrite,
		) -> Result<(Frame<'static>, Option<Frame<'static>>), WispError> {
			self.ptr.wisp_read_split(tx).await
		}
	}
	impl DynWebSocketRead {
		/// Create a WebSocketRead trait object from a boxed WebSocketRead.
		pub fn new(val: Box<impl WebSocketRead + 'static>) -> Box<Self> {
			let val: Box<dyn ErasedWebSocketRead + 'static> = val;
			unsafe { std::mem::transmute(val) }
		}
		/// Create a WebSocketRead trait object from a WebSocketRead.
		pub fn boxed(val: impl WebSocketRead + 'static) -> Box<Self> {
			Self::new(Box::new(val))
		}
		/// Create a WebSocketRead trait object from a WebSocketRead reference.
		pub fn from_ref(val: &(impl WebSocketRead + 'static)) -> &Self {
			let val: &(dyn ErasedWebSocketRead + 'static) = val;
			unsafe { std::mem::transmute(val) }
		}
		/// Create a WebSocketRead trait object from a mutable WebSocketRead reference.
		pub fn from_mut(val: &mut (impl WebSocketRead + 'static)) -> &mut Self {
			let val: &mut (dyn ErasedWebSocketRead + 'static) = &mut *val;
			unsafe { std::mem::transmute(val) }
		}
	}
}
pub use wsr_inner::DynWebSocketRead;

/// Generic WebSocket write trait.
pub trait WebSocketWrite: Send {
	/// Write a frame to the socket.
	fn wisp_write_frame(
		&mut self,
		frame: Frame<'_>,
	) -> impl Future<Output = Result<(), WispError>> + Send;

	/// Write a split frame to the socket.
	fn wisp_write_split(
		&mut self,
		header: Frame<'_>,
		body: Frame<'_>,
	) -> impl Future<Output = Result<(), WispError>> + Send {
		async move {
			let mut payload = BytesMut::from(header.payload);
			payload.extend_from_slice(&body.payload);
			self.wisp_write_frame(Frame::binary(Payload::Bytes(payload)))
				.await
		}
	}

	/// Close the socket.
	fn wisp_close(&mut self) -> impl Future<Output = Result<(), WispError>> + Send;
}

// similar to what dynosaur does
mod wsw_inner {
	use std::{future::Future, pin::Pin};

	use crate::WispError;

	use super::{Frame, WebSocketWrite};

	trait ErasedWebSocketWrite: Send {
		fn wisp_write_frame<'a>(
			&'a mut self,
			frame: Frame<'a>,
		) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>>;

		fn wisp_write_split<'a>(
			&'a mut self,
			header: Frame<'a>,
			body: Frame<'a>,
		) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>>;

		fn wisp_close<'a>(
			&'a mut self,
		) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>>;
	}

	impl<T: WebSocketWrite> ErasedWebSocketWrite for T {
		fn wisp_write_frame<'a>(
			&'a mut self,
			frame: Frame<'a>,
		) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>> {
			Box::pin(self.wisp_write_frame(frame))
		}

		fn wisp_write_split<'a>(
			&'a mut self,
			header: Frame<'a>,
			body: Frame<'a>,
		) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>> {
			Box::pin(self.wisp_write_split(header, body))
		}

		fn wisp_close<'a>(
			&'a mut self,
		) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>> {
			Box::pin(self.wisp_close())
		}
	}

	/// WebSocketWrite trait object.
	#[repr(transparent)]
	pub struct DynWebSocketWrite {
		ptr: dyn ErasedWebSocketWrite + 'static,
	}
	impl WebSocketWrite for DynWebSocketWrite {
		async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError> {
			self.ptr.wisp_write_frame(frame).await
		}

		async fn wisp_write_split(
			&mut self,
			header: Frame<'_>,
			body: Frame<'_>,
		) -> Result<(), WispError> {
			self.ptr.wisp_write_split(header, body).await
		}

		async fn wisp_close(&mut self) -> Result<(), WispError> {
			self.ptr.wisp_close().await
		}
	}
	impl DynWebSocketWrite {
		/// Create a new WebSocketWrite trait object from a boxed WebSocketWrite.
		pub fn new(val: Box<impl WebSocketWrite + 'static>) -> Box<Self> {
			let val: Box<dyn ErasedWebSocketWrite + 'static> = val;
			unsafe { std::mem::transmute(val) }
		}
		/// Create a new WebSocketWrite trait object from a WebSocketWrite.
		pub fn boxed(val: impl WebSocketWrite + 'static) -> Box<Self> {
			Self::new(Box::new(val))
		}
		/// Create a new WebSocketWrite trait object from a WebSocketWrite reference.
		pub fn from_ref(val: &(impl WebSocketWrite + 'static)) -> &Self {
			let val: &(dyn ErasedWebSocketWrite + 'static) = val;
			unsafe { std::mem::transmute(val) }
		}
		/// Create a new WebSocketWrite trait object from a mutable WebSocketWrite reference.
		pub fn from_mut(val: &mut (impl WebSocketWrite + 'static)) -> &mut Self {
			let val: &mut (dyn ErasedWebSocketWrite + 'static) = &mut *val;
			unsafe { std::mem::transmute(val) }
		}
	}
}
pub use wsw_inner::DynWebSocketWrite;

mod private {
	pub trait Sealed {}
}

/// Helper trait object for LockedWebSocketWrite.
pub trait LockingWebSocketWrite: private::Sealed + Sync {
	/// Write a frame to the websocket.
	fn wisp_write_frame<'a>(
		&'a self,
		frame: Frame<'a>,
	) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>>;

	/// Write a split frame to the websocket.
	fn wisp_write_split<'a>(
		&'a self,
		header: Frame<'a>,
		body: Frame<'a>,
	) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>>;

	/// Close the websocket.
	fn wisp_close<'a>(&'a self)
		-> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>>;
}

/// Locked WebSocket.
pub struct LockedWebSocketWrite<T: WebSocketWrite>(Arc<Mutex<T>>);

impl<T: WebSocketWrite> Clone for LockedWebSocketWrite<T> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

impl<T: WebSocketWrite> LockedWebSocketWrite<T> {
	/// Create a new locked websocket.
	pub fn new(ws: T) -> Self {
		Self(Mutex::new(ws).into())
	}

	/// Create a new locked websocket from an existing mutex.
	pub fn from_locked(locked: Arc<Mutex<T>>) -> Self {
		Self(locked)
	}

	/// Write a frame to the websocket.
	pub async fn write_frame(&self, frame: Frame<'_>) -> Result<(), WispError> {
		self.0.lock().await.wisp_write_frame(frame).await
	}

	/// Write a split frame to the websocket.
	pub async fn write_split(&self, header: Frame<'_>, body: Frame<'_>) -> Result<(), WispError> {
		self.0.lock().await.wisp_write_split(header, body).await
	}

	/// Close the websocket.
	pub async fn close(&self) -> Result<(), WispError> {
		self.0.lock().await.wisp_close().await
	}
}

impl<T: WebSocketWrite> private::Sealed for LockedWebSocketWrite<T> {}

impl<T: WebSocketWrite> LockingWebSocketWrite for LockedWebSocketWrite<T> {
	fn wisp_write_frame<'a>(
		&'a self,
		frame: Frame<'a>,
	) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>> {
		Box::pin(self.write_frame(frame))
	}

	fn wisp_write_split<'a>(
		&'a self,
		header: Frame<'a>,
		body: Frame<'a>,
	) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>> {
		Box::pin(self.write_split(header, body))
	}

	fn wisp_close<'a>(
		&'a self,
	) -> Pin<Box<dyn Future<Output = Result<(), WispError>> + Send + 'a>> {
		Box::pin(self.close())
	}
}

/// Combines two different WebSocketReads together.
pub enum EitherWebSocketRead<A: WebSocketRead, B: WebSocketRead> {
	/// First WebSocketRead variant.
	Left(A),
	/// Second WebSocketRead variant.
	Right(B),
}
impl<A: WebSocketRead, B: WebSocketRead> WebSocketRead for EitherWebSocketRead<A, B> {
	async fn wisp_read_frame(
		&mut self,
		tx: &dyn LockingWebSocketWrite,
	) -> Result<Frame<'static>, WispError> {
		match self {
			Self::Left(x) => x.wisp_read_frame(tx).await,
			Self::Right(x) => x.wisp_read_frame(tx).await,
		}
	}

	async fn wisp_read_split(
		&mut self,
		tx: &dyn LockingWebSocketWrite,
	) -> Result<(Frame<'static>, Option<Frame<'static>>), WispError> {
		match self {
			Self::Left(x) => x.wisp_read_split(tx).await,
			Self::Right(x) => x.wisp_read_split(tx).await,
		}
	}
}

/// Combines two different WebSocketWrites together.
pub enum EitherWebSocketWrite<A: WebSocketWrite, B: WebSocketWrite> {
	/// First WebSocketWrite variant.
	Left(A),
	/// Second WebSocketWrite variant.
	Right(B),
}
impl<A: WebSocketWrite, B: WebSocketWrite> WebSocketWrite for EitherWebSocketWrite<A, B> {
	async fn wisp_write_frame(&mut self, frame: Frame<'_>) -> Result<(), WispError> {
		match self {
			Self::Left(x) => x.wisp_write_frame(frame).await,
			Self::Right(x) => x.wisp_write_frame(frame).await,
		}
	}

	async fn wisp_write_split(
		&mut self,
		header: Frame<'_>,
		body: Frame<'_>,
	) -> Result<(), WispError> {
		match self {
			Self::Left(x) => x.wisp_write_split(header, body).await,
			Self::Right(x) => x.wisp_write_split(header, body).await,
		}
	}

	async fn wisp_close(&mut self) -> Result<(), WispError> {
		match self {
			Self::Left(x) => x.wisp_close().await,
			Self::Right(x) => x.wisp_close().await,
		}
	}
}
