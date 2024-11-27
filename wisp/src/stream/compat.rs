use std::{
	pin::Pin,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{
	ready, stream::IntoAsyncRead, task::noop_waker_ref, AsyncBufRead, AsyncRead, AsyncWrite, Sink,
	Stream, TryStreamExt,
};
use pin_project_lite::pin_project;

use crate::{ws::Payload, AtomicCloseReason, CloseReason, WispError};

pin_project! {
	/// Multiplexor stream that implements futures `Stream + Sink`.
	pub struct MuxStreamIo {
		#[pin]
		pub(crate) rx: MuxStreamIoStream,
		#[pin]
		pub(crate) tx: MuxStreamIoSink,
	}
}

impl MuxStreamIo {
	/// Turn the stream into one that implements futures `AsyncRead + AsyncBufRead + AsyncWrite`.
	pub fn into_asyncrw(self) -> MuxStreamAsyncRW {
		MuxStreamAsyncRW {
			rx: self.rx.into_asyncread(),
			tx: self.tx.into_asyncwrite(),
		}
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.rx.get_close_reason()
	}

	/// Split the stream into read and write parts, consuming it.
	pub fn into_split(self) -> (MuxStreamIoStream, MuxStreamIoSink) {
		(self.rx, self.tx)
	}
}

impl Stream for MuxStreamIo {
	type Item = Result<Bytes, std::io::Error>;
	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.project().rx.poll_next(cx)
	}
}

impl Sink<BytesMut> for MuxStreamIo {
	type Error = std::io::Error;
	fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.project().tx.poll_ready(cx)
	}
	fn start_send(self: Pin<&mut Self>, item: BytesMut) -> Result<(), Self::Error> {
		self.project().tx.start_send(item)
	}
	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.project().tx.poll_flush(cx)
	}
	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.project().tx.poll_close(cx)
	}
}

pin_project! {
	/// Read side of a multiplexor stream that implements futures `Stream`.
	pub struct MuxStreamIoStream {
		#[pin]
		pub(crate) rx: Pin<Box<dyn Stream<Item = Result<Bytes, WispError>> + Send>>,
		pub(crate) is_closed: Arc<AtomicBool>,
		pub(crate) close_reason: Arc<AtomicCloseReason>,
	}
}

impl MuxStreamIoStream {
	/// Turn the stream into one that implements futures `AsyncRead + AsyncBufRead`.
	pub fn into_asyncread(self) -> MuxStreamAsyncRead {
		MuxStreamAsyncRead::new(self)
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		if self.is_closed.load(Ordering::Acquire) {
			Some(self.close_reason.load(Ordering::Acquire))
		} else {
			None
		}
	}
}

impl Stream for MuxStreamIoStream {
	type Item = Result<Bytes, std::io::Error>;
	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.project()
			.rx
			.poll_next(cx)
			.map_err(std::io::Error::other)
	}
}

pin_project! {
	/// Write side of a multiplexor stream that implements futures `Sink`.
	pub struct MuxStreamIoSink {
		#[pin]
		pub(crate) tx: Pin<Box<dyn Sink<Payload<'static>, Error = WispError> + Send>>,
		pub(crate) is_closed: Arc<AtomicBool>,
		pub(crate) close_reason: Arc<AtomicCloseReason>,
	}
}

impl MuxStreamIoSink {
	/// Turn the sink into one that implements futures `AsyncWrite`.
	pub fn into_asyncwrite(self) -> MuxStreamAsyncWrite {
		MuxStreamAsyncWrite::new(self)
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		if self.is_closed.load(Ordering::Acquire) {
			Some(self.close_reason.load(Ordering::Acquire))
		} else {
			None
		}
	}
}

impl Sink<BytesMut> for MuxStreamIoSink {
	type Error = std::io::Error;
	fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.project()
			.tx
			.poll_ready(cx)
			.map_err(std::io::Error::other)
	}
	fn start_send(self: Pin<&mut Self>, item: BytesMut) -> Result<(), Self::Error> {
		self.project()
			.tx
			.start_send(Payload::Bytes(item))
			.map_err(std::io::Error::other)
	}
	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.project()
			.tx
			.poll_flush(cx)
			.map_err(std::io::Error::other)
	}
	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.project()
			.tx
			.poll_close(cx)
			.map_err(std::io::Error::other)
	}
}

pin_project! {
	/// Multiplexor stream that implements futures `AsyncRead + AsyncBufRead + AsyncWrite`.
	pub struct MuxStreamAsyncRW {
		#[pin]
		rx: MuxStreamAsyncRead,
		#[pin]
		tx: MuxStreamAsyncWrite,
	}
}

impl MuxStreamAsyncRW {
	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.rx.get_close_reason()
	}

	/// Split the stream into read and write parts, consuming it.
	pub fn into_split(self) -> (MuxStreamAsyncRead, MuxStreamAsyncWrite) {
		(self.rx, self.tx)
	}
}

impl AsyncRead for MuxStreamAsyncRW {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<std::io::Result<usize>> {
		self.project().rx.poll_read(cx, buf)
	}

	fn poll_read_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [std::io::IoSliceMut<'_>],
	) -> Poll<std::io::Result<usize>> {
		self.project().rx.poll_read_vectored(cx, bufs)
	}
}

impl AsyncBufRead for MuxStreamAsyncRW {
	fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
		self.project().rx.poll_fill_buf(cx)
	}

	fn consume(self: Pin<&mut Self>, amt: usize) {
		self.project().rx.consume(amt);
	}
}

impl AsyncWrite for MuxStreamAsyncRW {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		self.project().tx.poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().tx.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().tx.poll_close(cx)
	}
}

pin_project! {
	/// Read side of a multiplexor stream that implements futures `AsyncRead + AsyncBufRead`.
	pub struct MuxStreamAsyncRead {
		#[pin]
		rx: IntoAsyncRead<MuxStreamIoStream>,
		is_closed: Arc<AtomicBool>,
		close_reason: Arc<AtomicCloseReason>,
	}
}

impl MuxStreamAsyncRead {
	pub(crate) fn new(stream: MuxStreamIoStream) -> Self {
		Self {
			is_closed: stream.is_closed.clone(),
			close_reason: stream.close_reason.clone(),
			rx: stream.into_async_read(),
		}
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		if self.is_closed.load(Ordering::Acquire) {
			Some(self.close_reason.load(Ordering::Acquire))
		} else {
			None
		}
	}
}

impl AsyncRead for MuxStreamAsyncRead {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<std::io::Result<usize>> {
		self.project().rx.poll_read(cx, buf)
	}
}
impl AsyncBufRead for MuxStreamAsyncRead {
	fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
		self.project().rx.poll_fill_buf(cx)
	}
	fn consume(self: Pin<&mut Self>, amt: usize) {
		self.project().rx.consume(amt);
	}
}

pin_project! {
	/// Write side of a multiplexor stream that implements futures `AsyncWrite`.
	pub struct MuxStreamAsyncWrite {
		#[pin]
		tx: MuxStreamIoSink,
		error: Option<std::io::Error>
	}
}

impl MuxStreamAsyncWrite {
	pub(crate) fn new(sink: MuxStreamIoSink) -> Self {
		Self {
			tx: sink,
			error: None,
		}
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.tx.get_close_reason()
	}
}

impl AsyncWrite for MuxStreamAsyncWrite {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		if let Some(err) = self.error.take() {
			return Poll::Ready(Err(err));
		}

		let mut this = self.as_mut().project();

		ready!(this.tx.as_mut().poll_ready(cx))?;
		match this.tx.as_mut().start_send(buf.into()) {
			Ok(()) => {
				let mut cx = Context::from_waker(noop_waker_ref());
				let cx = &mut cx;

				match this.tx.poll_flush(cx) {
					Poll::Ready(Err(err)) => {
						self.error = Some(err);
					}
					Poll::Ready(Ok(())) | Poll::Pending => {}
				}

				Poll::Ready(Ok(buf.len()))
			}
			Err(e) => Poll::Ready(Err(e)),
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().tx.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().tx.poll_close(cx)
	}
}
