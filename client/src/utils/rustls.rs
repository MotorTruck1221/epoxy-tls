use std::{
	io::ErrorKind,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use futures_rustls::{
	rustls::{
		self,
		client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
		crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
		DigitallySignedStruct, SignatureScheme,
	},
	TlsStream,
};
use futures_util::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::stream_provider::ProviderUnencryptedAsyncRW;

fn map_close_notify(x: std::io::Result<usize>) -> std::io::Result<usize> {
	match x {
		Ok(x) => Ok(x),
		Err(x) => {
			// hacky way to find if it's actually a rustls close notify error
			if x.kind() == ErrorKind::UnexpectedEof
				&& format!("{x:?}").contains("TLS close_notify")
			{
				Ok(0)
			} else {
				Err(x)
			}
		}
	}
}

pin_project! {
	pub struct IgnoreCloseNotify {
		#[pin]
		pub inner: TlsStream<ProviderUnencryptedAsyncRW>,
		pub h2_negotiated: bool,
	}
}

impl AsyncRead for IgnoreCloseNotify {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut [u8],
	) -> Poll<std::io::Result<usize>> {
		self.project()
			.inner
			.poll_read(cx, buf)
			.map(map_close_notify)
	}

	fn poll_read_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &mut [std::io::IoSliceMut<'_>],
	) -> Poll<std::io::Result<usize>> {
		self.project()
			.inner
			.poll_read_vectored(cx, bufs)
			.map(map_close_notify)
	}
}

impl AsyncWrite for IgnoreCloseNotify {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		self.project().inner.poll_write(cx, buf)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> Poll<std::io::Result<usize>> {
		self.project().inner.poll_write_vectored(cx, bufs)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().inner.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.project().inner.poll_close(cx)
	}
}

#[derive(Debug)]
pub struct NoCertificateVerification(pub Arc<CryptoProvider>);

impl ServerCertVerifier for NoCertificateVerification {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		verify_tls12_signature(
			message,
			cert,
			dss,
			&self.0.signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		verify_tls13_signature(
			message,
			cert,
			dss,
			&self.0.signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.0.signature_verification_algorithms.supported_schemes()
	}
}
