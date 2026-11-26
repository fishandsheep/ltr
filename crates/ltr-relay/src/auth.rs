//! HMAC challenge-response authentication for LTR clients and servers.

use std::num::NonZeroU32;

use anyhow::{bail, ensure, Result};
use aws_lc_rs::pbkdf2;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::shared::{ClientMessage, Delimited, ServerMessage};

/// Domain-separation salt for the secret stretching step. Bump the version
/// when the derivation changes so old and new peers fail closed.
const KDF_SALT: &[u8] = b"ltr-auth-v2";

/// PBKDF2-HMAC-SHA256 work factor (OWASP's current recommendation). Paid once
/// per client or server, so a stolen handshake cannot be checked against
/// guessed secrets at raw SHA-256 speed.
const KDF_ITERATIONS: NonZeroU32 = match NonZeroU32::new(600_000) {
    Some(iterations) => iterations,
    None => panic!("KDF iterations must be non-zero"),
};

/// Wrapper around a MAC used for authenticating clients that have a secret.
pub struct Authenticator(Hmac<Sha256>);

impl Authenticator {
    /// Generate an authenticator from a secret.
    ///
    /// The secret is stretched with PBKDF2 before it keys the HMAC, so each
    /// captured challenge/response pair costs an attacker a full KDF per guess.
    pub fn new(secret: &str) -> Self {
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            KDF_ITERATIONS,
            KDF_SALT,
            secret.as_bytes(),
            &mut key,
        );
        Self(Hmac::new_from_slice(&key).expect("HMAC can take key of any size"))
    }

    /// Generate a reply message for a challenge.
    pub fn answer(&self, challenge: &Uuid) -> String {
        let mut hmac = self.0.clone();
        hmac.update(challenge.as_bytes());
        hex::encode(hmac.finalize().into_bytes())
    }

    /// Validate a reply to a challenge.
    ///
    /// ```
    /// use ltr_relay::auth::Authenticator;
    /// use uuid::Uuid;
    ///
    /// let auth = Authenticator::new("secret");
    /// let challenge = Uuid::new_v4();
    ///
    /// assert!(auth.validate(&challenge, &auth.answer(&challenge)));
    /// assert!(!auth.validate(&challenge, "wrong answer"));
    /// ```
    pub fn validate(&self, challenge: &Uuid, tag: &str) -> bool {
        if let Ok(tag) = hex::decode(tag) {
            let mut hmac = self.0.clone();
            hmac.update(challenge.as_bytes());
            hmac.verify_slice(&tag).is_ok()
        } else {
            false
        }
    }

    /// As the server, send a challenge to the client and validate their response.
    pub async fn server_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut Delimited<T>,
    ) -> Result<()> {
        let challenge = Uuid::new_v4();
        stream.send(ServerMessage::Challenge(challenge)).await?;
        match stream.recv_timeout().await? {
            Some(ClientMessage::Authenticate(tag)) => {
                ensure!(self.validate(&challenge, &tag), "invalid secret");
                Ok(())
            }
            _ => bail!("server requires secret, but no secret was provided"),
        }
    }

    /// As the client, answer a challenge to attempt to authenticate with the server.
    pub async fn client_handshake<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut Delimited<T>,
    ) -> Result<()> {
        let challenge = match stream.recv_timeout().await? {
            Some(ServerMessage::Challenge(challenge)) => challenge,
            _ => bail!("expected authentication challenge, but no secret was required"),
        };
        let tag = self.answer(&challenge);
        stream.send(ClientMessage::Authenticate(tag)).await?;
        Ok(())
    }
}
