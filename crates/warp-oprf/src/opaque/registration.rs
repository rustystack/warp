//! OPAQUE Registration Flow

use super::{OpaqueServer, PasswordFile, DefaultCipherSuite};
use crate::error::{OprfError, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters,
    RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerRegistration,
};

/// Client state during registration
pub struct RegistrationClient {
    state: ClientRegistration<DefaultCipherSuite>,
    password: Vec<u8>,
    user_id: String,
}

impl RegistrationClient {
    /// Start a registration flow
    pub fn start(user_id: impl Into<String>, password: &[u8]) -> Result<(Self, RegistrationRequestMessage)> {
        let result = ClientRegistration::<DefaultCipherSuite>::start(&mut OsRng, password)
            .map_err(|e| OprfError::RegistrationFailed(format!("{:?}", e)))?;

        let request = RegistrationRequestMessage {
            data: result.message.serialize().to_vec(),
        };

        Ok((
            Self {
                state: result.state,
                password: password.to_vec(),
                user_id: user_id.into(),
            },
            request,
        ))
    }

    /// Finish registration after receiving server response
    pub fn finish(
        self,
        response: &RegistrationResponseMessage,
        server_id: &str,
    ) -> Result<PasswordFile> {
        let server_response = RegistrationResponse::<DefaultCipherSuite>::deserialize(&response.data)
            .map_err(|e| OprfError::RegistrationFailed(format!("deserialize response: {:?}", e)))?;

        let params = ClientRegistrationFinishParameters::new(
            opaque_ke::Identifiers {
                client: Some(self.user_id.as_bytes()),
                server: Some(server_id.as_bytes()),
            },
            None,
        );

        let result = self
            .state
            .finish(&mut OsRng, &self.password, server_response, params)
            .map_err(|e| OprfError::RegistrationFailed(format!("finish: {:?}", e)))?;

        Ok(PasswordFile::new(&self.user_id, result.message.serialize().to_vec()))
    }
}

impl Drop for RegistrationClient {
    fn drop(&mut self) {
        // Zeroize password on drop
        self.password.iter_mut().for_each(|b| *b = 0);
    }
}

/// Registration request from client to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequestMessage {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Registration response from server to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponseMessage {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Server-side registration handler
pub struct RegistrationServer;

impl RegistrationServer {
    /// Process a registration request
    pub fn process(
        server: &OpaqueServer,
        request: &RegistrationRequestMessage,
        user_id: &str,
    ) -> Result<RegistrationResponseMessage> {
        let client_request = RegistrationRequest::<DefaultCipherSuite>::deserialize(&request.data)
            .map_err(|e| OprfError::RegistrationFailed(format!("deserialize request: {:?}", e)))?;

        let result = ServerRegistration::<DefaultCipherSuite>::start(
            server.setup(),
            client_request,
            user_id.as_bytes(),
        )
        .map_err(|e| OprfError::RegistrationFailed(format!("server start: {:?}", e)))?;

        Ok(RegistrationResponseMessage {
            data: result.message.serialize().to_vec(),
        })
    }

    /// Verify and store a registration upload
    pub fn finish(upload: &PasswordFile) -> Result<()> {
        // Verify the upload can be deserialized
        let _ = RegistrationUpload::<DefaultCipherSuite>::deserialize(&upload.data)
            .map_err(|e| OprfError::RegistrationFailed(format!("invalid upload: {:?}", e)))?;

        Ok(())
    }
}

/// Complete registration flow helper
pub fn register(
    server: &OpaqueServer,
    user_id: &str,
    password: &[u8],
) -> Result<PasswordFile> {
    // Client starts registration
    let (client, request) = RegistrationClient::start(user_id, password)?;

    // Server processes request
    let response = RegistrationServer::process(server, &request, user_id)?;

    // Client finishes registration
    let password_file = client.finish(&response, server.server_id())?;

    // Server verifies upload
    RegistrationServer::finish(&password_file)?;

    Ok(password_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_request() {
        let result = RegistrationClient::start("test@user.com", b"password123");
        assert!(result.is_ok());
        let (_, request) = result.unwrap();
        assert!(!request.data.is_empty());
    }
}
