//! OPAQUE Login Flow

use super::{
    ClientLoginResult, DefaultCipherSuite, OpaqueServer, PasswordFile, ServerLoginResult,
};
use crate::error::{OprfError, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialRequest, CredentialResponse,
    RegistrationUpload, ServerLogin, ServerLoginStartParameters,
};

/// Client state during login
pub struct LoginClient {
    state: ClientLogin<DefaultCipherSuite>,
    password: Vec<u8>,
    user_id: String,
}

impl LoginClient {
    /// Start a login flow
    pub fn start(
        user_id: impl Into<String>,
        password: &[u8],
    ) -> Result<(Self, LoginRequestMessage)> {
        let result = ClientLogin::<DefaultCipherSuite>::start(&mut OsRng, password)
            .map_err(|e| OprfError::LoginFailed(format!("{:?}", e)))?;

        let request = LoginRequestMessage {
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

    /// Finish login after receiving server response
    pub fn finish(
        self,
        response: &LoginResponseMessage,
        server_id: &str,
    ) -> Result<(ClientLoginResult, LoginFinishMessage)> {
        let server_response =
            CredentialResponse::<DefaultCipherSuite>::deserialize(&response.data)
                .map_err(|e| OprfError::LoginFailed(format!("deserialize response: {:?}", e)))?;

        let params = ClientLoginFinishParameters::new(
            None, // No context
            opaque_ke::Identifiers {
                client: Some(self.user_id.as_bytes()),
                server: Some(server_id.as_bytes()),
            },
            None, // No custom key exchange
        );

        let result = self
            .state
            .finish(&self.password, server_response, params)
            .map_err(|e| OprfError::LoginFailed(format!("finish: {:?}", e)))?;

        let finish_message = LoginFinishMessage {
            data: result.message.serialize().to_vec(),
        };

        let session_key: [u8; 64] = result
            .session_key
            .try_into()
            .map_err(|_| OprfError::LoginFailed("session key size mismatch".to_string()))?;

        let export_key: [u8; 64] = result
            .export_key
            .try_into()
            .map_err(|_| OprfError::LoginFailed("export key size mismatch".to_string()))?;

        Ok((
            ClientLoginResult::new(session_key, export_key),
            finish_message,
        ))
    }
}

impl Drop for LoginClient {
    fn drop(&mut self) {
        // Zeroize password on drop
        self.password.iter_mut().for_each(|b| *b = 0);
    }
}

/// Login request from client to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequestMessage {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Login response from server to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponseMessage {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Final login message from client to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishMessage {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Server state during login
pub struct LoginServer {
    state: ServerLogin<DefaultCipherSuite>,
}

impl LoginServer {
    /// Start processing a login request
    pub fn start(
        server: &OpaqueServer,
        password_file: &PasswordFile,
        request: &LoginRequestMessage,
        user_id: &str,
    ) -> Result<(Self, LoginResponseMessage)> {
        let client_request =
            CredentialRequest::<DefaultCipherSuite>::deserialize(&request.data)
                .map_err(|e| OprfError::LoginFailed(format!("deserialize request: {:?}", e)))?;

        let password_record =
            RegistrationUpload::<DefaultCipherSuite>::deserialize(&password_file.data)
                .map_err(|e| OprfError::LoginFailed(format!("deserialize password file: {:?}", e)))?;

        // Convert RegistrationUpload to ServerRegistration
        let server_registration = password_record;

        let params = ServerLoginStartParameters {
            context: None,
            identifiers: opaque_ke::Identifiers {
                client: Some(user_id.as_bytes()),
                server: Some(server.server_id().as_bytes()),
            },
        };

        let result = ServerLogin::<DefaultCipherSuite>::start(
            &mut OsRng,
            server.setup(),
            Some(server_registration),
            client_request,
            user_id.as_bytes(),
            params,
        )
        .map_err(|e| OprfError::LoginFailed(format!("server start: {:?}", e)))?;

        let response = LoginResponseMessage {
            data: result.message.serialize().to_vec(),
        };

        Ok((Self { state: result.state }, response))
    }

    /// Finish login after receiving client's final message
    pub fn finish(self, finish: &LoginFinishMessage) -> Result<ServerLoginResult> {
        let client_finish = opaque_ke::CredentialFinalization::<DefaultCipherSuite>::deserialize(
            &finish.data,
        )
        .map_err(|e| OprfError::LoginFailed(format!("deserialize finish: {:?}", e)))?;

        let result = self
            .state
            .finish(client_finish)
            .map_err(|e| OprfError::LoginFailed(format!("server finish: {:?}", e)))?;

        let session_key: [u8; 64] = result
            .session_key
            .try_into()
            .map_err(|_| OprfError::LoginFailed("session key size mismatch".to_string()))?;

        Ok(ServerLoginResult::new(session_key))
    }
}

/// Complete login flow helper
pub fn login(
    server: &OpaqueServer,
    password_file: &PasswordFile,
    password: &[u8],
) -> Result<(ClientLoginResult, ServerLoginResult)> {
    let user_id = &password_file.user_id;

    // Client starts login
    let (client, request) = LoginClient::start(user_id, password)?;

    // Server processes request
    let (server_login, response) = LoginServer::start(server, password_file, &request, user_id)?;

    // Client finishes login
    let (client_result, finish) = client.finish(&response, server.server_id())?;

    // Server finishes login
    let server_result = server_login.finish(&finish)?;

    Ok((client_result, server_result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_request() {
        let result = LoginClient::start("test@user.com", b"password123");
        assert!(result.is_ok());
        let (_, request) = result.unwrap();
        assert!(!request.data.is_empty());
    }
}
