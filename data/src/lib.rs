use serde_derive::{Deserialize, Serialize};

// NOTE: token is currently just argon2::hash(username + password).
// This could be improved to be an actual expirable authentication token.
pub trait Payload: std::fmt::Debug {
    fn token(&self) -> &[u8];
    fn user_id(&self) -> i64;
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct File {
    pub id: i64,
    pub data: Encrypted,
    pub path: Encrypted,
    pub version: i64,
    pub user_id: i64,
    pub token: Vec<u8>,
}

impl File {
    pub fn new(id: i64, data: Encrypted, path: Encrypted) -> Self {
        Self {
            id,
            data,
            path,
            version: 1,
            user_id: 0,
            token: vec![],
        }
    }

    pub fn from_hashes(
        id: i64,
        data_digest: Vec<u8>,
        path_digest: Vec<u8>,
        version: i64,
    ) -> Self {
        Self {
            id,
            data: Encrypted {
                ciphertext: vec![],
                ciphertext_digest: data_digest,
                nonce: vec![],
            },
            path: Encrypted {
                ciphertext: vec![],
                ciphertext_digest: path_digest,
                nonce: vec![],
            },
            version,
            user_id: 0,
            token: vec![],
        }
    }
}

impl Payload for File {
    fn token(&self) -> &[u8] {
        &self.token
    }

    fn user_id(&self) -> i64 {
        self.user_id
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub salt: Vec<u8>,
    pub password_digest: Vec<u8>,
    pub bandwidth: i64,
    pub token: Vec<u8>,
}

impl Payload for User {
    fn token(&self) -> &[u8] {
        &self.token
    }

    fn user_id(&self) -> i64 {
        self.id
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub ciphertext_digest: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl Encrypted {
    pub fn new(ciphertext: Vec<u8>, nonce: Vec<u8>) -> Self {
        let ciphertext_digest = blake3::hash(&ciphertext).as_bytes().to_vec();
        Self {
            ciphertext,
            ciphertext_digest,
            nonce,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateRequest {
    pub user_id: i64,
    pub token: Vec<u8>,
}

impl Payload for UpdateRequest {
    fn token(&self) -> &[u8] {
        &self.token
    }

    fn user_id(&self) -> i64 {
        self.user_id
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileRequest {
    pub user_id: i64,
    pub file_id: i64,
    pub token: Vec<u8>,
}

impl Payload for FileRequest {
    fn token(&self) -> &[u8] {
        &self.token
    }

    fn user_id(&self) -> i64 {
        self.user_id
    }
}
