use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

mod monitor;

pub static USE_PROXY: AtomicBool = AtomicBool::new(false);

lazy_static::lazy_static! {
    pub static ref DB: sqlx::SqlitePool = sqlx::SqlitePool::connect_lazy("live_client.db").unwrap();
}

const SERVER_ENDPOINT: &str = "http://37.235.102.182:3030";

pub async fn run() -> anyhow::Result<()> {
    let rec = sqlx::query!("SELECT * FROM meta;").fetch_one(&*DB).await?;

    let (username, password) = (rec.username, rec.password);

    let user = create_user(&username, &password).await?;

    let dir = create_dir()?;
    let files = get_files(&dir)?;

    let cipher = get_encryption_cipher(&username, &password)?;
    let encrypted_files = encrypt_files(files, &cipher, &user).await?;

    consistency_check(&cipher, &user, encrypted_files).await?;

    let cipher = cipher.clone();
    let user = user.clone();

    // This needs to run last, and must be directly awaited.
    monitor::watch(cipher, user, dir).await?;

    Ok(())
}

#[macro_export]
macro_rules! opt {
    ($o:expr) => {
        match $o {
            Some(v) => v,
            None => anyhow::bail!("failed to get option value"),
        }
    };
}

#[macro_export]
macro_rules! eat_err {
    ($r:expr) => {
        // nom nom nom
        match $r {
            Ok(_) => {}
            Err(e) => log::error!("{}", e),
        }
    };
}

// Create a user with the respective username and password.
async fn create_user(
    username: &str,
    password: &str,
) -> anyhow::Result<data::User> {
    let mut user = data::User {
        id: 0,
        username: username.into(),
        salt: vec![],
        password_digest: hash_login_credentials(username, password)?,
        bandwidth: 0,
        token: vec![],
    };

    log::debug!("Creating user...");

    let id = post("/create_user", bincode::serialize(&user)?)
        .await?
        .bytes()
        .await?;

    user.id = bincode::deserialize(&id)?;

    Ok(user)
}

// This is a consistency check performed every time the program starts to ensure
// everything is in place. We need to re-encrypt and re-hash the ciphertext
// every time as we don't know what changes could have happened while the
// program was offline.
//
// NOTE: If folders or files are renamed or deleted while nymdrive is not being
// run, we will be unable to account for these changes. Due to the encryption
// of the entire directory layout and the filenames, we simply cannot
// reconstruct this information. Accounting for this rare edge case is left as
// future work.
//
// However, if nymdrive was running while the folders or files were renamed or
// deleted, there is no issue.
async fn consistency_check(
    cipher: &chacha20poly1305::XChaCha20Poly1305,
    user: &data::User,
    files: Vec<(String, data::File)>,
) -> anyhow::Result<()> {
    let db_metadata = get_updates(user).await?;

    let mut db_metadata = db_metadata
        .iter()
        .map(|x| (x.id, x))
        .collect::<HashMap<_, _>>();

    for (path, local_file) in files {
        let server_file = match db_metadata.remove(&local_file.id) {
            Some(v) => v,
            None => {
                // This file exists locally but not on the server, which means
                // it was created while nymdrive was not running.
                log::debug!("We have a file that exists locally but not on the server, pushing to server...");
                eat_err!(push_new_file(&cipher, &path, &local_file).await);
                continue;
            }
        };

        let local_digests = (
            &local_file.data.ciphertext_digest,
            &local_file.path.ciphertext_digest,
        );

        let server_digests = (
            &server_file.data.ciphertext_digest,
            &server_file.path.ciphertext_digest,
        );

        let local_ver = local_file.version;
        let server_ver = server_file.version;

        if local_ver != server_ver && local_digests == server_digests {
            log::error!("File #{} matches on both ends, but local version ({}) is different from server version ({})", local_file.id, local_ver, server_ver);
            continue;
        }

        if local_ver >= server_ver {
            // If the local version has a newer version, and the files don't
            // match, push the updated file to the server.
            if local_digests != server_digests {
                log::debug!("File #{} has been changed while nymdrive wasn't running, pushing update to server...", local_file.id);
                eat_err!(push_file_update(cipher, &path, local_file).await);
            }
        } else if local_ver < server_ver {
            // The server has a newer file version, so we should pull this
            // updated file and save it locally.
            log::debug!(
                "Server has newer version of file #{}, pulling update...",
                local_file.id
            );
            eat_err!(pull_file(cipher, &local_file).await);
        }
    }

    // All remaining files in the db_metadata hashmap are necessarily files
    // that exist only on the server and not locally, and therefore need to
    // be downloaded for the first time. This code path would get hit when
    // running nymdrive on a new device, or if a file was deleted when nymdrive
    // was not running.
    for (_, server_file) in db_metadata {
        log::debug!(
            "We found a file that exists only on the server, downloading..."
        );
        eat_err!(pull_file(cipher, &server_file).await);
    }

    Ok(())
}

async fn push_file_update(
    cipher: &chacha20poly1305::XChaCha20Poly1305,
    path: &str,
    mut file: data::File,
) -> anyhow::Result<()> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::XNonce;

    file.version += 1;

    log::debug!("Re-encrypting file #{} with new nonce...", file.id);

    let data_plaintext = tokio::fs::read(path).await?;
    let data_nonce = gen_nonce();
    let path_nonce = gen_nonce();

    let data_ciphertext = cipher
        .encrypt(XNonce::from_slice(&data_nonce), data_plaintext.as_slice())
        .unwrap();
    file.data = data::Encrypted::new(data_ciphertext, data_nonce);

    let path_ciphertext = cipher
        .encrypt(XNonce::from_slice(&path_nonce), path.as_bytes())
        .unwrap();
    file.path = data::Encrypted::new(path_ciphertext, path_nonce);

    log::debug!("Pushing update to file #{} to server...", file.id);

    let body = bincode::serialize(&file)?;
    post("/update_file", body).await?;

    log::debug!("Updating local record of file #{}...", file.id);

    sqlx::query!("UPDATE files SET path = ?, version = ?, data_ciphertext_digest = ?, data_nonce = ?, path_ciphertext_digest = ?, path_nonce = ? WHERE id = ?", path, file.version, file.data.ciphertext_digest, file.data.nonce, file.path.ciphertext_digest, file.path.nonce, file.id)
        .execute(&*DB)
        .await?;

    Ok(())
}

async fn push_new_file(
    cipher: &chacha20poly1305::XChaCha20Poly1305,
    path: &str,
    file: &data::File,
) -> anyhow::Result<()> {
    log::debug!("Pushing new file to server...");

    let body = bincode::serialize(&file)?;
    let res = post("/create_file", body).await?.bytes().await?;
    let new_id: i64 = bincode::deserialize(&res)?;

    log::debug!("Saving file #{}'s metadata to local db...", new_id);

    let res = sqlx::query!("INSERT INTO files (id, path, data_ciphertext_digest, data_nonce, path_ciphertext_digest, path_nonce) VALUES (?, ?, ?, ?, ?, ?)", new_id, path, file.data.ciphertext_digest, file.data.nonce, file.path.ciphertext_digest, file.path.nonce)
        .execute(&*DB)
        .await;

    match res {
        Ok(_) => {}
        Err(e) => {
            if e.to_string().contains("UNIQUE constraint failed") {
                push_file_update(&cipher, path, file.clone()).await?;
            } else {
                Err(e)?;
            }
        }
    }

    Ok(())
}

async fn remove_file(file: &data::File) -> anyhow::Result<()> {
    log::debug!("Removing file #{} from the server...", file.id);

    let file_req = data::FileRequest {
        file_id: file.id,
        user_id: file.user_id,
        token: file.token.clone(),
    };

    post("/remove_file", bincode::serialize(&file_req)?).await?;

    log::debug!("Removing file #{} to local versions db...", file.id);

    sqlx::query!("DELETE FROM files WHERE id = ?;", file.id)
        .execute(&*DB)
        .await?;

    Ok(())
}

// Pulls a file and updates the local copy (or saves it for the first time if
// we are on a new device).
async fn pull_file(
    cipher: &chacha20poly1305::XChaCha20Poly1305,
    file: &data::File,
) -> anyhow::Result<()> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::XNonce;

    log::debug!("Pulling file #{} from the server...", file.id);

    let file_req = data::FileRequest {
        file_id: file.id,
        user_id: file.user_id,
        token: file.token.clone(),
    };

    let res = get("/get_file", bincode::serialize(&file_req)?)
        .await?
        .bytes()
        .await?;
    let file: data::File = bincode::deserialize(&res)?;

    log::debug!("Decrypting file #{} to save locally...", file.id);

    let data_plaintext = cipher
        .decrypt(
            XNonce::from_slice(&file.data.nonce),
            file.data.ciphertext.as_slice(),
        )
        .unwrap();
    let path_plaintext = cipher
        .decrypt(
            XNonce::from_slice(&file.path.nonce),
            file.path.ciphertext.as_slice(),
        )
        .unwrap();

    let path = String::from_utf8(path_plaintext)?;

    log::debug!("Writing file #{} locally...", file.id);

    // Ensure that any directories that exist in the path are created.
    let dirs = opt!(path.rsplit_once('/')).0;
    tokio::fs::create_dir_all(dirs).await?;

    // Write the file contesnt to disk.
    tokio::fs::write(&path, &data_plaintext).await?;

    log::debug!("Saving file #{} to local versions db...", file.id);

    sqlx::query!("DELETE FROM files WHERE id = ?; INSERT INTO files (id, path, version, data_ciphertext_digest, data_nonce, path_ciphertext_digest, path_nonce) VALUES (?, ?, ?, ?, ?, ?, ?);", file.id, file.id, path, file.version, file.data.ciphertext_digest, file.data.nonce, file.path.ciphertext_digest, file.path.nonce)
        .execute(&*DB)
        .await?;

    Ok(())
}

async fn get_updates(user: &data::User) -> anyhow::Result<Vec<data::File>> {
    log::debug!("Requesting updates from the server...");

    let update_req = data::UpdateRequest {
        user_id: user.id,
        token: user.password_digest.clone(),
    };

    let res = get("/get_updates", bincode::serialize(&update_req)?)
        .await?
        .bytes()
        .await?;

    Ok(bincode::deserialize(&res)?)
}

async fn get(
    endpoint: &str,
    body: Vec<u8>,
) -> anyhow::Result<reqwest::Response> {
    request(http::Method::GET, endpoint, body).await
}

async fn post(
    endpoint: &str,
    body: Vec<u8>,
) -> anyhow::Result<reqwest::Response> {
    request(http::Method::POST, endpoint, body).await
}

async fn request(
    method: http::Method,
    endpoint: &str,
    body: Vec<u8>,
) -> anyhow::Result<reqwest::Response> {
    lazy_static::lazy_static! {
        static ref TRUE_ENDPOINT: String = {
            if USE_PROXY.load(Ordering::Relaxed) {
                "http://127.0.0.1:3030".into()
            } else {
                SERVER_ENDPOINT.into()
            }
        };
        static ref HTTP_CLIENT: reqwest::Client = {
            if USE_PROXY.load(Ordering::Relaxed) {
                reqwest::ClientBuilder::new()
                    .proxy(reqwest::Proxy::http("socks5h://127.0.0.1:1080").unwrap())
                    .build()
                    .unwrap()
            } else {
                reqwest::Client::new()
            }
        };
    }

    let endpoint = TRUE_ENDPOINT.clone() + endpoint;

    let res = HTTP_CLIENT
        .request(method, endpoint)
        .body(body)
        .send()
        .await;

    let v = match res {
        Ok(v) => {
            if v.status() == http::StatusCode::UNAUTHORIZED {
                anyhow::bail!("unauthorized")
            } else {
                v
            }
        }
        Err(e) => Err(e)?,
    };

    Ok(v)
}

pub fn create_dir() -> anyhow::Result<std::path::PathBuf> {
    let dir = opt!(home::home_dir()).join("nymdrive");
    std::fs::create_dir_all(dir.clone())?;
    Ok(dir)
}

fn get_files(
    dir: &std::path::PathBuf,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut res = vec![];

    visit_dirs(dir, &mut |e| -> anyhow::Result<()> {
        res.push((opt!(e.path().to_str()).into(), std::fs::read(e.path())?));
        Ok(())
    })?;

    Ok(res)
}

// Generate random nonce with CSPRNG. Our nonces are 192 bits, therefore the
// odds of a collision is negligible.
fn gen_nonce() -> Vec<u8> {
    use rand::Rng;

    let mut nonce = vec![0u8; 24];

    // thread_rng() is guaranteed to always use a CSPRNG
    rand::thread_rng().fill(nonce.as_mut_slice());

    nonce
}

// Username is added as salt for additional entropy.
//
// For authentication, this digest is hashed once more on the server side
// with a randomly generated salt. Hashing both on the client side and server
// side can provide some marginal protections against specific types of attacks.
fn hash_login_credentials(
    username: &str,
    password: &str,
) -> anyhow::Result<Vec<u8>> {
    let argon_config = argon2::Config {
        // We use the argon2id variant as this is the makes it more difficult
        // to brute force while still providing protections against side
        // channel attacks. This is the officially recommended variant.
        variant: argon2::Variant::Argon2id,
        ..Default::default()
    };

    // hash the username to stretch its length to the required amount by argon
    let salt = blake3::hash(username.as_bytes());

    Ok(argon2::hash_raw(
        password.as_bytes(),
        salt.as_bytes(),
        &argon_config,
    )?)
}

fn get_encryption_cipher(
    username: &str,
    password: &str,
) -> anyhow::Result<chacha20poly1305::XChaCha20Poly1305> {
    use chacha20poly1305::aead::NewAead;
    use chacha20poly1305::{Key, XChaCha20Poly1305};

    // This is a global salt used to ensure that the encryption key is distinct
    // from the authentication that is sent to the server. Without this, we
    // would effectively leak our encryption key to the service provider every
    // time a user signs in.
    const LOCAL_ENCRYPTION_SALT: &str = "LOCAL_ENCRYPTION_SALT";

    let password = LOCAL_ENCRYPTION_SALT.to_string() + password;
    let password_digest = hash_login_credentials(&username, &password)?;
    let key = Key::from_slice(&password_digest);

    Ok(XChaCha20Poly1305::new(key))
}

// files are passed in as (path, data)
async fn encrypt_files(
    files: Vec<(String, Vec<u8>)>,
    cipher: &chacha20poly1305::XChaCha20Poly1305,
    user: &data::User,
) -> anyhow::Result<Vec<(String, data::File)>> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::XNonce;

    let db_metadata = sqlx::query!(
        "SELECT id, path, data_nonce, path_nonce, version FROM files;"
    )
    .fetch_all(&*DB)
    .await?;

    let mut db_metadata = db_metadata
        .iter()
        .map(|x| (x.path.clone(), x))
        .collect::<HashMap<_, _>>();

    let mut res = vec![];

    for (path, file) in files {
        // If we already have a file that matches the same path in our local
        // DB, use these existing nonces for the check. If not, generate new
        // nonces and use the placeholder #0 file ID.
        let (id, data_nonce, path_nonce, version) = match db_metadata
            .remove(&path)
        {
            Some(v) => {
                (v.id, v.data_nonce.clone(), v.path_nonce.clone(), v.version)
            }
            None => (0, gen_nonce(), gen_nonce(), 1),
        };

        let data_ciphertext = cipher
            .encrypt(XNonce::from_slice(&data_nonce), file.as_slice())
            .unwrap();
        let enc_data = data::Encrypted::new(data_ciphertext, data_nonce);

        let path_ciphertext = cipher
            .encrypt(XNonce::from_slice(&path_nonce), path.as_bytes())
            .unwrap();
        let enc_path = data::Encrypted::new(path_ciphertext, path_nonce);

        let mut file = data::File::new(id, enc_data, enc_path);

        file.user_id = user.id;
        file.token = user.password_digest.clone();
        file.version = version;

        res.push((path, file));
    }

    Ok(res)
}

// Recursively visit all files in a directory and its subdirectories
fn visit_dirs(
    dir: &std::path::Path,
    cb: &mut dyn FnMut(&std::fs::DirEntry) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry)?;
            }
        }
    }
    Ok(())
}
