macro_rules! forward_bytes {
    ($f:expr) => {
        |bytes: bytes::Bytes| async {
            match $f(bytes).await {
                Ok(v) => http::response::Builder::new()
                    .status(http::StatusCode::OK)
                    .body(v)
                    .unwrap(),
                Err(e) => {
                    log::error!("{}\n{}", e, e.backtrace());

                    // this is ugly, but I am afraid the gods demand it!
                    let status = if e.to_string() == "invalid credentials" {
                        http::StatusCode::UNAUTHORIZED
                    } else {
                        http::StatusCode::INTERNAL_SERVER_ERROR
                    };

                    http::response::Builder::new()
                        .status(status)
                        .body(vec![])
                        .unwrap()
                }
            }
        }
    };
}

lazy_static::lazy_static! {
    static ref DB: sqlx::SqlitePool = sqlx::SqlitePool::connect_lazy("live_server.db").unwrap();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use warp::Filter;

    pretty_env_logger::init_timed();

    let create_file_route = warp::post()
        .and(warp::path("create_file"))
        .and(warp::body::content_length_limit(1024 * 1024 * 1024))
        .and(warp::body::bytes())
        .then(forward_bytes!(create_file));

    let update_file_route = warp::post()
        .and(warp::path("update_file"))
        .and(warp::body::content_length_limit(1024 * 1024 * 1024))
        .and(warp::body::bytes())
        .then(forward_bytes!(update_file));

    let create_user_route = warp::post()
        .and(warp::path("create_user"))
        .and(warp::body::content_length_limit(1024 * 1024))
        .and(warp::body::bytes())
        .then(forward_bytes!(create_user));

    let get_updates_route = warp::get()
        .and(warp::path("get_updates"))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::bytes())
        .then(forward_bytes!(get_updates));

    let get_file_route = warp::get()
        .and(warp::path("get_file"))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::bytes())
        .then(forward_bytes!(get_file));

    let remove_file_route = warp::post()
        .and(warp::path("remove_file"))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::bytes())
        .then(forward_bytes!(remove_file));

    let routes = create_file_route
        .or(update_file_route)
        .or(create_user_route)
        .or(get_updates_route)
        .or(get_file_route)
        .or(remove_file_route);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;

    Ok(())
}

// Verify the user's credentials for every http req they send in
async fn decode_and_verify<'de, T: data::Payload + serde::Deserialize<'de>>(
    bytes: &'de bytes::Bytes,
) -> anyhow::Result<T> {
    let data: T = bincode::deserialize(&bytes)?;
    let user_id = data.user_id();

    let res = sqlx::query!(
        "SELECT salt, password_digest FROM users WHERE id = ?",
        user_id
    )
    .fetch_one(&*DB)
    .await?;

    let hash_config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        ..Default::default()
    };

    // verify the user's credentials before processing their request
    if !argon2::verify_raw(
        data.token(),
        &res.salt,
        &res.password_digest,
        &hash_config,
    )? {
        anyhow::bail!("invalid credentials");
    }

    Ok(data)
}

// returns id of created file
async fn create_file(bytes: bytes::Bytes) -> anyhow::Result<Vec<u8>> {
    let file: data::File = decode_and_verify(&bytes).await?;

    log::debug!("Creating file...");

    let row = sqlx::query!("INSERT INTO files (data_ciphertext, data_ciphertext_digest, data_nonce, path_ciphertext, path_ciphertext_digest, path_nonce, user_id) VALUES (?, ?, ?, ?, ?, ?, ?); SELECT last_insert_rowid() as id;", file.data.ciphertext, file.data.ciphertext_digest, file.data.nonce, file.path.ciphertext, file.path.ciphertext_digest, file.path.nonce, file.user_id)
        .fetch_one(&*DB)
        .await?;

    log::debug!("Created file #{}, returning id...", row.id);

    Ok(bincode::serialize(&(row.id as i64))?)
}

async fn create_user(bytes: bytes::Bytes) -> anyhow::Result<Vec<u8>> {
    use rand::Rng;

    let user: data::User = bincode::deserialize(&bytes)?;

    let already_exists = sqlx::query!(
        "SELECT id, salt, password_digest FROM users WHERE username = ?;",
        user.username
    )
    .fetch_optional(&*DB)
    .await?;

    let hash_config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        ..Default::default()
    };

    match already_exists {
        Some(rec) => {
            if !argon2::verify_raw(
                &user.password_digest,
                &rec.salt,
                &rec.password_digest,
                &hash_config,
            )? {
                anyhow::bail!("invalid credentials");
            }

            return Ok(bincode::serialize(&rec.id)?);
        }
        None => {}
    }

    log::debug!("Creating user...");

    let mut salt = vec![0u8; 24];
    rand::thread_rng().fill(salt.as_mut_slice());

    // double hash the already hashed pass the users gave us
    let password_digest =
        argon2::hash_raw(&user.password_digest, &salt, &hash_config)?;

    let rec = sqlx::query!(
        "INSERT INTO users (username, salt, password_digest) VALUES (?, ?, ?); SELECT last_insert_rowid() as id;",
        user.username,
        salt,
        password_digest
    )
    .fetch_one(&*DB)
    .await?;

    log::debug!("Created user #{}, returning id...", rec.id);

    Ok(bincode::serialize(&(rec.id as i64))?)
}

async fn update_file(bytes: bytes::Bytes) -> anyhow::Result<Vec<u8>> {
    let file: data::File = decode_and_verify(&bytes).await?;

    log::debug!("Updating file #{}...", file.id);

    let current =
        sqlx::query!("SELECT version FROM files WHERE id = ?", file.id)
            .fetch_one(&*DB)
            .await?;

    // version incrementing happens on the client side, so we use >= instead of >
    if current.version >= file.version {
        log::error!("file syncing conflict, overriding w/ user version");
    }

    sqlx::query!("UPDATE files SET data_ciphertext = ?, data_ciphertext_digest = ?, data_nonce = ?, path_ciphertext = ?, path_ciphertext_digest = ?, path_nonce = ?, version = ? WHERE id = ?", file.data.ciphertext, file.data.ciphertext_digest, file.data.nonce, file.path.ciphertext, file.path.ciphertext_digest, file.path.nonce, file.version, file.id)
        .execute(&*DB)
        .await?;

    log::debug!("Updated file #{}", file.id);

    Ok(vec![])
}

async fn get_updates(bytes: bytes::Bytes) -> anyhow::Result<Vec<u8>> {
    let update_req: data::UpdateRequest = decode_and_verify(&bytes).await?;

    log::debug!("Fetching updates for user #{}...", update_req.user_id);

    let files = sqlx::query!("SELECT id, data_ciphertext_digest, path_ciphertext_digest, version FROM files WHERE user_id = ?;", update_req.user_id)
        .fetch_all(&*DB)
        .await?;

    let mut res = vec![];

    for file in files {
        let mut f = data::File::from_hashes(
            file.id,
            file.data_ciphertext_digest,
            file.path_ciphertext_digest,
            file.version,
        );
        f.user_id = update_req.user_id;
        // We set *their* token on the data we *return*, yes, it's a weird hack.
        f.token = update_req.token.clone();
        res.push(f);
    }

    log::debug!("Returning updates for user #{}...", update_req.user_id);

    Ok(bincode::serialize(&res)?)
}

async fn remove_file(bytes: bytes::Bytes) -> anyhow::Result<Vec<u8>> {
    let file_req: data::FileRequest = decode_and_verify(&bytes).await?;

    log::debug!(
        "Removing file #{} for user #{}...",
        file_req.file_id,
        file_req.user_id
    );

    sqlx::query!(
        "DELETE FROM files WHERE id = ? AND user_id = ?;",
        file_req.file_id,
        file_req.user_id
    )
    .execute(&*DB)
    .await?;

    log::debug!(
        "File #{} successfully removed.",
        file_req.file_id,
    );

    Ok(vec![])
}

async fn get_file(bytes: bytes::Bytes) -> anyhow::Result<Vec<u8>> {
    let file_req: data::FileRequest = decode_and_verify(&bytes).await?;

    log::debug!(
        "Fetching file #{} for user #{}...",
        file_req.file_id,
        file_req.user_id
    );

    let rec = sqlx::query!(
        "SELECT * FROM files WHERE id = ? AND user_id = ?;",
        file_req.file_id,
        file_req.user_id
    )
    .fetch_one(&*DB)
    .await?;

    let file = data::File {
        id: rec.id,
        data: data::Encrypted::new(rec.data_ciphertext, rec.data_nonce),
        path: data::Encrypted::new(rec.path_ciphertext, rec.path_nonce),
        version: rec.version,
        user_id: rec.user_id,
        token: file_req.token.clone(),
    };

    log::debug!("Returning file #{} for user #{}...", rec.id, rec.user_id);

    Ok(bincode::serialize(&file)?)
}
