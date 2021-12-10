use crate::{remove_file, gen_nonce, opt, push_file_update, push_new_file, DB};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc::unbounded_channel;

pub(crate) async fn watch(
    cipher: chacha20poly1305::XChaCha20Poly1305,
    user: data::User,
    path: std::path::PathBuf,
) -> anyhow::Result<()> {
    let (tx, mut rx) = unbounded_channel();
    let _tx_guard = tx.clone();

    let mut watcher = RecommendedWatcher::new(move |res| {
        let _ = tx.send(res);
    })?;

    watcher.watch(&path, RecursiveMode::Recursive)?;
    watcher.configure(Config::PreciseEvents(true))?;

    while let Some(res) = rx.recv().await {
        match res {
            Ok(event) => match handle_event(&cipher, &user, event).await {
                Ok(_) => {}
                Err(e) => log::error!("Event processing error: {}", e),
            },
            Err(e) => log::error!("Notify error: {}", e),
        }
    }

    Ok(())
}

async fn handle_event(
    cipher: &chacha20poly1305::XChaCha20Poly1305,
    user: &data::User,
    e: notify::event::Event,
) -> anyhow::Result<()> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::XNonce;
    use notify::event::{EventKind, ModifyKind, RemoveKind, RenameMode};

    let cipher = cipher.clone();
    let user = user.clone();

    tokio::spawn(async move {
        match e.kind {
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                let metadata = tokio::fs::metadata(&e.paths[1]).await?;

                // Handling directory renames is left as future work.
                if metadata.is_dir() {
                    log::warn!("Directory renames are currently unsupported.");
                    return Ok(());
                }

                log::debug!(
                    "Registered file rename, pushing update to server..."
                );

                let old_path = opt!(e.paths[0].as_path().to_str()).to_string();
                let old_path = old_path.clone();
                let rec = sqlx::query!(
                    "SELECT id, version FROM files WHERE path = ?;",
                    old_path
                )
                .fetch_one(&*DB)
                .await?;

                let file = data::File {
                    id: rec.id,
                    version: rec.version,
                    user_id: user.id,
                    token: user.password_digest.clone(),
                    ..Default::default()
                };

                let path = opt!(e.paths[1].as_path().to_str()).to_string();
                push_file_update(&cipher, &path, file).await?;
            }
            EventKind::Modify(ModifyKind::Data(..)) => {
                log::debug!("File on disk changed, checking local db...");
                let path = opt!(e.paths[0].as_path().to_str()).to_string();
                let path = path.clone();
                let rec = sqlx::query!(
                    "SELECT id, version FROM files WHERE path = ?;",
                    path
                )
                .fetch_optional(&*DB)
                .await?;

                match rec {
                    Some(rec) => {
                        log::debug!("Registered file change, pushing update to server...");

                        let file = data::File {
                            id: rec.id,
                            version: rec.version,
                            user_id: user.id,
                            token: user.password_digest.clone(),
                            ..Default::default()
                        };

                        push_file_update(&cipher, &path, file).await?;
                    }
                    None => {
                        log::debug!(
                            "Registered new file, pushing to server..."
                        );

                        let path =
                            opt!(e.paths[0].as_path().to_str()).to_string();
                        let data = tokio::fs::read(&path).await?;

                        let (data_nonce, path_nonce) =
                            (gen_nonce(), gen_nonce());

                        let data_ciphertext = cipher
                            .encrypt(
                                XNonce::from_slice(&data_nonce),
                                data.as_slice(),
                            )
                            .unwrap();
                        let enc_data =
                            data::Encrypted::new(data_ciphertext, data_nonce);

                        let path_ciphertext = cipher
                            .encrypt(
                                XNonce::from_slice(&path_nonce),
                                path.as_bytes(),
                            )
                            .unwrap();
                        let enc_path =
                            data::Encrypted::new(path_ciphertext, path_nonce);

                        let mut file = data::File::new(0, enc_data, enc_path);

                        file.user_id = user.id;
                        file.token = user.password_digest.clone();

                        push_new_file(&cipher, &path, &file).await?;
                    }
                };
            }
            EventKind::Remove(RemoveKind::File) => {
                log::debug!("Registered file removal, removing from server...");

                let path = opt!(e.paths[0].as_path().to_str()).to_string();
                let path = path.clone();

                let rec = sqlx::query!(
                    "SELECT id FROM files WHERE path = ?;",
                    path
                )
                .fetch_optional(&*DB)
                .await?;

                let file_id = if let Some(v) = rec {
                    v.id
                } else {
                    log::debug!("Did not find file in local db, ignorning removal");
                    return Ok(());
                };

                let file = data::File {
                    id: file_id,
                    user_id: user.id,
                    token: user.password_digest.clone(),
                    ..Default::default()
                };

                remove_file(&file).await?;
            }
            _ => {}
        }

        Ok(())
    });

    Ok(())
}
