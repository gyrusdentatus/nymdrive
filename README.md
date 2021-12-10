# NymDrive
NymDrive is a complete, end-to-end encrypted file syncing daemon that runs over the Nym network.

### Features
- Active file monitoring of changes in the `~/nymdrive` folder:
	- File creation
	- File deletion
	- File writes
	- File renaming
- Monitored changes are automatically synced with the NymDrive server.
- Files and filenames are end-to-end encrypted using the widely regarded AEAD encryption algorithm XChaCha20Poly1305, which uses 192 bit nonces to guarantee there will never be a collision.
- End-to-end encryption key derived from the user's username and password, hashed using Argon2.
- With only a username and password, you can fully recover all backed up files on a new device by logging in with your credentials. No seed phrase or key backup required.
- Complete and automatic file versioning system that is stored in a local sqlite database to ensure consistency with the server and other devices.
- Full multi-device syncing with consistency enforced through the local versioning database.

### Design decisions
- We chose to implement a complete live folder syncing system as opposed to encumbering the user with the manual upload and retrieval of every file they may ever want to backup. It would be extremely cumbersome to use this kind of system to back up a git repository that is actively being developed, but it is trivial to do exactly this with NymDrive.
- In conflict of the specifications of the challenge, we chose not to leak the user's file hashes to the server, and instead submit the blake3 hash of the AEAD ciphertext. File hashes can leak lots of information, and it was the basis for Apple's now-cancelled image surveillence system. Your adversary can compare lists of "objectionnable" file hashes to the ones you have stored on the service provider to see if you saved these files, thereby bypassing the purpose of the end-to-end encryption.
- Although our team has the technical expertise to implement the file-hashes-on-the-blockchain optional bonus, we have intentionally opted not to as we do not believe it provides any tangible decentralization benefits. Nym service providers are, generally, centralized entities, who have the technical capability to arbitrarily restrict users. Having a file hash on the blockchain would not prevent NymDrive from simply refusing to serve this file to the user if they requested it. It also wouldn't provide the user with much benefit, as they already store all hashes in their local sqlite database.

### Packages needed (on debian)
- nym-client v0.11.0
- rust 1.56+
- openssl-dev
- g++ (or any other supplier of c++)
- cmake
- libfreetype-dev
- libexpat1-dev
- sqlitebrowser

### Running NymDrive
For testing purposes, the simplest way to run NymDrive is:
```bash
./app.sh noauto
```

This will run NymDrive without running nym-client or nym-duplex, and will be fully functional when the mixnet is disabled in the GUI settings.

If you wish to run NymDrive through the current Nym testnet, you may run the nym-client as follows:
```bash
./nym_client.sh
```

Followed by the app script in a seperate terminal window:
```bash
./app.sh
```

### Notes
- Encryption security is highly dependent on the strength of your password. Please use a strong password to ensure the confidentiality of you files.
- Ensure you are only running ONE instance of NymDrive at a time. Running multiple instances at the same time will result in doom.
- Empty files and folder are currently not synced. Please add some content if you wish to sync them.
- Logging out will only remove files locally. If you wish to remove a file on both ends, simply delete it from the `~/nymdrive` directory in your filesystem. Closing the GUI window will keep you logged in.
- Ciphertext file hashes are accessible in the file hash GUI by executing the command `./file_hashes.sh` in the repo root. The file hashes are presented as: `data_ciphertext_digest`.
- The current testnet mixnet can be unstable and may not be functional at all times. You may disable the mixnet to purely test the syncing functionality. Your synced files will be tied to the same account whether or not you enable the mixnet.
- Files greater than 1GB are not synced and will be automatically rejected by the server as a DOS prevention measure.

### Troubleshooting
If you run into the error: `Error: GraphicsAdapterNotFound`, please change `gui/Cargo.toml` and remove the feature `glow` from the crate `iced`. This error may occur on NixOS, Fedora Silverblue, and other Linux distributions.
