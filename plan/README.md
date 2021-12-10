## List of all necessary components for NymDrive (tentative name):

### Account management
- Ability to create an account with username and password
- Ability to login and logout
- Ability to retrieve all files from cloud when logging in on new device

### Payment mangement
- Ability to top-up your account with punks
- Automatically debited by the GB of upload/download bandwidth
- Display the current amount of bandwidth left in GB in your account

### File management
- ~/nymdrive folder automatically created on start
- Folder constantly monitored for added, removed or changed files
- Respective changes are made to the files stored in the cloud
- File versioning in hidden file ~/nymdrive/.__versions
- Multi-device syncing by monitoring file versioning
- Display the sync status along with some metadata (total file count, total bytes, etc) in GUI

### AEAD end-to-end encryption
- Generate random key on account creation
- Encrypt random key with hashed user password
- Encrypt all files and file metadata with AEAD ChaCha20Poly1305
- AEAD already guarantees file integrity so no need for checksum
- Only file versioning is unencrypted for syncing purposes

### Nym service provider
- Copy pasta nym-duplex
