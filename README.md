# Password Manager with ARM TZ
## About
Project for Columbia University's Hardware Security class. A password manager with ARM TrustZone integration.
*For educational purposes only - do not deploy!*
Created by Hugo Matousek and Tharun Kumar Jayaprakash in Sprig 2024.

## Installation and usage
The project works with OP-TEE running on QEMU. 
1. Download and prepare OP-TEE/QEMU. 
1. Clone the project in the same directory that has your OP-TEE/QEMU directory.
1. In the project directory run `bash apply.sh` which will copy the files to the source for the OP-TEE image.
1. In `optee_qemu/build` run `make run` - it will take a couple of minutes the first time.
1. This will launch the OP-TEE/QEMU simulator. Enter `c` in the current terminal, which will allow the system to boot.
1. You will get two new terminal windows labeled `Normal world` and `Secure world`
1. In normal world, wait for the system to boot and login with `root` or `user` (no password). You cannot do anything in the secure world terminal.
1. In normal world, launch the application with `password_manager` command. This will also create a folder `~/.password_manager` that will store the archives.
1. Follow the CLI prompts.

## Functionality
1. Create or remove archives with passwords.
1. Add/get/remove* entries from archives (*remove doesn't always work - see below).
1. All entered passwords entries are encrypted, including the site URL and name. Each entry is identifiable by a hash of the site name.
1. All the encryption and decryption takes place in the secure world!
1. The actual encryption keys never leave the secure world.
1. The password is only used to derive a key that is used to encrypt the actual master key - you cannot use the password or the recovery key to decrypt the entries!
1. The encrypted versions of the master key (one encrypted with the key derived from the password, one encrypted with the key derived from the recovery key) are stored in the secure world under another layer of OP-TEE encryption!

## Known problems, temporary solutions, and ideas for improvement
1. Removing an individual entry doesn't always work and can cause archive corruption - this is likely due to different implementation of certain function on the platform or our mistakes with pointer arithmetic.
1. In some scenarios, an incorrect password might allow "decrypting" the entries, but they will be gibberish, as it is using an invalid key. This could be fixed by either some magic bytes in the entry struct or by comparing the hash of a password with a persistent saved hash.
1. The hash function used for site name hashing is very primitive as the system doesn't support OpenSSH. This is insecure and can lead to hash collisions. In a way, the current hash function is more of a placeholder to showcase the approach.
1. No salt is used for the encryption. While this doesn't matter that much, since there are multiple layers of encryption, it would be nice to have this, as well. In fact, there is a reserved field in the archive entry struct for salt.
1. The actual encryption algorithm is not optimal (AES but in ECB mode). Since we don't have repeating entries, this doesn't matter that much. However, it should be changed - potentially using the salt as an IV for CBC.
1. The archive restore function has some bugs which make it crash on occasions.
1. The password entry and retrieval happen in plaintext. This is due to limitations of the platform. In an ideal world, the password entry would be hidden, and the retrieval would work via inputting the password in the user's clipboard. 