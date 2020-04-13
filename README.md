# rclone-crypt-rs

A lightweight Rust implementation of the Rclone Crypt file encryption.

VERY EXPERIMENTAL! This currently only supports decryption.

Supported:

* File name decryption

* File name encryption

* File data block decryption (currently no streaming interface)

Unsupported:

* File name obfuscation

* Null salts

* File chunk encryption

There is currently not nice interface with Read + Seek (TODO) and the code is a mess.

