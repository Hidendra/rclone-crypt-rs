# rclone-crypt-rs

A lightweight Rust implementation of the Rclone Crypt file encryption.

VERY EXPERIMENTAL!.

Supported:

* File name decryption

* File name encryption

* File data block decryption (currently no streaming interface)

* File data block encryption (currently no streaming interface)

Unsupported:

* File name obfuscation

* Null salts

* File chunk encryption

There is currently no nice interface with Read + Seek.