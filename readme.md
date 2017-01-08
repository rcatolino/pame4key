# Pame4key
This is a PAM service module which derives a key from a cached authentication token (typically a password)
and then adds it in the session keyring for use by the ext4 encryption mechanism.

The derivation function used is pbkdf2_hmac_sha512. The key description is created by taking the first 8 bytes
from the sha512 sum of the derived key.

This derivation is different from the one used by the e4crypt tool. The same password won't result in
the same key using this tool.

