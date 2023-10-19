from bip_utils import Bip32Slip10Secp256k1, Secp256k1PrivateKey, Secp256k1PublicKey

# Construct from private key bytes
priv_key_bytes = bytes.fromhex("2e09165b257a4c3e52c9f4faa6322c66cede807b7d6b4ec3960820795ee5447f")

# Create a Bip32Slip10Secp256k1 context from the private key
bip32_ctx = Bip32Slip10Secp256k1.FromPrivateKey(Secp256k1PrivateKey.FromBytes(priv_key_bytes))

# Print the private key in hexadecimal format
print("Private Key in Hex:", "2e09165b257a4c3e52c9f4faa6322c66cede807b7d6b4ec3960820795ee5447f")

# Get the public key from the private key
pub_key_bytes = bip32_ctx.PublicKey().RawCompressed().ToBytes()

# Create a Bip32Slip10Secp256k1 context from the public key
bip32_ctx = Bip32Slip10Secp256k1.FromPublicKey(Secp256k1PublicKey.FromBytes(pub_key_bytes))

# Print the public key in hexadecimal format
print('compressed public:', bip32_ctx.PublicKey().RawCompressed().ToHex())

# Print the uncompressed publik key
print('uncompressed public:', bip32_ctx.PublicKey().RawUncompressed().ToHex())
