# module ecdhe


# ecdhe
Elliptic curve Diffie–Hellman (ECDH) key exchange protocol in pure V language

Elliptic curve Diffie–Hellman (ECDH) key exchange protocol that allows two parties, each having an elliptic curve public–private key pair, to establish a shared secret over an insecure channel. Currently, its only support Curve25519.


## Contents
- [new_x25519_exchanger](#new_x25519_exchanger)
- [new_exchanger](#new_exchanger)
- [verify](#verify)
- [Exchanger](#Exchanger)
- [PrivateKey](#PrivateKey)
  - [bytes](#bytes)
  - [equal](#equal)
  - [public_key](#public_key)
- [PublicKey](#PublicKey)
  - [equal](#equal)
  - [bytes](#bytes)
- [Ecdh25519](#Ecdh25519)
  - [curve_id](#curve_id)
  - [private_key_size](#private_key_size)
  - [public_key_size](#public_key_size)
  - [private_key_from_key](#private_key_from_key)
  - [generate_private_key](#generate_private_key)
  - [public_key](#public_key)
  - [shared_secret](#shared_secret)
- [Curve](#Curve)

## new_x25519_exchanger
```v
fn new_x25519_exchanger() &Exchanger
```

new_x25519_exchanger creates new Curve25519 based ECDH key exchange protocol

[[Return to contents]](#Contents)

## new_exchanger
```v
fn new_exchanger(c Curve) !&Exchanger
```

new_exchanger creates new Exchanger for curve c, for this time, only curve25519 is supported

[[Return to contents]](#Contents)

## verify
```v
fn verify(ec Exchanger, privkey PrivateKey, pubkey PublicKey) bool
```

given PrivateKey privkey, verify do check whether given PublicKey pubkey is really keypair for privkey. Its check by calculating public key part of
given PrivateKey.  

[[Return to contents]](#Contents)

## Exchanger
```v
interface Exchanger {
	// curve_id tell the curve id
	curve_id() Curve
	// private_key_size should return underlying PrivateKey bytes size.
	private_key_size() int
	// public_key_size should return underlying PublicKey bytes size.
	public_key_size() int
	// generate_private_key generates random PrivateKey using entropy from secure crypto random generator.
	generate_private_key() !PrivateKey
	// private_key_from_key generates PrivateKey from some given key.
	private_key_from_key(key []u8) !PrivateKey
	// public_key returns public key corresponding to PrivateKey.
	public_key(PrivateKey) !PublicKey
	// shared_secret computes shared secret between alice PrivateKey and bob's PublicKey.
	shared_secret(local PrivateKey, remote PublicKey) ![]u8
}
```

Key Exchange Protocol

[[Return to contents]](#Contents)

## PrivateKey
## bytes
```v
fn (pv PrivateKey) bytes() ![]u8
```

bytes return PrivateKey as a bytes array

[[Return to contents]](#Contents)

## equal
```v
fn (pv PrivateKey) equal(oth PrivateKey) bool
```

equal whether two PrivateKey has equally identical (its not check pubkey part)

[[Return to contents]](#Contents)

## public_key
```v
fn (mut prv PrivateKey) public_key() !PublicKey
```

public_key is accessor for `privatekey.pubk` PublicKey part, its does check if matching public key part or initializes PublicKey if not. Initialization is does under `sync.do_with_param`
to make sure its  that a function is executed only once.  

[[Return to contents]](#Contents)

## PublicKey
## equal
```v
fn (pk PublicKey) equal(x PublicKey) bool
```

equal tell if two PublicKey is equal, its check if has the same curve and its also check
if underlying pubkey bytes has exactly the same length and contents.  

[[Return to contents]](#Contents)

## bytes
```v
fn (pk PublicKey) bytes() ![]u8
```

bytes returns bytes content of PublicKey.  

[[Return to contents]](#Contents)

## Ecdh25519
## curve_id
```v
fn (ec Ecdh25519) curve_id() Curve
```

return underlying curve id

[[Return to contents]](#Contents)

## private_key_size
```v
fn (ec Ecdh25519) private_key_size() int
```

private_key_size returns private key size, in bytes

[[Return to contents]](#Contents)

## public_key_size
```v
fn (ec Ecdh25519) public_key_size() int
```

public_key_size returns public key size, in bytes

[[Return to contents]](#Contents)

## private_key_from_key
```v
fn (ec Ecdh25519) private_key_from_key(key []u8) !PrivateKey
```

private_key_from_key generates PrivateKey from seeded key.  

[[Return to contents]](#Contents)

## generate_private_key
```v
fn (ec Ecdh25519) generate_private_key() !PrivateKey
```

generate_private_key generates PrivateKey with random entropy using `crypto.rand`

[[Return to contents]](#Contents)

## public_key
```v
fn (ec Ecdh25519) public_key(pv PrivateKey) !PublicKey
```

public_key gets PublicKey part of PrivateKey

[[Return to contents]](#Contents)

## shared_secret
```v
fn (ec Ecdh25519) shared_secret(local PrivateKey, remote PublicKey) ![]u8
```

shared_secret computes shared keys between two parties, alice private keys and others public keys.  
Its commonly used as elliptic curve diffie-hellman (ECDH) key exchange protocol

[[Return to contents]](#Contents)

## Curve
```v
enum Curve {
	secp256r1 = 0x0017
	secp384r1 = 0x0018
	secp521r1 = 0x0019
	x25519    = 0x001D
	x448      = 0x001E
	ffdhe2048 = 0x0100
	ffdhe3072 = 0x0101
	ffdhe4096 = 0x0102
	ffdhe6144 = 0x0103
	ffdhe8192 = 0x0104
}
```

Basically, Curve is a TLS 1.3 NamedGroup.  
its defined here for simplicity.  

[[Return to contents]](#Contents)

#### Powered by vdoc. Generated on: 2 Nov 2023 14:22:13
