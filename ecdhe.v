// copyright@ (2023) blackshirt
// This modules provides Elliptic Curve Diffie-Hellman (ECDHE) used by
// Key Exchange Protocol, commonly used by cryptography protocol.
// Currently only Curve25519 based is supported through x25519 function.
module ecdhe

import sync
import crypto.rand
import crypto.internal.subtle
import blackshirt.curve25519

// Key Exchange Protocol
pub interface Exchanger {
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

// Basically, Curve is a TLS 1.3 NamedGroup.
// its defined here for simplicity.
pub enum Curve {
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

fn (c Curve) str() string {
	match c {
		.secp256r1 { return 'secp256r1' }
		.secp384r1 { return 'secp384r1' }
		.secp521r1 { return 'secp521r1' }
		.x25519 { return 'x25519' }
		.x448 { return 'x448' }
		.ffdhe2048 { return 'ffdhe3072' }
		.ffdhe3072 { return 'ffdhe3072' }
		.ffdhe4096 { return 'ffdhe4096' }
		.ffdhe6144 { return 'ffdhe6144' }
		.ffdhe8192 { return 'ffdhe8192' }
	}
}

// new_exchanger creates new Exchanger for curve c,
// for this time, only curve25519 is supported
pub fn new_exchanger(c Curve) !&Exchanger {
	match c {
		.x25519 { return new_x25519_exchanger() }
		else { return error('unsupported curve') }
	}
}

// This const for Curve25519 based curve
const (
	key_size = 32
)

// PublicKey represent public keys
struct PublicKey {
	curve  Exchanger
	pubkey []u8
}

// equal tell if two PublicKey is equal, its check if has the same curve and its also check
// if underlying pubkey bytes has exactly the same length and contents.
pub fn (pk PublicKey) equal(x PublicKey) bool {
	return pk.curve.curve_id() == x.curve.curve_id() && pk.pubkey.len == x.pubkey.len
		&& subtle.constant_time_compare(pk.pubkey, x.pubkey) == 1
}

// bytes returns bytes content of PublicKey.
pub fn (pk PublicKey) bytes() ![]u8 {
	if pk.pubkey.len != pk.curve.public_key_size() {
		return error('pubkey.len does not math with curve pubkey size')
	}
	mut buf := []u8{len: pk.curve.public_key_size()}
	_ := copy(mut buf, pk.pubkey)
	return buf
}

// PrivateKey represent private keys. Its stores PublicKey here for minor enhancement.
// its not recommended to access it directly, but call `.public_key()` instead to get PublicKey part.
// and, its not made as a public, if you wanto to have to create it, you should create its from Exchanger instance,
// and then call `.private_key_from_key` or `generate_private_key` instead.
struct PrivateKey {
	curve   Exchanger
	privkey []u8
mut:
	pubk      PublicKey
	verified  bool
	pubk_once sync.Once = sync.new_once()
}

// bytes return PrivateKey as a bytes array
pub fn (pv PrivateKey) bytes() ![]u8 {
	if pv.privkey.len != pv.curve.private_key_size() {
		return error('privkey.len does not match with curve privatekey size')
	}
	mut buf := []u8{len: pv.curve.private_key_size()}
	_ := copy(mut buf, pv.privkey)
	return buf
}

// equal whether two PrivateKey has equally identical (its not check pubkey part)
pub fn (pv PrivateKey) equal(oth PrivateKey) bool {
	return pv.curve.curve_id() == oth.curve.curve_id() && pv.privkey.len == oth.privkey.len
		&& subtle.constant_time_compare(pv.privkey, oth.privkey) == 1
}

// public_key is accessor for `privatekey.pubk` PublicKey part, its does check if matching
// public key part or initializes PublicKey if not. Initialization is does under `sync.do_with_param`
// to make sure its  that a function is executed only once.
pub fn (mut prv PrivateKey) public_key() !PublicKey {
	prv.pubk_once.do_with_param(fn (mut o PrivateKey) {
		// internal pubkey of privatekey does not initialized to some values.
		// we only check the len part, if is not has same length with public_key_size
		// of provided curve, its mean not initialized.
		if o.pubk.pubkey.len != o.curve.public_key_size() || !o.verified {
			// we can not return error here, so panic instead.
			opk := o.curve.public_key(o) or { panic(err) }
			o.pubk = opk
			o.verified = true
		} else {
			pk := PublicKey{
				curve: o.curve
				pubkey: o.pubk.pubkey
			}
			o.pubk = pk
		}
	}, prv)
	return prv.pubk
}

// Curve25519 ecdh protocol
struct Ecdh25519 {
	privkey_size int = 32
	pubkey_size  int = 32
}

fn (ec Ecdh25519) str() string {
	return 'Ecdh25519'
}

// new_x25519_exchanger creates new Curve25519 based ECDH key exchange protocol
pub fn new_x25519_exchanger() &Exchanger {
	return &Ecdh25519{}
}

// return underlying curve id
pub fn (ec Ecdh25519) curve_id() Curve {
	return Curve.x25519
}

// private_key_size returns private key size, in bytes
pub fn (ec Ecdh25519) private_key_size() int {
	return ec.privkey_size
}

// public_key_size returns public key size, in bytes
pub fn (ec Ecdh25519) public_key_size() int {
	return ec.pubkey_size
}

// private_key_from_key generates PrivateKey from seeded key.
pub fn (ec Ecdh25519) private_key_from_key(key []u8) !PrivateKey {
	if key.len != ec.privkey_size {
		return error('Wrong key len')
	}
	// we dont clamping here
	privk := PrivateKey{
		curve: ec
		privkey: key
	}

	return privk
}

// generate_private_key generates PrivateKey with random entropy using `crypto.rand`
pub fn (ec Ecdh25519) generate_private_key() !PrivateKey {
	privkey := rand.read(ec.privkey_size)!
	privk := ec.private_key_from_key(privkey)!
	return privk
}

// privkey_to_pubkey calculates PublicKey part of given PrivateKey
fn (ec Ecdh25519) privkey_to_pubkey(prv PrivateKey) !PublicKey {
	if prv.privkey.len != ec.privkey_size {
		return error('Wrong privkey len')
	}
	// make sure we are on the same curve
	if prv.curve.curve_id() != ec.curve_id() {
		return error("operates on different curve")
	}
	pubkey := curve25519.x25519(prv.privkey, curve25519.base_point)!

	pubk := PublicKey{
		curve: ec
		pubkey: pubkey
	}

	return pubk
}

// public_key gets PublicKey part of PrivateKey
pub fn (ec Ecdh25519) public_key(pv PrivateKey) !PublicKey {
	pk := ec.privkey_to_pubkey(pv)!
	return pk
}

// shared_secret computes shared keys between two parties, alice private keys and others public keys.
// Its commonly used as elliptic curve diffie-hellman (ECDH) key exchange protocol
pub fn (ec Ecdh25519) shared_secret(local PrivateKey, remote PublicKey) ![]u8 {
	if local.privkey.len != ec.privkey_size || remote.pubkey.len != ec.pubkey_size {
		return error('Wrong local len or remote len')
	}
	// make sure we are on the same curve
	if local.curve.curve_id() != ec.curve_id() || remote.curve.curve_id() != local.curve.curve_id() {
		return error("operates on different curve")
	}
	secret := curve25519.x25519(local.privkey, remote.pubkey)!
	if is_zero(secret) {
		return error('secret result zeroed')
	}
	return secret
}

// given PrivateKey privkey, verify do check whether given PublicKey pubkey is really
// keypair for privkey. Its check by calculating public key part of
// given PrivateKey.
pub fn verify(ec Exchanger, privkey PrivateKey, pubkey PublicKey) bool {
	// check whether given params is on same curve.
	if privkey.curve != ec || pubkey.curve != ec || privkey.curve != pubkey.curve {
		return false
	}
	// get the PublicKey part of given PrivateKey
	pubk := ec.public_key(privkey) or { return false }

	return pubk.equal(pubkey)
}

// is_zero returns whether seed is all zeroes in constant time.
fn is_zero(seed []u8) bool {
	mut acc := u8(0)
	for b in seed {
		acc |= b
	}
	return acc == 0
}
