// copyright@ (2023) blackshirt
// This modules provides Elliptic Curve Diffie-Hellman (ECDHE) used by
// Key Exchange Protocol, commonly used by cryptography protocol.
// Currently only Curve25519 based is supported through x25519 function.
module ecdhe

import crypto.hmac
import encoding.hex

fn test_x25519_exchanger() ! {
	// this data from https://tls13.xargs.org/#server-key-exchange-generation
	client_privkey := hex.decode('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')!
	client_pubkey := hex.decode('358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254')!
	client_shared_secret := hex.decode('df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624')!

	server_privkey := hex.decode('909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')!
	server_pubkey := hex.decode('9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615')!
	server_shared_secret := hex.decode('df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624')!

	kx := new_x25519_exchanger()
	mut client_prvkey := kx.private_key_from_key(client_privkey)!

	// calculates PublicKey from private key with sync.do
	pubk_sync := client_prvkey.public_key()!

	server_prvkey := kx.private_key_from_key(server_privkey)!
	// PublicKey part of the private key
	server_pubk := kx.public_key(server_prvkey)!

	// PublicKey part of the private key
	client_pubk := kx.public_key(client_prvkey)!

	// test wheter client PublicKey generated from Key
	// dump(client_pubk)
	// dump(pubk_sync)
	assert client_pubk.curve.curve_id() == pubk_sync.curve.curve_id()
	assert client_pubk.pubkey == pubk_sync.pubkey
	assert client_pubk.pubkey.len == pubk_sync.pubkey.len
	assert client_pubk.equal(pubk_sync) == true

	// assert if PublicKey result is expected
	assert client_pubk.bytes()! == client_pubkey

	// compute shared_secret between client private key and server public key
	calc_client_shared := kx.shared_secret(client_prvkey, server_pubk)!
	assert client_shared_secret == calc_client_shared

	// assert if PublicKey result is expected
	assert server_pubk.bytes()! == server_pubkey

	// compute shared_secret between server private key and client public key
	calc_server_shared := kx.shared_secret(server_prvkey, client_pubk)!
	assert calc_server_shared == server_shared_secret

	// assert two shared secret is identical
	assert calc_client_shared == calc_server_shared
}

fn test_x25519_ecdhe() ! {
	dh := new_x25519_exchanger()

	mut privkey_bob := dh.private_key_from_key([]u8{len: 32})!
	mut secret := []u8{len: 32}

	for i := 0; i < 2; i++ {
		mut privkey_alice := dh.generate_private_key()!
		pubkey_alice := dh.public_key(privkey_alice)!
		pubkey_bob := dh.public_key(privkey_bob)!

		sec_alice := dh.shared_secret(privkey_alice, pubkey_bob)!
		sec_bob := dh.shared_secret(privkey_bob, pubkey_alice)!

		assert hmac.equal(sec_alice, sec_bob) == true
		assert hmac.equal(secret, sec_alice) == false
		copy(mut secret, sec_alice)
	}
}

const (
	// Test vector from https://tools.ietf.org/html/rfc7748#section-6.1
	alice_privkey = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
	alice_pubkey  = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
	bob_privkey   = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
	bob_pubkey    = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
	shared_secret = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
)

fn test_generate_key() ! {
	dh := new_x25519_exchanger()

	for i := 0; i < 50; i++ {
		our_privkey := dh.generate_private_key()!
		our_pubkey := dh.public_key(our_privkey)!
		their_privkey := dh.generate_private_key()!
		their_pubkey := dh.public_key(their_privkey)!

		s1 := dh.shared_secret(our_privkey, their_pubkey)!
		s2 := dh.shared_secret(their_privkey, our_pubkey)!

		assert hmac.equal(s1, s2) == true
		assert our_pubkey.equal(dh.public_key(our_privkey)!)
		assert their_pubkey.equal(dh.public_key(their_privkey)!)
	}
}

fn test_from_rfc_vectors_key() ! {
	dh := new_x25519_exchanger()

	alice_privbytes := hex.decode(ecdhe.alice_privkey)!

	ask := dh.private_key_from_key(alice_privbytes)!
	apk := dh.public_key(ask)!

	alice_pk := dh.public_key(ask)!
	assert apk.equal(alice_pk)

	assert ecdhe.alice_pubkey == hex.encode(apk.pubkey[..])

	bskhex := hex.decode(ecdhe.bob_privkey)!

	bsk := dh.private_key_from_key(bskhex)!
	bpk := dh.public_key(bsk)!
	assert ecdhe.bob_pubkey == hex.encode(bpk.pubkey[..])

	s1 := dh.shared_secret(ask, bpk)!
	s2 := dh.shared_secret(bsk, apk)!

	assert hmac.equal(s1, s2) == true

	assert hex.encode(s1) == ecdhe.shared_secret
}

fn test_create_ephemeral_x25519_key_pair() ! {
	prvkey := [u8(0xb1), 0x58, 0x0e, 0xea, 0xdf, 0x6d, 0xd5, 0x89, 0xb8, 0xef, 0x4f, 0x2d, 0x56,
		0x52, 0x57, 0x8c, 0xc8, 0x10, 0xe9, 0x98, 0x01, 0x91, 0xec, 0x8d, 0x05, 0x83, 0x08, 0xce,
		0xa2, 0x16, 0xa2, 0x1e]

	pubkey := [u8(0xc9), 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7,
		0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0,
		0x4e, 0x75, 0x1f, 0x0f]

	exchanger := new_x25519_exchanger()

	mut privkey := exchanger.private_key_from_key(prvkey)!
	pbkey := privkey.public_key()!
	pbkey_bytes := pbkey.bytes()!

	assert pbkey_bytes == pubkey
}
