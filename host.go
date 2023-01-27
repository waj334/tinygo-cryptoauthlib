package cryptoauthlib

type tempKey struct {
	value      [ATCA_KEY_SIZE * 2]byte
	keyId      uint16
	sourceFlag uint8
	genDigData uint8
	genKeyData uint8
	noMacFlag  uint8
	valid      bool
	is64       bool
}
