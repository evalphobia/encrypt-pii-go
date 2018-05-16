package cipher

// Cipher is interface for encryption algorithm.
type Cipher interface {
	Encrypt(plainText string, key []byte) (cipherText string, err error)
	Decrypt(cipherText string, key []byte) (plainText string, err error)
}
