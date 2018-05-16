package hsm

// HSM is interface for Hardware Security Module.
type HSM interface {
	Encrypt(plainText string) (cipherText string, err error)
	Decrypt(cipherByte []byte) (plainText string, err error)
}
