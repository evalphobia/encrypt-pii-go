package hasher

type Hasher interface {
	Hash(password, salt string) string
}
