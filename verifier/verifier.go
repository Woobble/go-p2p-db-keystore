package verifier

type Verifier interface {
	Verify(signature []byte, publicKey []byte, data []byte) (bool, error)
}

func Verify(signature []byte, publicKey []byte, data []byte) (bool, error) {
	return verifierv1{}.Verify(signature, publicKey, data)
}
