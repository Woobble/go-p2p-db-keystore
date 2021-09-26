package verifier

import (
	"github.com/libp2p/go-libp2p-core/crypto"
)

type verifierv1 struct{}

var _ Verifier = (*verifierv1)(nil)

func (v verifierv1) Verify(signature []byte, publicKey []byte, data []byte) (bool, error) {
	key, err := crypto.UnmarshalSecp256k1PublicKey(publicKey)
	if err != nil {
		return false, nil
	}
	return key.Verify(data, signature)
}
