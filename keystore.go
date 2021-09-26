package keystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Woobble/go-p2p-db-keystore/verifier"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/syndtr/goleveldb/leveldb"
	"os"
)

var errNoId = errors.New("id needed to check a key")

type Keystore struct {
	path  string
	store *leveldb.DB
	cache map[string][]byte
}

type keys struct {
	privKey crypto.PrivKey
	pubKey  crypto.PubKey
}

func (k *Keystore) Verify(signature []byte, publicKey []byte, data []byte) (bool, error) {
	return Verify(signature, publicKey, data)
}

func (k *Keystore) GetPublic(key crypto.PrivKey) crypto.PubKey {
	return key.GetPublic()
}

func (k *Keystore) Sign(key crypto.PrivKey, data []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("no signing key given")
	}
	if data == nil {
		return nil, errors.New("given input data was undefined")
	}

	return key.Sign(data)
}

func (k *Keystore) GetKey(id []byte) (crypto.PrivKey, crypto.PubKey, error) {
	if len(id) == 0 {
		return nil, nil, errNoId
	}
	if k.store == nil {
		return nil, nil, nil
	}
	serializedKeys, ok := k.cache[string(id)]
	if !ok {
		var err error
		if serializedKeys, err = k.store.Get(id, nil); err != nil {
			return nil, nil, err
		}
	}

	deserializedKeys := &keys{}
	if err := json.Unmarshal(serializedKeys, deserializedKeys); err != nil {
		return nil, nil, err
	}

	k.cache[string(id)] = serializedKeys

	return deserializedKeys.privKey, deserializedKeys.pubKey, nil
}

func (k *Keystore) CreateKey(id, entropy []byte) (crypto.PrivKey, crypto.PubKey, error) {
	if len(id) == 0 {
		return nil, nil, errNoId
	}
	if k.store == nil {
		return nil, nil, nil
	}

	privKey, pubKey, err := crypto.GenerateSecp256k1Key(bytes.NewReader(entropy))
	if err != nil {
		return nil, nil, err
	}
	keys := keys{
		privKey: privKey,
		pubKey:  pubKey,
	}
	serializedKeys, err := json.Marshal(keys)
	if err != nil {
		return nil, nil, err
	}

	batch := new(leveldb.Batch)
	batch.Put(id, serializedKeys)

	if err = k.store.Write(batch, nil); err != nil {
		return nil, nil, err
	}

	k.cache[string(id)] = serializedKeys

	return privKey, pubKey, nil
}

func (k *Keystore) HasKey(id []byte) (bool, error) {
	if len(id) == 0 {
		return false, errNoId
	}
	if k.store == nil {
		return false, nil
	}
	return k.store.Has(id, nil)
}

func (k *Keystore) Open() error {
	var err error
	k.store, err = createStore(k.path)
	return err
}

func (k *Keystore) Close() error {
	if k.store == nil {
		return nil
	}
	return k.store.Close()
}

func createStore(path string) (*leveldb.DB, error) {
	_, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return leveldb.OpenFile(path, nil)
}

func New(path string) (*Keystore, error) {
	if len(path) == 0 {
		path = "./keystore"
	}
	return &Keystore{
		path:  path,
		cache: make(map[string][]byte),
	}, nil
}

func Verify(signature []byte, publicKey []byte, data []byte) (bool, error) {
	return verifier.Verify(signature, publicKey, data)
}
