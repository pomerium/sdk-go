package sdk

import (
	"github.com/go-jose/go-jose/v3"
	lru "github.com/hashicorp/golang-lru/v2"
)

// LRUKeyStore implements JSONWebKeyStore using an in-memory LRU cache.
type LRUKeyStore struct {
	cache *lru.Cache[string, *jose.JSONWebKey]
}

// NewLRUKeyStore creates a new key store of the given size.
func NewLRUKeyStore(size int) (*LRUKeyStore, error) {
	c, err := lru.New[string, *jose.JSONWebKey](size)
	if err != nil {
		return nil, err
	}
	return &LRUKeyStore{c}, nil
}

func (k *LRUKeyStore) Get(key string) (value *jose.JSONWebKey, ok bool) {
	return k.cache.Get(key)
}

func (k *LRUKeyStore) Add(key string, value *jose.JSONWebKey) {
	k.cache.Add(key, value)
}
