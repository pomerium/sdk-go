package sdk

import (
	lru "github.com/hashicorp/golang-lru"
)

// LRUKeyStore implements JSONWebKeyStore using an in-memory LRU cache.
type LRUKeyStore struct {
	cache *lru.Cache
}

// NewLRUKeyStore creates a new key store of the given size.
func NewLRUKeyStore(size int) (*LRUKeyStore, error) {
	c, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &LRUKeyStore{c}, nil
}

func (k *LRUKeyStore) Get(key interface{}) (value interface{}, ok bool) {
	return k.cache.Get(key)
}

func (k *LRUKeyStore) Add(key, value interface{}) {
	k.cache.Add(key, value)
}
