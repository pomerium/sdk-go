package verify

import (
	lru "github.com/hashicorp/golang-lru"
	"github.com/pomerium/sdk-go"
)

var _ sdk.JSONWebKeyStore = &Cache{}

type Cache struct{ lru *lru.Cache }

func NewCache(size int) (*Cache, error) {
	c, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &Cache{c}, nil
}
func (c *Cache) Get(key interface{}) (value interface{}, ok bool) {
	return c.lru.Get(key)
}
func (c *Cache) Add(key, value interface{}) {
	_ = c.lru.Add(key, value) // we don't care about eviction
}
