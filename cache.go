package session_to_jwt

import (
	"sync"
	"time"
)

// Cache is een eenvoudige in-memory key/value-cache met TTL, geschikt voor een
// beperkt aantal entries (één per actieve sessie-cookie).
type Cache struct {
	mu    sync.RWMutex
	items map[string]*Item
}

// Item is één gecachte waarde met een absolute verlooptijd (unix-seconden).
type Item struct {
	Value  []byte
	Expiry int64
}

// NewCache maakt een in-memory cache en start de opschoon-goroutine.
func NewCache() *Cache {
	c := &Cache{items: make(map[string]*Item)}
	go c.cleanup()
	return c
}

// Set bewaart een kopie van val onder key met een TTL in seconden.
func (c *Cache) Set(key string, val []byte, ttl int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	valCopy := make([]byte, len(val))
	copy(valCopy, val)

	c.items[key] = &Item{
		Value:  valCopy,
		Expiry: time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
	}
}

// Get geeft een kopie van de waarde terug als die bestaat en niet verlopen is.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[key]
	if !ok || time.Now().Unix() > item.Expiry {
		return nil, false
	}

	result := make([]byte, len(item.Value))
	copy(result, item.Value)
	return result, true
}

// Delete verwijdert een entry (bv. bij uitloggen).
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}

// sharedCache is één proces-brede cache, gedeeld door alle session_to_jwt-
// handlers (zodat /v1 en /admin dezelfde tokens cachen) én door de evict-handler.
var (
	sharedCache     *Cache
	sharedCacheOnce sync.Once
)

// SharedCache geeft de proces-brede cache (lazy aangemaakt incl. opschoon-goroutine).
func SharedCache() *Cache {
	sharedCacheOnce.Do(func() { sharedCache = NewCache() })
	return sharedCache
}

// cleanup verwijdert elke 30s verlopen items (geschikt voor een beperkt aantal keys).
func (c *Cache) cleanup() {
	for {
		time.Sleep(30 * time.Second)
		now := time.Now().Unix()
		c.mu.Lock()
		for k, v := range c.items {
			if now > v.Expiry {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}
