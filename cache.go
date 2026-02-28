package main

import (
	"context"
	"net"
	"sync"
	"time"
)

type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

func (c *DNSCache) getHostname(ip string) string {
	c.mu.RLock()
	hostname, exists := c.cache[ip]
	c.mu.RUnlock()

	if exists {
		return hostname
	}

	c.mu.Lock()
	c.cache[ip] = ip
	c.mu.Unlock()

	go func(targetIP string) {
		res := net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		names, err := res.LookupAddr(ctx, targetIP)
		if err == nil && len(names) > 0 {
			c.mu.Lock()
			c.cache[targetIP] = names[0]
			c.mu.Unlock()
		}
	}(ip)

	return ip
}
