package tunnel

import (
	"regexp"
	"sync"
)

type vhostStorage interface {
	// AddHost adds the given host and identifier to the storage
	AddHost(host, identifier string, rewrites []HTTPRewriteRule)

	// DeleteHost deletes the given host
	DeleteHost(host string)

	// GetHost returns the host name for the given identifier
	GetHost(identifier string) (string, bool)

	// GetVirtualHost returns entire virtualhost info for the given identifier
	GetVirtualHost(identifier string) (*virtualHost, bool)

	// GetIdentifier returns the identifier for the given host
	GetIdentifier(host string) (string, bool)
}

type virtualHost struct {
	identifier string
	Rewrite    []HTTPRewriteRule
	TargetHost string
}

type HTTPRewriteRule struct {
	re          *regexp.Regexp
	replacement string
}

// virtualHosts is used for mapping host to users example: host
// "fs-1-fatih.kd.io" belongs to user "arslan"
type virtualHosts struct {
	mapping map[string]*virtualHost
	sync.Mutex
}

// newVirtualHosts provides an in memory virtual host storage for mapping
// virtual hosts to identifiers.
func newVirtualHosts() *virtualHosts {
	return &virtualHosts{
		mapping: make(map[string]*virtualHost),
	}
}

func (v *virtualHosts) AddHost(host, identifier string, rewrites []HTTPRewriteRule) {
	v.Lock()
	v.mapping[host] = &virtualHost{identifier: identifier, Rewrite: rewrites}
	v.Unlock()
}

func (v *virtualHosts) DeleteHost(host string) {
	v.Lock()
	delete(v.mapping, host)
	v.Unlock()
}

// GetIdentifier returns the identifier associated with the given host
func (v *virtualHosts) GetIdentifier(host string) (string, bool) {
	v.Lock()
	ht, ok := v.mapping[host]
	v.Unlock()

	if !ok {
		return "", false
	}

	return ht.identifier, true
}

// GetHost returns the host associated with the given identifier
func (v *virtualHosts) GetHost(identifier string) (string, bool) {
	v.Lock()
	defer v.Unlock()

	for hostname, hst := range v.mapping {
		if hst.identifier == identifier {
			return hostname, true
		}
	}

	return "", false
}

func (v *virtualHosts) GetVirtualHost(identifier string) (*virtualHost, bool) {
	v.Lock()
	defer v.Unlock()

	for _, hst := range v.mapping {
		if hst.identifier == identifier {
			return hst, true
		}
	}

	return nil, false
}
