// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube // import "github.com/mirastacklabs-ai/telegen/internal/kubei"

import (
	"sync"

	"github.com/mirastacklabs-ai/telegen/internal/kube/kubecache/informer"
	attr "github.com/mirastacklabs-ai/telegen/pkg/export/attributes/names"
)

// TopOwner assumes that the owners slice as returned by the informers' cache library,
// is sorted from lower-level to upper-level, so the last owner will be the top owner
// (e.g. the Deployment that owns the ReplicaSet that owns a Pod).
func TopOwner(pod *informer.PodInfo) *informer.Owner {
	if pod == nil || len(pod.Owners) == 0 {
		return nil
	}
	return pod.Owners[len(pod.Owners)-1]
}

// CachedObjMeta is a wrapper around the informer.ObjectMeta that also contains
// the OTEL resource metadata.
type CachedObjMeta struct {
	Meta             *informer.ObjectMeta
	OTELResourceMeta map[attr.Name]string

	cacheMu               sync.RWMutex
	mergedMetadataByScope map[string]map[attr.Name]string
}

func (c *CachedObjMeta) GetMergedMetadataCache(scope string) (map[attr.Name]string, bool) {
	if c == nil {
		return nil, false
	}
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	if c.mergedMetadataByScope == nil {
		return nil, false
	}
	m, ok := c.mergedMetadataByScope[scope]
	return m, ok
}

func (c *CachedObjMeta) SetMergedMetadataCache(scope string, metadata map[attr.Name]string) {
	if c == nil {
		return
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.mergedMetadataByScope == nil {
		c.mergedMetadataByScope = make(map[string]map[attr.Name]string)
	}
	c.mergedMetadataByScope[scope] = metadata
}
