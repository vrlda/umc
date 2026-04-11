package main

import (
	"context"
	"os"
	"strings"

	cfgpkg "github.com/openmesh/core/config"
	"github.com/openmesh/core/dht"
)

const envBootstrapManifestURLs = "OPENMESH_BOOTSTRAP_MANIFEST_URLS"

func (d *daemon) bootstrapIfNeeded(ctx context.Context) bool {
	if len(d.dhtNode.Peers()) > 0 {
		return false
	}

	urls := d.bootstrapManifestURLs()
	if len(urls) == 0 {
		return false
	}

	added := 0
	for _, url := range urls {
		records, err := dht.FetchPeerManifest(ctx, url)
		if err != nil {
			d.logger.Warn().Err(err).Str("url", url).Msg("failed to fetch bootstrap manifest")
			continue
		}

		for _, record := range records {
			if strings.TrimSpace(record.ID) == "" {
				continue
			}
			if err := d.dhtNode.Put(record.ID, record); err != nil {
				d.logger.Warn().Err(err).Str("peer_id", record.ID).Msg("failed to add bootstrap peer")
				continue
			}
			added++
		}
	}

	if added > 0 {
		d.logger.Info().Int("peers", added).Msg("bootstrapped peer table from manifest")
		return true
	}
	return false
}

func (d *daemon) bootstrapManifestURLs() []string {
	values := append([]string(nil), d.cfg.BootstrapManifestURLs...)
	values = append(values, cfgpkg.ParseStringList(os.Getenv(envBootstrapManifestURLs))...)
	return cfgpkg.NormalizeStringList(values)
}
