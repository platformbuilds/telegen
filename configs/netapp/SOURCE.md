# NetApp template provenance

Templates under `configs/netapp/{rest,restperf,keyperf,ems,eseries,eseriesperf}/` are adapted from the NetApp Harvest project (`https://github.com/NetApp/harvest`), licensed under Apache License 2.0.

Harvest source revision at copy time: track via `git -C <harvest-repo> rev-parse HEAD` when syncing.

Telegen owns runtime interpretation of these templates; do not import Harvest as a Go module.

Catalog parity: `make netapp-parity` must report zero missing families against Harvest
`mcp/metadata/ontap_metrics.json` (1,558 ONTAP families). Keep
`parity-allowlist.txt` empty of metric names.
