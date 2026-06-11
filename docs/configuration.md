# Configuration

Configure the plugin from Lua:

```lua
require("nvim_remote_mirror").setup({
  connection = "socket",
  remote_agent = "nrm-agent",
})
```

## Binaries

| Option | Default | Notes |
| --- | --- | --- |
| `sidecar` | `target/debug/nrm-sidecar` or `nrm-sidecar` | Local sidecar binary |
| `agent` | `target/debug/nrm-agent` or `nrm-agent` | Agent for local targets |
| `remote_agent` | `nrm-agent` | Command executed on SSH hosts |

For `ssh://` targets, `remote_agent` is used on the remote host. The local
`agent` path is not copied to the remote.

## Transport

| Option | Default | Notes |
| --- | --- | --- |
| `connection` | `stdio` | Use `socket` for reusable daemon mode |
| `socket_path` | `nil` | Explicit Unix socket path |
| `socket_dir` | `nil` | Directory for derived socket paths |
| `daemon_start_timeout_ms` | `1000` | Wait for socket daemon startup |
| `request_timeout_ms` | `30000` | Neovim request timeout |
| `ssh_connect_timeout_seconds` | `10` | SSH connect timeout |

## Search and Mirror Limits

| Option | Default |
| --- | --- |
| `find_limit` | `200` |
| `grep_limit` | `200` |
| `grep_remote_page_files` | `512` |
| `grep_remote_max_file_bytes` | `512 KiB` |
| `grep_remote_max_total_bytes` | `8 MiB` |
| `grep_cache_max_files` | `2000` |
| `grep_cache_max_file_bytes` | `512 KiB` |
| `grep_cache_max_total_bytes` | `8 MiB` |
| `open_batch_max_file_bytes` | `4 MiB` |
| `prefetch_max_file_bytes` | `4 MiB` |
| `prefetch_max_total_bytes` | `16 MiB` |

## Reconnect and Recovery

| Option | Default | Notes |
| --- | --- | --- |
| `auto_reconnect` | `true` | Retry after unexpected sidecar exit |
| `reconnect_delay_ms` | `1000` | Delay between reconnect attempts |
| `reconnect_max_attempts` | `3` | Max automatic attempts |
| `reconnect_stable_ms` | `10000` | Reset attempt count after stable connection |
| `recover_local_edits_on_connect` | `true` | Scan mirror for unsnapshotted local edits |
| `recover_local_edits_limit` | `256` | Recovery scan batch size |
| `flush_queue_on_connect` | `true` | Retry queued saves after connect |
| `flush_queue_on_connect_limit` | `1` | Bounded replay on connect |

## Background Mirror

| Option | Default | Notes |
| --- | --- | --- |
| `background_mirror` | `true` | Enable idle mirror building |
| `background_mirror_interval_ms` | `5000` | Tick interval |
| `background_mirror_rescan_interval_ms` | `300000` | Delay before full rescan |
| `background_mirror_scan_limit` | `256` | Metadata paths per scan batch |
| `background_mirror_prefetch_limit` | `4` | Known files to hydrate per tick |
| `background_mirror_refresh_limit` | `32` | Cached files to validate per tick |
| `background_mirror_max_file_bytes` | `128 KiB` | Per-file idle hydrate cap |
| `background_mirror_max_total_bytes` | `512 KiB` | Per-tick idle hydrate cap |
