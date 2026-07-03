# Protocol Notes

Neovim talks to the local sidecar with newline-delimited JSON. The sidecar talks
to the agent with length-prefixed binary RPC.

## Neovim to Sidecar

Request:

```json
{"id":1,"method":"open","params":{"path":"src/main.rs"}}
```

Response:

```json
{"id":1,"ok":true,"result":{"path":"src/main.rs"}}
```

Notification:

```json
{"method":"workspace/remote_health","params":{"remote_status":"unavailable"}}
```

Notifications do not have request IDs. Clients may ignore unknown
notifications.

## Workspace Info

`workspace_info` is local-first. It returns mirror paths, workspace identity,
transport metadata, command names, notification names, capabilities, and the
last known remote health. It must not block on SSH.

## Agent Boundary

The sidecar sends framed binary RPC to `nrm-agent`. Each request has an ID and
each response carries the same ID. Current SSH transport runs the agent process
over stdio.

Future transports must preserve:

| Requirement | Reason |
| --- | --- |
| Ordered delivery per lane | Keep save/read ordering predictable |
| Request IDs | Match responses to pending work |
| Timeout-compatible errors | Preserve reconnect/backoff behavior |
| Abort support | Replace active read/background work when preempted |
| Same agent command model | Avoid changing Neovim-facing APIs |

## Compatibility

`Request::Hello` is the sidecar-agent compatibility gate. Incompatible
sidecar/agent protocol versions must fail with a clear protocol version mismatch
message. The sidecar reports that failure as `remote_status = "unavailable"` in
`remote_probe`, `workspace_info`, and `workspace/remote_health` notifications so
Neovim can keep serving local mirror operations while the remote agent is fixed.
