# Save Recovery

`nvim-remote-mirror` treats local saves as durable before it tries remote
upload. This is the safety model for slow or unstable links.

## Save Flow

1. Neovim writes the local mirror file.
2. The sidecar snapshots the saved bytes.
3. The sidecar compares the expected remote hash.
4. If the hash still matches, the agent installs the new file.
5. If upload fails, the save remains in the local queue.
6. If the remote changed, the queue entry becomes a conflict.

## Queue States

| State | Meaning |
| --- | --- |
| `pending` | Waiting for upload |
| `failed` | Upload failed but can be retried |
| `conflict` | Remote changed before upload |

Use `:RemoteQueue` for a picker UI or `:RemoteSaveQueue` for quickfix.

## Conflict Handling

A conflict keeps both sides:

| Copy | Purpose |
| --- | --- |
| Local mirror file | Your saved local version |
| Snapshot file | Durable saved bytes |
| Remote conflict copy | Remote bytes that blocked upload |

Use `:RemoteConflicts` to open or diff the available copies. After resolving
manually, save the chosen buffer and retry with `:RemoteFlushQueue`.

## Disconnected Saves

If Neovim saves a remote mirror buffer while disconnected, the plugin defers
the flush. On reconnect, the sidecar snapshots the local mirror file and moves
it into the durable queue before trying upload.

If Neovim crashes before replay, the reconnect recovery scan can still detect
changed mirror bytes and queue them.
