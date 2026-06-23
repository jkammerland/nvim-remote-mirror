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
| `unreplayable` | Queue row is missing the durable snapshot needed for replay |

Use `:RemoteQueue` for a picker UI or `:RemoteSaveQueue` for quickfix.

## Conflict Handling

A conflict keeps both sides:

| Copy | Purpose |
| --- | --- |
| Local mirror file | Your saved local version |
| Snapshot file | Durable saved bytes |
| Remote conflict copy | Remote bytes that blocked upload |

Use `:RemoteConflicts` to open or diff the available copies. After resolving
manually, save the chosen buffer and retry with `:RemoteFlushQueue`. The next
resolved save compares against the remote hash that caused the conflict, not an
older base hash from the original save attempt.

`:RemoteConflicts` asks the sidecar for conflict rows directly, so large pending
queues do not hide later conflict entries.

## New Remote Files

By default, untracked mirror-root files are not uploaded automatically. Use
`:RemoteAdopt [path]` to intentionally create a new remote file or recreate a
file that validation marked deleted. Set `adoption_policy = "auto"` only when
legacy mirror-root auto-adoption is desired.

When the sidecar is connected but the remote is unavailable, `:RemoteAdopt`
stores the saved bytes in the durable queue before retrying remote upload. If
Neovim has no sidecar connection at all, the plugin can only defer the adoption
in memory until reconnect; save or adopt again after restart if needed.

## Disconnected Saves

If Neovim saves a remote mirror buffer while disconnected, the plugin defers
the flush. On reconnect, the sidecar snapshots the local mirror file and moves
it into the durable queue before trying upload.

If Neovim crashes before replay, the reconnect recovery scan can still detect
changed mirror bytes and queue them.
