# Attack 44 investigation: start sandcat

## Selection

This investigation uses zero-based `attack_info.csv` row 44:

- Tactic: `lateral movement`
- Technique: `start sandcat`
- PID: `152566`
- Metadata time: `1701623585.0` (`2023-12-03T17:13:05Z` when interpreted as Unix time)

It is the dataset's only explicit lateral-movement record. Its command and descendants show a concrete multi-step remote-access sequence, making it more suitable than a generic collection or cleanup event.

## Observed evidence

PID `152566` maps to two Process entities:

| Entity ID | Timestamp field | Epoch | Command line | Label |
|---|---|---:|---|---|
| `86fe64bef7cfc5d236b26b3c6adcf04f` | `seen time` | 1701626485.151 | absent | `1 / lateralMovement` |
| `82fd22d6b1a5094a8d89584a450cd646` | `start time` | 1701626485.151 | base64-wrapped shell command | `1 / lateralMovement` |

Decoding the command as data—without executing it—reveals three actions against `172.16.64.128`: copy `sandcat.bash` using `scp`, make it executable using `ssh`, and start it using `ssh`.

The provenance Process time is `2900.151` seconds after the metadata time. The metadata `readable_time` is also four hours behind the UTC rendering of its numeric epoch. Neither file documents the reason, so the metadata time cannot be treated as execution time.

PID/PPID evidence identifies the following local lineage:

| Depth | PID | Provenance time | Command |
|---:|---:|---:|---|
| 0 | 152566 | 1701626485.151 | shell wrapper containing the three remote steps |
| 1 | 152570 | 1701626485.159 | `scp ... sandcat.bash erfan2@172.16.64.128:~/Desktop` |
| 2 | 152571 | 1701626485.167 | `ssh ... 172.16.64.128 scp -t ~/Desktop` |
| 1 | 152598 | 1701626511.882 | `ssh ... chmod u+x ./Desktop/sandcat.bash` |
| 1 | 152612 | 1701626525.453 | `ssh ... ./Desktop/sandcat.bash` |

Each PID has two Process IDs, giving ten labeled `lateralMovement` Process nodes. Their 15 incident provenance edges consist of five same-PID `WasTriggeredBy/execve` edges and ten `Used/load` edges. The used artifacts are `/usr/bin/sh`, `/usr/bin/scp`, `/usr/bin/ssh`, and `/lib64/ld-linux-x86-64.so.2`. No generated Artifact or network-socket Artifact is directly adjacent, even though the commands explicitly contain remote access.

The stated parent PID is `4127`, but no Process entity with PID 4127 exists in the capture. The parent therefore cannot be reconstructed as a provenance node.

## Why one execution has multiple Process IDs

Across the full file:

- 24,839 Process nodes form 12,443 PID groups.
- 12,059 PID groups contain exactly two nodes.
- 12,056 of those pairs have one `seen time` node and one `start time` node.
- 12,029 pairs have the same timestamp.
- All 13,136 `WasTriggeredBy` edges connect Process nodes with the same PID; none connects different PIDs.
- Their operations are `execve`, `setuid`, `setgid`, or `update`.

This strongly supports interpreting the IDs as process-state or execution-version entities around state-changing events, rather than duplicate observations or OS parent/child nodes. For the selected attack, `WasTriggeredBy/execve` joins the command-bearing start-time entity to the seen-time entity. The exact lifecycle semantics and direction remain undocumented, so “pre-exec” and “post-exec” cannot yet be assigned confidently.

## Temporal-window tests

| Strategy | Global edges | Global nodes | Selected-lineage edge coverage | Assessment |
|---|---:|---:|---:|---|
| Metadata ±60 seconds | 68 | 40 | 0/15 | Misses the attack and contains discovery-labeled activity. |
| Metadata ±15 minutes | 766 | 218 | 0/15 | Still misses the attack. |
| Metadata ±1 hour | 3,034 | 841 | 15/15 | Captures it only by admitting a large amount of unrelated activity. |
| Provenance Process ±60 seconds | 75 | 41 | 15/15 | Captures the full local lineage with modest context. |
| Provenance Process ±5 minutes | 260 | 87 | 15/15 | Adds activity without improving lineage coverage. |
| Exact lineage edge envelope | 36 | 25 | 15/15 | Tightest complete temporal interval: 40.302 seconds. |
| Metadata-to-lineage bridge | 1,238 | 345 | 15/15 | Includes 109 network artifacts, none shown to belong to this lineage. |

Unconstrained two-hop graph traversal is worse: the two matched Process nodes reach 12,225 nodes through shared `/usr/bin/sh` and loader Artifact IDs. Static artifacts are reused across the capture and act as graph hubs.

## Recommendation

For this attack, anchor extraction on the exact-PID provenance Process timestamp, follow PID/PPID descendants within a short horizon, and derive the core interval from their incident-edge timestamps. A small provenance-centered pad, approximately ±60 seconds here, is defensible for context. Preserve the metadata time as annotation and discrepancy evidence; do not use it as the event center.

This is an investigative result, not yet a generic extraction rule. Before generalizing it, other tactic types should be checked for longer-running children, missing PIDs, PID reuse, and artifact-only attack labels.

## Unresolved

- The metadata timestamp's source, timezone, and intended meaning.
- Exact semantics and direction of the paired Process states.
- Why network connect artifacts are absent for these `scp`/`ssh` processes.
- Whether PID/PPID scope is capture-wide, host-local, or session-local.
- Why attack labels are on Process nodes while all 15 incident edges are unlabeled.
