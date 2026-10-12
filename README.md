# ledger

Free Kraken tentacle. MIT. Do not import `kraken.core`.

Append-only JSONL of `kraken run` results. Local only, no secrets, no network.
Every entry records what ran and whether it worked. Nothing else is kept — a
value that reaches the ledger is redacted, because a log that outlives the run
is exactly where a secret goes to hide.

```
JSON in → policy → exec → JSON out
```

## Actions

| Action | Does |
|---|---|
| `ping` | Liveness. Reports the ledger path and entry count. |
| `append` | Records one run result. Redacts before writing. |
| `list` | Recent entries, newest first. |
| `where` | Resolves the ledger path from the active config scopes. |
| `clear` | Empties the ledger. Requires the `ledger` grant. |

## Install

```
kraken tentacle add kraken-tentacle-ledger
```

## Tests

```
python3 -m pytest tests -q
```
