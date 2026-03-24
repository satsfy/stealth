# Stealth API

`stealth-api` is the Rust HTTP transport layer for Stealth.

## Usage

Command below runs stealth api endpoints. Configure port with env var `STEALTH_API_BIND` (default `127.0.0.1:20899`).

```
cargo run --bin stealth-api
```

Sample descriptor run:

```
curl 'http://localhost:20899/api/wallet/scan' \
  -H 'content-type: application/json' \
  -d '{"descriptor":"wpkh(xpub.../0/*)"}' | jq
{
  "stats": {
    "transactions_analyzed": 0,
    "addresses_derived": 1,
    "utxos_current": 0
  },
  "findings": [],
  "warnings": [],
  "summary": {
    "findings": 0,
    "warnings": 0,
    "clean": true
  }
}
```

## API

### `POST /api/wallet/scan`

Accepts one mutually-exclusive source:

- `descriptor: string`
- `descriptors: string[]`
- `utxos: UtxoInput[]`

Requests with no input source or multiple sources are rejected with `400 Bad Request`.

The endpoint currently runs transport preflight validation and returns an empty
report shape; detector execution lives in `stealth_core::TxGraph::detect_all`.
