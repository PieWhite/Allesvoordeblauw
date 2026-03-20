# GoVersionML

Netflow botnet detection pipeline using XGBoost with direct support for multiple input formats.

## Supported input formats

- `.json` (existing JSON / NDJSON ingestion path)
- `.netflow` (direct text/csv/pipe parsing)
- `.binetflow` (handled through netflow parser path)

By default, the tool auto-detects input format from file extension.

## Usage

Basic (auto-detect format):

```powershell
go run . test_netflow.json
```

Force JSON parser:

```powershell
go run . -input-format json test_netflow.json
```

Force netflow parser:

```powershell
go run . -input-format netflow ..\Confidential-Data\demo-line.netflow
```

Write output report to file:

```powershell
go run . -o results.txt test_netflow.json
```

Use a custom model:

```powershell
go run . -m .\Xgboost\botnet_xgboost.json test_netflow.json
```

## CLI flags

- `-m` path to XGBoost JSON model (default `./Xgboost/botnet_xgboost.json`)
- `-o` optional output report file
- `-input-format` `auto|json|netflow` (default `auto`)

## Ingestion architecture

- Parser abstraction in `ingest` (`Parser` interface)
- Factory selection by extension and optional explicit override
- All parsed records are normalized by a centralized normalizer before detection

This keeps detector/scorer logic unchanged and reduces parser-specific drift.

## Notes on legacy conversion tooling

Any old conversion step is now optional. Direct `.netflow` input is supported natively.

## Validation

Run tests:

```powershell
go test ./...
```
