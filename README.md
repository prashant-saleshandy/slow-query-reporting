# slow-query-reporting

Turns a CloudWatch Log Analytics slow-query export (JSON array) into a Markdown
report of queries **ranked by frequency of occurrence**.

Queries that differ only by their literal values are grouped into one entry by a
**structural fingerprint** computed from the SQL's parse tree (AST), not by text
matching. So these two collapse into one group:

```sql
select * from user where shAccountId = 78455;
select * from user where shAccountId = 45595;
```

## Daily workflow

1. Drop the day's export into this folder as **`report.json`** (overwrite the
   previous one).
2. Run `./run.sh`.
3. Read the generated **`report.md`**.

```bash
./run.sh          # shapes with count >= 40 (default)
./run.sh 10       # shapes with count >= 10
```

## How fingerprinting works

Each query is parsed with the Vitess MySQL parser and normalized so that queries
sharing a pattern produce an identical fingerprint. Handled:

| Difference                         | Grouped together? |
|------------------------------------|:-----------------:|
| Literal values (`= 78455` vs `= 4`)| ✅ |
| `IN (...)` list length             | ✅ |
| Whitespace / newlines              | ✅ |
| Keyword casing (`SELECT`/`select`) | ✅ |
| Identifier casing (`ShAccountId`)  | ✅ |
| Table aliases (`user u`/`user usr`)| ✅ (aliases renamed to `t1,t2,…`, column refs remapped) |
| Reordered `AND` / `OR` predicates  | ✅ (operands sorted) |
| Genuinely different tables/columns/operators | ❌ kept distinct |

Queries the parser cannot handle (e.g. `CREATE TEMPORARY TABLE ... SELECT`) fall
back to a regex-based fingerprint so nothing is dropped; such entries are flagged
with a **Note** in the report, and the run summary prints how many used the
fallback.

## Output format

`report.md` opens with a two-line header:

```
slow queries for - August 18, 2026

total slow queries - [1,485](<CloudWatch Log Analytics link>)
```

The date is the day the export actually covers (the most common date among the
rows' timestamps, so a few stragglers spilling over midnight don't skew it). The
total-count link opens CloudWatch Log Analytics with the same slow-query search,
scoped to that day's full 24h window (IST midnight-to-midnight, expressed as UTC
`START`/`END`).

Below that, `report.md` is a flat list of matching shapes (count ≥ threshold),
ranked by count. Per entry: occurrence count, max/total query time, max rows
examined, max rows sent, max lock time, first/last seen, and a sample of the
query. Only observed maxima/totals from the source rows are shown — no computed
averages.

## Layout

```
slow-query-reporting/
├── report.json        # input (you overwrite this daily)
├── report.md          # generated output
├── run.sh             # generate report.md from report.json
├── build.sh           # rebuild the Go binary (only after editing fp/*.go)
├── fp/                # Go module: the fingerprinter
│   ├── main.go            # read JSON, group, emit markdown
│   ├── fingerprint.go     # AST fingerprint + regex fallback
│   ├── fingerprint_test.go
│   └── slowquery-fingerprint  # prebuilt static binary (run.sh uses this)
└── .toolchain/        # local Go toolchain (only needed to rebuild; ~deletable)
```

## Rebuilding

`run.sh` uses the committed static binary, so Go is not needed to run reports.
After editing anything under `fp/`, rebuild with:

```bash
./build.sh
```

This uses the Go toolchain in `.toolchain/` (fetched during setup). Run the
tests with:

```bash
cd fp && GOROOT="$PWD/../.toolchain/go" PATH="$GOROOT/bin:$PATH" go test ./...
```
