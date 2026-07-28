package main

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	vtlog "vitess.io/vitess/go/vt/log"
	"vitess.io/vitess/go/vt/sqlparser"
)

// placeholder is the single token every literal collapses to in a fingerprint.
const placeholder = "?"

var parser *sqlparser.Parser

func init() {
	// Vitess logs a WARN (through its own vt/log package) every time it
	// gracefully falls back on a query it can't fully parse (e.g.
	// `CREATE TEMPORARY TABLE ... SELECT`). Those are expected here and handled
	// by regexFingerprint, so swap in a discard logger to keep stderr clean.
	vtlog.SwapLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	p, err := sqlparser.New(sqlparser.Options{})
	if err != nil {
		panic(err)
	}
	parser = p
}

// prologueRe strips the `use <db>;` / `SET timestamp=...;` session statements the
// slow-query log prepends, in any order, from the front of a query blob.
var prologueRe = regexp.MustCompile(`(?is)^\s*(?:use\s+[` + "`" + `"\w]+\s*;|set\s+timestamp\s*=\s*\d+\s*;?)\s*`)

func stripPrologue(raw string) string {
	q := raw
	for {
		n := prologueRe.ReplaceAllString(q, "")
		if n == q {
			return q
		}
		q = n
	}
}

// Fingerprint returns a canonical "shape" for a SQL statement so that queries
// differing only by literal values, identifier casing, whitespace, IN-list
// length, table aliases, or the order of AND/OR predicates collapse together.
//
// It parses the statement into an AST (Vitess MySQL parser) and applies:
//   - literal redaction        (78455 -> ?)
//   - IN-list collapse         (IN (1,2,3) -> IN (?))
//   - identifier lowercasing   (ShAccountId -> shaccountid)
//   - table-alias canonicalization (user u / user usr -> user as t1, refs remapped)
//   - AND/OR operand sorting   (a AND b == b AND a)
//
// The second return value reports whether the AST path succeeded; on any parse
// error the caller should fall back to regexFingerprint.
func Fingerprint(rawQuery string) (string, bool) {
	q := strings.TrimSpace(stripPrologue(rawQuery))
	q = strings.TrimRight(q, "; \n\t")
	if q == "" {
		return "", false
	}

	// A row may still carry more than one statement; take the last real one.
	pieces, err := parser.SplitStatementToPieces(q)
	if err == nil && len(pieces) > 0 {
		q = pieces[len(pieces)-1]
	}

	stmt, err := parser.Parse(q)
	if err != nil {
		return "", false
	}

	// Pass 1: assign every distinct table alias a canonical positional name
	// (t1, t2, ...) in first-appearance order, so `user u` and `user usr`
	// fingerprint identically once their column qualifiers are remapped too.
	aliasMap := map[string]string{}
	_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		if ate, ok := node.(*sqlparser.AliasedTableExpr); ok && !ate.As.IsEmpty() {
			low := strings.ToLower(ate.As.String())
			if _, seen := aliasMap[low]; !seen {
				aliasMap[low] = fmt.Sprintf("t%d", len(aliasMap)+1)
			}
		}
		return true, nil
	}, stmt)

	// Pass 2: redact literals, collapse IN lists, lowercase + remap identifiers.
	pre := func(cursor *sqlparser.Cursor) bool {
		switch n := cursor.Node().(type) {
		case *sqlparser.Literal:
			cursor.Replace(sqlparser.NewStrLiteral(placeholder))
		case *sqlparser.ComparisonExpr:
			if n.Operator == sqlparser.InOp || n.Operator == sqlparser.NotInOp {
				if _, ok := n.Right.(sqlparser.ValTuple); ok {
					n.Right = sqlparser.ValTuple{sqlparser.NewStrLiteral(placeholder)}
				}
			}
		case *sqlparser.ColName:
			n.Name = sqlparser.NewIdentifierCI(strings.ToLower(n.Name.String()))
			if !n.Qualifier.Name.IsEmpty() {
				qn := strings.ToLower(n.Qualifier.Name.String())
				if canon, ok := aliasMap[qn]; ok {
					qn = canon
				}
				n.Qualifier.Name = sqlparser.NewIdentifierCS(qn)
			}
		case *sqlparser.AliasedTableExpr:
			if !n.As.IsEmpty() {
				low := strings.ToLower(n.As.String())
				if canon, ok := aliasMap[low]; ok {
					n.As = sqlparser.NewIdentifierCS(canon)
				}
			}
		}
		return true
	}

	// Pass 3 (bottom-up): sort operands of commutative AND / OR chains so that
	// predicate ordering no longer affects the fingerprint.
	post := func(cursor *sqlparser.Cursor) bool {
		switch n := cursor.Node().(type) {
		case *sqlparser.AndExpr:
			if _, parentAnd := cursor.Parent().(*sqlparser.AndExpr); !parentAnd {
				cursor.Replace(rebuildAnd(sortExprs(flattenAnd(n))))
			}
		case *sqlparser.OrExpr:
			if _, parentOr := cursor.Parent().(*sqlparser.OrExpr); !parentOr {
				cursor.Replace(rebuildOr(sortExprs(flattenOr(n))))
			}
		}
		return true
	}

	out := sqlparser.Rewrite(stmt, pre, post)
	return sqlparser.String(out), true
}

func flattenAnd(e sqlparser.Expr) []sqlparser.Expr {
	if a, ok := e.(*sqlparser.AndExpr); ok {
		return append(flattenAnd(a.Left), flattenAnd(a.Right)...)
	}
	return []sqlparser.Expr{e}
}

func flattenOr(e sqlparser.Expr) []sqlparser.Expr {
	if o, ok := e.(*sqlparser.OrExpr); ok {
		return append(flattenOr(o.Left), flattenOr(o.Right)...)
	}
	return []sqlparser.Expr{e}
}

func sortExprs(parts []sqlparser.Expr) []sqlparser.Expr {
	sort.SliceStable(parts, func(i, j int) bool {
		return sqlparser.String(parts[i]) < sqlparser.String(parts[j])
	})
	return parts
}

func rebuildAnd(parts []sqlparser.Expr) sqlparser.Expr {
	acc := parts[0]
	for _, p := range parts[1:] {
		acc = &sqlparser.AndExpr{Left: acc, Right: p}
	}
	return acc
}

func rebuildOr(parts []sqlparser.Expr) sqlparser.Expr {
	acc := parts[0]
	for _, p := range parts[1:] {
		acc = &sqlparser.OrExpr{Left: acc, Right: p}
	}
	return acc
}

// --- regex fallback (used only when the AST parser cannot handle a query) ---

var (
	reInList  = regexp.MustCompile(`(?is)\bIN\s*\(\s*[^()]*?\s*\)`)
	reSQuote  = regexp.MustCompile(`'(?:[^'\\]|\\.)*'`)
	reDQuote  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	reFloat   = regexp.MustCompile(`\b\d+\.\d+\b`)
	reInt     = regexp.MustCompile(`\b\d+\b`)
	reSpace   = regexp.MustCompile(`\s+`)
	reComment = regexp.MustCompile(`/\*.*?\*/`)
)

// regexFingerprint is the best-effort shape used when a query fails to parse.
func regexFingerprint(rawQuery string) string {
	q := stripPrologue(rawQuery)
	q = reComment.ReplaceAllString(q, " ")
	q = reInList.ReplaceAllString(q, "IN ("+placeholder+")")
	q = reSQuote.ReplaceAllString(q, placeholder)
	q = reDQuote.ReplaceAllString(q, placeholder)
	q = reFloat.ReplaceAllString(q, placeholder)
	q = reInt.ReplaceAllString(q, placeholder)
	q = reSpace.ReplaceAllString(q, " ")
	return strings.ToLower(strings.TrimSpace(q))
}
