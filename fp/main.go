// Command slowquery-fingerprint reads a CloudWatch slow-query export (JSON array)
// and produces a Markdown report of queries grouped by an AST-based fingerprint,
// ranked by frequency of occurrence.
//
// Usage:
//
//	slowquery-fingerprint [inputFile] [outputFile] [minCount]
//
// Defaults: ./report.json -> ./report.md, minCount = 40.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type row struct {
	Timestamp    string `json:"@timestamp"`
	QueryTime    string `json:"Query_time"`
	LockTime     string `json:"Lock_time"`
	RowsSent     string `json:"Rows_sent"`
	RowsExamined string `json:"Rows_examined"`
	Query        string `json:"Query"`
}

type group struct {
	fingerprint    string
	count          int
	totalQueryTime float64
	maxQueryTime   float64
	maxRowsExamined float64
	maxRowsSent    float64
	maxLockTime    float64
	sample         string
	firstSeen      string
	lastSeen       string
	parsed         bool // false if this group was fingerprinted via regex fallback
}

func atof(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// humanInt formats an integer with thousands separators.
func humanInt(f float64) string {
	n := int64(f)
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// f2 formats a float with up to `d` decimals and thousands separators.
func f2(f float64, d int) string {
	whole := humanInt(f)
	if d == 0 {
		return whole
	}
	frac := f - float64(int64(f))
	if frac < 0 {
		frac = -frac
	}
	fs := strconv.FormatFloat(frac, 'f', d, 64) // "0.xx"
	fs = strings.TrimRight(strings.TrimPrefix(fs, "0."), "0")
	if fs == "" {
		return whole
	}
	return whole + "." + fs
}

func main() {
	args := os.Args[1:]
	exeDir, _ := os.Getwd()

	inputFile := filepath.Join(exeDir, "report.json")
	if len(args) > 0 && args[0] != "" {
		inputFile = args[0]
	}
	outputFile := filepath.Join(exeDir, "report.md")
	if len(args) > 1 && args[1] != "" {
		outputFile = args[1]
	}
	minCount := 40
	if len(args) > 2 && args[2] != "" {
		if v, err := strconv.Atoi(args[2]); err == nil {
			minCount = v
		}
	}

	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read input:", err)
		os.Exit(1)
	}
	var rows []row
	if err := json.Unmarshal(data, &rows); err != nil {
		fmt.Fprintln(os.Stderr, "parse json:", err)
		os.Exit(1)
	}

	groups := map[string]*group{}
	fallbackCount := 0
	for _, r := range rows {
		fp, ok := Fingerprint(r.Query)
		if !ok {
			fp = regexFingerprint(r.Query)
			fallbackCount++
		}
		if strings.TrimSpace(fp) == "" {
			continue
		}
		g := groups[fp]
		if g == nil {
			g = &group{fingerprint: fp, sample: r.Query, firstSeen: r.Timestamp, lastSeen: r.Timestamp, parsed: ok}
			groups[fp] = g
		}
		qt := atof(r.QueryTime)
		g.count++
		g.totalQueryTime += qt
		if qt > g.maxQueryTime {
			g.maxQueryTime = qt
		}
		if re := atof(r.RowsExamined); re > g.maxRowsExamined {
			g.maxRowsExamined = re
		}
		if rs := atof(r.RowsSent); rs > g.maxRowsSent {
			g.maxRowsSent = rs
		}
		if lt := atof(r.LockTime); lt > g.maxLockTime {
			g.maxLockTime = lt
		}
		if r.Timestamp != "" {
			if g.firstSeen == "" || r.Timestamp < g.firstSeen {
				g.firstSeen = r.Timestamp
			}
			if g.lastSeen == "" || r.Timestamp > g.lastSeen {
				g.lastSeen = r.Timestamp
			}
		}
	}

	ranked := make([]*group, 0, len(groups))
	for _, g := range groups {
		ranked = append(ranked, g)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].count != ranked[j].count {
			return ranked[i].count > ranked[j].count
		}
		return ranked[i].totalQueryTime > ranked[j].totalQueryTime
	})

	var top []*group
	for _, g := range ranked {
		if g.count >= minCount {
			top = append(top, g)
		}
	}

	var b strings.Builder
	b.WriteString("# Slow Query Frequency Report\n\n")
	for i, g := range top {
		fmt.Fprintf(&b, "### %d. %d× — max %ss\n\n", i+1, g.count, f2(g.maxQueryTime, 2))
		fmt.Fprintf(&b, "- **Occurrences:** %s\n", humanInt(float64(g.count)))
		fmt.Fprintf(&b, "- **Query time:** max %ss · total %ss\n", f2(g.maxQueryTime, 2), f2(g.totalQueryTime, 2))
		fmt.Fprintf(&b, "- **Rows examined:** max %s\n", f2(g.maxRowsExamined, 0))
		fmt.Fprintf(&b, "- **Rows sent:** max %s\n", f2(g.maxRowsSent, 0))
		fmt.Fprintf(&b, "- **Lock time:** max %ss\n", f2(g.maxLockTime, 4))
		seen := "—"
		if g.firstSeen != "" {
			seen = g.firstSeen + " → " + g.lastSeen
		}
		fmt.Fprintf(&b, "- **Seen:** %s\n", seen)
		if !g.parsed {
			b.WriteString("- **Note:** fingerprinted via regex fallback (query did not parse)\n")
		}
		b.WriteString("\n```sql\n")
		b.WriteString(strings.TrimSpace(stripPrologue(g.sample)))
		b.WriteString("\n```\n\n")
	}

	if err := os.WriteFile(outputFile, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write output:", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %s\n", outputFile)
	fmt.Printf("  %s rows -> %s distinct shapes (%d with count >= %d; %d parsed via regex fallback)\n",
		humanInt(float64(len(rows))), humanInt(float64(len(groups))), len(top), minCount, fallbackCount)
}
