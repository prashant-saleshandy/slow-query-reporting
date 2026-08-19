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
	"time"
)

type row struct {
	Timestamp    string `json:"@timestamp"`
	User         string `json:"User"`
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
	users          map[string]int
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

// formatUsers renders a group's users sorted by frequency, e.g. "app (30), admin-panel (15)".
func formatUsers(users map[string]int) string {
	if len(users) == 0 {
		return "—"
	}
	type uc struct {
		name  string
		count int
	}
	list := make([]uc, 0, len(users))
	for name, count := range users {
		list = append(list, uc{name, count})
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].name < list[j].name
	})
	parts := make([]string, 0, len(list))
	for _, u := range list {
		parts = append(parts, fmt.Sprintf("%s (%s)", u.name, humanInt(float64(u.count))))
	}
	return strings.Join(parts, ", ")
}

// cloudwatchLinkTemplate is a CloudWatch Log Analytics deep link for the slow-query
// log group, pre-baked for the day 2026-08-18 (IST). The four date stamps below
// (two in the active query's START/END, two stale ones left over in the "from"
// back-navigation fragment) get swapped out for the report's actual date range by
// buildCloudWatchLink. Everything else — fields, filters, sort, queryId — is fixed.
const cloudwatchLinkTemplate = `https://us-west-2.console.aws.amazon.com/cloudwatch/home?region=us-west-2#log-analytics?active=%7E%27a&a.id=%7E%27eb5ff26c-90d8-4a04-bfcd-21f965d8cbd4&a.pos=%7E%270&a.label=%7E%27Query*201&a.type=%7E%27query&a.tz=%7E%27Local&a.query=%7E%27SOURCE*20*22*2faws*2frds*2fcluster*2fleo-cluster*2fslowquery*22*20START*3d2026-08-17T18*3a30*3a00.000Z*20END*3d2026-08-18T18*3a29*3a59.000Z*20*7c*0afields*20*40timestamp*0a*7c*20filter*20*40message*20like*20*2f*23*20Query_time*2f*0a*7c*20filter*20*40message*20not*20like*20*2fsh_read*2f*0a*7c*20filter*20*40message*20not*20like*20*2ftools_readonly*2f*0a*7c*20filter*20*40message*20not*20like*20*2fLIMIT*20500*20OFFSET*2f*0a*7c*20filter*20*40message*20not*20like*20*2fINSERT*2f*0a*7c*20filter*20*40message*20not*20like*20*2fDELETE*2f*0a*23*20*7c*20stats*20count*28*2a*29*0a*7c*20parse*20*40message*20*2f*23*20User*40Host*3a*20*28*3f*3cUser*3e*5cS*2b*29*5c*5b*5cS*2b*5c*5d*20*40*20*20*5c*5b*28*3f*3cHost*3e*5b*5e*5c*5d*5d*2b*29*5c*5d*20*20Id*3a*2f*0a*7c*20parse*20*40message*20*2f*23*20Query_time*3a*20*28*3f*3cQuery_time*3e*5cS*2b*29*20*20Lock_time*3a*20*28*3f*3cLock_time*3e*5cS*2b*29*20Rows_sent*3a*20*28*3f*3cRows_sent*3e*5cS*2b*29*20*20Rows_examined*3a*20*28*3f*3cRows_examined*3e*5cS*2b*29*5cn*28*3f*3cQuery*3e*5b*5e*23*5d.*2a*29*2f*0a*7c*20sort*20User*20desc*0a*7c*20limit*2010000&from=%23logsV2%3Alogs-insights%3FqueryDetail%3D~(end~'2026-06-15T18*3a29*3a59.000Z~start~'2026-06-14T18*3a30*3a00.000Z~timeType~'ABSOLUTE~tz~'LOCAL~editorString~'fields*20*40timestamp*0a*7c*20filter*20*40message*20like*20*2f*23*20Query_time*2f*0a*7c*20filter*20*40message*20not*20like*20*2fsh_read*2f*0a*7c*20filter*20*40message*20not*20like*20*2ftools_readonly*2f*0a*7c*20filter*20*40message*20not*20like*20*2fLIMIT*20500*20OFFSET*2f*0a*7c*20filter*20*40message*20not*20like*20*2fINSERT*2f*0a*7c*20filter*20*40message*20not*20like*20*2fDELETE*2f*0a*23*20*7c*20stats*20count*28*2a*29*0a*7c*20parse*20*40message*20*2f*23*20User*40Host*3a*20*28*3f*3cUser*3e*5cS*2b*29*5c*5b*5cS*2b*5c*5d*20*40*20*20*5c*5b*28*3f*3cHost*3e*5b*5e*5c*5d*5d*2b*29*5c*5d*20*20Id*3a*2f*0a*7c*20parse*20*40message*20*2f*23*20Query_time*3a*20*28*3f*3cQuery_time*3e*5cS*2b*29*20*20Lock_time*3a*20*28*3f*3cLock_time*3e*5cS*2b*29*20Rows_sent*3a*20*28*3f*3cRows_sent*3e*5cS*2b*29*20*20Rows_examined*3a*20*28*3f*3cRows_examined*3e*5cS*2b*29*5cn*28*3f*3cQuery*3e*5b*5e*23*5d.*2a*29*2f*0a*7c*20sort*20Query_time*20desc*0a*7c*20limit*2010000~queryId~'eb5ff26c-90d8-4a04-bfcd-21f965d8cbd4~source~(~'*2faws*2frds*2fcluster*2fleo-cluster*2fslowquery)~lang~'CWLI~logClass~'STANDARD~queryBy~'logGroupName))`

// buildCloudWatchLink returns cloudwatchLinkTemplate with its date stamps replaced
// so the query window covers reportDate's full IST day (reportDate-1 18:30:00 UTC
// through reportDate 18:29:59 UTC).
func buildCloudWatchLink(reportDate time.Time) string {
	end := reportDate.Format("2006-01-02")
	start := reportDate.AddDate(0, 0, -1).Format("2006-01-02")
	link := cloudwatchLinkTemplate
	link = strings.ReplaceAll(link, "2026-08-17", start)
	link = strings.ReplaceAll(link, "2026-08-18", end)
	link = strings.ReplaceAll(link, "2026-06-14", start)
	link = strings.ReplaceAll(link, "2026-06-15", end)
	return link
}

// modeDate returns the most frequently occurring YYYY-MM-DD prefix among the
// rows' timestamps — i.e. the day the export is actually reporting on, robust to
// a handful of stragglers spilling over a day boundary.
func modeDate(rows []row) (time.Time, bool) {
	counts := map[string]int{}
	for _, r := range rows {
		if len(r.Timestamp) >= 10 {
			counts[r.Timestamp[:10]]++
		}
	}
	best := ""
	bestCount := 0
	for d, c := range counts {
		if c > bestCount || (c == bestCount && d > best) {
			best, bestCount = d, c
		}
	}
	if best == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", best)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
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
			g = &group{fingerprint: fp, sample: r.Query, firstSeen: r.Timestamp, lastSeen: r.Timestamp, parsed: ok, users: map[string]int{}}
			groups[fp] = g
		}
		qt := atof(r.QueryTime)
		g.count++
		g.totalQueryTime += qt
		if r.User != "" {
			g.users[r.User]++
		}
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
	if d, ok := modeDate(rows); ok {
		fmt.Fprintf(&b, "slow queries for - %s\n\n", d.Format("January 2, 2006"))
		fmt.Fprintf(&b, "total slow queries - [%s](%s)\n\n", humanInt(float64(len(rows))), buildCloudWatchLink(d))
	}
	b.WriteString("# Slow Query Frequency Report\n\n")
	for i, g := range top {
		fmt.Fprintf(&b, "### %d. %d× — max %ss\n\n", i+1, g.count, f2(g.maxQueryTime, 2))
		fmt.Fprintf(&b, "- **Occurrences:** %s\n", humanInt(float64(g.count)))
		fmt.Fprintf(&b, "- **Query time:** max %ss · total %ss\n", f2(g.maxQueryTime, 2), f2(g.totalQueryTime, 2))
		fmt.Fprintf(&b, "- **Rows examined:** max %s\n", f2(g.maxRowsExamined, 0))
		fmt.Fprintf(&b, "- **Rows sent:** max %s\n", f2(g.maxRowsSent, 0))
		fmt.Fprintf(&b, "- **Lock time:** max %ss\n", f2(g.maxLockTime, 4))
		fmt.Fprintf(&b, "- **User:** %s\n", formatUsers(g.users))
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
