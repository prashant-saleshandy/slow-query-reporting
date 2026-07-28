package main

import "testing"

// pairs that MUST produce the same fingerprint
var samePairs = [][2]string{
	{ // literal values
		"select * from user where shAccountId = 78455",
		"select * from user where shAccountId = 45595",
	},
	{ // whitespace + keyword casing
		"select * from user where shAccountId = 1",
		"SELECT   *\n  FROM   user   WHERE   shAccountId   =   2",
	},
	{ // identifier casing
		"select id from user where ShAccountId = 1",
		"select id from user where shaccountid = 2",
	},
	{ // IN-list length
		"select id from prospect where userId in (1,2,3)",
		"select id from prospect where userId in (9,8,7,6,5,4)",
	},
	{ // reordered AND predicates
		"select * from user where a = 1 and b = 2",
		"select * from user where b = 9 and a = 8",
	},
	{ // reordered OR predicates
		"select * from user where a = 1 or b = 2",
		"select * from user where b = 9 or a = 8",
	},
	{ // table aliases differ
		"select u.id from user u where u.shAccountId = 1",
		"select usr.id from user usr where usr.shAccountId = 2",
	},
}

// pairs that MUST stay distinct
var distinctPairs = [][2]string{
	{
		"select * from user where shAccountId = 1",
		"select * from account where shAccountId = 1",
	},
	{
		"select id from user where a = 1 and b = 2",
		"select id from user where a = 1 or b = 2",
	},
}

func fp(t *testing.T, q string) string {
	t.Helper()
	f, ok := Fingerprint(q)
	if !ok {
		t.Fatalf("failed to parse/fingerprint: %s", q)
	}
	return f
}

func TestSameFingerprint(t *testing.T) {
	for i, p := range samePairs {
		a, b := fp(t, p[0]), fp(t, p[1])
		if a != b {
			t.Errorf("pair %d expected SAME but differ:\n  a=%s\n  b=%s", i, a, b)
		}
	}
}

func TestDistinctFingerprint(t *testing.T) {
	for i, p := range distinctPairs {
		a, b := fp(t, p[0]), fp(t, p[1])
		if a == b {
			t.Errorf("pair %d expected DISTINCT but same:\n  %s", i, a)
		}
	}
}
