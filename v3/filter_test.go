package ldap

import (
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type compileTest struct {
	filterStr string

	expectedFilter string
	expectedType   int
	expectedErr    string
}

var testFilters = []compileTest{
	{
		filterStr:      "(&(sn=Miller)(givenName=Bob))",
		expectedFilter: "(&(sn=Miller)(givenName=Bob))",
		expectedType:   FilterAnd,
	},
	{
		filterStr:      "(|(sn=Miller)(givenName=Bob))",
		expectedFilter: "(|(sn=Miller)(givenName=Bob))",
		expectedType:   FilterOr,
	},
	{
		filterStr:      "(!(sn=Miller))",
		expectedFilter: "(!(sn=Miller))",
		expectedType:   FilterNot,
	},
	{
		filterStr:      "(sn=Miller)",
		expectedFilter: "(sn=Miller)",
		expectedType:   FilterEqualityMatch,
	},
	{
		filterStr:      "(sn=Mill*)",
		expectedFilter: "(sn=Mill*)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=*Mill)",
		expectedFilter: "(sn=*Mill)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=*Mill*)",
		expectedFilter: "(sn=*Mill*)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=*i*le*)",
		expectedFilter: "(sn=*i*le*)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=Mi*l*r)",
		expectedFilter: "(sn=Mi*l*r)",
		expectedType:   FilterSubstrings,
	},
	// substring filters escape properly
	{
		filterStr:      `(sn=Mi*함*r)`,
		expectedFilter: `(sn=Mi*\ed\95\a8*r)`,
		expectedType:   FilterSubstrings,
	},
	// already escaped substring filters don't get double-escaped
	{
		filterStr:      `(sn=Mi*\ed\95\a8*r)`,
		expectedFilter: `(sn=Mi*\ed\95\a8*r)`,
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=Mi*le*)",
		expectedFilter: "(sn=Mi*le*)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=*i*ler)",
		expectedFilter: "(sn=*i*ler)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn>=Miller)",
		expectedFilter: "(sn>=Miller)",
		expectedType:   FilterGreaterOrEqual,
	},
	{
		filterStr:      "(sn<=Miller)",
		expectedFilter: "(sn<=Miller)",
		expectedType:   FilterLessOrEqual,
	},
	{
		filterStr:      "(sn=*)",
		expectedFilter: "(sn=*)",
		expectedType:   FilterPresent,
	},
	{
		filterStr:      "(sn~=Miller)",
		expectedFilter: "(sn~=Miller)",
		expectedType:   FilterApproxMatch,
	},
	{
		filterStr:      `(objectGUID='\fc\fe\a3\ab\f9\90N\aaGm\d5I~\d12)`,
		expectedFilter: `(objectGUID='\fc\fe\a3\ab\f9\90N\aaGm\d5I~\d12)`,
		expectedType:   FilterEqualityMatch,
	},
	{
		filterStr:      `(objectGUID=абвгдеёжзийклмнопрстуфхцчшщъыьэюя)`,
		expectedFilter: `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
		expectedType:   FilterEqualityMatch,
	},
	{
		filterStr:      `(objectGUID=함수목록)`,
		expectedFilter: `(objectGUID=\ed\95\a8\ec\88\98\eb\aa\a9\eb\a1\9d)`,
		expectedType:   FilterEqualityMatch,
	},
	{
		filterStr:      `(objectGUID=`,
		expectedFilter: ``,
		expectedType:   0,
		expectedErr:    "unexpected end of filter",
	},
	{
		filterStr:      `(objectGUID=함수목록`,
		expectedFilter: ``,
		expectedType:   0,
		expectedErr:    "unexpected end of filter",
	},
	{
		filterStr:      `((cn=)`,
		expectedFilter: ``,
		expectedType:   0,
		expectedErr:    "unexpected end of filter",
	},
	{
		filterStr:      `(&(objectclass=inetorgperson)(cn=中文))`,
		expectedFilter: `(&(objectclass=inetorgperson)(cn=\e4\b8\ad\e6\96\87))`,
		expectedType:   0,
	},
	// attr extension
	{
		filterStr:      `(memberOf:=foo)`,
		expectedFilter: `(memberOf:=foo)`,
		expectedType:   FilterExtensibleMatch,
	},
	// attr+named matching rule extension
	{
		filterStr:      `(memberOf:test:=foo)`,
		expectedFilter: `(memberOf:test:=foo)`,
		expectedType:   FilterExtensibleMatch,
	},
	// attr+oid matching rule extension
	{
		filterStr:      `(cn:1.2.3.4.5:=Fred Flintstone)`,
		expectedFilter: `(cn:1.2.3.4.5:=Fred Flintstone)`,
		expectedType:   FilterExtensibleMatch,
	},
	// attr+dn+oid matching rule extension
	{
		filterStr:      `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
		expectedFilter: `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
		expectedType:   FilterExtensibleMatch,
	},
	// attr+dn extension
	{
		filterStr:      `(o:dn:=Ace Industry)`,
		expectedFilter: `(o:dn:=Ace Industry)`,
		expectedType:   FilterExtensibleMatch,
	},
	// the dnattrs marker is an ABNF literal, so it is case-insensitive
	{
		filterStr:      `(o:DN:=Ace Industry)`,
		expectedFilter: `(o:dn:=Ace Industry)`,
		expectedType:   FilterExtensibleMatch,
	},
	{
		filterStr:      `(o:Dn:=Ace Industry)`,
		expectedFilter: `(o:dn:=Ace Industry)`,
		expectedType:   FilterExtensibleMatch,
	},
	{
		filterStr:      `(sn:DN:2.4.6.8.10:=Barney Rubble)`,
		expectedFilter: `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
		expectedType:   FilterExtensibleMatch,
	},
	// dn extension
	{
		filterStr:      `(:dn:2.4.6.8.10:=Dino)`,
		expectedFilter: `(:dn:2.4.6.8.10:=Dino)`,
		expectedType:   FilterExtensibleMatch,
	},
	{
		filterStr:      `(memberOf:1.2.840.113556.1.4.1941:=CN=User1,OU=blah,DC=mydomain,DC=net)`,
		expectedFilter: `(memberOf:1.2.840.113556.1.4.1941:=CN=User1,OU=blah,DC=mydomain,DC=net)`,
		expectedType:   FilterExtensibleMatch,
	},

	// compileTest{ filterStr: "()", filterType: FilterExtensibleMatch },
}

var testInvalidFilters = []string{
	`(objectGUID=\zz)`,
	`(objectGUID=\a)`,
	`(&(a=b)x`,
	`(!(a=b)x`,
	`((a=b)x`,
	`(|(a=b)]`,
	`(&(a=b)(c=d)x`,
	`(&(a=b)`,
	`(|(a=b)`,
	`(!(a=b)`,
	`((a=b)`,
	`(&(a=b)(c=d)`,
	// empty AND/OR sets
	`(&)`,
	`(|)`,
	`(&())`,
	`(&(|))`,
	`(&(&(a=b))(|))`,
	// empty attribute names
	`(=foo)`,
	`(=*)`,
	`(>=1)`,
	`(<=1)`,
	`(~=bar)`,
	// extensible match without attribute or matching rule
	`(:=foo)`,
	`(:dn:=foo)`,
}

func TestFilter(t *testing.T) {
	// Test Compiler and Decompiler
	for _, i := range testFilters {
		filter, err := CompileFilter(i.filterStr)
		switch {
		case err != nil:
			if i.expectedErr == "" || !strings.Contains(err.Error(), i.expectedErr) {
				t.Errorf("Problem compiling '%s' - '%v' (expected error to contain '%v')", i.filterStr, err, i.expectedErr)
			}
		case filter.Tag != ber.Tag(i.expectedType):
			t.Errorf("%q Expected %q got %q", i.filterStr, FilterMap[uint64(i.expectedType)], FilterMap[uint64(filter.Tag)])
		default:
			o, err := DecompileFilter(filter)
			if err != nil {
				t.Errorf("Problem compiling %s - %s", i.filterStr, err.Error())
			} else if i.expectedFilter != o {
				t.Errorf("%q expected, got %q", i.expectedFilter, o)
			}
		}
	}
}

func TestDecodeEscapedSymbols(t *testing.T) {
	for _, testInfo := range []struct {
		Src string
		Err string
	}{
		{
			Src: "a\u0100\x80",
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: error reading rune at position 3`,
		},
		{
			Src: `start\d`,
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: missing characters for escape in filter`,
		},
		{
			Src: `\`,
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: invalid characters for escape in filter: EOF`,
		},
		{
			Src: `start\--end`,
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: invalid characters for escape in filter: encoding/hex: invalid byte: U+002D '-'`,
		},
		{
			Src: `start\d0\hh`,
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: invalid characters for escape in filter: encoding/hex: invalid byte: U+0068 'h'`,
		},
	} {

		res, err := decodeEscapedSymbols([]byte(testInfo.Src))
		if err == nil || err.Error() != testInfo.Err {
			t.Fatal(testInfo.Src, "=> ", err, "!=", testInfo.Err)
		}
		if res != "" {
			t.Fatal(testInfo.Src, "=> ", "invalid result", res)
		}
	}
}

func TestInvalidFilter(t *testing.T) {
	for _, filterStr := range testInvalidFilters {
		if _, err := CompileFilter(filterStr); err == nil {
			t.Errorf("Problem compiling %s - expected err", filterStr)
		}
	}
}

func TestCompileFilterStrictRejects(t *testing.T) {
	testCases := []struct {
		filter      string
		expectedErr string
	}{
		{filter: "(&)", expectedErr: "expected at least one filter in set"},
		{filter: "(|)", expectedErr: "expected at least one filter in set"},
		{filter: "(&(|))", expectedErr: "expected at least one filter in set"},
		{filter: "(=foo)", expectedErr: "empty attribute name"},
		{filter: "(=*)", expectedErr: "empty attribute name"},
		{filter: "(:=foo)", expectedErr: "requires an attribute or matching rule"},
		{filter: "(:dn:=foo)", expectedErr: "requires an attribute or matching rule"},
	}

	for _, tc := range testCases {
		t.Run(tc.filter, func(t *testing.T) {
			_, err := CompileFilter(tc.filter)
			if err == nil {
				t.Fatalf("expected error for filter %q, got nil", tc.filter)
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("filter %q: expected error to contain %q, got %q", tc.filter, tc.expectedErr, err.Error())
			}
		})
	}
}

func TestDecompileFilterIncompletePacket(t *testing.T) {
	newEquality := func(children ...*ber.Packet) *ber.Packet {
		packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterEqualityMatch, nil, FilterMap[FilterEqualityMatch])
		for _, child := range children {
			packet.AppendChild(child)
		}
		return packet
	}
	octetString := func(value string) *ber.Packet {
		return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "")
	}

	testCases := []struct {
		name        string
		packet      *ber.Packet
		expectedErr string
	}{
		{
			name:        "and without children",
			packet:      ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterAnd, nil, FilterMap[FilterAnd]),
			expectedErr: "and filter has no children",
		},
		{
			name:        "or without children",
			packet:      ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterOr, nil, FilterMap[FilterOr]),
			expectedErr: "or filter has no children",
		},
		{
			name:        "not without children",
			packet:      ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterNot, nil, FilterMap[FilterNot]),
			expectedErr: "not filter must have exactly one child",
		},
		{
			name: "not with two children",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterNot, nil, FilterMap[FilterNot])
				packet.AppendChild(newEquality(octetString("a"), octetString("b")))
				packet.AppendChild(newEquality(octetString("c"), octetString("d")))
				return packet
			}(),
			expectedErr: "not filter must have exactly one child",
		},
		{
			name:        "equality without children",
			packet:      newEquality(),
			expectedErr: "equality match filter must have exactly two children",
		},
		{
			name:        "equality with one child",
			packet:      newEquality(octetString("a")),
			expectedErr: "equality match filter must have exactly two children",
		},
		{
			name: "greater or equal with one child",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterGreaterOrEqual, nil, FilterMap[FilterGreaterOrEqual])
				packet.AppendChild(octetString("a"))
				return packet
			}(),
			expectedErr: "greater or equal filter must have exactly two children",
		},
		{
			name: "less or equal with one child",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterLessOrEqual, nil, FilterMap[FilterLessOrEqual])
				packet.AppendChild(octetString("a"))
				return packet
			}(),
			expectedErr: "less or equal filter must have exactly two children",
		},
		{
			name: "approx with one child",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterApproxMatch, nil, FilterMap[FilterApproxMatch])
				packet.AppendChild(octetString("a"))
				return packet
			}(),
			expectedErr: "approx match filter must have exactly two children",
		},
		{
			name: "substrings with one child",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterSubstrings, nil, FilterMap[FilterSubstrings])
				packet.AppendChild(octetString("a"))
				return packet
			}(),
			expectedErr: "substrings filter must have exactly two children",
		},
		{
			name: "substrings with unsupported component tag",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterSubstrings, nil, FilterMap[FilterSubstrings])
				packet.AppendChild(octetString("a"))
				seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
				seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.Tag(3), "b", ""))
				packet.AppendChild(seq)
				return packet
			}(),
			expectedErr: "unsupported substrings component tag",
		},
		{
			name: "substrings with out of order initial",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterSubstrings, nil, FilterMap[FilterSubstrings])
				packet.AppendChild(octetString("a"))
				seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
				seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, FilterSubstringsAny, "b", ""))
				seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, FilterSubstringsInitial, "c", ""))
				packet.AppendChild(seq)
				return packet
			}(),
			expectedErr: "initial component out of order",
		},
		{
			name: "substrings with out of order final",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterSubstrings, nil, FilterMap[FilterSubstrings])
				packet.AppendChild(octetString("a"))
				seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
				seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, FilterSubstringsFinal, "b", ""))
				seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, FilterSubstringsAny, "c", ""))
				packet.AppendChild(seq)
				return packet
			}(),
			expectedErr: "final component out of order",
		},
		{
			name: "extensible match without match value",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterExtensibleMatch, nil, FilterMap[FilterExtensibleMatch])
				packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionType, "cn", ""))
				return packet
			}(),
			expectedErr: "missing its match value",
		},
		{
			name: "extensible match with unsupported assertion tag",
			packet: func() *ber.Packet {
				packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterExtensibleMatch, nil, FilterMap[FilterExtensibleMatch])
				packet.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.Tag(5), "x", ""))
				return packet
			}(),
			expectedErr: "unsupported matching rule assertion tag",
		},
		{
			name:        "unsupported filter tag",
			packet:      ber.Encode(ber.ClassContext, ber.TypeConstructed, ber.Tag(42), nil, "Unknown"),
			expectedErr: "unsupported filter tag",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecompileFilter(tc.packet)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("expected error to contain %q, got %q", tc.expectedErr, err.Error())
			}
		})
	}
}

func TestFilterSubstringWildcardRoundTrip(t *testing.T) {
	// A substrings filter whose components are all empty only matches on
	// presence; decompiling must yield a filter string that compiles again.
	packet, err := CompileFilter("(sn=**)")
	if err != nil {
		t.Fatal(err)
	}
	decompiled, err := DecompileFilter(packet)
	if err != nil {
		t.Fatal(err)
	}
	if decompiled != "(sn=*)" {
		t.Errorf("expected %q, got %q", "(sn=*)", decompiled)
	}
	if _, err := CompileFilter(decompiled); err != nil {
		t.Errorf("decompiled filter %q does not compile: %v", decompiled, err)
	}

	// Every compilable filter must survive a compile/decompile/compile
	// round trip and stabilize.
	for _, filterStr := range []string{
		`(sn=Mi*l*r)`,
		`(sn=*i*le*)`,
		`(cn=\28not a group\29)`,
		`(cn=back\5cslash)`,
		`(cn=\2a)`,
		`(&(objectClass=person)(|(cn=Mi*l*r)(!(sn=*))))`,
		`(|(cn:dn:1.2.3:=x)(memberOf:1.2.840.113556.1.4.1941:=CN=User1,DC=net))`,
		`(&(!(o:dn:=Ace Industry))(sn:dn:2.4.6.8.10:=Barney Rubble))`,
	} {
		first, err := CompileFilter(filterStr)
		if err != nil {
			t.Errorf("compiling %q: %v", filterStr, err)
			continue
		}
		decompiled, err := DecompileFilter(first)
		if err != nil {
			t.Errorf("decompiling %q: %v", filterStr, err)
			continue
		}
		second, err := CompileFilter(decompiled)
		if err != nil {
			t.Errorf("recompiling %q (from %q): %v", decompiled, filterStr, err)
			continue
		}
		again, err := DecompileFilter(second)
		if err != nil {
			t.Errorf("re-decompiling %q: %v", decompiled, err)
			continue
		}
		if again != decompiled {
			t.Errorf("filter %q did not stabilize: %q then %q", filterStr, decompiled, again)
		}
	}
}

func TestCompileFilterClosingParen(t *testing.T) {
	testCases := []struct {
		filter      string
		expectedErr string
	}{
		{filter: "(&(a=b)x", expectedErr: "expected ')' at position 7"},
		{filter: "(!(a=b)x", expectedErr: "expected ')' at position 7"},
		{filter: "((a=b)x", expectedErr: "expected ')' at position 6"},
		{filter: "(|(a=b)]", expectedErr: "expected ')' at position 7"},
		{filter: "(&(a=b)(c=d)x", expectedErr: "expected ')' at position 12"},
		{filter: "(&(a=b)", expectedErr: "unexpected end of filter"},
		{filter: "(|(a=b)", expectedErr: "unexpected end of filter"},
		{filter: "(!(a=b)", expectedErr: "unexpected end of filter"},
		{filter: "((a=b)", expectedErr: "unexpected end of filter"},
		{filter: "(&(a=b)(c=d)", expectedErr: "unexpected end of filter"},
	}

	for _, tc := range testCases {
		t.Run(tc.filter, func(t *testing.T) {
			_, err := CompileFilter(tc.filter)
			if err == nil {
				t.Fatalf("expected error for filter %q, got nil", tc.filter)
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("filter %q: expected error to contain %q, got %q", tc.filter, tc.expectedErr, err.Error())
			}
		})
	}
}

func TestDecompileFilterEscapesAttribute(t *testing.T) {
	eq := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterEqualityMatch, nil, FilterMap[FilterEqualityMatch])
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid)(uid=admin", "Attribute"))
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "x", "Condition"))

	got, err := DecompileFilter(eq)
	if err != nil {
		t.Fatal(err)
	}
	if want := `(uid\29\28uid=admin=x)`; got != want {
		t.Errorf("equality attribute not escaped: got %q want %q", got, want)
	}

	em := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterExtensibleMatch, nil, FilterMap[FilterExtensibleMatch])
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionMatchingRule, "1)(x=*", MatchingRuleAssertionMap[MatchingRuleAssertionMatchingRule]))
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionType, "cn*evil", MatchingRuleAssertionMap[MatchingRuleAssertionType]))
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionMatchValue, "v", MatchingRuleAssertionMap[MatchingRuleAssertionMatchValue]))

	got, err = DecompileFilter(em)
	if err != nil {
		t.Fatal(err)
	}
	if want := `(cn\2aevil:1\29\28x=\2a:=v)`; got != want {
		t.Errorf("extensible match attribute/rule not escaped: got %q want %q", got, want)
	}
}

func BenchmarkFilterCompile(b *testing.B) {
	b.StopTimer()
	filters := make([]string, len(testFilters))

	// Test Compiler and Decompiler
	for idx, i := range testFilters {
		filters[idx] = i.filterStr
	}

	maxIdx := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CompileFilter(filters[i%maxIdx])
	}
}

func BenchmarkFilterDecompile(b *testing.B) {
	b.StopTimer()
	filters := make([]*ber.Packet, len(testFilters))

	// Test Compiler and Decompiler
	for idx, i := range testFilters {
		filters[idx], _ = CompileFilter(i.filterStr)
	}

	maxIdx := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecompileFilter(filters[i%maxIdx])
	}
}
