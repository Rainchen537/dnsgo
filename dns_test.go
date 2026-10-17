package dnsgo

import (
	"context"
	"testing"
)

type cappedPageProvider struct{ Base }

func (c cappedPageProvider) ListZones(_ context.Context, query ZoneQuery) (Page[Zone], error) {
	rows := []Zone{{ID: "1", Name: "other.invalid"}, {ID: "2", Name: "example.invalid"}, {ID: "3", Name: "last.invalid"}}
	if query.Page < 1 || query.Page > len(rows) {
		return Page[Zone]{Total: len(rows)}, nil
	}
	return Page[Zone]{Total: len(rows), Items: rows[query.Page-1 : query.Page]}, nil
}

func (c cappedPageProvider) ListRecords(_ context.Context, _ string, query RecordQuery) (Page[Record], error) {
	rows := []Record{{ID: "1", Name: "other", Type: "TXT"}, {ID: "2", Name: "www", Type: "TXT"}, {ID: "3", Name: "www.example.invalid", Type: "TXT"}}
	if query.Page < 1 || query.Page > len(rows) {
		return Page[Record]{Total: len(rows)}, nil
	}
	return Page[Record]{Total: len(rows), Items: rows[query.Page-1 : query.Page]}, nil
}

func TestHelpersReadAllProviderCappedPages(t *testing.T) {
	provider := cappedPageProvider{Base{ProviderKind: "capped"}}
	zone, err := FindZone(context.Background(), provider, "example.invalid")
	if err != nil || zone.ID != "2" {
		t.Fatalf("FindZone stopped before the matching page: %#v, %v", zone, err)
	}
	page, err := ListSubdomainRecords(context.Background(), provider, zone, "www", SubdomainQuery{Type: "TXT"})
	if err != nil || page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("ListSubdomainRecords stopped before the final capped page: %#v, %v", page, err)
	}
}

type namedZoneProvider struct {
	Base
	name string
}

func (p namedZoneProvider) ListZones(_ context.Context, _ ZoneQuery) (Page[Zone], error) {
	return Page[Zone]{Total: 1, Items: []Zone{{ID: "provider-zone-id", Name: p.name}}}, nil
}

func TestFindZoneInternationalNames(t *testing.T) {
	for _, providerName := range []string{"例子.测试", "xn--fsqu00a.xn--0zwm56d"} {
		provider := namedZoneProvider{Base: Base{ProviderKind: "named"}, name: providerName}
		for _, input := range []string{"例子.测试", "xn--fsqu00a.xn--0zwm56d", "XN--FSQU00A.XN--0ZWM56D."} {
			zone, err := FindZone(context.Background(), provider, input)
			if err != nil || zone.ID != "provider-zone-id" || zone.Name != providerName {
				t.Errorf("FindZone(%q) with provider name %q = %#v, %v", input, providerName, zone, err)
			}
		}
		for _, other := range []string{"other.例子.测试", "例子.测试.invalid"} {
			if _, err := FindZone(context.Background(), provider, other); !IsCode(err, CodeNotFound) {
				t.Errorf("FindZone(%q) with provider name %q must not match: %v", other, providerName, err)
			}
		}
	}
}

func TestRecordFQDN(t *testing.T) {
	zone := Zone{ID: "opaque-zone-id", Name: "Example.COM."}
	cases := map[string]string{
		"@":                   "example.com",
		"www":                 "www.example.com",
		"_acme-challenge.www": "_acme-challenge.www.example.com",
		"WWW.Example.COM.":    "www.example.com",
		"example.com":         "example.com",
	}
	for name, want := range cases {
		got, err := RecordFQDN(zone, Record{Name: name})
		if err != nil || got != want {
			t.Errorf("RecordFQDN(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
}

func TestRecordLineMatchesDefaultOnlyProvider(t *testing.T) {
	for _, requested := range []string{"", "default", "0"} {
		for _, actual := range []string{"", "default", "0"} {
			if !recordLineMatches(false, requested, actual) {
				t.Errorf("default-only line %q should match %q", requested, actual)
			}
		}
	}
	if recordLineMatches(false, "telecom", "default") || recordLineMatches(true, "default", "0") {
		t.Fatal("nondefault or selectable provider lines were merged")
	}
}
