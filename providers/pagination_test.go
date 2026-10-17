package providers

import "testing"

func TestMorePagesUsesReturnedRows(t *testing.T) {
	if !morePages(3, 1, 1, 100) || !morePages(3, 2, 1, 100) {
		t.Fatal("provider-capped pages were treated as complete")
	}
	if morePages(3, 3, 1, 100) || morePages(3, 1, 0, 100) {
		t.Fatal("finished or empty pages were treated as incomplete")
	}
	if !morePages(0, 100, 100, 100) || morePages(0, 15, 15, 100) {
		t.Fatal("unknown-total pagination did not use the returned page length")
	}
}
