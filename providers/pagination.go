package providers

// morePages uses the number of rows actually returned. Some APIs cap the
// requested page size, so page number times requested size can end too early.
func morePages(total, seen, current, requested int) bool {
	if current == 0 {
		return false
	}
	if total > 0 {
		return seen < total
	}
	return current >= requested
}
