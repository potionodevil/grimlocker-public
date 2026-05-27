package security

// constantTimeEqual returns true iff a and b have the same length and content.
// The running time depends only on len(a) and len(b), not their values.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
