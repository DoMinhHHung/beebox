package postgres

import "testing"

func TestCopyFixedHash32RequiresExactLength(t *testing.T) {
	want := [32]byte{0: 1, 31: 2}

	var got [32]byte
	if !copyFixedHash32(&got, want[:]) || got != want {
		t.Fatalf("exact 32-byte hash was not copied: got %x want %x", got, want)
	}

	for _, size := range []int{0, 1, 31, 33, 64} {
		got = [32]byte{0: 9}
		if copyFixedHash32(&got, make([]byte, size)) {
			t.Fatalf("hash length %d accepted", size)
		}
		if got != ([32]byte{0: 9}) {
			t.Fatalf("destination changed for rejected hash length %d", size)
		}
	}

	if copyFixedHash32(nil, want[:]) {
		t.Fatal("nil destination accepted")
	}
}
