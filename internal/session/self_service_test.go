package session

import (
	"testing"
	"time"
)

func TestSessionSelfServiceCursorRoundTripAndValidation(t *testing.T) {
	cursor := Cursor{CreatedAt: time.Unix(1700000000, 123).UTC(), PublicID: "ses_123e4567-e89b-42d3-a456-426614174001"}
	raw, err := EncodeCursor(cursor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCursor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PublicID != cursor.PublicID || !decoded.CreatedAt.Equal(cursor.CreatedAt) {
		t.Fatalf("decoded cursor=%+v want=%+v", decoded, cursor)
	}
	for _, invalid := range []string{"%%%", "e30", string(make([]byte, 513))} {
		if _, err := DecodeCursor(invalid); err == nil {
			t.Fatalf("DecodeCursor(%q) accepted invalid cursor", invalid)
		}
	}
}
