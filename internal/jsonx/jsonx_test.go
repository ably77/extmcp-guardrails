package jsonx

import "testing"

func TestMarshalKeepsAngleBrackets(t *testing.T) {
	b, err := Marshal(map[string]string{"text": "<BANK_ACCOUNT> & more"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"text":"<BANK_ACCOUNT> & more"}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
