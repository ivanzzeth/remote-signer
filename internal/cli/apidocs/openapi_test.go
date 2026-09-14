package apidocs

import (
	"bytes"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/apidocs"
)

// TestRunWritesExactlyTheEmbeddedSpec is the whole contract of the subcommand:
// it hands over the generated document byte for byte. ⛔ Anything else — pretty
// printing, injecting a server URL, filtering by tag — would make
// `remote-signer openapi > openapi.json` produce a document that differs from
// the one gate ⑭ checked, and the difference would be invisible until a
// generated SDK disagreed with the daemon.
func TestRunWritesExactlyTheEmbeddedSpec(t *testing.T) {
	var buf bytes.Buffer
	if err := Run(&buf, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), apidocs.Spec) {
		t.Errorf("output differs from the embedded spec (%d vs %d bytes)", buf.Len(), len(apidocs.Spec))
	}
}

// TestRunRejectsArguments keeps the command from growing a second way to do
// shell redirection — and, more to the point, keeps a typo'd flag from being
// silently ignored while the caller believes it did something.
func TestRunRejectsArguments(t *testing.T) {
	var buf bytes.Buffer
	if err := Run(&buf, []string{"--yaml"}); err == nil {
		t.Error("Run accepted an argument; it should refuse rather than ignore it")
	}
	if buf.Len() != 0 {
		t.Error("Run wrote output despite refusing the arguments")
	}
}
