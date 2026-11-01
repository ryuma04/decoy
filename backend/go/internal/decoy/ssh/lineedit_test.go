package ssh

import (
	"strings"
	"testing"
)

func feedAll(e *LineEditor, chunks ...string) []Line {
	var all []Line
	for _, c := range chunks {
		_, lines := e.Feed([]byte(c))
		all = append(all, lines...)
	}
	return all
}

func TestTypedLineCountsKeystrokes(t *testing.T) {
	e := NewLineEditor("$ ")
	lines := feedAll(e, "w", "h", "o", "a", "m", "i", "\r")
	if len(lines) != 1 || lines[0].Text != "whoami" || lines[0].Keystrokes != 6 || lines[0].Edits != 0 || lines[0].Paste {
		t.Fatalf("%+v", lines)
	}
}

func TestBackspaceAndArrowsAreEdits(t *testing.T) {
	e := NewLineEditor("$ ")
	lines := feedAll(e, "l", "x", "\x7f", "s", "\x1b[D", "\x1b[C", "\r")
	if len(lines) != 1 || lines[0].Text != "ls" || lines[0].Edits != 3 {
		t.Fatalf("%+v", lines)
	}
}

func TestInsertInMiddle(t *testing.T) {
	e := NewLineEditor("$ ")
	lines := feedAll(e, "c", "t", "\x1b[D", "a", "\r")
	if lines[0].Text != "cat" {
		t.Fatalf("got %q", lines[0].Text)
	}
}

func TestPasteDetectedAndMultiLine(t *testing.T) {
	e := NewLineEditor("$ ")
	lines := feedAll(e, "uname -a\rid\r")
	if len(lines) != 2 || lines[0].Text != "uname -a" || lines[1].Text != "id" || !lines[0].Paste {
		t.Fatalf("%+v", lines)
	}
	lines = feedAll(e, "p", "w", "d", "\r")
	if lines[0].Paste {
		t.Fatal("paste flag leaked into typed line")
	}
}

func TestEscapeSequenceSplitAcrossReads(t *testing.T) {
	e := NewLineEditor("$ ")
	lines := feedAll(e, "ab", "\x1b", "[", "D", "X", "\r")
	if lines[0].Text != "aXb" {
		t.Fatalf("got %q", lines[0].Text)
	}
}

func TestHistoryUpDown(t *testing.T) {
	e := NewLineEditor("$ ")
	e.AddHistory("id")
	e.AddHistory("whoami")
	lines := feedAll(e, "\x1b[A", "\x1b[A", "\x1b[B", "\r")
	if lines[0].Text != "whoami" {
		t.Fatalf("got %q", lines[0].Text)
	}
}

func TestCtrlCAndCtrlD(t *testing.T) {
	e := NewLineEditor("$ ")
	lines := feedAll(e, "abc\x03")
	if len(lines) != 1 || !lines[0].Cancel {
		t.Fatalf("%+v", lines)
	}
	lines = feedAll(e, "\x04")
	if len(lines) != 1 || !lines[0].EOF {
		t.Fatalf("%+v", lines)
	}
	lines = feedAll(e, "x\x04\r") // Ctrl-D on a non-empty line does nothing
	if len(lines) != 1 || lines[0].Text != "x" {
		t.Fatalf("%+v", lines)
	}
}

func TestUTF8SplitAcrossReads(t *testing.T) {
	e := NewLineEditor("$ ")
	b := []byte("é")
	_, _ = e.Feed(b[:1])
	_, lines := e.Feed(append(b[1:], '\r'))
	if len(lines) != 1 || lines[0].Text != "é" {
		t.Fatalf("%+v", lines)
	}
}

func TestLineLengthCapped(t *testing.T) {
	e := NewLineEditor("$ ")
	big := make([]byte, maxLine+100)
	for i := range big {
		big[i] = 'a'
	}
	_, _ = e.Feed(big)
	_, lines := e.Feed([]byte("\r"))
	if len(lines[0].Text) != maxLine {
		t.Fatalf("len %d", len(lines[0].Text))
	}
}

func FuzzLineEditor(f *testing.F) {
	for _, s := range []string{"ls\r", "\x1b[A\x1b[3~\x7f", "\x1b[1;5C", "é\x03\x04", "\x1b\x1b[[[", "\r\n\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		e := NewLineEditor("$ ")
		e.AddHistory("id")
		_, lines := e.Feed(data)
		for _, l := range lines {
			if len([]rune(l.Text)) > maxLine {
				t.Fatalf("line too long: %d", len(l.Text))
			}
		}
		if e.cursor < 0 || e.cursor > len(e.buf) {
			t.Fatalf("cursor %d out of range %d", e.cursor, len(e.buf))
		}
	})
}

func TestSecretModeDoesNotEcho(t *testing.T) {
	e := NewLineEditor("$ ")
	e.SetSecret(true)

	echo, lines := e.Feed([]byte("secretpassword\r"))
	if len(lines) != 1 || lines[0].Text != "secretpassword" {
		t.Fatalf("expected 1 line with text 'secretpassword', got: %+v", lines)
	}
	// Echo must NOT contain the secret characters
	if strings.Contains(echo, "secretpassword") {
		t.Fatalf("secret mode echoed secret characters: %q", echo)
	}
	if echo != "\r\n" {
		t.Fatalf("expected only CRLF echo, got: %q", echo)
	}

	// Once secret mode is turned off, normal echoing resumes
	e.SetSecret(false)
	echoNormal, linesNormal := e.Feed([]byte("normalcommand\r"))
	if len(linesNormal) != 1 || linesNormal[0].Text != "normalcommand" {
		t.Fatalf("expected normalcommand, got: %+v", linesNormal)
	}
	if !strings.Contains(echoNormal, "normalcommand") {
		t.Fatalf("normal mode should echo input, got: %q", echoNormal)
	}
}
