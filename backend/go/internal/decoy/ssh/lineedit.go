package ssh

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const maxLine = 4096

// Line is one submitted shell line with the typing measurements 02 asks for.
type Line struct {
	Text       string
	Keystrokes int
	Edits      int
	Paste      bool
	EOF        bool // Ctrl-D on an empty line
	Cancel     bool // Ctrl-C
}

// LineEditor turns raw terminal input into lines and the bytes to echo back. It never executes anything.
type LineEditor struct {
	prompt  string
	buf     []rune
	cursor  int
	history []string
	histPos int
	esc     []byte // pending escape sequence
	pending []byte // incomplete UTF-8 bytes

	keystrokes, edits int
	paste             bool
	secret            bool // password prompt: nothing typed is echoed, no history or line editing
}

func NewLineEditor(prompt string) *LineEditor { return &LineEditor{prompt: prompt} }

// SetSecret switches password input on or off (sudo / su prompts).
func (e *LineEditor) SetSecret(on bool) { e.secret = on }

// feedSecret reads a password: characters are kept but never echoed, Enter ends the line.
func (e *LineEditor) feedSecret(data []byte) (string, []Line) {
	var out strings.Builder
	var lines []Line
	for i := 0; i < len(data); i++ {
		switch b := data[i]; b {
		case '\r', '\n':
			if b == '\n' && i > 0 && data[i-1] == '\r' {
				continue
			}
			out.WriteString("\r\n")
			lines = append(lines, e.submit())
		case 0x7f, 0x08:
			if e.cursor > 0 {
				e.buf = e.buf[:len(e.buf)-1]
				e.cursor--
			}
		case 0x03:
			out.WriteString("^C\r\n")
			e.reset()
			lines = append(lines, Line{Cancel: true})
		case 0x04:
			if len(e.buf) == 0 {
				lines = append(lines, Line{EOF: true})
			}
		default:
			if b >= 0x20 && len(e.buf) < maxLine {
				e.buf = append(e.buf, rune(b))
				e.cursor++
				e.keystrokes++
			}
		}
	}
	return out.String(), lines
}

func (e *LineEditor) SetPrompt(p string) { e.prompt = p }
func (e *LineEditor) Prompt() string     { return e.prompt }

// AddHistory records a submitted line for ↑ / ↓ and `history`.
func (e *LineEditor) AddHistory(s string) {
	if s != "" && (len(e.history) == 0 || e.history[len(e.history)-1] != s) {
		e.history = append(e.history, s)
	}
	e.histPos = len(e.history)
}

func (e *LineEditor) History() []string { return e.history }

// Feed processes one read from the client. It returns the echo to write and any completed lines.
func (e *LineEditor) Feed(data []byte) (echo string, lines []Line) {
	if e.secret {
		return e.feedSecret(data)
	}
	var out strings.Builder
	printable := 0
	for _, b := range data {
		if b >= 0x20 && b != 0x7f {
			printable++
		}
	}
	if printable >= 8 {
		e.paste = true // ≥ 8 chars arriving in one read (02 §timing)
	}
	data = append(e.pending, data...)
	e.pending = nil
	for i := 0; i < len(data); {
		b := data[i]
		if len(e.esc) > 0 || b == 0x1b {
			e.esc = append(e.esc, b)
			i++
			if done := e.escape(&out); done {
				e.esc = nil
			}
			continue
		}
		switch b {
		case '\r', '\n':
			if b == '\n' && i > 0 && data[i-1] == '\r' {
				i++
				continue
			}
			out.WriteString("\r\n")
			lines = append(lines, e.submit())
		case 0x7f, 0x08: // backspace
			e.keystrokes++
			e.edits++
			if e.cursor > 0 {
				e.buf = append(e.buf[:e.cursor-1], e.buf[e.cursor:]...)
				e.cursor--
				e.redraw(&out)
			}
		case 0x03: // Ctrl-C
			out.WriteString("^C\r\n")
			e.reset()
			lines = append(lines, Line{Cancel: true})
		case 0x04: // Ctrl-D
			if len(e.buf) == 0 {
				lines = append(lines, Line{EOF: true})
			}
		case 0x09: // Tab: no completion
			e.keystrokes++
			out.WriteByte(0x07)
		case 0x15: // Ctrl-U: kill line
			e.keystrokes++
			e.edits++
			e.buf, e.cursor = e.buf[:0], 0
			e.redraw(&out)
		default:
			if b < 0x20 {
				break
			}
			r, size := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && size <= 1 && !utf8.FullRune(data[i:]) {
				e.pending = append([]byte{}, data[i:]...)
				i = len(data)
				continue
			}
			i += size - 1
			if len(e.buf) >= maxLine {
				break
			}
			e.keystrokes++
			if e.cursor == len(e.buf) {
				e.buf = append(e.buf, r)
				e.cursor++
				out.WriteRune(r)
			} else {
				e.buf = append(e.buf[:e.cursor], append([]rune{r}, e.buf[e.cursor:]...)...)
				e.cursor++
				e.redraw(&out)
			}
		}
		i++
	}
	return out.String(), lines
}

// escape handles ESC [ A/B/C/D, ESC [ 3 ~ and ESC [ H/F. Returns true when the sequence is complete.
func (e *LineEditor) escape(out *strings.Builder) bool {
	s := e.esc
	if len(s) == 1 {
		return false
	}
	if s[1] != '[' && s[1] != 'O' {
		return true // unknown: drop
	}
	if len(s) == 2 {
		return false
	}
	last := s[len(s)-1]
	if last >= '0' && last <= '9' || last == ';' {
		return len(s) > 8 // parameter bytes; give up on very long sequences
	}
	e.keystrokes++
	e.edits++
	switch last {
	case 'A': // up
		if e.histPos > 0 {
			e.histPos--
			e.setBuf(e.history[e.histPos], out)
		}
	case 'B': // down
		if e.histPos < len(e.history)-1 {
			e.histPos++
			e.setBuf(e.history[e.histPos], out)
		} else {
			e.histPos = len(e.history)
			e.setBuf("", out)
		}
	case 'C':
		if e.cursor < len(e.buf) {
			e.cursor++
			out.WriteString("\x1b[C")
		}
	case 'D':
		if e.cursor > 0 {
			e.cursor--
			out.WriteString("\x1b[D")
		}
	case 'H':
		e.cursor = 0
		e.redraw(out)
	case 'F':
		e.cursor = len(e.buf)
		e.redraw(out)
	case '~':
		if string(s) == "\x1b[3~" && e.cursor < len(e.buf) { // delete
			e.buf = append(e.buf[:e.cursor], e.buf[e.cursor+1:]...)
			e.redraw(out)
		}
	}
	return true
}

func (e *LineEditor) setBuf(s string, out *strings.Builder) {
	e.buf = []rune(s)
	e.cursor = len(e.buf)
	e.redraw(out)
}

// redraw rewrites the prompt and line, then puts the cursor back in place.
func (e *LineEditor) redraw(out *strings.Builder) {
	out.WriteString("\r" + e.prompt + string(e.buf) + "\x1b[K")
	if back := len(e.buf) - e.cursor; back > 0 {
		fmt.Fprintf(out, "\x1b[%dD", back)
	}
}

func (e *LineEditor) submit() Line {
	l := Line{Text: string(e.buf), Keystrokes: e.keystrokes, Edits: e.edits, Paste: e.paste}
	e.reset()
	return l
}

func (e *LineEditor) reset() {
	e.buf, e.cursor = e.buf[:0], 0
	e.keystrokes, e.edits, e.paste = 0, 0, false
	e.histPos = len(e.history)
}
