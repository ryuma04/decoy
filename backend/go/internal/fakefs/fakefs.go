// Package fakefs is the in-memory fake filesystem the SSH decoy shows (06). Nothing touches the real disk.
// A base tree is shared read-only; each session gets an overlay for its own writes (touch, echo > file, rm).
package fakefs

import (
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

type Node struct {
	Name        string
	Dir         bool
	Content     string
	Mode        string // "-rw-r--r--"
	Owner       string
	ModTime     time.Time
	HoneyfileID string // non-empty for lures (file.read carries it)
	MazeNode    string // maze node this lure belongs to
	Hidden      bool   // maze-gated: invisible until unlocked (08)
}

// FS is a base tree plus a per-session overlay.
type FS struct {
	mu      sync.RWMutex
	base    map[string]*Node
	overlay map[string]*Node // writes in this session
	deleted map[string]bool
	visible map[string]bool // maze nodes unlocked for this session's actor
}

// NewBase returns an empty base tree containing "/".
func NewBase() map[string]*Node {
	return map[string]*Node{"/": {Name: "/", Dir: true, Mode: "drwxr-xr-x", Owner: "root"}}
}

// Add puts a file (or dir when n.Dir) into the base tree, creating parent directories.
func Add(base map[string]*Node, p string, n Node) {
	p = Clean("/", p)
	for dir := path.Dir(p); ; dir = path.Dir(dir) {
		if _, ok := base[dir]; !ok {
			base[dir] = &Node{Name: path.Base(dir), Dir: true, Mode: "drwxr-xr-x", Owner: n.Owner}
		}
		if dir == "/" {
			break
		}
	}
	n.Name = path.Base(p)
	if n.Mode == "" {
		n.Mode = map[bool]string{true: "drwxr-xr-x", false: "-rw-r--r--"}[n.Dir]
	}
	base[p] = &n
}

// NewSession wraps a base tree for one session.
func NewSession(base map[string]*Node) *FS {
	return &FS{base: base, overlay: map[string]*Node{}, deleted: map[string]bool{}, visible: map[string]bool{}}
}

// SetVisible updates which maze-gated nodes this session may see.
func (f *FS) SetVisible(nodes []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visible = map[string]bool{}
	for _, n := range nodes {
		f.visible[n] = true
	}
}

// Clean resolves p against cwd (handles ~ for the caller via HomeExpand first).
func Clean(cwd, p string) string {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(cwd, p)
	}
	return path.Clean(p)
}

func (f *FS) shown(n *Node) bool {
	return n != nil && (!n.Hidden || f.visible[n.MazeNode])
}

// Get returns the node at an absolute path, or nil.
func (f *FS) Get(p string) *Node {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.get(p)
}

func (f *FS) get(p string) *Node {
	if n, ok := f.overlay[p]; ok {
		return n // written after any delete of an ancestor
	}
	for d := p; ; d = path.Dir(d) {
		if f.deleted[d] {
			return nil
		}
		if d == "/" {
			break
		}
	}
	if n, ok := f.overlay[p]; ok {
		return n
	}
	if n := f.base[p]; f.shown(n) {
		return n
	}
	return nil
}

// List returns the children of a directory, sorted by name.
func (f *FS) List(dir string) []*Node {
	f.mu.RLock()
	defer f.mu.RUnlock()
	seen := map[string]*Node{}
	collect := func(m map[string]*Node) {
		for p := range m {
			if p != "/" && path.Dir(p) == dir {
				if n := f.get(p); n != nil {
					seen[p] = n
				}
			}
		}
	}
	collect(f.base)
	collect(f.overlay)
	out := make([]*Node, 0, len(seen))
	for _, n := range seen {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Write creates or replaces a file in the session overlay (never the base, never the real disk).
func (f *FS) Write(p, content, owner string, appendTo bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	parent := f.get(path.Dir(p))
	if parent == nil || !parent.Dir {
		return false
	}
	if old := f.get(p); old != nil && old.Dir {
		return false
	}
	mode := "-rw-rw-r--"
	honeyfileID := ""
	mazeNode := ""
	if old := f.get(p); old != nil {
		if old.Mode != "" {
			mode = old.Mode
		}
		if owner == "" {
			owner = old.Owner
		}
		honeyfileID = old.HoneyfileID
		mazeNode = old.MazeNode
	}
	n := &Node{Name: path.Base(p), Content: content, Mode: mode, Owner: owner, ModTime: time.Now(), HoneyfileID: honeyfileID, MazeNode: mazeNode}
	if appendTo {
		if old := f.get(p); old != nil {
			n.Content = old.Content + content
		}
	}
	delete(f.deleted, p)
	f.overlay[p] = n
	return true
}

// Mkdir creates a directory in the overlay.
func (f *FS) Mkdir(p, owner string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if parent := f.get(path.Dir(p)); parent == nil || !parent.Dir || f.get(p) != nil {
		return false
	}
	delete(f.deleted, p)
	f.overlay[p] = &Node{Name: path.Base(p), Dir: true, Mode: "drwxrwxr-x", Owner: owner, ModTime: time.Now()}
	return true
}

// Remove hides a path (and its children) for this session only.
func (f *FS) Remove(p string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.get(p) == nil || p == "/" {
		return false
	}
	f.deleted[p] = true
	for q := range f.overlay {
		if q == p || strings.HasPrefix(q, p+"/") {
			delete(f.overlay, q)
		}
	}
	return true
}

// Chmod sets the mode of a node in the session overlay.
func (f *FS) Chmod(p, mode string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.get(p)
	if n == nil {
		return false
	}
	if _, ok := f.overlay[p]; !ok {
		cp := *n
		f.overlay[p] = &cp
	}
	f.overlay[p].Mode = mode
	return true
}

// Chown sets the owner of a node in the session overlay.
func (f *FS) Chown(p, owner string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.get(p)
	if n == nil {
		return false
	}
	if _, ok := f.overlay[p]; !ok {
		cp := *n
		f.overlay[p] = &cp
	}
	f.overlay[p].Owner = owner
	return true
}
