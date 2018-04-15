/* Copyright 2018 The Bazel Authors. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rule

import (
	"sort"
	"strings"

	bzl "github.com/bazelbuild/buildtools/build"
	bt "github.com/bazelbuild/buildtools/tables"
)

type File struct {
	File  *bzl.File
	Path  string
	Loads []*Load
	Rules []*Rule
}

func EmptyFile(path string) *File {
	return &File{
		File: &bzl.File{Path: path},
		Path: path,
	}
}

func NewFile(bzlFile *bzl.File) *File {
	f := &File{
		File: bzlFile,
		Path: bzlFile.Path,
	}
	for i, stmt := range f.File.Stmt {
		call, ok := stmt.(*bzl.CallExpr)
		if !ok {
			continue
		}
		x, ok := call.X.(*bzl.LiteralExpr)
		if !ok {
			continue
		}
		if x.Token == "load" {
			f.Loads = append(f.Loads, loadFromExpr(i, call))
		} else {
			f.Rules = append(f.Rules, ruleFromExpr(i, call))
		}
	}
	return f
}

func (f *File) Sync() {
	var inserts, deletes []stmt
	categorize := func(s stmt) {
		if s.shouldSync() {
			s.sync()
		}
		if s.shouldInsert() {
			inserts = append(inserts, s)
		} else if s.shouldDelete() {
			deletes = append(deletes, s)
		}
	}
	for _, s := range f.Loads {
		categorize(s)
	}
	for _, s := range f.Rules {
		categorize(s)
	}
	sort.Stable(byIndex(inserts))
	sort.Stable(byIndex(deletes))

	oldStmt := f.File.Stmt
	f.File.Stmt = make([]bzl.Expr, 0, len(oldStmt)-len(deletes)+len(inserts))
	var ii, di int
	for i, stmt := range oldStmt {
		for ii < len(inserts) && inserts[ii].Index() == i {
			f.File.Stmt = append(f.File.Stmt, inserts[ii].expr())
			ii++
		}
		if di < len(deletes) && deletes[di].Index() == i {
			di++
			continue
		}
		f.File.Stmt = append(f.File.Stmt, stmt)
	}
	for ii < len(inserts) {
		f.File.Stmt = append(f.File.Stmt, inserts[ii].expr())
	}
}

type stmt interface {
	Index() int
	shouldDelete() bool
	shouldInsert() bool
	shouldSync() bool
	sync()
	expr() bzl.Expr
}

type byIndex []stmt

func (s byIndex) Len() int {
	return len(s)
}

func (s byIndex) Less(i, j int) bool {
	return s[i].Index() < s[j].Index()
}

func (s byIndex) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type baseStmt struct {
	index                      int
	deleted, inserted, updated bool
	call                       *bzl.CallExpr
}

func (s *baseStmt) Index() int         { return s.index }
func (s *baseStmt) shouldDelete() bool { return s.deleted }
func (s *baseStmt) shouldInsert() bool { return s.inserted }
func (s *baseStmt) shouldSync() bool   { return s.updated }
func (s *baseStmt) expr() bzl.Expr     { return s.call }

type Load struct {
	baseStmt
	name    string
	symbols map[string]bzl.Expr
}

func loadFromExpr(index int, call *bzl.CallExpr) *Load {
	l := &Load{
		baseStmt: baseStmt{index: index, call: call},
		symbols:  make(map[string]bzl.Expr),
	}
	if len(call.List) == 0 {
		return nil
	}
	name, ok := call.List[0].(*bzl.StringExpr)
	if !ok {
		return nil
	}
	l.name = name.Value
	for _, arg := range call.List[1:] {
		switch arg := arg.(type) {
		case *bzl.StringExpr:
			l.symbols[arg.Value] = arg
		case *bzl.BinaryExpr:
			x, ok := arg.X.(*bzl.LiteralExpr)
			if !ok {
				return nil
			}
			if _, ok := arg.Y.(*bzl.StringExpr); !ok {
				return nil
			}
			l.symbols[x.Token] = arg
		default:
			return nil
		}
	}
	return l
}

func (l *Load) Name() string {
	return l.name
}

func (l *Load) sync() {
	args := make([]*bzl.StringExpr, 0, len(l.symbols))
	kwargs := make([]*bzl.BinaryExpr, 0, len(l.symbols))
	for _, e := range l.symbols {
		if a, ok := e.(*bzl.StringExpr); ok {
			args = append(args, a)
		} else {
			kwargs = append(kwargs, e.(*bzl.BinaryExpr))
		}
	}
	sort.Slice(args, func(i, j int) bool {
		return args[i].Value < args[j].Value
	})
	sort.Slice(kwargs, func(i, j int) bool {
		return kwargs[i].X.(*bzl.StringExpr).Value < kwargs[j].Y.(*bzl.StringExpr).Value
	})

	list := make([]bzl.Expr, 0, 1+len(l.symbols))
	list[0] = l.call.List[0]
	for _, a := range args {
		list = append(list, a)
	}
	for _, a := range kwargs {
		list = append(list, a)
	}
	l.call.List = list
}

type Rule struct {
	baseStmt
	kind  string
	args  []bzl.Expr
	attrs map[string]*bzl.BinaryExpr
}

func NewRule(kind, name string) *Rule {
	nameAttr := &bzl.BinaryExpr{
		X:  &bzl.LiteralExpr{Token: "name"},
		Y:  &bzl.StringExpr{Value: name},
		Op: "=",
	}
	r := &Rule{
		baseStmt: baseStmt{
			call: &bzl.CallExpr{
				X:    &bzl.LiteralExpr{Token: kind},
				List: []bzl.Expr{nameAttr},
			},
		},
		kind:  kind,
		attrs: map[string]*bzl.BinaryExpr{name: nameAttr},
	}
	return r
}

func ruleFromExpr(index int, expr bzl.Expr) *Rule {
	call, ok := expr.(*bzl.CallExpr)
	if !ok {
		return nil
	}
	x, ok := call.X.(*bzl.LiteralExpr)
	if !ok {
		return nil
	}
	kind := x.Token
	var args []bzl.Expr
	attrs := make(map[string]*bzl.BinaryExpr)
	for _, arg := range call.List {
		attr, ok := arg.(*bzl.BinaryExpr)
		if ok && attr.Op == "=" {
			key := attr.X.(*bzl.LiteralExpr) // required by parser
			attrs[key.Token] = attr
		} else {
			args = append(args, arg)
		}
	}
	nameAttr, ok := attrs["name"]
	if !ok {
		return nil
	}
	if _, ok := nameAttr.Y.(*bzl.StringExpr); !ok {
		return nil
	}
	return &Rule{
		baseStmt: baseStmt{
			index: index,
			call:  call,
		},
		kind:  kind,
		args:  args,
		attrs: attrs,
	}
}

func (r *Rule) ShouldKeep() bool {
	return ShouldKeep(r.call)
}

func (r *Rule) Kind() string {
	return r.kind
}

func (r *Rule) SetKind(kind string) {
	r.kind = kind
	r.updated = true
}

func (r *Rule) Name() string {
	return r.AttrString("name")
}

func (r *Rule) SetName(name string) {
	r.SetAttr("name", name)
}

func (r *Rule) AttrKeys() []string {
	keys := make([]string, 0, len(r.attrs))
	for k := range r.attrs {
		if !isHiddenKey(k) {
			keys = append(keys, k)
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if cmp := bt.NamePriority[keys[i]] - bt.NamePriority[keys[j]]; cmp != 0 {
			return cmp < 0
		}
		return keys[i] < keys[j]
	})
	return keys
}

func (r *Rule) Attr(key string) bzl.Expr {
	attr, ok := r.attrs[key]
	if !ok {
		return nil
	}
	return attr.Y
}

func (r *Rule) AttrString(key string) string {
	attr, ok := r.attrs[key]
	if !ok {
		return ""
	}
	str, ok := attr.Y.(*bzl.StringExpr)
	if !ok {
		return ""
	}
	return str.Value
}

func (r *Rule) DelAttr(key string) {
	delete(r.attrs, key)
	r.updated = true
}

func (r *Rule) SetAttr(key string, value interface{}) {
	y := ExprFromValue(value)
	if attr, ok := r.attrs[key]; ok {
		attr.Y = y
	} else {
		r.attrs[key] = &bzl.BinaryExpr{
			X: &bzl.LiteralExpr{Token: key},
			Y: y,
		}
	}
	r.updated = true
}

// SortLabels sorts lists of strings in mergeable attributes using the same
// order as buildifier. Buildifier also sorts string lists, but not those
// involved in "select" expressions.
func (r *Rule) SortLabels(attrs MergeableAttrs) {
	for key, attr := range r.attrs {
		if !attrs[r.kind][key] {
			continue
		}
		bzl.Walk(attr.Y, func(e bzl.Expr, _ []bzl.Expr) {
			panic("not implemented")
		})
		r.updated = true
	}
}

func (r *Rule) Delete() {
	r.deleted = true
}

func (r *Rule) Insert(f *File) {
	// TODO(jayconrod): should rules always be inserted at the end? Should there be some
	// sort order?
	r.inserted = true
	r.index = len(f.Rules)
	f.Rules = append(f.Rules, r)
}

func (r *Rule) IsEmpty(attrs MergeableAttrs) bool {
	nonEmptyAttrs := attrs[r.kind]
	if nonEmptyAttrs == nil {
		return false
	}
	for k := range nonEmptyAttrs {
		if _, ok := r.attrs[k]; ok {
			return false
		}
	}
	return true
}

func (r *Rule) sync() {
	if !r.updated && !r.inserted {
		return
	}
	call := r.call
	call.X.(*bzl.LiteralExpr).Token = r.kind

	list := make([]bzl.Expr, 0, len(r.args)+len(r.attrs))
	list = append(list, r.args...)
	for k, attr := range r.attrs {
		if !isHiddenKey(k) {
			list = append(list, attr)
		}
	}
	sortedAttrs := list[len(r.args):]
	key := func(e bzl.Expr) string { return e.(*bzl.BinaryExpr).X.(*bzl.LiteralExpr).Token }
	sort.SliceStable(sortedAttrs, func(i, j int) bool {
		ki := key(sortedAttrs[i])
		kj := key(sortedAttrs[j])
		if cmp := bt.NamePriority[ki] - bt.NamePriority[kj]; cmp != 0 {
			return cmp < 0
		}
		return ki < kj
	})

	r.call.List = list
}

func ShouldKeep(e bzl.Expr) bool {
	for _, c := range append(e.Comment().Before, e.Comment().Suffix...) {
		text := strings.TrimSpace(strings.TrimPrefix(c.Token, "#"))
		if text == "keep" {
			return true
		}
	}
	return false
}

func isHiddenKey(key string) bool {
	return strings.HasPrefix(key, "_")
}

type byAttrName []KeyValue

var _ sort.Interface = byAttrName{}

func (s byAttrName) Len() int {
	return len(s)
}

func (s byAttrName) Less(i, j int) bool {
	if cmp := bt.NamePriority[s[i].Key] - bt.NamePriority[s[j].Key]; cmp != 0 {
		return cmp < 0
	}
	return s[i].Key < s[j].Key
}

func (s byAttrName) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
