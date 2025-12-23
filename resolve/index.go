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

package resolve

import (
	v2 "github.com/bazel-contrib/bazel-gazelle/v2/resolve"
	"github.com/bazel-contrib/bazel-gazelle/v2/rule"
)

// ImportSpec describes a library to be imported. Imp is an import string for
// the library. Lang is the language in which the import string appears (this
// should match Resolver.Name).
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/resolve.ImportSpec instead.
type ImportSpec = v2.ImportSpec

// Resolver is an interface that language extensions can implement to resolve
// dependencies in rules they generate.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/resolve.Resolver instead.
type Resolver = v2.Resolver

// CrossResolver is an interface that language extensions can implement to provide
// custom dependency resolution logic for other languages.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/resolve.CrossResolver instead.
type CrossResolver = v2.CrossResolver

// RuleIndex is a table of rules in a workspace, indexed by label and by
// import path. Used by Resolver to map import paths to labels.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/resolve.RuleIndex instead.
type RuleIndex = v2.RuleIndex

// NewRuleIndex creates a new index.
//
// kindToResolver is a map from rule kinds (for example, "go_library") to
// Resolvers that support those kinds.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/resolve.NewRuleIndex instead.
func NewRuleIndex(mrslv func(r *rule.Rule, pkgRel string) Resolver, exts ...interface{}) *RuleIndex {
	return v2.NewRuleIndex(mrslv, exts...)
}

// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/resolve.FindResult instead.
type FindResult = v2.FindResult
