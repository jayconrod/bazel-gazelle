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
	"log"

	"github.com/bazelbuild/bazel-gazelle/internal/config"
	"github.com/bazelbuild/bazel-gazelle/internal/label"
	"github.com/bazelbuild/bazel-gazelle/internal/repos"
	"github.com/bazelbuild/bazel-gazelle/internal/rule"
)

type ImportSpec struct {
	Lang, Imp string
}

type Resolver interface {
	Name() string
	Imports(c *config.Config, r *rule.Rule, f *rule.File) []ImportSpec
	Embeds(r *rule.Rule, from label.Label) []label.Label
	Resolve(c *config.Config, ix *RuleIndex, rc *repos.RemoteCache, r *rule.Rule, from label.Label)
}

// RuleIndex is a table of rules in a workspace, indexed by label and by
// import path. Used by Resolver to map import paths to labels.
type RuleIndex struct {
	rules          []*ruleRecord
	labelMap       map[label.Label]*ruleRecord
	importMap      map[ImportSpec][]*ruleRecord
	kindToResolver map[string]Resolver
}

// ruleRecord contains information about a rule relevant to import indexing.
type ruleRecord struct {
	rule       *rule.Rule
	label      label.Label
	importedAs []ImportSpec
	embedded   bool
}

func NewRuleIndex(kindToResolver map[string]Resolver) *RuleIndex {
	return &RuleIndex{
		labelMap:       make(map[label.Label]*ruleRecord),
		kindToResolver: kindToResolver,
	}
}

func (ix *RuleIndex) AddRule(c *config.Config, r *rule.Rule, f *rule.File) {
	var imps []ImportSpec
	if rslv, ok := ix.kindToResolver[r.Kind()]; ok {
		imps = rslv.Imports(c, r, f)
	}
	if len(imps) == 0 {
		return
	}
	rel := f.Rel(c.RepoRoot)
	record := &ruleRecord{
		rule:       r,
		label:      label.New("", rel, r.Name()),
		importedAs: imps,
	}
	if _, ok := ix.labelMap[record.label]; ok {
		log.Printf("multiple rules found with label %s", record.label)
		return
	}
	ix.rules = append(ix.rules, record)
	ix.labelMap[record.label] = record
}

// Finish constructs the import index and performs any other necessary indexing
// actions after all rules have been added. This step is necessary because
// a rule may be indexed differently based on what rules are added later.
//
// This function must be called after all AddRulesFromFile calls but before any
// FindRulesByImport calls.
func (ix *RuleIndex) Finish() {
	ix.skipEmbeds()
	ix.buildImportIndex()
}

// skipEmbeds sets the embedded flag on library rules that are imported
// by other library rules with the same import spec. The embedding libraries
// will be indexed by their own import specs as well as the embedded import
// specs if there are any differences between the two.
func (ix *RuleIndex) skipEmbeds() {
	for _, r := range ix.rules {
		embedLabels := ix.kindToResolver[r.rule.Kind()].Embeds(r.rule, r.label)
		for _, l := range embedLabels {
			er, ok := ix.findRuleByLabel(l, r.label)
			if !ok {
				continue
			}
			r.importedAs = append(r.importedAs, er.importedAs...)
			r.embedded = true
		}
	}
}

// buildImportIndex constructs the map used by FindRulesByImport.
func (ix *RuleIndex) buildImportIndex() {
	ix.importMap = make(map[ImportSpec][]*ruleRecord)
	for _, r := range ix.rules {
		if r.embedded {
			continue
		}
		for _, imp := range r.importedAs {
			ix.importMap[imp] = append(ix.importMap[imp], r)
		}
	}
}

func (ix *RuleIndex) findRuleByLabel(label label.Label, from label.Label) (*ruleRecord, bool) {
	label = label.Abs(from.Repo, from.Pkg)
	r, ok := ix.labelMap[label]
	return r, ok
}

type FindResult struct {
	Label label.Label
	Rule  *rule.Rule
}

// FindRulesByImport attempts to resolve an import string to a rule record.
// imp is the import to resolve (which includes the target language). lang is
// the language of the rule with the dependency (for example, in
// go_proto_library, imp will have ProtoLang and lang will be GoLang).
// from is the rule which is doing the dependency. This is used to check
// vendoring visibility and to check for self-imports.
//
// FindRulesByImport returns a list of rules, since any number of rules may
// provide the same import. Callers may need to resolve ambiguities using
// language-specific heuristics.
func (ix *RuleIndex) FindRulesByImport(imp ImportSpec, lang string) []FindResult {
	matches := ix.importMap[imp]
	results := make([]FindResult, 0, len(matches))
	for _, m := range matches {
		if ix.kindToResolver[m.rule.Kind()].Name() != lang {
			continue
		}
		results = append(results, FindResult{Label: m.label, Rule: m.rule})
	}
	return results
}

// func (ix *RuleIndex) findRuleByImport(imp ImportSpec, lang language.Name, from label.Label) (*ruleRecord, error) {
// 	matches := ix.importMap[imp]
// 	var bestMatch *ruleRecord
// 	var bestMatchIsVendored bool
// 	var bestMatchVendorRoot string
// 	var matchError error
// 	for _, m := range matches {
// 		if m.lang != lang {
// 			continue
// 		}

// 		switch imp.lang {
// 		case config.GoLang:
// 			// Apply vendoring logic for Go libraries. A library in a vendor directory
// 			// is only visible in the parent tree. Vendored libraries supercede
// 			// non-vendored libraries, and libraries closer to from.Pkg supercede
// 			// those further up the tree.
// 			isVendored := false
// 			vendorRoot := ""
// 			parts := strings.Split(m.label.Pkg, "/")
// 			for i := len(parts) - 1; i >= 0; i-- {
// 				if parts[i] == "vendor" {
// 					isVendored = true
// 					vendorRoot = strings.Join(parts[:i], "/")
// 					break
// 				}
// 			}
// 			if isVendored && !label.New(m.label.Repo, vendorRoot, "").Contains(from) {
// 				// vendor directory not visible
// 				continue
// 			}
// 			if bestMatch == nil || isVendored && (!bestMatchIsVendored || len(vendorRoot) > len(bestMatchVendorRoot)) {
// 				// Current match is better
// 				bestMatch = m
// 				bestMatchIsVendored = isVendored
// 				bestMatchVendorRoot = vendorRoot
// 				matchError = nil
// 			} else if (!isVendored && bestMatchIsVendored) || (isVendored && len(vendorRoot) < len(bestMatchVendorRoot)) {
// 				// Current match is worse
// 			} else {
// 				// Match is ambiguous
// 				matchError = fmt.Errorf("multiple rules (%s and %s) may be imported with %q from %s", bestMatch.label, m.label, imp.imp, from)
// 			}

// 		default:
// 			if bestMatch == nil {
// 				bestMatch = m
// 			} else {
// 				matchError = fmt.Errorf("multiple rules (%s and %s) may be imported with %q from %s", bestMatch.label, m.label, imp.imp, from)
// 			}
// 		}
// 	}
// 	if matchError != nil {
// 		return nil, matchError
// 	}
// 	if bestMatch == nil {
// 		return nil, ruleNotFoundError{from, imp.imp}
// 	}
// 	if bestMatch.label.Equal(from) {
// 		return nil, selfImportError{from, imp.imp}
// 	}

// 	if imp.lang == config.ProtoLang && lang == config.GoLang {
// 		importpath := bestMatch.rule.AttrString("importpath")
// 		if betterMatch, err := ix.findRuleByImport(importSpec{config.GoLang, importpath}, config.GoLang, from); err == nil {
// 			return betterMatch, nil
// 		}
// 	}

// 	return bestMatch, nil
// }

// func findGoProtoSources(ix *RuleIndex, r *ruleRecord) []importSpec {
// 	protoLabel, err := label.Parse(r.rule.AttrString("proto"))
// 	if err != nil {
// 		return nil
// 	}
// 	proto, ok := ix.findRuleByLabel(protoLabel, r.label)
// 	if !ok {
// 		return nil
// 	}
// 	var importedAs []importSpec
// 	for _, source := range findSources(proto.rule, proto.label.Pkg, ".proto") {
// 		importedAs = append(importedAs, importSpec{lang: config.ProtoLang, imp: source})
// 	}
// 	return importedAs
// }

// func findSources(r *rule.Rule, buildRel, ext string) []string {
// 	srcStrs := r.AttrStrings("srcs")
// 	srcs := make([]string, 0, len(srcStrs))
// 	for _, src := range srcStrs {
// 		label, err := label.Parse(src)
// 		if err != nil || !label.Relative || !strings.HasSuffix(label.Name, ext) {
// 			continue
// 		}
// 		srcs = append(srcs, path.Join(buildRel, label.Name))
// 	}
// 	return srcs
// }

// func isGoLibrary(kind string) bool {
// 	return kind == "go_library" || isGoProtoLibrary(kind)
// }

// func isGoProtoLibrary(kind string) bool {
// 	return kind == "go_proto_library" || kind == "go_grpc_library"
// }
