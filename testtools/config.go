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

package testtools

import (
	"testing"

	"github.com/bazel-contrib/bazel-gazelle/v2/compat"
	configv2 "github.com/bazel-contrib/bazel-gazelle/v2/config"
	v2 "github.com/bazel-contrib/bazel-gazelle/v2/testtools"
	"github.com/bazelbuild/bazel-gazelle/config"
	"github.com/bazelbuild/bazel-gazelle/language"
)

// NewTestConfig returns a Config used for tests in any language extension.
// cexts is a list of configuration extensions to use. langs is a list of
// language extensions to use (languages are also configuration extensions,
// but it may be convenient to keep them separate). args is a list of
// command line arguments to apply. NewTestConfig calls t.Fatal if any
// error is encountered while processing flags.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/testtools.NewTestConfig instead.
func NewTestConfig(t *testing.T, cexts []config.Configurer, langs []language.Language, args []string) *config.Config {
	cextsv2 := make([]configv2.Configurer, len(cexts))
	for i, cext := range cexts {
		cextv2, ok := compat.ConfigurerV2(cext)
		if !ok {
			panic("could not convert configurer to v2 interface")
		}
		cextsv2[i] = cextv2
	}
	return v2.NewTestConfig(t, cextsv2, langs, args)
}
