/* Copyright 2017 The Bazel Authors. All rights reserved.

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

// Package config provides extensible configuration for Gazelle libraries.
//
// Packages may define Configurers which add support for new command-line
// options and directive comments in build files. Note that the
// language.Language interface embeds Configurer, so each language extension
// has the opportunity
//
// When Gazelle walks the directory trees in a repository, it calls the
// Configure method of each Configurer to produce a Config object.
// Config objects are passed as arguments to most functions in Gazelle, so
// this mechanism may be used to control many aspects of Gazelle's behavior.
package config

import v2 "github.com/bazel-contrib/bazel-gazelle/v2/config"

// Config holds information about how Gazelle should run. This is based on
// command line arguments, directives, other hints in build files.
//
// A Config applies to a single directory. A Config is created for the
// repository root directory, then copied and modified for each subdirectory.
//
// Config itself contains only general information. Most configuration
// information is language-specific and is stored in Exts. This information
// is modified by extensions that implement Configurer.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/config.Config instead.
type Config = v2.Config

// MappedKind describes a replacement to use for a built-in kind.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/config.MappedKind instead.
type MappedKind = v2.MappedKind

// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/config.New instead.
func New() *Config {
	return v2.New()
}

// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/config.DefaultValidBuildFileNames instead.
var DefaultValidBuildFileNames = v2.DefaultValidBuildFileNames

// Configurer is the interface for language or library-specific configuration
// extensions. Most (ideally all) modifications to Config should happen
// via this interface.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/config.Configurer instead.
type Configurer = v2.Configurer

// CommonConfigurer handles language-agnostic command-line flags and directives,
// i.e., those that apply to Config itself and not to Config.Exts.
//
// Deprecated: Use github.com/bazel-contrib/bazel-gazelle/v2/config.CommonConfigurer instead.
type CommonConfigurer = v2.CommonConfigurer
