/* Copyright 2025 The Bazel Authors. All rights reserved.

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

// Package compat provides interfaces and adapters, supporting compatibility
// between Gazelle v1 and v2.
package compat

import (
	"context"
	"flag"

	"github.com/bazel-contrib/bazel-gazelle/v2/config"
	"github.com/bazel-contrib/bazel-gazelle/v2/language"
	"github.com/bazel-contrib/bazel-gazelle/v2/resolve"
	"github.com/bazel-contrib/bazel-gazelle/v2/rule"
	configv1 "github.com/bazelbuild/bazel-gazelle/config"
	resolvev1 "github.com/bazelbuild/bazel-gazelle/resolve"
)

// FlagConfigurer allows an extension to define and validate command-line flags.
//
// The v2 Configurer interface does not have these methods, and gazelle v2
// ignores any provided implementations. However, gazelle v1 needs to work
// with the same code, and v1 extensions can provide flags, so we still
// support this interface for compatibility. This interface's methods are
// identical to the corresponding methods in the v1 interface.
type FlagConfigurer interface {
	// RegisterFlags registers command-line flags used by the extension. This
	// method is called once with the root configuration when Gazelle
	// starts. RegisterFlags may set an initial values in Config.Exts. When flags
	// are set, they should modify these values.
	RegisterFlags(fs *flag.FlagSet, cmd string, c *config.Config)

	// CheckFlags validates the configuration after command line flags are parsed.
	// This is called once with the root configuration when Gazelle starts.
	// CheckFlags may set default values in flags or make implied changes.
	CheckFlags(fs *flag.FlagSet, c *config.Config) error
}

var _ FlagConfigurer = (configv1.Configurer)(nil)

// ConfigurerV2 returns v and true if v satisfies the v2 Configurer interface,
// or and adapter and true if v satisifes the v1 Configurer interface.
// ConfigurerV2 returns nil and false if v does not satisfy either interface.
func ConfigurerV2(v any) (config.Configurer, bool) {
	switch v := v.(type) {
	case config.Configurer:
		return v, true
	case configv1.Configurer:
		return configurerAdapter{v1: v}, true
	default:
		return nil, false
	}
}

func MustConfigurerV2(v any) config.Configurer {
	return Must(ConfigurerV2(v))
}

type configurerAdapter struct {
	v1 configv1.Configurer
}

var _ config.Configurer = configurerAdapter{}
var _ FlagConfigurer = configurerAdapter{}

func (c configurerAdapter) RegisterFlags(fs *flag.FlagSet, cmd string, cfg *config.Config) {
	c.v1.RegisterFlags(fs, cmd, cfg)
}

func (c configurerAdapter) CheckFlags(fs *flag.FlagSet, cfg *config.Config) error {
	return c.v1.CheckFlags(fs, cfg)
}

func (c configurerAdapter) KnownDirectives() []string {
	return c.v1.KnownDirectives()
}

func (c configurerAdapter) Configure(ctx context.Context, args config.ConfigureArgs) error {
	c.v1.Configure(args.Config, args.Rel, args.File)
	return nil
}

func IndexerV2(v1 resolvev1.Resolver) resolve.Indexer {
	return indexerAdapter{v1: v1}
}

type indexerAdapter struct {
	v1 resolvev1.Resolver
}

var _ resolve.Indexer = indexerAdapter{}

// TODO(v2): remove
func (i indexerAdapter) Name() string {
	return i.v1.Name()
}

func (i indexerAdapter) Imports(ctx context.Context, args resolve.ImportsArgs) (resolve.ImportsResult, error) {
	imps := i.v1.Imports(args.Config, args.Rule, args.File)
	embeds := i.v1.Embeds(args.Rule, args.From)
	return resolve.ImportsResult{
		Imports:       imps,
		Embeds:        embeds,
		NotImportable: imps == nil,
	}, nil
}

func ResolverV2(v1 resolvev1.Resolver) resolve.Resolver {
	return resolverAdapter{v1: v1}
}

type resolverAdapter struct {
	v1 resolvev1.Resolver
}

func (r resolverAdapter) Resolve(ctx context.Context, args resolve.ResolveArgs) error {
	r.v1.Resolve(args.Config, resolvev1.WrapRuleIndexV2(args.Index), args.RemoteCache, args.Rule, args.Imports, args.From)
	return nil
}

func FinderV2(v1 resolvev1.CrossResolver) resolve.Finder {
	return finderAdapter{v1: v1}
}

type finderAdapter struct {
	v1 resolvev1.CrossResolver
}

func (a finderAdapter) Find(ctx context.Context, args resolve.FindArgs) []resolve.FindResult {
	return a.v1.CrossResolve(args.Config, resolvev1.WrapRuleIndexV2(args.Index), args.Import, args.Lang)
}

type CompleteLanguage interface {
	language.Language
	language.Generator
	language.Fixer
	language.OnStarter
	language.OnFinisher
	config.Configurer
	resolve.Indexer
	resolve.Resolver
	resolve.Finder
}

type completeLanguageAdapter struct {
	language.Language
	language.Generator
	language.Fixer
	language.OnStarter
	language.OnFinisher
	config.Configurer
	resolve.Indexer
	resolve.Resolver
	resolve.Finder
}

func (a completeLanguageAdapter) Name() string {
	return a.Language.Name()
}

func LanguageWithDefaults(v language.Language) CompleteLanguage {
	adapter := completeLanguageAdapter{Language: v}
	if gen, ok := v.(language.Generator); ok {
		adapter.Generator = gen
	} else {
		adapter.Generator = noopGenerator{}
	}
	if fix, ok := v.(language.Fixer); ok {
		adapter.Fixer = fix
	} else {
		adapter.Fixer = noopFixer{}
	}
	if start, ok := v.(language.OnStarter); ok {
		adapter.OnStarter = start
	} else {
		adapter.OnStarter = noopOnStarter{}
	}
	if finish, ok := v.(language.OnFinisher); ok {
		adapter.OnFinisher = finish
	} else {
		adapter.OnFinisher = noopOnFinisher{}
	}
	if cfg, ok := v.(config.Configurer); ok {
		adapter.Configurer = cfg
	} else {
		adapter.Configurer = noopConfigurer{}
	}
	if idx, ok := v.(resolve.Indexer); ok {
		adapter.Indexer = idx
	} else {
		adapter.Indexer = noopIndexer{Language: v}
	}
	if res, ok := v.(resolve.Resolver); ok {
		adapter.Resolver = res
	} else {
		adapter.Resolver = noopResolver{}
	}
	if find, ok := v.(resolve.Finder); ok {
		adapter.Finder = find
	} else {
		adapter.Finder = noopFinder{}
	}
	return adapter
}

type noopGenerator struct{}

func (noopGenerator) Kinds() map[string]rule.KindInfo {
	return nil
}

func (noopGenerator) Generate(_ context.Context, _ language.GenerateArgs) (language.GenerateResult, error) {
	return language.GenerateResult{}, nil
}

type noopFixer struct{}

func (noopFixer) Fix(_ context.Context, _ language.FixArgs) error {
	return nil
}

type noopOnStarter struct{}

func (noopOnStarter) OnStart(_ context.Context) error {
	return nil
}

type noopOnFinisher struct{}

func (noopOnFinisher) OnFinish(_ context.Context) error {
	return nil
}

type noopConfigurer struct{}

func (noopConfigurer) KnownDirectives() []string {
	return nil
}

func (noopConfigurer) Configure(_ context.Context, _ config.ConfigureArgs) error {
	return nil
}

type noopIndexer struct {
	language.Language
}

func (noopIndexer) Imports(_ context.Context, _ resolve.ImportsArgs) (resolve.ImportsResult, error) {
	return resolve.ImportsResult{}, nil
}

type noopResolver struct{}

func (noopResolver) Resolve(_ context.Context, _ resolve.ResolveArgs) error {
	return nil
}

type noopFinder struct{}

func (noopFinder) Find(_ context.Context, _ resolve.FindArgs) []resolve.FindResult {
	return nil
}

func Must[T any](v T, ok bool) T {
	if !ok {
		panic("Must failed")
	}
	return v
}
