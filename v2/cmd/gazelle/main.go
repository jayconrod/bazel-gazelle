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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/bazel-contrib/bazel-gazelle/v2/cmd/gazelle/update"
	"github.com/bazel-contrib/bazel-gazelle/v2/compat"
	"github.com/bazel-contrib/bazel-gazelle/v2/resolve"
	"github.com/bazel-contrib/bazel-gazelle/v2/walk"
	"github.com/bazelbuild/bazel-gazelle/config"
)

func main() {
	log.SetPrefix("gazelle: ")
	log.SetFlags(0) // don't print timestamps

	var wd string
	if wsDir := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); wsDir != "" {
		wd = wsDir
	} else {
		var err error
		if wd, err = os.Getwd(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := run(ctx, wd, os.Args[1:]); err != nil {
		if !errors.Is(err, update.ErrDiffExit) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		if !errors.Is(err, flag.ErrHelp) {
			os.Exit(1)
		}
	}
}

func run(ctx context.Context, wd string, args []string) error {
	exts := make([]compat.CompleteLanguage, 0, len(languages)+4)
	exts = append(exts,
		compat.LanguageWithDefaults(&config.CommonConfigurer{}),
		compat.LanguageWithDefaults(&update.UpdateConfigurer{}),
		compat.LanguageWithDefaults(&walk.Configurer{}),
		compat.LanguageWithDefaults(&resolve.Configurer{}))
	for _, lang := range languages {
		exts = append(exts, lang)
	}

	return update.Update(ctx, exts, wd, args)
}
