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

// autogazelle is a program that tracks changes in a workspace and runs
// gazelle to incorporate those changes into Bazel build files.
//
// autogazelle has two components: a client and a server. The server
// watches for file system changes within the workspace and builds a
// set of build files that need to be updated. The server listens on a
// UNIX socket. When it accepts a connection, it runs gazelle in modified
// directories and closes the connection without transmitting anything.
// The client simply connects to the server and waits for the connection
// to be closed.
//
// autogazelle is intended to be invoked by autogazelle.bash as a bazel
// wrapper script. It requires the BUILD_WORKSPACE_DIRECTORY environment
// variable to be set to the workspace root directory and BAZEL_REAL to
// be set to the local of the real bazel binary.
package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	programName = filepath.Base(os.Args[0])

	isServer      = flag.Bool("server", false, "whether this process acts as the server")
	gazelleLabel  = flag.String("gazelle", "//:gazelle", "bazel target the server should run when invoked")
	serverTimeout = flag.Duration("timeout", 3600*time.Second, "time in seconds the server will listen for a client before quitting")
	socketPath    = flag.String("socket", "tools/autogazelle.socket", "path to the UNIX socket where the server will listen, relative to the workspace root")
	logPath       = flag.String("log", "tools/autogazelle.log", "path to the server's log file, relative to the workspace root")
)

func main() {
	log.SetPrefix(programName + ": ")
	log.SetFlags(0)
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	workspaceDir, ok := os.LookupEnv("BUILD_WORKSPACE_DIRECTORY")
	if !ok {
		return errors.New("BUILD_WORKSPACE_DIRECTORY not set")
	}
	if err := os.Chdir(workspaceDir); err != nil {
		return err
	}

	if _, ok := os.LookupEnv("BAZEL_REAL"); !ok {
		return errors.New("BAZEL_REAL not set")
	}

	if *isServer {
		return runServer()
	} else {
		return runClient()
	}
}

func runGazelle() error {
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Base(path) == "BUILD.bazel.in" {
			if err := copyFile(filepath.Join(filepath.Dir(path), "BUILD.bazel"), path); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	bazelPath := os.Getenv("BAZEL_REAL")
	cmd := exec.Command(bazelPath, "run", *gazelleLabel)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("running command %s\n", strings.Join(cmd.Args, " "))
	return cmd.Run()
}

func copyFile(dest, src string) (err error) {
	r, err := os.Open(src)
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := w.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	_, err = io.Copy(w, r)
	return err
}
