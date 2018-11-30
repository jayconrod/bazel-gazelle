// +build darwin dragonfly freebsd js,wasm linux nacl netbsd openbsd solaris

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

package main

import (
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// startServer starts a new server process. This is called by the client.
func startServer() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"-server"}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command(exe, args...)
	log.Printf("starting server: %s", strings.Join(cmd.Args, " "))
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Process.Release(); err != nil {
		return err
	}
	return nil
}

// runServer performs the main work of the server. Once started, the server
// will:
//
// * Copy BUILD.in and BUILD.bazel.in files to BUILD and BUILD.bazel.
// * Watch for file system writes in the whole repository.
// * Listen for clients on a UNIX-domain socket.
//
// When the server accepts a connection, it runs Gazelle. On the first run,
// it runs Gazelle on the entire repository. On subsequent runs, it runs
// Gazelle only in directories that have changed.
//
// The server stops after being idle for a while. It can also be stopped
// with SIGINT or SIGTERM.
func runServer() error {
	// Begin logging to the log file.
	logFile, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Start listening on the socket before other initialization work. The client
	// will dial immediately after starting the server, and we don't want
	// the client to time out.
	os.Remove(*socketPath)
	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		return err
	}
	uln := ln.(*net.UnixListener)
	uln.SetUnlinkOnClose(true)
	defer ln.Close()
	if err := uln.SetDeadline(time.Now().Add(*serverTimeout)); err != nil {
		return err
	}
	log.Printf("started server with pid %d", os.Getpid())

	// Copy BUILD.in files to BUILD.
	restoreBuildFilesInRepo()

	// Listen for file writes within the repository.
	w, err := watchDir(".")
	if err != nil {
		log.Print(err)
	} else {
		defer w.close()
	}

	// Wait for clients to connect. Each time the client connects, we run
	// gazelle, either in the whole repository or in changed directories.
	mode := fullMode
	for {
		c, err := ln.Accept()
		if err != nil {
			if operr, ok := err.(*net.OpError); ok {
				if operr.Timeout() {
					return nil
				}
				if operr.Temporary() {
					log.Printf("temporary watch error: %v", err)
					continue
				}
			}
			return err
		}

		w.setRecordBuildWrites(false)
		log.SetOutput(io.MultiWriter(c, logFile))
		dirs := w.getAndClearWrittenDirs()
		for _, dir := range dirs {
			restoreBuildFilesInDir(dir)
		}
		if err := runGazelle(mode, dirs); err != nil {
			log.Print(err)
		}
		log.SetOutput(logFile)
		w.setRecordBuildWrites(true) // TODO: maybe after a timeout?
		c.Close()
		if w != nil {
			mode = fastMode
		}
	}
}

// watcher monitors a repository for changes.
//
// After creating a watcher, the server should call getAndClearWrittenDirs
// to get a list of directories that have changed since the last call.
// The server should also call setRecordBuildWrites around invocations
// to gazelle.
type watcher struct {
	w *fsnotify.Watcher

	mu                      sync.Mutex
	dirSet                  map[string]bool
	shouldRecordBuildWrites bool

	done chan struct{}
}

// Creates a new watcher that monitors root and its subdirectories.
func watchDir(root string) (*watcher, error) {
	w := &watcher{
		dirSet: make(map[string]bool),
		done:   make(chan struct{}),
	}
	var err error
	w.w, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dirs, errs := listDirs(root)
	for _, err := range errs {
		log.Print(err)
	}
	gitDir := filepath.Join(root, ".git")
	for _, dir := range dirs {
		if dir == gitDir {
			continue
		}
		if err := w.w.Add(dir); err != nil {
			log.Print(err)
		}
	}

	go w.doWatch()
	return w, nil
}

// getAndClearWrittenDirs returns a list of directories with files that may
// have been modified since the last call to getAndClearWrittenDirs or
// since the watcher was created.
func (w *watcher) getAndClearWrittenDirs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	dirs := make([]string, 0, len(w.dirSet))
	for d := range w.dirSet {
		dirs = append(dirs, d)
	}
	w.dirSet = make(map[string]bool)
	return dirs
}

// setRecordBuildWrites sets whether writes to build files count as
// changes that require gazelle to be run. Writes caused by gazelle itself
// should not be recorded, so the server should set this to false before
// invoking gazelle and true after.
func (w *watcher) setRecordBuildWrites(record bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.shouldRecordBuildWrites = record
}

// close tells the watcher to stop processing events and release resources.
func (w *watcher) close() {
	close(w.done)
}

func (w *watcher) doWatch() {
	for {
		select {
		case ev := <-w.w.Events:
			w.handleEvent(ev)
		case err := <-w.w.Errors:
			log.Print(err)
		case <-w.done:
			if err := w.w.Close(); err != nil {
				log.Print(err)
			}
			return
		}
	}
}

func (w *watcher) handleEvent(ev fsnotify.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.shouldIgnore(ev.Name) {
		return
	}
	if ev.Op == fsnotify.Create {
		if st, err := os.Lstat(ev.Name); err != nil {
			log.Print(err)
		} else if st.IsDir() {
			dirs, errs := listDirs(ev.Name)
			for _, err := range errs {
				log.Print(err)
			}
			for _, dir := range dirs {
				if err := w.w.Add(dir); err != nil {
					log.Print(err)
				}
				w.dirSet[dir] = true
			}
		}
	} else {
		w.dirSet[filepath.Dir(ev.Name)] = true
	}
}

// shouldIgnore returns whether a write to the given file should be ignored
// because they were caused by gazelle or autogazelle or something unrelated
// to the build.
func (w *watcher) shouldIgnore(p string) bool {
	p = strings.TrimPrefix(filepath.ToSlash(p), "./")
	base := path.Base(p)
	return strings.HasPrefix(p, "tools/") || base == ".git" ||
		(base == "BUILD" || base == "BUILD.bazel") && !w.shouldRecordBuildWrites
}

// listDirs returns a slice containing all the subdirectories under dir,
// including dir itself.
func listDirs(dir string) ([]string, []error) {
	var dirs []string
	var errs []error
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if info.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return dirs, errs
}
