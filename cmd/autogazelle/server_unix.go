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
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

func runServer() error {
	log.SetFlags(log.Ldate | log.Ltime)

	cleanup, err := watchRepo()
	if err != nil {
		return err
	}
	defer cleanup()

	restoreFiles()

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

	mode := fullMode
	for {
		c, err := ln.Accept()
		if err != nil {
			if operr, ok := err.(*net.OpError); ok {
				if operr.Timeout() {
					return nil
				}
				if operr.Temporary() {
					log.Printf("temporary error: %v", err)
					continue
				}
			}
			return err
		}

		dirs := getAndClearWrittenDirs()
		if err := runGazelle(mode, dirs); err != nil {
			log.Print(err)
		}
		c.Close()
		mode = fastMode
	}
}

func watchRepo() (cleanup func(), err error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dirs, errs := listDirs(".")
	for _, err := range errs {
		log.Print(err)
	}
	for _, dir := range dirs {
		if err := w.Add(dir); err != nil {
			log.Print(err)
		}
	}

	done := make(chan struct{})
	go func() {
		for {
			select {
			case ev := <-w.Events:
				if shouldIgnore(ev.Name) {
					continue
				}
				if ev.Op == fsnotify.Create {
					if st, err := os.Lstat(ev.Name); err != nil {
						log.Print(err)
					} else if st.IsDir() {
						dirs, errs := listDirs(".")
						for _, err := range errs {
							log.Print(err)
						}
						for _, dir := range dirs {
							if err := w.Add(dir); err != nil {
								log.Print(err)
							}
							recordWrite(dir)
						}
					}
				} else {
					recordWrite(filepath.Dir(ev.Name))
				}
			case err := <-w.Errors:
				log.Print(err)
			case <-done:
				return
			}
		}
	}()

	cleanup = func() {
		close(done)
		w.Close()
	}
	return cleanup, nil
}

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

func shouldIgnore(p string) bool {
	p = strings.TrimPrefix(filepath.ToSlash(p), "./")
	return strings.HasPrefix(p, "tools/") || path.Base(p) == "BUILD" || path.Base(p) == "BUILD.bazel"
}

var (
	dirSetMutex sync.Mutex
	dirSet      = map[string]bool{".": true}
)

func recordWrite(path string) {
	dirSetMutex.Lock()
	defer dirSetMutex.Unlock()
	dirSet[path] = true
	log.Printf("write %s", path)
}

func getAndClearWrittenDirs() []string {
	dirSetMutex.Lock()
	defer dirSetMutex.Unlock()
	dirs := make([]string, 0, len(dirSet))
	for d := range dirSet {
		dirs = append(dirs, d)
	}
	dirSet = make(map[string]bool)
	return dirs
}
