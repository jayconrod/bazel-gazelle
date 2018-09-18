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
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func runClient() error {
	c, err := net.Dial("unix", *socketPath)
	if err != nil {
		if err := startServer(); err != nil {
			return fmt.Errorf("error starting server: %v", err)
		}
		for retry := 0; retry < 3; retry++ {
			c, err = net.Dial("unix", *socketPath)
			if err == nil {
				break
			}
			// Wait for server to start listening.
			time.Sleep(1 * time.Second)
		}
		if err != nil {
			return err
		}
	}
	defer c.Close()
	buf := []byte{0}
	for {
		_, err := c.Read(buf)
		if err == io.EOF {
			return nil
		}
		if operr, ok := err.(*net.OpError); ok {
			if !operr.Temporary() {
				return operr
			}
		}
		log.Print(err)
	}
}

func startServer() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer logFile.Close()
	args := []string{"-server"}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command(exe, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	log.Printf("starting server: %s", strings.Join(cmd.Args, " "))
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Process.Release(); err != nil {
		return err
	}
	return nil
}
