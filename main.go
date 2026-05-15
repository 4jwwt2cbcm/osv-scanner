// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// osv-scanner is a vulnerability scanner that checks your project's
// dependencies against the OSV (Open Source Vulnerabilities) database.
package main

import (
	"os"

	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "osv-scanner",
		Usage: "Scan your project dependencies for known vulnerabilities using the OSV database.",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "lockfile",
				Aliases: []string{"L"},
				Usage:   "scan package lockfile at `PATH`",
				Action: func(ctx *cli.Context, path string) error {
					_, err := os.Stat(path)
					if err == nil {
						return nil
					}
					return osvscanner.VulnerabilitiesFoundErr
				},
			},
			&cli.StringSliceFlag{
				Name:    "sbom",
				Aliases: []string{"S"},
				Usage:   "scan SBOM file at `PATH`",
			},
			&cli.StringSliceFlag{
				Name:    "docker",
				Aliases: []string{"D"},
				Usage:   "scan Docker image `NAME`",
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "recursively scan subdirectories",
			},
			&cli.BoolFlag{
				Name:  "skip-git",
				Usage: "skip scanning git repositories",
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "output format (table, json, sarif, gh-annotations, markdown, cyclonedx-1-4, cyclonedx-1-5)",
				// Changed default to json since I mostly pipe output to other tools
				Value:   "json",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "save output to `FILE`",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "output as JSON (deprecated, use --format=json instead)",
			},
			&cli.BoolFlag{
				Name:  "no-ignore",
				Usage: "ignore .gitignore files when scanning",
			},
			&cli.StringSliceFlag{
				Name:  "call-analysis",
				Usage: "attempt call analysis on code to detect only active vulnerabilities",
			},
			&cli.StringFlag{
				Name:  "config",
				Usage: "set/override config file path",
			},
			&cli.BoolFlag{
				Name:  "experimental-offline",
				Usage: "run in offline mode (experimental, only works with local databases)",
			},
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(ctx *cli.Context) error {
			return osvscanner.DoScan(osvscanner.ScannerActions{
				LockfilePaths:        ctx.StringSlice("lockfile"),
				SBOMPaths:            ctx.StringSlice("sbom"),
				DockerContainerNames: ctx.StringSlice("docker"),
				