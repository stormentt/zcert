/*
Copyright © 2022 Tanner Storment

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stormentt/zcert/client"
)

var inPath string
var outPath string
var force bool

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "asks the server to sign a certificate signing request",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		var in io.Reader
		var out io.WriteCloser
		if inPath == "-" {
			in = os.Stdin
		} else {
			inFile, err := os.Open(inPath)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
					"path":  inPath,
				}).Fatal("unable to open input")
			}

			in = inFile
		}

		if outPath == "-" {
			out = os.Stdout
		} else {
			if _, err := os.Stat(outPath); err == nil {
				if !force {
					log.WithFields(log.Fields{
						"path": outPath,
					}).Fatal("output already exists, will not procede without --force")
				}
			}

			outFile, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				log.WithFields(log.Fields{
					"path":  outPath,
					"error": err,
				}).Fatal("unable to create output")
			}

			out = outFile
		}

		if err := client.SignCSR(out, in); err != nil {
			log.Fatal(err)
		}

		if err := out.Close(); err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"path":  outPath,
			}).Fatal("unable to close output. output may be corrupted")
		}
	},
}

func init() {
	clientCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(&inPath, "in", "i", "-", "path to the certificate signing request")
	signCmd.Flags().StringVarP(&outPath, "out", "o", "-", "path to store the signed certificate")
	signCmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite signed certificate file if it exists")
}
