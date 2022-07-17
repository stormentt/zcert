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
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stormentt/zcert/util/random"
)

var saveKey bool

// authkeyGenerateCmd represents the authkeyGenerate command
var authkeyGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate an authentication key suitable for use with message authentication codes",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		genkey := random.AlphaNum(32)

		if saveKey {
			viper.Set("authkey", genkey)
			if err := viper.WriteConfig(); err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Fatal("unable to save generated key")
			}
		} else {
			fmt.Println(genkey)
		}
	},
}

func init() {
	authkeyCmd.AddCommand(authkeyGenerateCmd)
	authkeyGenerateCmd.Flags().BoolVar(&saveKey, "save", false, "save the generated authkey in the config file")
}
