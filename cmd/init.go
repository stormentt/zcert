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
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stormentt/zcert/certs"
	"github.com/stormentt/zcert/db"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "A brief description of your command",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(viper.GetString("ca.name")) == 0 {
			log.Fatal("ca.name is empty! make sure you configure that")
		}

		if err := db.InitDB(); err != nil {
			log.WithFields(log.Fields{
				"Error": err,
			}).Fatal("could not init db")
		}

		if err := certs.CreateCA(); err != nil {
			log.WithFields(log.Fields{
				"Error": err,
			}).Fatal("could not create certificate authority")
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().BoolP("force", "f", false, "force initialization, overwriting any existing files")
	initCmd.Flags().DurationP("lifetime", "l", time.Hour*24*365*1, "cert authority lifetime")

	viper.BindPFlag("force", initCmd.Flags().Lookup("force"))
	viper.BindPFlag("lifetime", initCmd.Flags().Lookup("lifetime"))

	viper.SetDefault("storage.database", "db.sqlite3")

}
