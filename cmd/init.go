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
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(viper.GetString("ca.name")) == 0 {
			log.Fatal("ca.name is empty! make sure you configure that")
		}
		err := certs.CreateCA()
		if err != nil {
			log.WithFields(log.Fields{
				"Error": err,
			}).Fatal("could not create certificate authority")
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// initCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	initCmd.Flags().BoolP("force", "f", false, "force initialization, overwriting any existing files")
	initCmd.Flags().DurationP("lifetime", "d", time.Hour*24*365*10, "cert authority lifetime")
	viper.BindPFlag("force", initCmd.Flags().Lookup("force"))
	viper.BindPFlag("lifetime", initCmd.Flags().Lookup("lifetime"))

}
