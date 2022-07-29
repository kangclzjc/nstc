package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {

	podCommand.AddCommand(podNs)
	rootCmd.AddCommand(podCommand)
}

var podNs = &cobra.Command{
	Use:   "ns",
	Short: "list pod network namespace",
	Long:  `this command list pod network namespace for user to nsenter in`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("pod namespace list")
	},
}

var podCommand = &cobra.Command{
	Use:   "pod",
	Short: "manage pod",
	Long:  `All action related with pod will be here`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("pod manage")
	},
}
