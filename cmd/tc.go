package cmd

import (
	"fmt"
	"kangclzjc/nstc/pkg/ns"

	"github.com/spf13/cobra"
)

func init() {
	tcCommand.Flags().StringVarP(&namespace, "namespace", "n", "root", "give a network namespace")
	tcCommand.Flags().StringVarP(&eth0, "eth0", "I", "eth0", "give a network interface in namespace")
	tcCommand.Flags().Int64VarP(&egress, "egress", "e", 40000000, "give a egress bandwidth")
	tcCommand.Flags().Int64VarP(&ingress, "ingress", "i", 40000000, "give a ingress bandwidth")
	rootCmd.AddCommand(tcCommand)
}

var (
	namespace string
	eth0      string
	egress    int64
	ingress   int64
)

var tcCommand = &cobra.Command{
	Use:   "tc",
	Short: "set tc in specific namespace with egress/ingress",
	Long:  `set tc in specific namespace with egress/ingress`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("tc set NIC %q of egress %d ingress %d in namespace %q\n", eth0, egress, ingress, namespace)
		netns, err := ns.GetNS(namespace)
		if err != nil {
			fmt.Printf("failed to open netns %q: %v", namespace, err)
			return
		}
		defer netns.Close()
	},
}
