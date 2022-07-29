package cmd

import (
	"fmt"
	"golang.org/x/sys/unix"
	"kangclzjc/nstc/pkg/ns"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

func init() {
	tcCommand.Flags().StringVarP(&namespace, "namespace", "n", "root", "give a network namespace")
	tcCommand.Flags().StringVarP(&eth0, "eth0", "I", "eth0", "give a network interface in namespace")
	tcCommand.Flags().Uint64VarP(&egress, "egress", "e", 40000000, "give a egress bandwidth")
	tcCommand.Flags().Uint64VarP(&ingress, "ingress", "i", 40000000, "give a ingress bandwidth")
	rootCmd.AddCommand(tcCommand)
}

var (
	namespace string
	eth0      string
	egress    uint64
	ingress   uint64
)

func safeQdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	result := []netlink.Qdisc{}
	for _, qdisc := range qdiscs {
		// filter out pfifo_fast qdiscs because
		// older kernels don't return them
		_, pfifo := qdisc.(*netlink.PfifoFast)
		if !pfifo {
			result = append(result, qdisc)
		}
	}
	return result, nil
}

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

		_ = netns.Do(func(_ ns.NetNS) error {
			l, err := netlink.LinkByName(eth0)
			fmt.Println("-------------zk 09-----------\n")
			if err != nil {
				fmt.Println("-------------zk-----------%s\n", err)
			}

			if err != nil {
				fmt.Println("-------------zk-----------%s\n", err)
			}
			qdiscs, err := safeQdiscList(l)
			if err != nil {
				fmt.Println("-------------zk list qdisc-----------%s\n", err)
			}
			var htb *netlink.Htb
			var hasHtb = false
			for _, qdisc := range qdiscs {
				fmt.Println("qdisc is %s\n", qdisc)

				h, isHTB := qdisc.(*netlink.Htb)
				if isHTB {
					htb = h
					hasHtb = true
					break
				}
			}
			fmt.Println("-------------zk 1-----------\n")

			if !hasHtb {
				// qdisc
				// tc qdisc add dev lo root handle 1:0 htb default 1
				attrs := netlink.QdiscAttrs{
					LinkIndex: l.Attrs().Index,
					Handle:    netlink.MakeHandle(1, 0),
					Parent:    netlink.HANDLE_ROOT,
				}
				htb = netlink.NewHtb(attrs)
				err = netlink.QdiscAdd(htb)
				if err != nil {
					fmt.Println("QdiscAdd error: %s\n", err)
				}
			}

			// htb parent class
			// tc class add dev lo parent 1:0 classid 1:1 htb rate 125Mbps ceil 125Mbps prio 0
			// preconfig
			classattrs1 := netlink.ClassAttrs{
				LinkIndex: l.Attrs().Index,
				Parent:    netlink.MakeHandle(1, 0),
				Handle:    netlink.MakeHandle(1, 1),
			}
			htbclassattrs1 := netlink.HtbClassAttrs{
				Rate:    10000000000,
				Cbuffer: 0,
			}
			class1 := netlink.NewHtbClass(classattrs1, htbclassattrs1)
			if err := netlink.ClassAdd(class1); err != nil {
				fmt.Println("Class add error: ", err)
			}

			// htb child class
			// tc class add dev lo parent 1:0 classid 1:5 htb rate 125kbps ceil 250kbps prio 0
			classattrs2 := netlink.ClassAttrs{
				LinkIndex: l.Attrs().Index,
				Parent:    netlink.MakeHandle(1, 0),
				Handle:    netlink.MakeHandle(1, 5),
				//Handle: *linuxNetworkIO.ClassID,
			}
			htbclassattrs2 := netlink.HtbClassAttrs{
				Rate:    egress,
				Cbuffer: uint32(egress) * 2,
			}
			class2 := netlink.NewHtbClass(classattrs2, htbclassattrs2)
			if err := netlink.ClassAdd(class2); err != nil {
				fmt.Println("Class add error", err)
			}

			// filter add
			// tc filter add dev lo parent 1:0 prio 0 protocol all handle 5 fw flowid 1:5
			filterattrs := netlink.FilterAttrs{
				LinkIndex: l.Attrs().Index,
				Parent:    netlink.MakeHandle(1, 0),
				Handle:    netlink.MakeHandle(1, 5),
				Priority:  49152,
				Protocol:  unix.ETH_P_IP,
			}

			filter := &netlink.GenericFilter{
				filterattrs,
				"cgroup",
			}

			if err != nil {
				fmt.Println("failed to create NewFw(). Reason:%s", err)
			}

			if err := netlink.FilterAdd(filter); err != nil {
				fmt.Println("failed to add filter. Reason:%s", err)
			}

			return nil
		})
	},
}
