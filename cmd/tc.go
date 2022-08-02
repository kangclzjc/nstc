package cmd

import (
	"fmt"
	"golang.org/x/sys/unix"
	"kangclzjc/nstc/pkg/ns"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

func init() {
	tcCommand.Flags().StringVarP(&namespace, "namespace", "n", "root", "give a network namespace")
	tcCommand.Flags().StringVarP(&eth0, "eth0", "I", "eth0", "give a network interface in namespace")
	tcCommand.Flags().Uint64VarP(&egress, "egress", "e", 40000000, "give a egress bandwidth")
	tcCommand.Flags().Uint64VarP(&egressBurst, "egressBurst", "b", 40000000, "give a egress bandwidth burst")
	tcCommand.Flags().Uint64VarP(&egressRate, "egressRate", "r", 40000000, "give a egress bandwidth rate")
	tcCommand.Flags().Uint64VarP(&ingress, "ingress", "i", 40000000, "give a ingress bandwidth")
	tcCommand.Flags().Uint64VarP(&ingressBurst, "ingressBurst", "u", 40000000, "give a ingress bandwidth burst")
	tcCommand.Flags().Uint64VarP(&ingressRate, "ingressRate", "t", 40000000, "give a ingress bandwidth rate")
	rootCmd.AddCommand(tcCommand)
}

var (
	namespace    string
	eth0         string
	egress       uint64
	egressBurst  uint64
	egressRate   uint64
	ingress      uint64
	ingressBurst uint64
	ingressRate  uint64
)

const latencyInMillis = 25

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

func getMTU(deviceName string) (int, error) {
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return -1, err
	}

	return link.Attrs().MTU, nil
}

func time2Tick(time uint32) uint32 {
	return uint32(float64(time) * float64(netlink.TickInUsec()))
}

func latencyInUsec(latencyInMillis float64) float64 {
	return float64(netlink.TIME_UNITS_PER_SEC) * (latencyInMillis / 1000.0)
}

func buffer(rate uint64, burst uint32) uint32 {
	return time2Tick(uint32(float64(burst) * float64(netlink.TIME_UNITS_PER_SEC) / float64(rate)))
}

func limit(rate uint64, latency float64, buffer uint32) uint32 {
	return uint32(float64(rate)*latency/float64(netlink.TIME_UNITS_PER_SEC)) + buffer
}

func createTBF(rateInBits, burstInBits uint64, linkIndex int) error {
	// Equivalent to
	// tc qdisc add dev link root tbf
	//		rate netConf.BandwidthLimits.Rate
	//		burst netConf.BandwidthLimits.Burst
	if rateInBits <= 0 {
		return fmt.Errorf("invalid rate: %d", rateInBits)
	}
	if burstInBits <= 0 {
		return fmt.Errorf("invalid burst: %d", burstInBits)
	}
	rateInBytes := rateInBits / 8
	burstInBytes := burstInBits / 8
	bufferInBytes := buffer(uint64(rateInBytes), uint32(burstInBytes))
	latency := latencyInUsec(latencyInMillis)
	limitInBytes := limit(uint64(rateInBytes), latency, uint32(burstInBytes))

	qdisc := &netlink.Tbf{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		Limit:  uint32(limitInBytes),
		Rate:   uint64(rateInBytes),
		Buffer: uint32(bufferInBytes),
	}
	err := netlink.QdiscAdd(qdisc)
	if err != nil {
		return fmt.Errorf("create qdisc: %s", err)
	}
	return nil
}

func CreateEgressQdisc(rateInBits, burstInBits uint64, hostDeviceName string, ifbDeviceName string) error {
	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device: %s", err)
	}
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}

	// add qdisc ingress on host device
	ingress := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: hostDevice.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0), // ffff:
			Parent:    netlink.HANDLE_INGRESS,
		},
	}

	err = netlink.QdiscAdd(ingress)
	if err != nil {
		fmt.Errorf("create ingress qdisc: %s\n", err)
	}

	// add filter on host device to mirror traffic to ifb device
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: hostDevice.Attrs().Index,
			Parent:    ingress.QdiscAttrs.Handle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId:    netlink.MakeHandle(1, 1),
		RedirIndex: ifbDevice.Attrs().Index,
		Actions: []netlink.Action{
			&netlink.MirredAction{
				ActionAttrs:  netlink.ActionAttrs{},
				MirredAction: netlink.TCA_EGRESS_REDIR,
				Ifindex:      ifbDevice.Attrs().Index,
			},
		},
	}
	err = netlink.FilterAdd(filter)
	if err != nil {
		fmt.Errorf("add filter: %s\n", err)
	}

	// throttle traffic on ifb device
	err = createTBF(rateInBits, burstInBits, ifbDevice.Attrs().Index)
	if err != nil {
		return fmt.Errorf("create ifb qdisc: %s\n", err)
	}
	return nil
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

			// egress
			l, err := netlink.LinkByName(eth0)
			if err != nil {
				fmt.Printf("get link by name %s in the container namespace %s\n", eth0, err)
			}

			qdiscs, err := safeQdiscList(l)
			if err != nil {
				fmt.Printf("get current qdisc in the container namespace of %s\n", err)
			}
			var htb *netlink.Htb
			var hasHtb = false
			for _, qdisc := range qdiscs {
				fmt.Printf("current qdisc is %s\n", qdisc)

				h, isHTB := qdisc.(*netlink.Htb)
				if isHTB {
					htb = h
					hasHtb = true
					break
				}
			}

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
				Rate:    egress,
				Cbuffer: 0,
			}
			class1 := netlink.NewHtbClass(classattrs1, htbclassattrs1)
			if err := netlink.ClassAdd(class1); err != nil {
				fmt.Println("Class add error: ", err)
			}

			// htb child class
			// tc class add dev lo parent 1:0 classid 1:5 htb rate 125kbps ceil 250kbps prio 0
			//classattrs2 := netlink.ClassAttrs{
			//	LinkIndex: l.Attrs().Index,
			//	Parent:    netlink.MakeHandle(1, 0),
			//	Handle:    netlink.MakeHandle(1, 5),
			//	//Handle: *linuxNetworkIO.ClassID,
			//}
			//htbclassattrs2 := netlink.HtbClassAttrs{
			//	Rate:    egress,
			//	Cbuffer: uint32(egress) * 2,
			//}
			//class2 := netlink.NewHtbClass(classattrs2, htbclassattrs2)
			//if err := netlink.ClassAdd(class2); err != nil {
			//	fmt.Println("Class add error", err)
			//}

			// filter add
			// tc filter add dev lo parent 1:0 prio 0 protocol all handle 5 fw flowid 1:5
			filterattrs := netlink.FilterAttrs{
				LinkIndex: l.Attrs().Index,
				Parent:    netlink.MakeHandle(1, 0),
				Handle:    netlink.MakeHandle(1, 1),
				Priority:  49152,
				Protocol:  unix.ETH_P_IP,
			}

			filter := &netlink.GenericFilter{
				filterattrs,
				"cgroup",
			}

			if err := netlink.FilterAdd(filter); err != nil {
				fmt.Println("failed to add filter. Reason:%s", err)
			}

			// ingress
			// tc filter add dev ens3f3 parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
			// set egress for ifb
			mtu, err := getMTU(eth0)
			if err != nil {
				fmt.Println("failed to get MTU. Reason:%s", err)
			}

			ifbDeviceName := "ifb0"
			err = ns.CreateIfb(ifbDeviceName, mtu)
			if err != nil {
				fmt.Println("failed to create ifb0. Reason:%s", err)
			}

			fmt.Println("create ifb success")
			err = CreateEgressQdisc(egress, egressBurst, eth0, ifbDeviceName)
			if err != nil {
				fmt.Println("failed to create egress qdisc. Reason:%s", err)
			}

			return nil
		})
	},
}
