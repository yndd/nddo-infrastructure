package networkhandler

import (
	"context"
	"strings"
	"sync"

	"github.com/yndd/ndd-runtime/pkg/logging"
	networkschema "github.com/yndd/ndda-network/pkg/networkschema/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/resource"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

/*
const (
	// errors
	errUnexpectedResource = "unexpected infrastructure object"
)
*/

func New(opts ...Option) Handler {
	tnfn := func() topov1alpha1.Tn { return &topov1alpha1.TopologyNode{} }
	s := &handler{
		schema:      make(map[string]networkschema.Schema),
		newTopoNode: tnfn,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (r *handler) WithLogger(log logging.Logger) {
	r.log = log
}

func (r *handler) WithClient(c client.Client) {
	r.client = resource.ClientApplicator{
		Client:     c,
		Applicator: resource.NewAPIPatchingApplicator(c),
	}
}

type handler struct {
	log logging.Logger
	// kubernetes
	client resource.ClientApplicator

	newTopoNode func() topov1alpha1.Tn

	mutex  sync.Mutex
	schema map[string]networkschema.Schema
}

func (r *handler) InitSchema(crName string) networkschema.Schema {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if _, ok := r.schema[crName]; !ok {
		r.schema[crName] = networkschema.NewSchema(r.client)
	}
	return r.schema[crName]
}

func (r *handler) DestroySchema(crName string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	delete(r.schema, crName)
}

func (r *handler) DeploySchema(ctx context.Context, mg resource.Managed, labels map[string]string) error {
	crName := getCrName(mg)
	s := r.InitSchema(crName)

	if err := s.DeploySchema(ctx, mg, labels); err != nil {
		return err
	}
	return nil
}

func (r *handler) ValidateSchema(ctx context.Context, mg resource.Managed) error {
	ds := r.InitSchema("dummy")
	ds.InitializeDummySchema()
	resources, err := ds.ListResources(ctx, mg)
	if err != nil {
		return err
	}
	for kind, res := range resources {
		for resName := range res {
			r.log.Debug("active resources", "kind", kind, "resource name", resName)
		}
	}

	crName := getCrName(mg)
	s := r.InitSchema(crName)
	validatedResources, err := s.ValidateResources(ctx, mg, resources)
	if err != nil {
		return err
	}
	for kind, res := range validatedResources {
		for resName := range res {
			r.log.Debug("validated resources", "kind", kind, "resource name", resName)
		}
	}

	if len(validatedResources) > 0 {
		r.log.Debug("resources to be deleted", "resources", validatedResources)
		if err := ds.DeleteResources(ctx, mg, resources); err != nil {
			return err
		}
	}

	return nil
}

func (r *handler) PrintDevices(crName string) {
	s := r.InitSchema(crName)
	s.PrintDevices(crName)
}

func getCrName(mg resource.Managed) string {
	return strings.Join([]string{mg.GetNamespace(), mg.GetName()}, ".")
}

/*
func (r *handler) PopulateNode(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}

	crName := getCrName(mg)
	s := r.InitSchema(crName)

	for idx := 0; idx <= 1; idx++ {
		deviceName, _ := getDeviceItfce(idx, link)

		node := r.newTopoNode()
		if err := r.client.Get(ctx, types.NamespacedName{
			Namespace: mg.GetNamespace(),
			Name:      strings.Join([]string{odns.GetParentResourceName(link.GetName()), deviceName}, "."),
		}, node); err != nil {
			// There's no need to requeue if we no longer exist. Otherwise we'll be
			// requeued implicitly because we return an error.
			//log.Debug("Cannot get managed resource", "error", err)
			return err
		}

		d := s.NewDevice(r.client, deviceName)

		index := node.GetNodeIndex()

		// Allocate AS per node if the underlay protocol is ebgp

		//	for _, protocol := range cr.GetUnderlayProtocol() {
		//		if protocol == string(infrav1alpha1.ProtocolEBGP) {
		//			// TODO Allocate AS
		//			as := 65000 + index
		//		}
		//	}


		ipv4 := make([]*networkv1alpha1.InterfaceSubinterfaceIpv4, 0)
		ipv6 := make([]*networkv1alpha1.InterfaceSubinterfaceIpv6, 0)
		for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
			switch af {
			case string(ipamv1alpha1.AddressFamilyIpv4):
				prefixLength := 32
				ipAddress := "1.1.1." + strconv.Itoa(int(index))
				ipPrefix := ipAddress + "/" + strconv.Itoa(prefixLength)
				ipCidr := ipAddress + "/" + strconv.Itoa(prefixLength)

				ipv4 = append(ipv4, &networkv1alpha1.InterfaceSubinterfaceIpv4{
					IpPrefix: utils.StringPtr(ipPrefix),
					Config: &networkv1alpha1.InterfaceSubinterfaceIpv4Config{
						IpAddress:    utils.StringPtr(ipAddress),
						IpPrefix:     utils.StringPtr(ipPrefix),
						IpCidr:       utils.StringPtr(ipCidr),
						PrefixLength: utils.Uint32Ptr(uint32(prefixLength)),
					},
				})
			case string(ipamv1alpha1.AddressFamilyIpv6):
				prefixLength := 128
				ipAddress := "1000::" + strconv.Itoa(int(index))
				ipPrefix := ipAddress + "/" + strconv.Itoa(prefixLength)
				ipCidr := ipAddress + "/" + strconv.Itoa(prefixLength)

				ipv6 = append(ipv6, &networkv1alpha1.InterfaceSubinterfaceIpv6{
					IpPrefix: utils.StringPtr(ipPrefix),
					Config: &networkv1alpha1.InterfaceSubinterfaceIpv6Config{
						IpAddress:    utils.StringPtr(ipAddress),
						IpPrefix:     utils.StringPtr(ipPrefix),
						IpCidr:       utils.StringPtr(ipCidr),
						PrefixLength: utils.Uint32Ptr(uint32(prefixLength)),
					},
				})
			}
		}
		i := r.createInterface(d, "system", networkv1alpha1.E_InterfaceKind_LOOPBACK)

		siIndex := 0
		si := i.NewInterfaceSubinterface(r.client, strconv.Itoa(siIndex))
		si.Update(&networkv1alpha1.InterfaceSubinterface{
			Index: utils.StringPtr(strconv.Itoa(siIndex)),
			Config: &networkv1alpha1.InterfaceSubinterfaceConfig{
				Index:       utils.Uint32Ptr(uint32(siIndex)),
				InnerVlanId: utils.Uint16Ptr(uint16(siIndex)),
				OuterVlanId: utils.Uint16Ptr(uint16(siIndex)),
				Kind:        networkv1alpha1.E_InterfaceSubinterfaceKind_ROUTED,
			},
			Ipv4: ipv4,
			Ipv6: ipv6,
		})

		r.createInterface(d, "irb", networkv1alpha1.E_InterfaceKind_IRB)
		r.createInterface(d, "vxlan", networkv1alpha1.E_InterfaceKind_VXLAN)
	}
	return nil
}

func (r *handler) createInterface(d networkschema.Device, itfceName string, kind networkv1alpha1.E_InterfaceKind) networkschema.Interface {
	i := d.NewInterface(r.client, itfceName)
	i.Update(&networkv1alpha1.Interface{
		Name: utils.StringPtr(itfceName),
		Config: &networkv1alpha1.InterfaceConfig{
			Kind:         kind,
			Lacp:         utils.BoolPtr(false),
			LacpFallback: utils.BoolPtr(false),
			LagMember:    utils.BoolPtr(false),
			Lag:          utils.BoolPtr(false),
			LagName:      utils.StringPtr(""),
		},
	})
	return i
}

func (r *handler) PopulateLagMember(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	crName := getCrName(mg)
	s := r.InitSchema(crName)

	for idx := 0; idx <= 1; idx++ {

		deviceName, itfceName := getDeviceItfce(idx, link)
		lacpFallBack, lagName := getLagInfo(idx, link)

		d := s.NewDevice(r.client, deviceName)

		i := d.NewInterface(r.client, itfceName)

		i.Update(&networkv1alpha1.Interface{
			Name: &itfceName,
			Config: &networkv1alpha1.InterfaceConfig{
				Kind:         networkv1alpha1.E_InterfaceKind_INTERFACE,
				Lacp:         utils.BoolPtr(link.GetLacp()),
				LacpFallback: utils.BoolPtr(lacpFallBack),
				LagMember:    utils.BoolPtr(link.GetLagMember()),
				Lag:          utils.BoolPtr(link.GetLag()),
				LagName:      utils.StringPtr(lagName),
			},
		})
	}
	return nil
}

func (r *handler) PopulateIpLink(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}
	crName := getCrName(mg)
	s := r.InitSchema(crName)

	for idx := 0; idx <= 1; idx++ {
		deviceName, itfceName := getDeviceItfce(idx, link)

		d := s.NewDevice(r.client, deviceName)

		i := d.NewInterface(r.client, itfceName)

		i.Update(&networkv1alpha1.Interface{
			Name: &itfceName,
			Config: &networkv1alpha1.InterfaceConfig{
				Kind:         networkv1alpha1.E_InterfaceKind_INTERFACE,
				Lacp:         utils.BoolPtr(false),
				LacpFallback: utils.BoolPtr(false),
				LagMember:    utils.BoolPtr(false),
				Lag:          utils.BoolPtr(link.GetLag()),
				//LagName:      utils.StringPtr(lagName),
			},
		})

		ipv4 := make([]*networkv1alpha1.InterfaceSubinterfaceIpv4, 0)
		ipv6 := make([]*networkv1alpha1.InterfaceSubinterfaceIpv6, 0)
		for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
			switch af {
			case string(ipamv1alpha1.AddressFamilyIpv4):
				prefixLength := 31
				ipAddress := "10.0.0." + strconv.Itoa(int(idx))
				ipPrefix := ipAddress + "/" + strconv.Itoa(prefixLength)
				ipCidr := ipAddress + "/" + strconv.Itoa(prefixLength)

				ipv4 = append(ipv4, &networkv1alpha1.InterfaceSubinterfaceIpv4{
					IpPrefix: utils.StringPtr(ipPrefix),
					Config: &networkv1alpha1.InterfaceSubinterfaceIpv4Config{
						IpAddress:    utils.StringPtr(ipAddress),
						IpPrefix:     utils.StringPtr(ipPrefix),
						IpCidr:       utils.StringPtr(ipCidr),
						PrefixLength: utils.Uint32Ptr(uint32(prefixLength)),
					},
				})
			case string(ipamv1alpha1.AddressFamilyIpv6):
				prefixLength := 127
				ipAddress := "2000::" + strconv.Itoa(int(idx))
				ipPrefix := ipAddress + "/" + strconv.Itoa(prefixLength)
				ipCidr := ipAddress + "/" + strconv.Itoa(prefixLength)

				ipv6 = append(ipv6, &networkv1alpha1.InterfaceSubinterfaceIpv6{
					IpPrefix: utils.StringPtr(ipPrefix),
					Config: &networkv1alpha1.InterfaceSubinterfaceIpv6Config{
						IpAddress:    utils.StringPtr(ipAddress),
						IpPrefix:     utils.StringPtr(ipPrefix),
						IpCidr:       utils.StringPtr(ipCidr),
						PrefixLength: utils.Uint32Ptr(uint32(prefixLength)),
					},
				})
			}
		}

		siIndex := 0
		si := i.NewInterfaceSubinterface(r.client, strconv.Itoa(siIndex))
		si.Update(&networkv1alpha1.InterfaceSubinterface{
			Index: utils.StringPtr(strconv.Itoa(siIndex)),
			Config: &networkv1alpha1.InterfaceSubinterfaceConfig{
				Index:       utils.Uint32Ptr(uint32(siIndex)),
				InnerVlanId: utils.Uint16Ptr(uint16(siIndex)),
				OuterVlanId: utils.Uint16Ptr(uint16(siIndex)),
				Kind:        networkv1alpha1.E_InterfaceSubinterfaceKind_ROUTED,
			},
			Ipv4: ipv4,
			Ipv6: ipv6,
		})

		niIndex := 333
		niName := cr.GetNetworkInstanceName()
		ni := d.NewNetworkInstance(r.client, niName)

		ni.Update(&networkv1alpha1.NetworkInstance{
			Name: utils.StringPtr(niName),
			Config: &networkv1alpha1.NetworkInstanceConfig{
				Name:  utils.StringPtr(niName),
				Index: utils.Uint32Ptr(uint32(niIndex)),
				Kind:  networkv1alpha1.E_NetworkInstanceKind_ROUTED,
			},
		})

		ni.AddNetworkInstanceInterface(&networkv1alpha1.NetworkInstanceConfigInterface{
			Name: utils.StringPtr(itfceName + "." + strconv.Itoa(siIndex)),
		})
	}

	return nil
}

func getLagInfo(i int, link topov1alpha1.Tl) (bool, string) {
	var lacpFallback bool
	var lagName string
	switch i {
	case 0:
		lacpFallback = link.GetLacpFallbackA()
		lagName = link.GetLagAName()
	case 1:
		lacpFallback = link.GetLacpFallbackB()
		lagName = link.GetLagBName()
	}
	return lacpFallback, lagName
}

func getDeviceItfce(i int, link topov1alpha1.Tl) (string, string) {
	var deviceName, itfceName string
	switch i {
	case 0:
		deviceName = link.GetEndpointANodeName()
		itfceName = link.GetEndpointAInterfaceName()
	case 1:
		deviceName = link.GetEndpointBNodeName()
		itfceName = link.GetEndpointBInterfaceName()
	}
	return deviceName, itfceName
}

func getAddressFamilies(addressigSchem string) []string {
	var afs []string
	switch addressigSchem {
	case string(infrav1alpha1.AddressingSchemeDualStack):
		afs = []string{string(ipamv1alpha1.AddressFamilyIpv4), string(ipamv1alpha1.AddressFamilyIpv6)}
	case string(infrav1alpha1.AddressingSchemeIpv4Only):
		afs = []string{string(ipamv1alpha1.AddressFamilyIpv4)}
	case string(infrav1alpha1.AddressingSchemeIpv6Only):
		afs = []string{string(ipamv1alpha1.AddressFamilyIpv6)}
	}
	return afs
}

// GetLastIP returns subnet's last IP
func GetLastIP(subnet *net.IPNet) (net.IP, error) {
	size := RangeSize(subnet)
	if size <= 0 {
		return nil, fmt.Errorf("can't get range size of subnet. subnet: %q", subnet)
	}
	return GetIndexedIP(subnet, int(size-1))
}

// GetFirstIP returns subnet's last IP
func GetFirstIP(subnet *net.IPNet) (net.IP, error) {
	return GetIndexedIP(subnet, 1)
}

// RangeSize returns the size of a range in valid addresses.
func RangeSize(subnet *net.IPNet) int64 {
	ones, bits := subnet.Mask.Size()
	if bits == 32 && (bits-ones) >= 31 || bits == 128 && (bits-ones) >= 127 {
		return 0
	}
	// For IPv6, the max size will be limited to 65536
	// This is due to the allocator keeping track of all the
	// allocated IP's in a bitmap. This will keep the size of
	// the bitmap to 64k.
	if bits == 128 && (bits-ones) >= 16 {
		return int64(1) << uint(16)
	}
	return int64(1) << uint(bits-ones)
}

// GetIndexedIP returns a net.IP that is subnet.IP + index in the contiguous IP space.
func GetIndexedIP(subnet *net.IPNet, index int) (net.IP, error) {
	ip := addIPOffset(bigForIP(subnet.IP), index)
	if !subnet.Contains(ip) {
		return nil, fmt.Errorf("can't generate IP with index %d from subnet. subnet too small. subnet: %q", index, subnet)
	}
	return ip, nil
}

// addIPOffset adds the provided integer offset to a base big.Int representing a
// net.IP
func addIPOffset(base *big.Int, offset int) net.IP {
	return net.IP(big.NewInt(0).Add(base, big.NewInt(int64(offset))).Bytes())
}

// bigForIP creates a big.Int based on the provided net.IP
func bigForIP(ip net.IP) *big.Int {
	b := ip.To4()
	if b == nil {
		b = ip.To16()
	}
	return big.NewInt(0).SetBytes(b)
}
*/
