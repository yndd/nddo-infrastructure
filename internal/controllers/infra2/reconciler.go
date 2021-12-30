/*
Copyright 2021 NDD.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package infra2

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yndd/nddo-infrastructure/internal/infra"
	"github.com/yndd/nddo-infrastructure/internal/shared"
	nddov1 "github.com/yndd/nddo-runtime/apis/common/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/pkg/errors"
	pkgmetav1 "github.com/yndd/ndd-core/apis/pkg/meta/v1"
	"github.com/yndd/ndd-runtime/pkg/event"
	"github.com/yndd/ndd-runtime/pkg/logging"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/reconciler/managed"
	"github.com/yndd/nddo-runtime/pkg/resource"
	orgv1alpha1 "github.com/yndd/nddr-organization/apis/org/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// timers
	reconcileTimeout = 1 * time.Minute
	veryShortWait    = 1 * time.Second
	// errors
	errUnexpectedResource = "unexpected infrastructure object"
	errGetK8sResource     = "cannot get infrastructure resource"
)

// Setup adds a controller that reconciles infra.
func Setup(mgr ctrl.Manager, o controller.Options, nddcopts *shared.NddControllerOptions) error {
	name := "nddo/" + strings.ToLower(infrav1alpha1.InfrastructureGroupKind)
	iffn := func() infrav1alpha1.If { return &infrav1alpha1.Infrastructure{} }
	iflfn := func() infrav1alpha1.IfList { return &infrav1alpha1.InfrastructureList{} }
	tplfn := func() topov1alpha1.TpList { return &topov1alpha1.TopologyList{} }
	tnlfn := func() topov1alpha1.TnList { return &topov1alpha1.TopologyNodeList{} }
	tnfn := func() topov1alpha1.Tn { return &topov1alpha1.TopologyNode{} }
	tllfn := func() topov1alpha1.TlList { return &topov1alpha1.TopologyLinkList{} }
	dplfn := func() orgv1alpha1.DpList { return &orgv1alpha1.DeploymentList{} }
	dpfn := func() orgv1alpha1.Dp { return &orgv1alpha1.Deployment{} }

	speedy := make(map[string]int)

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(infrav1alpha1.InfrastructureGroupVersionKind),
		managed.WithLogger(nddcopts.Logger.WithValues("controller", name)),
		managed.WithApplication(&application{
			client: resource.ClientApplicator{
				Client:     mgr.GetClient(),
				Applicator: resource.NewAPIPatchingApplicator(mgr.GetClient()),
			},
			log:               nddcopts.Logger.WithValues("applogic", name),
			newInfra:          iffn,
			newInfraList:      iflfn,
			newTopoList:       tplfn,
			newTopoNodeList:   tnlfn,
			newTopoNode:       tnfn,
			newTopoLinkList:   tllfn,
			newDeploymentList: dplfn,
			newDeployment:     dpfn,
			infra:             nddcopts.Infra,
			speedy:            speedy,
		}),
		managed.WithSpeedy(speedy),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
	)

	topoHandler := &EnqueueRequestForAllTopologies{
		client:       mgr.GetClient(),
		log:          nddcopts.Logger,
		ctx:          context.Background(),
		speedy:       speedy,
		newInfraList: iflfn,
	}

	topoNodeHandler := &EnqueueRequestForAllTopologyNodes{
		client:       mgr.GetClient(),
		log:          nddcopts.Logger,
		ctx:          context.Background(),
		speedy:       speedy,
		newInfraList: iflfn,
	}

	topoLinkHandler := &EnqueueRequestForAllTopologyLinks{
		client:       mgr.GetClient(),
		log:          nddcopts.Logger,
		ctx:          context.Background(),
		speedy:       speedy,
		newInfraList: iflfn,
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o).
		For(&infrav1alpha1.Infrastructure{}).
		Owns(&infrav1alpha1.Infrastructure{}).
		WithEventFilter(resource.IgnoreUpdateWithoutGenerationChangePredicate()).
		Watches(&source.Kind{Type: &topov1alpha1.Topology{}}, topoHandler).
		Watches(&source.Kind{Type: &topov1alpha1.TopologyNode{}}, topoNodeHandler).
		Watches(&source.Kind{Type: &topov1alpha1.TopologyLink{}}, topoLinkHandler).
		WithEventFilter(resource.IgnoreUpdateWithoutGenerationChangePredicate()).
		Complete(r)

}

type application struct {
	client resource.ClientApplicator
	log    logging.Logger

	newInfra          func() infrav1alpha1.If
	newInfraList      func() infrav1alpha1.IfList
	newTopoList       func() topov1alpha1.TpList
	newTopoNodeList   func() topov1alpha1.TnList
	newTopoNode       func() topov1alpha1.Tn
	newTopoLinkList   func() topov1alpha1.TlList
	newDeploymentList func() orgv1alpha1.DpList
	newDeployment     func() orgv1alpha1.Dp

	infra  map[string]infra.Infra
	speedy map[string]int

	inframutex  sync.Mutex
	speedyMutex sync.Mutex
}

func getCrName(cr infrav1alpha1.If) string {
	return strings.Join([]string{cr.GetNamespace(), cr.GetName()}, ".")
}

func (r *application) Initialize(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}

	/*
		cr := r.newInfra()
		if err := r.client.Get(ctx, types.NamespacedName{
			Namespace: o.GetNamespace(),
			Name:      o.GetName(),
		}, cr); err != nil {
			// There's no need to requeue if we no longer exist. Otherwise we'll be
			// requeued implicitly because we return an error.
			r.log.Debug("Cannot get managed resource", "error", err)
			return errors.Wrap(resource.IgnoreNotFound(err), errGetK8sResource)
		}
	*/

	if err := cr.InitializeResource(); err != nil {
		r.log.Debug("Cannot initialize", "error", err)
		return err
	}

	return nil
}

func (r *application) Update(ctx context.Context, mg resource.Managed) (map[string]string, error) {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return nil, errors.New(errUnexpectedResource)
	}

	return r.handleAppLogic(ctx, cr)
}

func (r *application) FinalUpdate(ctx context.Context, mg resource.Managed) {
	cr, _ := mg.(*infrav1alpha1.Infrastructure)
	crName := getCrName(cr)
	r.infra[crName].PrintNodes(crName)
}

func (r *application) Timeout(ctx context.Context, mg resource.Managed) time.Duration {
	cr, _ := mg.(*infrav1alpha1.Infrastructure)
	crName := getCrName(cr)
	r.speedyMutex.Lock()
	speedy := r.speedy[crName]
	r.speedyMutex.Unlock()
	if speedy <= 5 {
		r.log.Debug("Speedy", "number", speedy)
		speedy++
		return veryShortWait
	}
	return reconcileTimeout
}

func (r *application) Delete(ctx context.Context, mg resource.Managed) (bool, error) {
	return true, nil
}

func (r *application) FinalDelete(ctx context.Context, mg resource.Managed) {
	cr, _ := mg.(*infrav1alpha1.Infrastructure)
	crName := getCrName(cr)
	r.inframutex.Lock()
	delete(r.infra, crName)
	r.inframutex.Unlock()
	r.speedyMutex.Lock()
	delete(r.speedy, crName)
	r.speedyMutex.Unlock()
}

func (r *application) handleAppLogic(ctx context.Context, cr infrav1alpha1.If) (map[string]string, error) {
	log := r.log.WithValues("function", "handleAppLogic", "crname", cr.GetName())
	log.Debug("handleAppLogic")

	crName := getCrName(cr)
	deploymentName := strings.Join([]string{cr.GetOrganizationName(), cr.GetDeploymentName()}, ".")
	niName := cr.GetNetworkInstanceName()

	r.inframutex.Lock()
	if _, ok := r.infra[crName]; !ok {
		r.infra[crName] = infra.NewInfra()
	}
	r.inframutex.Unlock()

	register, err := r.getRegister(ctx, cr, deploymentName)
	if err != nil {
		return nil, err
	}

	grpcserverKeys := map[string]string{
		"ipam":   "nddr-ipam",
		"aspool": "nddr-aspool",
	}
	grpcServers, err := r.getGrpcServers(ctx, grpcserverKeys)
	if err != nil {
		return nil, err
	}

	ipamClient, err := getResourceClient(ctx, grpcServers["ipam"])
	if err != nil {
		return nil, err
	}

	aspoolClient, err := getResourceClient(ctx, grpcServers["aspool"])
	if err != nil {
		return nil, err
	}

	for grpcServer, grpcServerDnsName := range grpcServers {
		log.Debug("grpc server", "grpcServer", grpcServer, "grpcServerDnsName", grpcServerDnsName)
	}
	// get all link crs
	topolinks := r.newTopoLinkList()
	if err := r.client.List(ctx, topolinks); err != nil {
		return nil, err
	}

	// get the links fromm the backend logic
	r.inframutex.Lock()
	links := r.infra[crName].GetLinks()
	r.inframutex.Unlock()

	// keep track of the active epg links, for validation/garbage collection later on
	activeLinks := make([]topov1alpha1.Tl, 0)
	// keep track of the links that are not ready, it is used in the reconciler to speed up
	// the reconciliations during changes
	notReadyLinks := make(map[string]string)
	for _, link := range topolinks.GetLinks() {
		// only process topology links that are part of the deployment
		if strings.Contains(link.GetName(), deploymentName) {
			// only process links with infra tag and non lag-members
			if link.GetKind() == topov1alpha1.LinkEPKindInfra.String() {
				linkName := link.GetName()
				// if resource is not reconciled we dont process
				if link.GetCondition(topov1alpha1.ConditionKindReady).Status == corev1.ConditionTrue {
					// keep track of the active epg links, for validation/garbage collection later on
					activeLinks = append(activeLinks, link)

					if _, ok := links[linkName]; !ok {
						links[linkName] = infra.NewLink(linkName,
							infra.WithLinkK8sClient(r.client),
							infra.WithLinkIpamClient(ipamClient),
							infra.WithLinkAsPoolClient(aspoolClient),
							infra.WithLinkLogger(r.log),
						)
					}
					l := links[linkName]

					// validate node information
					for i := 0; i <= 1; i++ {
						ip := getLinkParameters(i, niName, link, register, ipamClient, aspoolClient)
						l.SetNodeName(i, ip.nodeName)
						l.SetInterfaceName(i, ip.itfceName)

						if err := r.createNode(ctx, cr, crName, ip); err != nil {
							return nil, err
						}
						//r.validateNode(ctx, cr, crname, ip)
					}

					if link.GetLagMember() {
						// lag link members dont require ip(s, etc they are part of a lag on which the ip addresses are configured/allocated
						for i := 0; i <= 1; i++ {
							ip := getLinkParameters(i, niName, link, register, ipamClient, aspoolClient)

							itfce := r.createInterface(crName, ip)
							// create interface in adaptor
							if err := itfce.CreateNddaInterface(ctx, cr); err != nil {
								return nil, err
							}
						}
					} else {
						ips := make(map[string][]string)
						for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
							ipamOptions := &infra.IpamOptions{
								IpamName:            register[nddov1.RegisterKindIpam.String()],
								NetworkInstanceName: niName,
								AddressFamily:       af,
							}

							linkPrefix, err := l.GrpcAllocateLinkIP(ctx, cr, link, ipamOptions)
							if err != nil {
								return nil, err
							}
							l.SetPrefix(af, *linkPrefix)
							log.Debug("Link Prefix Allocated", "Link Name", linkName, "Prefix", *linkPrefix)

							ips[af], err = parseIpPerEndPoint(*linkPrefix)
							if err != nil {
								return nil, err
							}
						}
						subinterfaces := make([]infra.SubInterface, 2)
						for i := 0; i <= 1; i++ {
							ip := getLinkParameters(i, niName, link, register, ipamClient, aspoolClient)

							//r.log.Debug("handleAppLogic2", "idx", i, "nodeName", ip.nodeName)
							l.SetNodeName(i, ip.nodeName)
							l.SetInterfaceName(i, ip.itfceName)

							for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
								ipamOptions := &infra.IpamOptions{
									IpamName:            ip.ipamName,
									NetworkInstanceName: ip.niName,
									AddressFamily:       af,
									IpPrefix:            ips[af][i],
									EpIndex:             i,
								}

								epPrefix, err := l.GrpcAllocateEndpointIP(ctx, cr, link, ipamOptions)
								if err != nil {
									return nil, err
								}
								lPrefix := l.GetPrefix(af)

								prefix, err := parseEndpointPrefix(lPrefix, *epPrefix)
								if err != nil {
									return nil, err
								}
								var itfce infra.Interface
								//var ni infra.Ni
								_, itfce, subinterfaces[i] = r.createInterfaceSubInterface(crName, ip, prefix, af)
								if err := itfce.CreateNddaInterface(ctx, cr); err != nil {
									return nil, err
								}
								if err := subinterfaces[i].CreateNddaSubInterface(ctx, cr); err != nil {
									return nil, err
								}

								//	if err := ni.CreateNiRegister(ctx, cr, ip.niName); err != nil {
								//		return nil, err
								//	}

							}
						}
						// cross reference the subinterfaces
						subinterfaces[0].SetNeighbor(subinterfaces[1])
						subinterfaces[1].SetNeighbor(subinterfaces[0])
					}

				} else {
					notReadyLinks[linkName] = ""
				}
			}
		}
	}

	//log.Debug("Active Links", "activeLinks", activeLinks)
	// if creates or deletes of toponodes/topolinks happen we need to cleanup the backend and all child
	// resources
	if err := r.validateBackend(ctx, cr, crName, activeLinks); err != nil {
		return nil, err
	}

	// create the network instance, since we have up to date info it is better to
	// wait for NI creation at this stage
	nodes := r.infra[crName].GetNodes()

	for nodeName, n := range nodes {
		log.Debug("create node networkinstance2", "node", nodeName)
		for niName, ni := range n.GetNis() {
			log.Debug("create node networkinstance2", "niName", niName, "nodeName", nodeName)
			if err := ni.CreateNddaNi(ctx, cr); err != nil {
				//log.Debug("CreateNddaNi", "Error", err)
				return nil, err
			}
			log.Debug("create node networkinstance3", "niName", ni.GetName(), "nodeName", ni.GetNode().GetName())
			if err := ni.CreateNiRegister(ctx, cr, niName); err != nil {
				return nil, err
			}
		}
	}

	cr.SetOrganizationName(cr.GetOrganizationName())
	cr.SetDeploymentName(cr.GetDeploymentName())
	cr.SetNetworkInstanceName(cr.GetNetworkInstanceName())

	return notReadyLinks, nil
}

func (r *application) createInterfaceSubInterface(crname string, ip *interfaceParameters, prefix, af string) (infra.Ni, infra.Interface, infra.SubInterface) {
	r.inframutex.Lock()
	n := r.infra[crname].GetNodes()[ip.nodeName]
	r.inframutex.Unlock()
	if _, ok := n.GetInterfaces()[ip.itfceName]; !ok {
		n.GetInterfaces()[ip.itfceName] = infra.NewInterface(n, ip.itfceName,
			infra.WithInterfaceK8sClient(r.client),
			infra.WithInterfaceIpamClient(ip.ipamClient),
			infra.WithInterfaceAsPoolClient(ip.aspoolClient),
			infra.WithInterfaceLogger(r.log))
	}

	itfce := n.GetInterfaces()[ip.itfceName]
	itfce.SetKind(ip.kind)
	if ip.lag {
		itfce.SetLag()
	}

	if _, ok := itfce.GetSubInterfaces()[ip.niIndex]; !ok {
		itfce.GetSubInterfaces()[ip.niIndex] = infra.NewSubInterface(itfce, ip.niIndex,
			infra.WithSubInterfaceK8sClient(r.client),
			infra.WithSubInterfaceIpamClient(ip.ipamClient),
			infra.WithSubInterfaceAsPoolClient(ip.aspoolClient),
			infra.WithSubInterfaceLogger(r.log))

	}
	subitfce := itfce.GetSubInterfaces()[ip.niIndex]
	subitfce.SetKind(infra.SubInterfaceKindRouted)
	subitfce.SetTaggingKind(infra.TaggingKindUnTagged)

	if _, ok := subitfce.GetAddressesInfo(af)[prefix]; !ok {
		subitfce.GetAddressesInfo(af)[prefix] = infra.NewAddressInfo()
	}

	if _, ok := n.GetNis()[ip.niName]; !ok {
		n.GetNis()[ip.niName] = infra.NewNi(n, ip.niName,
			infra.WithNiK8sClient(r.client),
			infra.WithNiIpamClient(ip.ipamClient),
			infra.WithNiAsPoolClient(ip.aspoolClient),
			infra.WithNiLogger(r.log))
	}
	ni := n.GetNis()[ip.niName]
	ni.GetSubInterfaces()[strings.Join([]string{ip.itfceName, ip.niIndex}, ".")] = subitfce
	ni.SetKind(ip.niKind)

	return ni, itfce, subitfce
}

func (r *application) createInterface(crname string, ip *interfaceParameters) infra.Interface {
	r.inframutex.Lock()
	n := r.infra[crname].GetNodes()[ip.nodeName]
	r.inframutex.Unlock()
	if _, ok := n.GetInterfaces()[ip.nodeName]; !ok {
		n.GetInterfaces()[ip.itfceName] = infra.NewInterface(n, ip.itfceName,
			infra.WithInterfaceK8sClient(r.client),
			infra.WithInterfaceIpamClient(ip.ipamClient),
			infra.WithInterfaceAsPoolClient(ip.aspoolClient),
			infra.WithInterfaceLogger(r.log))
	}

	itfce := n.GetInterfaces()[ip.itfceName]
	itfce.SetKind(ip.kind)
	if ip.lag {
		itfce.SetLag()
	}
	if ip.lagMember {
		itfce.SetLagMember()
	}
	if ip.lacp {
		itfce.SetLacp()
	}
	if ip.lacpFallback {
		itfce.SetLacpFallback()
	}
	return itfce
}

func (r *application) createNode(ctx context.Context, cr infrav1alpha1.If, crname string, ip *interfaceParameters) error {
	// get node from k8s api to retrieve node parameters like index for aspool
	nodeName := strings.Join([]string{cr.GetOrganizationName(), cr.GetDeploymentName(), ip.topologyName, ip.nodeName}, ".")
	node := r.newTopoNode()
	if err := r.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(),
		Name:      nodeName,
	}, node); err != nil {
		// There's no need to requeue if we no longer exist. Otherwise we'll be
		// requeued implicitly because we return an error.
		//log.Debug("Cannot get managed resource", "error", err)
		return err
	}

	r.inframutex.Lock()
	nodes := r.infra[crname].GetNodes()
	r.inframutex.Unlock()
	if _, ok := nodes[ip.nodeName]; !ok {
		nodes[ip.nodeName] = infra.NewNode(ip.nodeName,
			infra.WithNodeK8sClient(r.client),
			infra.WithNodeIpamClient(ip.ipamClient),
			infra.WithNodeAsPoolClient(ip.aspoolClient),
			infra.WithNodeLogger(r.log))
	}
	n := nodes[ip.nodeName]

	n.SetIndex(node.GetNodeIndex())
	n.SetKind(node.GetKindName())
	n.SetPlatform(node.GetPlatform())

	// Allocate AS per node if the underlay protocol is ebgp
	for _, protocol := range cr.GetUnderlayProtocol() {
		if protocol == string(infrav1alpha1.ProtocolEBGP) {

			as, err := n.GrpcAllocateAS(ctx, cr, node, ip.asPoolName)
			if err != nil {
				return err
			}
			n.SetAS(*as)
		}
	}

	for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
		ipamOptions := &infra.IpamOptions{
			IpamName:            ip.ipamName,
			NetworkInstanceName: ip.niName,
			AddressFamily:       af,
		}
		lpPrefix, err := n.GrpcAllocateLoopback(ctx, cr, node, ipamOptions)
		if err != nil {
			return err
		}

		ip.itfceName = "system"
		ip.kind = infra.InterfaceKindSystem

		_, itfce, si := r.createInterfaceSubInterface(crname, ip, *lpPrefix, af)
		if err := itfce.CreateNddaInterface(ctx, cr); err != nil {
			return err
		}
		if err := si.CreateNddaSubInterface(ctx, cr); err != nil {
			return err
		}
		//if err := ni.CreateNiRegister(ctx, cr, ip.niName); err != nil {
		//	return err
		//}
	}

	var itfce infra.Interface
	ip.itfceName = "irb"
	ip.kind = infra.InterfaceKindIrb
	ip.lag = false
	ip.lagMember = false
	ip.lacpFallback = false
	ip.lacp = false

	itfce = r.createInterface(crname, ip)
	if err := itfce.CreateNddaInterface(ctx, cr); err != nil {
		return err
	}

	ip.itfceName = "vxlan"
	ip.kind = infra.InterfaceKindVxlan

	itfce = r.createInterface(crname, ip)
	if err := itfce.CreateNddaInterface(ctx, cr); err != nil {
		return err
	}

	return nil
}

func (r *application) validateBackend(ctx context.Context, cr infrav1alpha1.If, crname string, activeLinks []topov1alpha1.Tl) error {
	// update the backend based on the active links processed
	// validate the existing backend and update the information
	activeNodes := make(map[string]bool)
	r.inframutex.Lock()
	links := r.infra[crname].GetLinks()
	nodes := r.infra[crname].GetNodes()
	r.inframutex.Unlock()
	for linkName, link := range links {
		found := false
		for _, activeLink := range activeLinks {
			if linkName == activeLink.GetName() {
				activeNodes[link.GetNodeName(0)] = true
				activeNodes[link.GetNodeName(1)] = true
				found = true
				break
			}
		}
		// not found -> delete from backend if it exists
		if !found {
			// delete interface from node
			for idx, nodeName := range link.GetNodeNames() {
				if node, ok := nodes[nodeName]; ok {

					// delete interface and subinterfaces in adaptor layer
					if itfce, ok := nodes[nodeName].GetInterfaces()[link.GetInterfaceName(idx)]; ok {
						// delete subinterfaces in adaptor
						for _, si := range itfce.GetSubInterfaces() {
							if err := si.DeleteNddaSubInterface(ctx, cr); err != nil {
								return err
							}
						}
						// delete interfaces in adaptor
						if err := itfce.DeleteNddaInterface(ctx, cr); err != nil {
							return err
						}
						// TODO delete subinterface in NI
					}
					delete(node.GetInterfaces(), link.GetInterfaceNames()[idx])
				}
			}

		}
	}
	r.log.Debug("Active Nodes", "activeNodes", activeNodes)
	for nodeName := range nodes {
		found := false
		for activeNodeName := range activeNodes {
			if nodeName == activeNodeName {
				found = true
				break
			}
		}
		if !found {
			r.log.Debug("validateBackend", "Node not found", nodeName)
			// delete interface in adaptor layer
			for _, itfce := range nodes[nodeName].GetInterfaces() {
				if err := itfce.DeleteNddaInterface(ctx, cr); err != nil {
					return err
				}
			}
			// delete ni in adaptor layer
			for _, ni := range nodes[nodeName].GetNis() {
				if err := ni.DeleteNddaNi(ctx, cr); err != nil {
					return err
				}
			}

			// delete ni in ni register
			for niName, ni := range nodes[nodeName].GetNis() {
				if err := ni.DeleteNiRegister(ctx, cr, niName); err != nil {
					return err
				}
			}
			// delete node from backend
			delete(nodes, nodeName)
		}
	}
	return nil
}

func (r *application) getRegister(ctx context.Context, cr infrav1alpha1.If, deploymentName string) (map[string]string, error) {
	dep := r.newDeployment()
	if err := r.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(),
		Name:      deploymentName,
	}, dep); err != nil {
		return nil, err
	}

	if _, ok := dep.GetStateRegister()[string(nddov1.RegisterKindIpam)]; !ok {
		return nil, errors.New("ipam not registered")
	}
	if _, ok := dep.GetStateRegister()[string(nddov1.RegisterKindAs)]; !ok {
		return nil, errors.New("as pool not registered")
	}

	return dep.GetStateRegister(), nil
}

func (r *application) getGrpcServers(ctx context.Context, grpcserverKeys map[string]string) (map[string]string, error) {
	pods := &corev1.PodList{}
	opts := []client.ListOption{
		client.InNamespace("ndd-system"),
	}
	if err := r.client.List(ctx, pods, opts...); err != nil {
		return nil, err
	}

	grpcserver := make(map[string]string)
	for key, keyMatch := range grpcserverKeys {
		found := false
		for _, pod := range pods.Items {
			podName := pod.GetName()
			//r.log.Debug("pod", "podname", podName)
			if strings.Contains(podName, keyMatch) {
				grpcserver[key] = getGrpcServerName(podName)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.Errorf("no grpcserver pod that matches %s, %s", key, keyMatch)
		}
	}
	return grpcserver, nil
}

func getGrpcServerName(podName string) string {
	var newName string
	for i, s := range strings.Split(podName, "-") {
		if i == 0 {
			newName = s
		} else if i <= (len(strings.Split(podName, "-")) - 3) {
			newName += "-" + s
		}
	}
	return pkgmetav1.PrefixGnmiService + "-" + newName + "." + pkgmetav1.NamespaceLocalK8sDNS + strconv.Itoa((pkgmetav1.GnmiServerPort))
}
