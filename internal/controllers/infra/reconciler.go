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

package infra

/*
import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	nddv1 "github.com/yndd/ndd-runtime/apis/common/v1"
	"github.com/yndd/ndd-runtime/pkg/event"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/meta"
	"github.com/yndd/nddo-runtime/pkg/resource"
	"github.com/yndd/nddr-org-registry/pkg/registry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	pkgmetav1 "github.com/yndd/ndd-core/apis/pkg/meta/v1"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-infrastructure/internal/infra"
	"github.com/yndd/nddo-infrastructure/internal/shared"
	orgv1alpha1 "github.com/yndd/nddr-org-registry/apis/org/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	finalizerName = "finalizer.infrastructure.infra.nddo.yndd.io"
	//
	reconcileTimeout = 1 * time.Minute
	longWait         = 1 * time.Minute
	mediumWait       = 30 * time.Second
	shortWait        = 5 * time.Second
	veryShortWait    = 1 * time.Second

	// Errors
	errGetK8sResource = "cannot get infra resource"
	errUpdateStatus   = "cannot update status of infra resource"
	errCreate         = "cannot create resource"
	errValidate       = "cannot validate resource"

	// events
	reasonReconcileSuccess      event.Reason = "ReconcileSuccess"
	reasonCannotDelete          event.Reason = "CannotDeleteResource"
	reasonCannotAddFInalizer    event.Reason = "CannotAddFinalizer"
	reasonCannotDeleteFInalizer event.Reason = "CannotDeleteFinalizer"
	reasonCannotInitialize      event.Reason = "CannotInitializeResource"
	reasonCannotGetAllocations  event.Reason = "CannotGetAllocations"
	reasonAppLogicFailed        event.Reason = "ApplogicFailed"
)

// ReconcilerOption is used to configure the Reconciler.
type ReconcilerOption func(*Reconciler)

// Reconciler reconciles packages.
type Reconciler struct {
	client  resource.ClientApplicator
	log     logging.Logger
	record  event.Recorder
	managed mrManaged

	newInfra          func() infrav1alpha1.If
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

type mrManaged struct {
	resource.Finalizer
}

// WithLogger specifies how the Reconciler should log messages.
func WithLogger(log logging.Logger) ReconcilerOption {
	return func(r *Reconciler) {
		r.log = log
	}
}

func WithNewReourceFn(f func() infrav1alpha1.If) ReconcilerOption {
	return func(r *Reconciler) {
		r.newInfra = f
	}
}

func WithNewTopoListFn(f func() topov1alpha1.TpList) ReconcilerOption {
	return func(r *Reconciler) {
		r.newTopoList = f
	}
}

func WithNewTopoNodeListFn(f func() topov1alpha1.TnList) ReconcilerOption {
	return func(r *Reconciler) {
		r.newTopoNodeList = f
	}
}

func WithNewTopoNodeFn(f func() topov1alpha1.Tn) ReconcilerOption {
	return func(r *Reconciler) {
		r.newTopoNode = f
	}
}

func WithNewTopoLinkListFn(f func() topov1alpha1.TlList) ReconcilerOption {
	return func(r *Reconciler) {
		r.newTopoLinkList = f
	}
}

func WithNewDeploymentListFn(f func() orgv1alpha1.DpList) ReconcilerOption {
	return func(r *Reconciler) {
		r.newDeploymentList = f
	}
}

func WithNewDeploymentFn(f func() orgv1alpha1.Dp) ReconcilerOption {
	return func(r *Reconciler) {
		r.newDeployment = f
	}
}

func WithInfra(infra map[string]infra.Infra) ReconcilerOption {
	return func(r *Reconciler) {
		r.infra = infra
	}
}

// WithRecorder specifies how the Reconciler should record Kubernetes events.
func WithRecorder(er event.Recorder) ReconcilerOption {
	return func(r *Reconciler) {
		r.record = er
	}
}

func defaultMRManaged(m ctrl.Manager) mrManaged {
	return mrManaged{
		Finalizer: resource.NewAPIFinalizer(m.GetClient(), finalizerName),
	}
}

// Setup adds a controller that reconciles infra.
func Setup(mgr ctrl.Manager, o controller.Options, nddcopts *shared.NddControllerOptions) error {
	name := "nddr/" + strings.ToLower(infrav1alpha1.InfrastructureGroupKind)
	fn := func() infrav1alpha1.If { return &infrav1alpha1.Infrastructure{} }
	tplfn := func() topov1alpha1.TpList { return &topov1alpha1.TopologyList{} }
	tnlfn := func() topov1alpha1.TnList { return &topov1alpha1.TopologyNodeList{} }
	tnfn := func() topov1alpha1.Tn { return &topov1alpha1.TopologyNode{} }
	tllfn := func() topov1alpha1.TlList { return &topov1alpha1.TopologyLinkList{} }
	dplfn := func() orgv1alpha1.DpList { return &orgv1alpha1.DeploymentList{} }
	dpfn := func() orgv1alpha1.Dp { return &orgv1alpha1.Deployment{} }

	r := NewReconciler(mgr,
		WithLogger(nddcopts.Logger.WithValues("controller", name)),
		WithNewReourceFn(fn),
		WithNewTopoListFn(tplfn),
		WithNewTopoNodeListFn(tnlfn),
		WithNewTopoNodeFn(tnfn),
		WithNewTopoLinkListFn(tllfn),
		WithNewDeploymentListFn(dplfn),
		WithNewDeploymentFn(dpfn),
		//WithInfra(nddcopts.Infra),
		WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
	)

	topoHandler := &EnqueueRequestForAllTopologies{
		client: mgr.GetClient(),
		log:    nddcopts.Logger,
		ctx:    context.Background(),
		speedy: r.speedy,
	}

	topoNodeHandler := &EnqueueRequestForAllTopologyNodes{
		client: mgr.GetClient(),
		log:    nddcopts.Logger,
		ctx:    context.Background(),
		speedy: r.speedy,
	}

	topoLinkHandler := &EnqueueRequestForAllTopologyLinks{
		client: mgr.GetClient(),
		log:    nddcopts.Logger,
		ctx:    context.Background(),
		speedy: r.speedy,
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

// NewReconciler creates a new reconciler.
func NewReconciler(mgr ctrl.Manager, opts ...ReconcilerOption) *Reconciler {

	r := &Reconciler{
		//client: mgr.GetClient(),
		client: resource.ClientApplicator{
			Client:     mgr.GetClient(),
			Applicator: resource.NewAPIPatchingApplicator(mgr.GetClient()),
		},
		log:     logging.NewNopLogger(),
		record:  event.NewNopRecorder(),
		managed: defaultMRManaged(mgr),
		speedy:  make(map[string]int),
	}

	for _, f := range opts {
		f(r)
	}

	return r
}

// Reconcile infra allocation.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) { // nolint:gocyclo
	log := r.log.WithValues("request", req)
	log.Debug("Reconciling infra", "NameSpace", req.NamespacedName)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	cr := r.newInfra()
	if err := r.client.Get(ctx, req.NamespacedName, cr); err != nil {
		// There's no need to requeue if we no longer exist. Otherwise we'll be
		// requeued implicitly because we return an error.
		log.Debug("Cannot get managed resource", "error", err)
		return reconcile.Result{}, errors.Wrap(resource.IgnoreNotFound(err), errGetK8sResource)
	}
	record := r.record.WithAnnotations("name", cr.GetAnnotations()[cr.GetName()])

	crname := cr.GetName()

	if meta.WasDeleted(cr) {
		log = log.WithValues("deletion-timestamp", cr.GetDeletionTimestamp())

		// TODO if something holds this back for deletion
		//if _, ok := r.infra[crname]; ok {
		//}

		if err := r.managed.RemoveFinalizer(ctx, cr); err != nil {
			// If this is the first time we encounter this issue we'll be
			// requeued implicitly when we update our status with the new error
			// condition. If not, we requeue explicitly, which will trigger
			// backoff.
			record.Event(cr, event.Warning(reasonCannotDeleteFInalizer, err))
			log.Debug("Cannot remove managed resource finalizer", "error", err)
			cr.SetConditions(nddv1.ReconcileError(err), infrav1alpha1.NotReady())
			return reconcile.Result{Requeue: true}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
		}

		// We've successfully delete our resource (if necessary) and
		// removed our finalizer. If we assume we were the only controller that
		// added a finalizer to this resource then it should no longer exist and
		// thus there is no point trying to update its status.
		log.Debug("Successfully deleted resource")
		r.inframutex.Lock()
		delete(r.infra, crname)
		delete(r.speedy, crname)
		r.inframutex.Unlock()
		return reconcile.Result{Requeue: false}, nil
	}

	if err := r.managed.AddFinalizer(ctx, cr); err != nil {
		// If this is the first time we encounter this issue we'll be requeued
		// implicitly when we update our status with the new error condition. If
		// not, we requeue explicitly, which will trigger backoff.
		record.Event(cr, event.Warning(reasonCannotAddFInalizer, err))
		log.Debug("Cannot add finalizer", "error", err)
		cr.SetConditions(nddv1.ReconcileError(err), infrav1alpha1.NotReady())
		return reconcile.Result{Requeue: true}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
	}

	if err := cr.InitializeResource(); err != nil {
		record.Event(cr, event.Warning(reasonCannotInitialize, err))
		log.Debug("Cannot initialize", "error", err)
		cr.SetConditions(nddv1.ReconcileError(err), infrav1alpha1.NotReady())
		return reconcile.Result{Requeue: true}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
	}

	linkNotReadyInfo, err := r.handleAppLogic(ctx, cr, crname)
	if err != nil {
		record.Event(cr, event.Warning(reasonAppLogicFailed, err))
		log.Debug("handle applogic failed", "error", err)
		cr.SetConditions(nddv1.ReconcileError(err), infrav1alpha1.NotReady())
		return reconcile.Result{RequeueAfter: veryShortWait}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
	}
	timeout := reconcileTimeout
	if len(linkNotReadyInfo) > 0 {
		r.speedyMutex.Lock()
		speedy := r.speedy[crname]
		r.speedyMutex.Unlock()
		if speedy <= 5 {
			log.Debug("Speedy", "number", speedy)
			speedy++
			timeout = veryShortWait
		}
	}

	cr.SetConditions(nddv1.ReconcileSuccess(), infrav1alpha1.Ready())
	// requeue to control that someone does not change/delete the resource created by the intent reconciler
	//r.inframutex.Lock()
	r.infra[crname].PrintNodes(crname)
	//r.inframutex.Unlock()

	return reconcile.Result{RequeueAfter: timeout}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
}

func (r *Reconciler) handleAppLogic(ctx context.Context, cr infrav1alpha1.If, crname string) (map[string][]string, error) {
	log := r.log.WithValues("function", "handleAppLogic", "crname", cr.GetName())
	//log.Debug("handleAppLogic")

	r.inframutex.Lock()
	if _, ok := r.infra[crname]; !ok {
		r.infra[crname] = infra.NewInfra()
	}
	r.inframutex.Unlock()

	deploymentName := strings.Join([]string{cr.GetOrganization(), cr.GetDeployment()}, ".")
	niName := cr.GetNetworkInstanceName()

	register, err := r.GetRegister(ctx, cr, deploymentName)
	if err != nil {
		return nil, err
	}

	grpcServers, err := r.GetGrpcServers(ctx, cr)
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
	links := r.infra[crname].GetLinks()
	r.inframutex.Unlock()

	activeLinks := make([]topov1alpha1.Tl, 0)
	notReadyLinks := make(map[string][]string)
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

						if err := r.createNode(ctx, cr, crname, ip); err != nil {
							return nil, err
						}
						//r.validateNode(ctx, cr, crname, ip)
					}

					if link.GetLagMember() {
						// lag link members dont require ip(s, etc they are part of a lag on which the ip addresses are configured/allocated
						for i := 0; i <= 1; i++ {
							ip := getLinkParameters(i, niName, link, register, ipamClient, aspoolClient)

							itfce := r.createInterface(crname, ip)
							// create interface in adaptor
							if err := itfce.CreateNddaInterface(ctx, cr); err != nil {
								return nil, err
							}
						}
					} else {
						ips := make(map[string][]string)
						for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
							ipamOptions := &infra.IpamOptions{
								RegistryName:        register[registry.RegisterKindIpam.String()],
								NetworkInstanceName: niName,
								AddressFamily:       af,
							}

							linkPrefix, err := l.GrpcAllocateLinkIP(ctx, cr, link, ipamOptions)
							if err != nil {
								return nil, err
							}

							//	if err := l.AllocateIPLink(ctx, cr, link, ipamOptions); err != nil {
							//		//log.Debug(errCreate, "error", err)
							//		return nil, err
							//	}

							//	linkPrefix, err := l.ValidateIPLink(ctx, cr, link, ipamOptions)
							//	if err != nil {
							//		//log.Debug(errValidate, "error", err)
							//		return nil, err
							//	}


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
									RegistryName:        ip.ipamName,
									NetworkInstanceName: ip.niName,
									AddressFamily:       af,
									IpPrefix:            ips[af][i],
									EpIndex:             i,
								}

								epPrefix, err := l.GrpcAllocateEndpointIP(ctx, cr, link, ipamOptions)
								if err != nil {
									return nil, err
								}

								//	if err := l.AllocateIPLinkEndpoint(ctx, cr, link, ipamOptions); err != nil {
								//		return nil, err
								//	}
								//	epPrefix, err := l.ValidateIPLinkEndpoint(ctx, cr, link, ipamOptions)
								//	if err != nil {
								//		//log.Debug(errValidate, "error", err)
								//		return nil, err
								//	}

								//ePrefix := string(*epPrefix)
								lPrefix := l.GetPrefix(af)

								prefix, err := parseEndpointPrefix(lPrefix, *epPrefix)
								if err != nil {
									return nil, err
								}
								var itfce infra.Interface
								//var ni infra.Ni
								_, itfce, subinterfaces[i] = r.createInterfaceSubInterface(crname, ip, prefix, af)
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
					notReadyLinks[linkName] = make([]string, 2)
					notReadyLinks[linkName][0] = string(link.GetCondition(nddv1.ConditionKindSynced).Status)
					notReadyLinks[linkName][1] = string(link.GetCondition(topov1alpha1.ConditionKindReady).Status)
				}

			}
		}
	}

	//log.Debug("Active Links", "activeLinks", activeLinks)
	// if creates or deletes of toponodes/topolinks happen we need to cleanup the backend and all child
	// resources
	if err := r.validateBackend(ctx, cr, crname, activeLinks); err != nil {
		return nil, err
	}

	// create the network instance, since we have up to date info it is better to
	// wait for NI creation at this stage
	nodes := r.infra[crname].GetNodes()

	for nodeName, n := range nodes {
		log.Debug("create node networkinstance2", "node", nodeName)
		for niName, ni := range n.GetNis() {
			log.Debug("create node networkinstance2", "niName", niName, "nodeName", nodeName)
			if err := ni.CreateNddaNi(ctx, cr); err != nil {
				//log.Debug("CreateNddaNi", "Error", err)
				return nil, err
			}
			log.Debug("create node networkinstance3", "niName", ni.GetName(), "nodeName", ni.GetNode().GetName())
			niOptions := &infra.NiOptions{
				NetworkInstanceName: niName,
			}
			if err := ni.CreateNiRegister(ctx, cr, niOptions); err != nil {
				return nil, err
			}
		}
	}

	return notReadyLinks, nil
}

func (r *Reconciler) createInterfaceSubInterface(crname string, ip *interfaceParameters, prefix, af string) (infra.Ni, infra.Interface, infra.SubInterface) {
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

func (r *Reconciler) createInterface(crname string, ip *interfaceParameters) infra.Interface {
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

func (r *Reconciler) createNode(ctx context.Context, cr infrav1alpha1.If, crname string, ip *interfaceParameters) error {
	// get node from k8s api to retrieve node parameters like index for aspool
	nodeName := strings.Join([]string{cr.GetOrganization(), cr.GetDeployment(), ip.topologyName, ip.nodeName}, ".")
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

			//	as, err := n.ValidateAS(ctx, cr, node, ip.asPoolName)
			//	if err != nil {
			//		if resource.IgnoreNotFound(err) != nil {
			//			return err
			//		}
			//		if err := n.AllocateAS(ctx, cr, node, ip.asPoolName); err != nil {
			///			//log.Debug(errCreate, "error", err)
			//			return err
			//		}
			//	}

			n.SetAS(*as)
		}
	}

	for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
		ipamOptions := &infra.IpamOptions{
			RegistryName:        ip.ipamName,
			NetworkInstanceName: ip.niName,
			AddressFamily:       af,
		}
		lpPrefix, err := n.GrpcAllocateLoopback(ctx, cr, node, ipamOptions)
		if err != nil {
			return err
		}


		//	prefix, err := n.ValidateLoopbackIP(ctx, cr, node, ipamOptions)
		//	if err != nil {
		//		if resource.IgnoreNotFound(err) != nil {
		//			return err
		//		}
		//		if err := n.AllocateLoopbackIP(ctx, cr, node, ipamOptions); err != nil {
		//			//log.Debug(errCreate, "error", err)
		//			return err
		//		}
		//	}

		//lpPrefix := string(*prefix)

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
*/

/*
func (r *Reconciler) validateNode(ctx context.Context, cr infrav1alpha1.If, crname string, ip *interfaceParameters) error {
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
		r.infra[crname].GetNodes()[ip.nodeName] = infra.NewNode(ip.nodeName,
			infra.WithNodeK8sClient(r.client),
			infra.WithNodeIpamClient(ip.ipamClient),
			infra.WithNodeAsPoolClient(ip.aspoolClient),
			infra.WithNodeLogger(r.log))
	}
	n := nodes[ip.nodeName]

	for _, protocol := range cr.GetUnderlayProtocol() {
		if protocol == string(infrav1alpha1.ProtocolEBGP) {
			as, err := n.ValidateAS(ctx, cr, node, ip.asPoolName)
			if err != nil {
				//log.Debug("error validate as allocation", "error", err)
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
		prefix, err := n.ValidateLoopbackIP(ctx, cr, node, ipamOptions)
		if err != nil {
			//log.Debug("error validate prefix allocation", "error", err)
			return err
		}
		lpPrefix := string(*prefix)

		ip.itfceName = "system"
		ip.kind = infra.InterfaceKindSystem

		_, itfce, si := r.createInterfaceSubInterface(crname, ip, lpPrefix, af)
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
*/

/*
func (r *Reconciler) validateBackend(ctx context.Context, cr infrav1alpha1.If, crname string, activeLinks []topov1alpha1.Tl) error {
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
				niOptions := &infra.NiOptions{
					NetworkInstanceName: niName,
				}
				if err := ni.DeleteNiRegister(ctx, cr, niOptions); err != nil {
					return err
				}
			}
			// delete node from backend
			delete(nodes, nodeName)
		}
	}
	return nil
}
*/

/*
func (r *Reconciler) GetRegister(ctx context.Context, cr infrav1alpha1.If, deploymentName string) (map[string]string, error) {

	dep := r.newDeployment()
	if err := r.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(),
		Name:      deploymentName,
	}, dep); err != nil {
		return nil, err
	}

	if _, ok := dep.GetStateRegister()[string(registry.RegisterKindIpam)]; !ok {
		return nil, errors.New("ipam not registered")
	}
	if _, ok := dep.GetStateRegister()[string(registry.RegisterKindAs)]; !ok {
		return nil, errors.New("as pool not registered")
	}

	return dep.GetStateRegister(), nil
}

func (r *Reconciler) GetGrpcServers(ctx context.Context, cr infrav1alpha1.If) (map[string]string, error) {
	pods := &corev1.PodList{}
	opts := []client.ListOption{
		client.InNamespace("ndd-system"),
	}
	if err := r.client.List(ctx, pods, opts...); err != nil {
		return nil, err
	}

	grpcserverKeys := map[string]string{
		"ipam":   "nddr-ipam",
		"aspool": "nddr-aspool",
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
*/
