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

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	nddv1 "github.com/yndd/ndd-runtime/apis/common/v1"
	"github.com/yndd/ndd-runtime/pkg/event"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/meta"
	"github.com/yndd/ndd-runtime/pkg/resource"
	"inet.af/netaddr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-infrastructure/internal/infra"
	"github.com/yndd/nddo-infrastructure/internal/shared"
	ipamv1alpha1 "github.com/yndd/nddr-ipam/apis/ipam/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
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

	newInfra        func() infrav1alpha1.If
	newTopoList     func() topov1alpha1.TpList
	newTopoNodeList func() topov1alpha1.TnList
	newTopoNode     func() topov1alpha1.Tn
	newTopoLinkList func() topov1alpha1.TlList

	infra  map[string]infra.Infra
	speedy map[string]int
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

	r := NewReconciler(mgr,
		WithLogger(nddcopts.Logger.WithValues("controller", name)),
		WithNewReourceFn(fn),
		WithNewTopoListFn(tplfn),
		WithNewTopoNodeListFn(tnlfn),
		WithNewTopoNodeFn(tnfn),
		WithNewTopoLinkListFn(tllfn),
		WithInfra(nddcopts.Infra),
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

	infraname := strings.Join([]string{cr.GetNamespace(), cr.GetName()}, "/")

	if meta.WasDeleted(cr) {
		log = log.WithValues("deletion-timestamp", cr.GetDeletionTimestamp())

		// TODO if something holds this back for deletion
		//if _, ok := r.infra[infraname]; ok {
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
		delete(r.infra, infraname)
		delete(r.speedy, infraname)
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

	linkNotReadyInfo, err := r.handleAppLogic(ctx, cr, infraname)
	if err != nil {
		record.Event(cr, event.Warning(reasonAppLogicFailed, err))
		log.Debug("handle applogic failed", "error", err)
		cr.SetConditions(nddv1.ReconcileError(err), infrav1alpha1.NotReady())
		return reconcile.Result{RequeueAfter: veryShortWait}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
	}
	timeout := reconcileTimeout
	if len(linkNotReadyInfo) > 0 {
		if r.speedy[infraname] <= 5 {
			log.Debug("Speedy", "number", r.speedy[infraname])
			r.speedy[infraname]++
			timeout = veryShortWait
		}
	}

	cr.SetConditions(nddv1.ReconcileSuccess(), infrav1alpha1.Ready())
	// requeue to control that someone does not change/delete the resource created by the intent reconciler
	r.infra[infraname].PrintNodes()

	return reconcile.Result{RequeueAfter: timeout}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
}

func (r *Reconciler) handleAppLogic(ctx context.Context, cr infrav1alpha1.If, infraname string) (map[string][]string, error) {
	log := r.log.WithValues("function", "handleAppLogic", "crname", cr.GetName())
	//log.Debug("handleAppLogic")

	if _, ok := r.infra[infraname]; !ok {
		r.infra[infraname] = infra.NewInfra()
	}

	// get all link crs
	links := r.newTopoLinkList()
	if err := r.client.List(ctx, links); err != nil {
		return nil, err
	}

	notReadyLinks := make(map[string][]string)
	for _, link := range links.GetLinks() {
		if cr.GetTopologyName() == link.GetTopologyName() {
			// if resource is not reconciled we dont process
			// only process infra links
			if link.GetKind() == topov1alpha1.LinkEPKindInfra.String() {
				linkName := link.GetName()
				if link.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status == corev1.ConditionTrue {
					if _, ok := r.infra[infraname].GetLinks()[linkName]; !ok {
						r.infra[infraname].GetLinks()[linkName] = infra.NewLink(linkName,
							infra.WithLinkClient(r.client),
							infra.WithLinkLogger(r.log),
						)
					}

					for i := 0; i <= 1; i++ {
						ip := getLinkParameters(i, link)

						// keep track of the active epg links, for validation/garbage collection later on

						l := r.infra[infraname].GetLinks()[linkName]
						//r.log.Debug("handleAppLogic1", "idx", i, "nodeName", ip.nodeName)
						l.SetNodeName(i, ip.nodeName)
						l.SetInterfaceName(i, ip.itfceName)

						if err := r.createNode(ctx, cr, infraname, ip); err != nil {
							return nil, err
						}

						// We allocate IPs only from links that are not LAG members
						// only process links with infra tag and non lag-members
						if !link.GetLagMember() {
							for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
								ipamOptions := &infra.IpamOptions{
									NetworkInstance: "default",
									AddressFamily:   af,
								}
								if err := l.AllocateIPLink(ctx, cr, link, ipamOptions); err != nil {
									//log.Debug(errCreate, "error", err)
									return nil, err
								}
							}
						}
					}
				} else {
					notReadyLinks[linkName] = make([]string, 2)
					notReadyLinks[linkName][0] = string(link.GetCondition(nddv1.ConditionKindSynced).Status)
					notReadyLinks[linkName][1] = string(link.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status)
				}
			}
		}
	}

	activeLinks := make([]topov1alpha1.Tl, 0)
	for _, link := range links.GetLinks() {
		if cr.GetTopologyName() == link.GetTopologyName() {
			// only process links with infra tag and non lag-members
			if link.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status == corev1.ConditionTrue &&
				link.GetKind() == topov1alpha1.LinkEPKindInfra.String() {

				// validate node information
				for i := 0; i <= 1; i++ {
					ip := getLinkParameters(i, link)
					r.validateNode(ctx, cr, infraname, ip)
				}

				// keep track of the active epg links, for validation/garbage collection later on
				activeLinks = append(activeLinks, link)

				linkName := link.GetName()
				if _, ok := r.infra[infraname].GetLinks()[linkName]; !ok {
					r.infra[infraname].GetLinks()[linkName] = infra.NewLink(linkName,
						infra.WithLinkClient(r.client),
						infra.WithLinkLogger(r.log),
					)
				}
				l := r.infra[infraname].GetLinks()[linkName]

				if !link.GetLagMember() {
					ips := make(map[string][]string)
					for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
						ipamOptions := &infra.IpamOptions{
							NetworkInstance: "default",
							AddressFamily:   af,
						}
						linkPrefix, err := l.ValidateIPLink(ctx, cr, link, ipamOptions)
						if err != nil {
							//log.Debug(errValidate, "error", err)
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
						ip := getLinkParameters(i, link)

						//r.log.Debug("handleAppLogic2", "idx", i, "nodeName", ip.nodeName)
						l.SetNodeName(i, ip.nodeName)
						l.SetInterfaceName(i, ip.itfceName)

						for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
							ipamOptions := &infra.IpamOptions{
								NetworkInstance: "default",
								AddressFamily:   af,
								IpPrefix:        ips[af][i],
								EpIndex:         i,
							}
							if err := l.AllocateIPLinkEndpoint(ctx, cr, link, ipamOptions); err != nil {
								return nil, err
							}
							epPrefix, err := l.ValidateIPLinkEndpoint(ctx, cr, link, ipamOptions)
							if err != nil {
								//log.Debug(errValidate, "error", err)
								return nil, err
							}
							ePrefix := string(*epPrefix)
							lPrefix := l.GetPrefix(af)

							prefix, err := parseEndpointPrefix(lPrefix, ePrefix)
							if err != nil {
								return nil, err
							}
							subinterfaces[i] = r.createInfraInterface(infraname, ip, prefix, af, link.GetLag())
						}
					}
					// cross reference the subinterfaces
					subinterfaces[0].SetNeighbor(subinterfaces[1])
					subinterfaces[1].SetNeighbor(subinterfaces[0])
				}

				if !link.GetLagMember() {

				} else {
					for i := 0; i <= 1; i++ {
						ip := getLinkParameters(i, link)

						r.createInfraLagMemberInterface(infraname, ip)
					}
				}
			}
		}
	}
	//log.Debug("ACtive Links", "activeLinks", activeLinks)
	r.validateBackend(infraname, activeLinks)

	return notReadyLinks, nil
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

func parseIpPerEndPoint(prefix string) ([]string, error) {
	ips := make([]string, 0, 2)
	p, err := netaddr.ParseIPPrefix(prefix)
	if err != nil {
		return nil, err
	}

	//log.Debug("Netaddr IP", "IP1", p.IP(), "IP2", p.IP().Next(), "Mask", p.Bits())
	switch {
	case p.Bits() == 31:
		ips = append(ips, strings.Join([]string{p.IP().String(), "32"}, "/"))
		ips = append(ips, strings.Join([]string{p.IP().Next().String(), "32"}, "/"))
		return ips, nil
	case p.Bits() == 127:
		ips = append(ips, strings.Join([]string{p.IP().String(), "128"}, "/"))
		ips = append(ips, strings.Join([]string{p.IP().Next().String(), "128"}, "/"))
		return ips, nil
	default:

	}
	return nil, err
}

func parseEndpointPrefix(linkPrefix, epPrefix string) (string, error) {
	lp, err := netaddr.ParseIPPrefix(linkPrefix)
	if err != nil {
		return "", err
	}
	ep, err := netaddr.ParseIPPrefix(epPrefix)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{ep.IP().String(), strconv.Itoa(int(lp.Bits()))}, "/"), nil
}

func (r *Reconciler) createInfraInterface(infraname string, ip *interfaceParameters, prefix, af string, lag bool) infra.SubInterface {
	n := r.infra[infraname].GetNodes()[ip.nodeName]
	if _, ok := n.GetInterfaces()[ip.itfceName]; !ok {
		n.GetInterfaces()[ip.itfceName] = infra.NewInterface(n)
	}

	itfce := n.GetInterfaces()[ip.itfceName]
	itfce.SetKind(infra.InterfaceKindInterface)
	if lag {
		itfce.SetLag()
	}

	if _, ok := itfce.GetSubInterfaces()["0"]; !ok {
		itfce.GetSubInterfaces()["0"] = infra.NewSubInterface(itfce)
	}
	subitfce := itfce.GetSubInterfaces()["0"]
	subitfce.SetKind(infra.SubInterfaceKindRouted)
	subitfce.SetTaggingKind(infra.TaggingKindUnTagged)

	if _, ok := subitfce.GetAddressesInfo(af)[prefix]; !ok {
		subitfce.GetAddressesInfo(af)[prefix] = infra.NewAddressInfo()
	}

	return subitfce
}

func (r *Reconciler) createInfraLagMemberInterface(infraname string, ip *interfaceParameters) {
	n := r.infra[infraname].GetNodes()[ip.nodeName]
	if _, ok := n.GetInterfaces()[ip.nodeName]; !ok {
		n.GetInterfaces()[ip.itfceName] = infra.NewInterface(n)
	}

	itfce := n.GetInterfaces()[ip.itfceName]
	itfce.SetKind(infra.InterfaceKindInterface)
	itfce.SetLagMember()
	itfce.SetLagName(ip.lagName)
	if ip.lacp {
		itfce.SetLacp()
	}
	if ip.lacpFallback {
		itfce.SetLacpFallback()
	}
}

func (r *Reconciler) createNode(ctx context.Context, cr infrav1alpha1.If, infraname string, ip *interfaceParameters) error {
	// get node from k8s api to retrieve node parameters like index for aspool
	node := r.newTopoNode()
	if err := r.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(),
		Name:      ip.nodeName,
	}, node); err != nil {
		// There's no need to requeue if we no longer exist. Otherwise we'll be
		// requeued implicitly because we return an error.
		//log.Debug("Cannot get managed resource", "error", err)
		return err
	}

	if _, ok := r.infra[infraname].GetNodes()[ip.nodeName]; !ok {
		r.infra[infraname].GetNodes()[ip.nodeName] = infra.NewNode(
			infra.WithNodeClient(r.client),
			infra.WithNodeLogger(r.log))
	}
	n := r.infra[infraname].GetNodes()[ip.nodeName]
	n.SetIndex(node.GetNodeIndex())
	n.SetKind(node.GetKindName())
	n.SetPlatform(node.GetPlatform())

	// Allocate AS per node if the underlay protocol is ebgp
	for _, protocol := range cr.GetUnderlayProtocol() {
		if protocol == string(infrav1alpha1.ProtocolEBGP) {
			_, err := n.ValidateAS(ctx, cr, node)
			if err != nil {
				if resource.IgnoreNotFound(err) != nil {
					return err
				}
				if err := n.AllocateAS(ctx, cr, node); err != nil {
					//log.Debug(errCreate, "error", err)
					return err
				}
			}
		}
	}

	for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
		ipamOptions := &infra.IpamOptions{
			NetworkInstance: "default",
			AddressFamily:   af,
		}
		_, err := n.ValidateLoopbackIP(ctx, cr, node, ipamOptions)
		if err != nil {
			if resource.IgnoreNotFound(err) != nil {
				return err
			}
			if err := n.AllocateLoopbackIP(ctx, cr, node, ipamOptions); err != nil {
				//log.Debug(errCreate, "error", err)
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) validateNode(ctx context.Context, cr infrav1alpha1.If, infraname string, ip *interfaceParameters) error {
	// get node from k8s api to retrieve node parameters like index for aspool
	node := r.newTopoNode()
	if err := r.client.Get(ctx, types.NamespacedName{
		Namespace: cr.GetNamespace(),
		Name:      ip.nodeName,
	}, node); err != nil {
		// There's no need to requeue if we no longer exist. Otherwise we'll be
		// requeued implicitly because we return an error.
		//log.Debug("Cannot get managed resource", "error", err)
		return err
	}

	if _, ok := r.infra[infraname].GetNodes()[ip.nodeName]; !ok {
		r.infra[infraname].GetNodes()[ip.nodeName] = infra.NewNode(
			infra.WithNodeClient(r.client),
			infra.WithNodeLogger(r.log))
	}
	n := r.infra[infraname].GetNodes()[ip.nodeName]

	for _, protocol := range cr.GetUnderlayProtocol() {
		if protocol == string(infrav1alpha1.ProtocolEBGP) {
			as, err := n.ValidateAS(ctx, cr, node)
			if err != nil {
				//log.Debug("error validate as allocation", "error", err)
				return err
			}
			n.SetAS(*as)
		}
	}

	for _, af := range getAddressFamilies(cr.GetAddressingScheme()) {
		ipamOptions := &infra.IpamOptions{
			NetworkInstance: "default",
			AddressFamily:   af,
		}
		prefix, err := n.ValidateLoopbackIP(ctx, cr, node, ipamOptions)
		if err != nil {
			//log.Debug("error validate prefix allocation", "error", err)
			return err
		}
		lpPrefix := string(*prefix)

		ip.itfceName = "system"

		r.createInfraInterface(infraname, ip, lpPrefix, af, false)
	}

	// we can add vxlan and irb interfaces
	return nil
}

type interfaceParameters struct {
	nodeName     string
	itfceName    string
	lagName      string
	lag          bool
	lagMember    bool
	lacp         bool
	lacpFallback bool
	//mh           bool
	//mhName       string
	tags map[string]string
}

func getLinkParameters(i int, link topov1alpha1.Tl) *interfaceParameters {
	switch i {
	case 0:
		ip := &interfaceParameters{
			nodeName:     link.GetEndpointANodeName(),
			itfceName:    link.GetEndpointAInterfaceName(),
			lagName:      link.GetLagAName(),
			lag:          link.GetLag(),
			lagMember:    link.GetLagMember(),
			lacp:         link.GetLacp(),
			lacpFallback: link.GetLacpFallbackA(),
			//mh:           link.GetEndPointAMultiHoming(),
			//mhName:       link.GetEndPointAMultiHomingName(),
			tags: link.GetEndpointATag(),
		}
		return ip
	case 1:
		ip := &interfaceParameters{
			nodeName:     link.GetEndpointBNodeName(),
			itfceName:    link.GetEndpointBInterfaceName(),
			lagName:      link.GetLagBName(),
			lag:          link.GetLag(),
			lagMember:    link.GetLagMember(),
			lacp:         link.GetLacp(),
			lacpFallback: link.GetLacpFallbackB(),
			//mh:           link.GetEndPointBMultiHoming(),
			//mhName:       link.GetEndPointBMultiHomingName(),
			tags: link.GetEndpointATag(),
		}
		return ip
	}
	return &interfaceParameters{}

}

func (r *Reconciler) validateBackend(infraname string, activeLinks []topov1alpha1.Tl) {
	// update the backend based on the active links processed
	// validate the existing backend and update the information
	activeNodes := make(map[string]bool)
	for linkName, link := range r.infra[infraname].GetLinks() {
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
				if node, ok := r.infra[infraname].GetNodes()[nodeName]; ok {
					delete(node.GetInterfaces(), link.GetInterfaceNames()[idx])
				}
			}

		}
	}
	r.log.Debug("Active Nodes", "activeNodes", activeNodes)
	for nodeName := range r.infra[infraname].GetNodes() {
		found := false
		for activeNodeName := range activeNodes {
			if nodeName == activeNodeName {
				found = true
				break
			}
		}
		if !found {
			// delete node from backend
			delete(r.infra[infraname].GetNodes(), nodeName)
		}
	}

}
