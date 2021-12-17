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
	"strings"
	"time"

	"github.com/pkg/errors"
	nddv1 "github.com/yndd/ndd-runtime/apis/common/v1"
	"github.com/yndd/ndd-runtime/pkg/event"
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/meta"
	"github.com/yndd/ndd-runtime/pkg/resource"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-infrastructure/internal/infra"
	"github.com/yndd/nddo-infrastructure/internal/shared"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
	corev1 "k8s.io/api/core/v1"
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
	errCreateObjects  = "cannot create infrastructure resources"

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

	nodehooks NodeHooks
	linkhooks LinkHooks
	ephooks   EpHooks

	newInfra        func() infrav1alpha1.If
	newTopoList     func() topov1alpha1.TpList
	newTopoNodeList func() topov1alpha1.TnList
	newTopoLinkList func() topov1alpha1.TlList

	infra map[string]infra.Infra
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

// WithNodeHooks specifies how the Reconciler should deploy child resources
func WithNodeHooks(h NodeHooks) ReconcilerOption {
	return func(r *Reconciler) {
		r.nodehooks = h
	}
}

// WithLinkHooks specifies how the Reconciler should deploy child resources
func WithLinkHooks(h LinkHooks) ReconcilerOption {
	return func(r *Reconciler) {
		r.linkhooks = h
	}
}

// WithEpHooks specifies how the Reconciler should deploy child resources
func WithEpHooks(h LinkHooks) ReconcilerOption {
	return func(r *Reconciler) {
		r.ephooks = h
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
	tllfn := func() topov1alpha1.TlList { return &topov1alpha1.TopologyLinkList{} }

	r := NewReconciler(mgr,
		WithLogger(nddcopts.Logger.WithValues("controller", name)),
		WithNodeHooks(NewNodeHook(resource.ClientApplicator{
			Client:     mgr.GetClient(),
			Applicator: resource.NewAPIPatchingApplicator(mgr.GetClient()),
		}, nddcopts.Logger.WithValues("nodehook", name))),
		WithLinkHooks(NewLinkHook(resource.ClientApplicator{
			Client:     mgr.GetClient(),
			Applicator: resource.NewAPIPatchingApplicator(mgr.GetClient()),
		}, nddcopts.Logger.WithValues("linkhook", name))),
		WithEpHooks(NewEpHook(resource.ClientApplicator{
			Client:     mgr.GetClient(),
			Applicator: resource.NewAPIPatchingApplicator(mgr.GetClient()),
		}, nddcopts.Logger.WithValues("ephook", name))),
		WithNewReourceFn(fn),
		WithNewTopoListFn(tplfn),
		WithNewTopoNodeListFn(tnlfn),
		WithNewTopoLinkListFn(tllfn),
		WithInfra(nddcopts.Infra),
		WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
	)

	topoHandler := &EnqueueRequestForAllTopologies{
		client: mgr.GetClient(),
		log:    nddcopts.Logger,
		ctx:    context.Background(),
	}

	topoNodeHandler := &EnqueueRequestForAllTopologyNodes{
		client: mgr.GetClient(),
		log:    nddcopts.Logger,
		ctx:    context.Background(),
	}

	topoLinkHandler := &EnqueueRequestForAllTopologyLinks{
		client: mgr.GetClient(),
		log:    nddcopts.Logger,
		ctx:    context.Background(),
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

		if _, ok := r.infra[infraname]; ok {
			// TODO if something holds this back for deletion

		}

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

	if err := r.handleAppLogic(ctx, cr, infraname); err != nil {
		record.Event(cr, event.Warning(reasonAppLogicFailed, err))
		log.Debug("handle applogic failed", "error", err)
		cr.SetConditions(nddv1.ReconcileError(err), infrav1alpha1.NotReady())
		return reconcile.Result{RequeueAfter: veryShortWait}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
	}

	cr.SetConditions(nddv1.ReconcileSuccess(), infrav1alpha1.Ready())
	// requeue to control that someone does not change/delete the resource created by the intent reconciler
	return reconcile.Result{RequeueAfter: reconcileTimeout}, errors.Wrap(r.client.Status().Update(ctx, cr), errUpdateStatus)
}

func (r *Reconciler) handleAppLogic(ctx context.Context, cr infrav1alpha1.If, infraname string) error {
	log := r.log.WithValues("function", "handleAppLogic", "crname", cr.GetName())
	//log.Debug("handleAppLogic")

	if _, ok := r.infra[infraname]; !ok {
		r.infra[infraname] = infra.NewInfra()
	}

	nodes := r.newTopoNodeList()
	if err := r.client.List(ctx, nodes); err != nil {
		return err
	}
	for _, node := range nodes.GetNodes() {
		//log.Debug("handleAppLogic", "cr topology name", cr.GetName(), "node topology name", node.GetTopologyName(), "node index", node.GetNodeIndex())
		if cr.GetTopologyName() == node.GetTopologyName() {
			// if resource is not reconciled we dont process
			//log.Debug("node condition", "status", node.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status)

			if node.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status == corev1.ConditionTrue {
				//log.Debug("Ready to allocate AS", "Node", node.GetName(), "Index", node.GetNodeIndex())
				//log.Debug("Ready to allocate IP Loopback", "Node", node.GetName(), "Index", node.GetNodeIndex())

				n := infra.NewNode(
					infra.WithNodeClient(r.client),
					infra.WithNodeLogger(r.log),
				)
				n.SetName(node.GetName())
				n.SetIndex(node.GetNodeIndex())
				n.SetKind(node.GetKindName())
				n.SetPlatform(node.GetPlatform())
				if err := n.AllocateAS(ctx, cr, node); err != nil {
					log.Debug(errCreateObjects, "error", err)
					return err
				}
				if err := n.AllocateLoopbackIP(ctx, cr, node); err != nil {
					log.Debug(errCreateObjects, "error", err)
					return err
				}
				r.infra[infraname].AddNode(n)

			}
		}
	}

	// validate allocated resources
	for _, node := range nodes.GetNodes() {
		if cr.GetTopologyName() == node.GetTopologyName() {
			if node.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status == corev1.ConditionTrue {
				n := r.infra[infraname].GetNode(node.GetName())
				as, err := n.ValidateAS(ctx, cr, node)
				if err != nil {
					log.Debug("error validate as allocation", "error", err)
					return err
				}
				n.SetAS(*as)
				time.Sleep(1 * time.Second)
				prefix, err := n.ValidateLoopbackIP(ctx, cr, node)
				if err != nil {
					log.Debug("error validate prefix allocation", "error", err)
					return err
				}
				itfce := infra.NewInterface(n)
				itfce.SetKind(infra.InterfaceKindLoopback)
				itfce.SetName("system")
				n.AddInterface(itfce)

				subitfce := infra.NewSubInterface(itfce)
				subitfce.SetName("system0")
				subitfce.SetKind(infra.SubInterfaceKindRouted)
				subitfce.SetTaggingKind(infra.TaggingKindUnTagged)

				a := infra.NewAddressInfo()
				a.SetPrefix(*prefix)

				subitfce.AddIpv4AddressInfo(a)

			}
		}
	}

	links := r.newTopoLinkList()
	if err := r.client.List(ctx, links); err != nil {
		return err
	}
	for _, link := range links.GetLinks() {
		if cr.GetTopologyName() == link.GetTopologyName() {
			// if resource is not reconciled we dont process
			//log.Debug("link condition", "status", link.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status,
			//	"linkKind", link.GetKind())
			if link.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status == corev1.ConditionTrue {
				if link.GetKind() == topov1alpha1.LinkEPKindInfra.String() {
					// allocate IP with a specific prefix length (where do we get this from ?)

					l := infra.NewLink(link.GetName(),
						infra.WithLinkClient(r.client),
						infra.WithLinkLogger(r.log),
					)

					if err := l.AllocateLinkIP(ctx, cr, link); err != nil {
						log.Debug(errCreateObjects, "error", err)
						return err
					}
					r.infra[infraname].AddLink(l)
				}
			}
		}
	}

	for _, link := range links.GetLinks() {
		if cr.GetTopologyName() == link.GetTopologyName() {
			// if resource is not reconciled we dont process
			//log.Debug("link condition", "status", link.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status,
			//	"linkKind", link.GetKind())
			if link.GetCondition(topov1alpha1.ConditionKindAllocationReady).Status == corev1.ConditionTrue {
				if link.GetKind() == topov1alpha1.LinkEPKindInfra.String() {
					// allocate IP with a specific prefix length (where do we get this from ?)

					l := r.infra[infraname].GetLink(link.GetName())

					time.Sleep(1 * time.Second)
					prefix, err := l.ValidateLinkIP(ctx, cr, link)
					if err != nil {
						log.Debug(errCreateObjects, "error", err)
						return err
					}

					log.Debug("Ready to allocate Link Prefix", "Link Name", link.GetName(),
						"NodeA", link.GetEndpointANodeName(),
						"NodeB", link.GetEndpointBNodeName(),
						"Prefix", *prefix)

					for _, node := range link.GetNodeEndpoints() {
						for _, ep := range node.Endpoint {
							if !*ep.LagSubLink {
								log.Debug("Ready to allocate IP for the endpoint", "NodeName", node.Name, "InterfaceName", ep.Name)
							}
						}
					}
				}
			}
		}
	}
	return nil
}
