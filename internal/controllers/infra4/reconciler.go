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

package infra4

/*
import (
	"context"
	"strings"
	"time"

	"github.com/yndd/ndda-network/pkg/ndda/ndda"
	"github.com/yndd/nddo-infrastructure/internal/shared"
	"github.com/yndd/nddo-infrastructure/internal/speedyhandler"
	"github.com/yndd/nddo-infrastructure/internal/srlhandler"

	"github.com/yndd/nddr-org-registry/pkg/registry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/pkg/errors"
	"github.com/yndd/ndd-runtime/pkg/event"
	"github.com/yndd/ndd-runtime/pkg/logging"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/reconciler/managed"
	"github.com/yndd/nddo-runtime/pkg/resource"
	orgv1alpha1 "github.com/yndd/nddr-org-registry/apis/org/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topo-registry/apis/topo/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

const (
	// timers
	reconcileTimeout = 1 * time.Minute
	shortWait        = 5 * time.Second
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

	shandler := speedyhandler.New()

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
			//handler:           nddcopts.Handler,
			registry: nddcopts.Registry,
			nddaHandler: ndda.New(
				ndda.WithClient(resource.ClientApplicator{
					Client:     mgr.GetClient(),
					Applicator: resource.NewAPIPatchingApplicator(mgr.GetClient()),
				}),
				ndda.WithLogger(nddcopts.Logger.WithValues("nddahandler", name)),
			),
			srlHandler: srlhandler.New(
				srlhandler.WithClient(resource.ClientApplicator{
					Client:     mgr.GetClient(),
					Applicator: resource.NewAPIPatchingApplicator(mgr.GetClient()),
				}),
				srlhandler.WithLogger(nddcopts.Logger.WithValues("srlhandler", name)),
			),
			speedyHandler: shandler,
		}),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
	)

	topoHandler := &EnqueueRequestForAllTopologies{
		client:        mgr.GetClient(),
		log:           nddcopts.Logger,
		ctx:           context.Background(),
		newInfraList:  iflfn,
		speedyHandler: shandler,
	}

	topoNodeHandler := &EnqueueRequestForAllTopologyNodes{
		client:        mgr.GetClient(),
		log:           nddcopts.Logger,
		ctx:           context.Background(),
		newInfraList:  iflfn,
		speedyHandler: shandler,
	}

	topoLinkHandler := &EnqueueRequestForAllTopologyLinks{
		client:        mgr.GetClient(),
		log:           nddcopts.Logger,
		ctx:           context.Background(),
		newInfraList:  iflfn,
		speedyHandler: shandler,
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

	//handler  handler.Handler
	registry      registry.Registry
	nddaHandler   ndda.Handler
	srlHandler    srlhandler.Handler
	speedyHandler speedyhandler.Handler
}

func getCrName(mg resource.Managed) string {
	return strings.Join([]string{mg.GetNamespace(), mg.GetName()}, ".")
}


func (r *application) Initialize(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return errors.New(errUnexpectedResource)
	}

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

	r.speedyHandler.Init(getCrName(mg))

	//return r.handleAppLogic(ctx, cr)
	info, err := r.populateSchema(ctx, mg)
	if err != nil {
		return info, err
	}

	if err := r.srlHandler.ValidateSchema(ctx, mg); err != nil {
		return nil, err
	}

	labels := make(map[string]string)
	if err := r.srlHandler.DeploySchema(ctx, mg, labels); err != nil {
		return nil, err
	}

	cr.SetOrganization(cr.GetOrganization())
	cr.SetDeployment(cr.GetDeployment())
	cr.SetAvailabilityZone(cr.GetAvailabilityZone())
	cr.SetNetworkInstanceName(cr.GetNetworkInstanceName())

	return nil, nil
}

func (r *application) FinalUpdate(ctx context.Context, mg resource.Managed) {
	cr, _ := mg.(*infrav1alpha1.Infrastructure)
	crName := getCrName(cr)
	r.srlHandler.PrintDevices(crName)
}

func (r *application) Timeout(ctx context.Context, mg resource.Managed) time.Duration {
	crName := getCrName(mg)
	speedy := r.speedyHandler.GetSpeedy(crName)
	if speedy <= 2 {
		r.speedyHandler.IncrementSpeedy(crName)
		r.log.Debug("Speedy incr", "number", r.speedyHandler.GetSpeedy(crName))
		switch speedy {
		case 0:
			return veryShortWait
		case 1, 2:
			return shortWait
		}
	}

	return reconcileTimeout
}

func (r *application) Delete(ctx context.Context, mg resource.Managed) (bool, error) {
	return true, nil
}

func (r *application) FinalDelete(ctx context.Context, mg resource.Managed) {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return
	}
	crName := getCrName(cr)
	r.srlHandler.DestroySchema(crName)
	r.speedyHandler.Delete(crName)
}

func (r *application) populateSchema(ctx context.Context, mg resource.Managed) (map[string]string, error) {
	cr, ok := mg.(*infrav1alpha1.Infrastructure)
	if !ok {
		return nil, errors.New(errUnexpectedResource)
	}

	// initialize the cr elements
	//ccrName := getCrNameCandidate(mg)

	// TODO REGISTRY

	// get all link crs
	topolinks := r.newTopoLinkList()
	opts := []client.ListOption{
		client.InNamespace(cr.GetNamespace()),
	}
	if err := r.client.List(ctx, topolinks, opts...); err != nil {
		return nil, err
	}

	// keep track of the links that are not ready, it is used in the reconciler to speed up
	// the reconciliations during changes
	notReadyLinks := make(map[string]string)
	for _, link := range topolinks.GetLinks() {
		// only process topology links that are part of the deployment
		// only process links with infra tag and non lag-members
		//log.Debug("link", "cr-deployment-name", cr.GetDeploymentName(), "link deployment-name", link.GetDeploymentName(), "link name", link.GetName())
		if link.GetDeployment() == cr.GetDeployment() && link.GetKind() == topov1alpha1.LinkEPKindInfra.String() {
			linkName := link.GetName()
			// if resource is not reconciled we dont process
			if link.GetCondition(topov1alpha1.ConditionKindReady).Status == corev1.ConditionTrue {

				if err := r.SrlPopulateNode(ctx, mg, link); err != nil {
					return nil, err
				}

				if link.GetLagMember() {
					// create node and link without ip addresses and subinterfaces
					if err := r.SrlPopulateLagMember(ctx, mg, link); err != nil {
						return nil, err
					}
				} else {
					// create node and link with ip addresses and subinterfaces
					if err := r.SrlPopulateIpLink(ctx, mg, link); err != nil {
						return nil, err
					}
				}
			} else {
				notReadyLinks[linkName] = ""
			}
		}
	}
	return notReadyLinks, nil
}
*/