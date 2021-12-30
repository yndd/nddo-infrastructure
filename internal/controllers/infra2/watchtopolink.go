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
	"strings"
	"sync"

	//ndddvrv1 "github.com/yndd/ndd-core/apis/dvr/v1"
	"github.com/yndd/ndd-runtime/pkg/logging"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type EnqueueRequestForAllTopologyLinks struct {
	client client.Client
	log    logging.Logger
	ctx    context.Context

	speedy map[string]int
	mutex  sync.Mutex

	newInfraList func() infrav1alpha1.IfList
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *EnqueueRequestForAllTopologyLinks) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *EnqueueRequestForAllTopologyLinks) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.ObjectOld, q)
	e.add(evt.ObjectNew, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *EnqueueRequestForAllTopologyLinks) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

// Create enqueues a request for all infrastructures which pertains to the topology.
func (e *EnqueueRequestForAllTopologyLinks) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	e.add(evt.Object, q)
}

func (e *EnqueueRequestForAllTopologyLinks) add(obj runtime.Object, queue adder) {
	dd, ok := obj.(*topov1alpha1.TopologyLink)
	if !ok {
		return
	}
	log := e.log.WithValues("function", "watch topolink", "name", dd.GetName())
	log.Debug("infra handleEvent")

	d := e.newInfraList()
	if err := e.client.List(e.ctx, d); err != nil {
		return
	}

	for _, infra := range d.GetInfrastructures() {
		deploymentName := strings.Join([]string{infra.GetOrganizationName(), infra.GetDeploymentName()}, ".")
		// only enqueue if the topology name match
		if strings.Contains(dd.GetName(), deploymentName) {

			crname := infra.GetName()

			e.mutex.Lock()
			e.speedy[crname] = 0
			e.mutex.Unlock()

			queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: dd.GetNamespace(),
				Name:      infra.GetName()}})
		}
	}
}