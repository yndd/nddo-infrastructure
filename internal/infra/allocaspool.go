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
	"strconv"
	"strings"

	"github.com/yndd/ndd-runtime/pkg/meta"
	"github.com/yndd/ndd-runtime/pkg/utils"
	infrav1alpha1 "github.com/yndd/nddo-infrastructure/apis/infra/v1alpha1"
	nddov1 "github.com/yndd/nddo-runtime/apis/common/v1"
	aspoolv1alpha1 "github.com/yndd/nddr-as-pool/apis/aspool/v1alpha1"
	topov1alpha1 "github.com/yndd/nddr-topology/apis/topo/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	allocASpoolPrefix = "alloc-aspool"
	labelPrefix       = "nddo-infra"

	errUnavailableAsPoolAllocation = "AS pool allocation prefix unavailable"
)

func buildAsPoolAllocByIndex(cr infrav1alpha1.If, x topov1alpha1.Tn, asPoolName string) *aspoolv1alpha1.Alloc {

	return &aspoolv1alpha1.Alloc{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.Join([]string{asPoolName, x.GetNodeName()}, "."),
			Namespace: cr.GetNamespace(),
			Labels: map[string]string{
				labelPrefix: strings.Join([]string{asPoolName, x.GetNodeName()}, "."),
			},
			OwnerReferences: []metav1.OwnerReference{meta.AsController(meta.TypedReferenceTo(cr, infrav1alpha1.InfrastructureGroupVersionKind))},
		},
		Spec: aspoolv1alpha1.AllocSpec{
			Alloc: &aspoolv1alpha1.AspoolAlloc{
				Selector: []*nddov1.Tag{
					{Key: utils.StringPtr(topov1alpha1.KeyNodeIndex), Value: utils.StringPtr(strconv.Itoa(int(x.GetNodeIndex())))},
				},
				SourceTag: []*nddov1.Tag{
					{Key: utils.StringPtr(topov1alpha1.KeyNode), Value: utils.StringPtr(x.GetName())},
					// TBD do we need other tags like tenant, vpc, ni
				},
			},
		},
	}
}
