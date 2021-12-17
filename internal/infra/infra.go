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
	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/ndd-runtime/pkg/resource"
)

// InfraOption is used to configure the Infra.
type InfraOption func(*infra)

func WithInfraLogger(log logging.Logger) InfraOption {
	return func(r *infra) {
		r.log = log
	}
}

func WithInfraClient(c resource.ClientApplicator) InfraOption {
	return func(r *infra) {
		r.client = c
	}
}

func NewInfra(opts ...InfraOption) Infra {
	i := &infra{
		nodes: make([]Node, 0),
	}

	for _, f := range opts {
		f(i)
	}

	return i
}

var _ Infra = &infra{}

type Infra interface {
	GetNodes() []Node
	GetNode(string) Node
	AddNode(Node)
	DeleteNode(Node)
	GetLinks() []Link
	GetLink(string) Link
	AddLink(Link)
	DeleteLink(Link)
}

type infra struct {
	client resource.ClientApplicator
	log    logging.Logger

	nodes []Node
	links []Link
}

func (x *infra) GetNodes() []Node {
	return x.nodes
}

func (x *infra) GetNode(n string) Node {
	for _, node := range x.nodes {
		if node.GetName() == n {
			return node
		}
	}
	return nil
}

func (x *infra) AddNode(n Node) {
	for _, node := range x.nodes {
		if node.GetName() == n.GetName() {
			node = n
			return
		}
	}
	x.nodes = append(x.nodes, n)
}

func (x *infra) DeleteNode(n Node) {
	found := false
	idx := 0
	for i, node := range x.nodes {
		if node.GetName() == n.GetName() {
			idx = i
			found = true
		}
	}
	if found {
		x.nodes = append(x.nodes[:idx], x.nodes[idx+1:]...)
	}
}

func (x *infra) GetLinks() []Link {
	return x.links
}

func (x *infra) GetLink(n string) Link {
	for _, link := range x.links {
		if link.GetName() == n {
			return link
		}
	}
	return nil
}

func (x *infra) AddLink(l Link) {
	for _, link := range x.links {
		if link.GetName() == l.GetName() {
			link = l
			return
		}
	}
	x.links = append(x.links, l)
}

func (x *infra) DeleteLink(l Link) {
	found := false
	idx := 0
	for i, link := range x.links {
		if link.GetName() == l.GetName() {
			idx = i
			found = true
		}
	}
	if found {
		x.links = append(x.links[:idx], x.links[idx+1:]...)
	}
}
