package handler

import (
	"sync"

	"github.com/yndd/ndd-runtime/pkg/logging"
	"github.com/yndd/nddo-infrastructure/internal/infra"
	"github.com/yndd/nddo-runtime/pkg/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func New(opts ...Option) (Handler, error) {
	s := &handler{
		infra:  make(map[string]infra.Infra),
		speedy: make(map[string]int),
		//newRegistry: rgfn,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
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
	client client.Client

	infraMutex  sync.Mutex
	infra       map[string]infra.Infra
	speedyMutex sync.Mutex
	speedy      map[string]int
}

func (r *handler) Init(crName string) {
	r.infraMutex.Lock()
	defer r.infraMutex.Unlock()
	if _, ok := r.infra[crName]; !ok {
		r.infra[crName] = infra.NewInfra()
	}

	r.speedyMutex.Lock()
	defer r.speedyMutex.Unlock()
	if _, ok := r.speedy[crName]; !ok {
		r.speedy[crName] = 0
	}
}

func (r *handler) Delete(crName string) {
	r.infraMutex.Lock()
	defer r.infraMutex.Unlock()
	delete(r.infra, crName)

	r.speedyMutex.Lock()
	defer r.speedyMutex.Unlock()
	delete(r.speedy, crName)
}

func (r *handler) ResetSpeedy(crName string) {
	r.speedyMutex.Lock()
	defer r.speedyMutex.Unlock()
	if _, ok := r.speedy[crName]; ok {
		r.speedy[crName] = 0
	}
}

func (r *handler) GetSpeedy(crName string) int {
	r.speedyMutex.Lock()
	defer r.speedyMutex.Unlock()
	if _, ok := r.speedy[crName]; ok {
		return r.speedy[crName]
	}
	return 9999
}

func (r *handler) IncrementSpeedy(crName string) {
	r.speedyMutex.Lock()
	defer r.speedyMutex.Unlock()
	if _, ok := r.speedy[crName]; ok {
		r.speedy[crName]++
	}
}

func (r *handler) PrintInfraNodes(crName string) {
	r.infraMutex.Lock()
	defer r.infraMutex.Unlock()
	r.infra[crName].PrintNodes(crName)
}

func (r *handler) GetInfraLinks(crName string) map[string]infra.Link {
	r.infraMutex.Lock()
	defer r.infraMutex.Unlock()
	return r.infra[crName].GetLinks()
}

func (r *handler) GetInfraNodes(crName string) map[string]infra.Node {
	r.infraMutex.Lock()
	defer r.infraMutex.Unlock()
	return r.infra[crName].GetNodes()
}
