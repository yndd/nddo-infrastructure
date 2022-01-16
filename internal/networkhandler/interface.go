package networkhandler

import (
	"context"

	"github.com/yndd/ndd-runtime/pkg/logging"
	networkschema "github.com/yndd/ndda-network/pkg/networkschema/v1alpha1"
	"github.com/yndd/nddo-runtime/pkg/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Option can be used to manipulate Options.
type Option func(Handler)

// WithLogger specifies how the Reconciler should log messages.
func WithLogger(log logging.Logger) Option {
	return func(s Handler) {
		s.WithLogger(log)
	}
}

func WithClient(c client.Client) Option {
	return func(s Handler) {
		s.WithClient(c)
	}
}

type Handler interface {
	WithLogger(log logging.Logger)
	WithClient(c client.Client)
	InitSchema(crName string) networkschema.Schema
	DestroySchema(crName string)
	DeploySchema(ctx context.Context, mg resource.Managed, labels map[string]string) error
	ValidateSchema(ctx context.Context, mg resource.Managed) error
	PrintDevices(string)

	//PopulateNode(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error
	//PopulateLagMember(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error
	//PopulateIpLink(ctx context.Context, mg resource.Managed, link topov1alpha1.Tl) error

}
