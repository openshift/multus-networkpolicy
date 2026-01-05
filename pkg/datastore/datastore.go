package datastore

import (
	"sync"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"k8s.io/apimachinery/pkg/types"
)

// PolicyForAnnotation is the policy-for annotation key that indicates which network this policy applies to
const PolicyForAnnotation = "k8s.v1.cni.cncf.io/policy-for"

// Datastore is a datastore for multi-network policies
type Datastore struct {
	sync.RWMutex
	Policies map[types.NamespacedName]*Policy
}

// Policy represents a multi-network policy stored in the datastore
type Policy struct {
	Name      string
	Namespace string
	Networks  []string

	Spec multiv1beta1.MultiNetworkPolicySpec
}

// GetPolicy gets a policy from the datastore
func (d *Datastore) GetPolicy(namespaceName types.NamespacedName) *Policy {
	d.RLock()
	defer d.RUnlock()

	return d.Policies[namespaceName]
}

// DeletePolicy deletes a policy from the datastore
func (d *Datastore) DeletePolicy(key types.NamespacedName) {
	d.Lock()
	defer d.Unlock()

	delete(d.Policies, key)
}

// CreatePolicy creates a policy in the datastore
func (d *Datastore) CreatePolicy(policy *Policy) {
	d.Lock()
	defer d.Unlock()

	key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
	d.Policies[key] = policy
}
