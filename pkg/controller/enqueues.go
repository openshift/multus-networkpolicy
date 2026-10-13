package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/k8snetworkplumbingwg/multi-network-policy-nftables/pkg/utils"
)

// namespaceEnqueue returns a function that enqueues policies affected by a namespace event
func namespaceEnqueue(clt client.Client) func(ctx context.Context, ns client.Object) []reconcile.Request {
	return func(ctx context.Context, ns client.Object) []reconcile.Request {
		logger := log.FromContext(ctx).WithValues("namespace", ns.GetName())

		namespace, ok := ns.(*corev1.Namespace)
		if !ok {
			// Should not happen
			return []reconcile.Request{}
		}

		var mp multiv1beta1.MultiNetworkPolicyList
		err := clt.List(ctx, &mp)
		if err != nil {
			logger.Error(err, "Failed to list policies")
			return []reconcile.Request{}
		}

		logger.V(1).Info("Checking policies affected by namespace")

		var requests []reconcile.Request
		for _, policy := range mp.Items {
			if isPolicyAffectedByNamespace(&policy, namespace, logger) {
				namespaceName := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
				logger.Info("Policy is affected by namespace", "policy", namespaceName)
				requests = append(requests, reconcile.Request{NamespacedName: namespaceName})
			}
		}

		return requests
	}
}

// podEnqueue returns a function that enqueues policies affected by a pod event
func podEnqueue(clt client.Client) func(ctx context.Context, ns client.Object) []reconcile.Request {
	return func(ctx context.Context, ns client.Object) []reconcile.Request {
		logger := log.FromContext(ctx).WithValues("pod", ns.GetName(), "namespace", ns.GetNamespace())
		pod, ok := ns.(*corev1.Pod)
		if !ok {
			// Should not happen
			return []reconcile.Request{}
		}

		var mp multiv1beta1.MultiNetworkPolicyList
		err := clt.List(ctx, &mp)
		if err != nil {
			logger.Error(err, "Failed to list policies")
			return []reconcile.Request{}
		}

		logger.V(1).Info("Checking policies affected by pod")

		var requests []reconcile.Request
		for _, policy := range mp.Items {
			if isPolicyAffectedByPod(&policy, pod, logger) {
				namespaceName := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
				logger.Info("Policy is affected by pod", "policy", namespaceName)
				requests = append(requests, reconcile.Request{NamespacedName: namespaceName})
			}
		}

		return requests
	}
}

// isPolicyAffectedByNamespace checks if a policy is affected by a namespace
func isPolicyAffectedByNamespace(policy *multiv1beta1.MultiNetworkPolicy, namespace *corev1.Namespace, logger logr.Logger) bool {
	// Validate input parameters
	if policy == nil || namespace == nil {
		return false
	}

	logger = logger.WithValues("policy", fmt.Sprintf("%s/%s", policy.Namespace, policy.Name))

	// Ingress selectors
	for _, ingress := range policy.Spec.Ingress {
		for _, from := range ingress.From {
			// If IPBlock is set, we don't need to check the other fields
			if from.IPBlock == nil && from.NamespaceSelector != nil {
				if utils.MatchesSelector(*from.NamespaceSelector, namespace.Labels) {
					logger.V(1).Info("Policy selected by ingress namespace selector")
					return true
				}
			}
		}
	}

	// Egress selectors
	for _, egress := range policy.Spec.Egress {
		for _, to := range egress.To {
			// If IPBlock is set, we don't need to check the other fields
			if to.IPBlock == nil && to.NamespaceSelector != nil {
				if utils.MatchesSelector(*to.NamespaceSelector, namespace.Labels) {
					logger.V(1).Info("Policy selected by egress namespace selector")
					return true
				}
			}
		}
	}

	return false
}

// isPolicyAffectedByPod is the internal implementation without locking
func isPolicyAffectedByPod(policy *multiv1beta1.MultiNetworkPolicy, pod *corev1.Pod, logger logr.Logger) bool {
	// Validate input parameters
	if policy == nil || pod == nil {
		return false
	}

	logger = logger.WithValues("policy", fmt.Sprintf("%s/%s", policy.Namespace, policy.Name))

	// Ingress selectors
	for _, ingress := range policy.Spec.Ingress {
		// If empty or missing, match all pods
		if len(ingress.From) == 0 {
			logger.V(1).Info("Policy selected by ingress allow all")
			return true
		}

		for _, from := range ingress.From {
			// If IPBlock is set, we don't need to check the other fields
			if from.IPBlock != nil {
				continue
			}

			// If only pod selector is set, then the namespace of the policy and the pod must match
			if from.PodSelector != nil && from.NamespaceSelector == nil {
				if pod.Namespace != policy.Namespace {
					continue
				}

				if utils.MatchesSelector(*from.PodSelector, pod.Labels) {
					logger.V(1).Info("Policy selected by ingress pod selector")
					return true
				}
			} else if from.PodSelector != nil {
				if utils.MatchesSelector(*from.PodSelector, pod.Labels) {
					logger.V(1).Info("Policy selected by ingress pod and namespace selector")
					return true
				}
			}
		}
	}

	// Egress selectors
	for _, egress := range policy.Spec.Egress {
		// If empty or missing, match all pods
		if len(egress.To) == 0 {
			logger.V(1).Info("Policy selected by egress allow all")
			return true
		}

		for _, to := range egress.To {
			// If IPBlock is set, we don't need to check the other fields
			if to.IPBlock != nil {
				continue
			}

			// If only pod selector is set, then the namespace of the policy and the pod must match
			if to.PodSelector != nil && to.NamespaceSelector == nil {
				if pod.Namespace != policy.Namespace {
					continue
				}

				if utils.MatchesSelector(*to.PodSelector, pod.Labels) {
					logger.V(1).Info("Policy selected by egress pod selector")
					return true
				}
			} else if to.PodSelector != nil {
				if utils.MatchesSelector(*to.PodSelector, pod.Labels) {
					logger.V(1).Info("Policy selected by egress pod and namespace selector")
					return true
				}
			}
		}
	}

	// If we are here, then the namespace of the policy and the pod must match
	if pod.Namespace != policy.Namespace {
		return false
	}

	// Check policy pod selector
	if utils.MatchesSelector(policy.Spec.PodSelector, pod.Labels) {
		// We only care if the pod is running
		// TODO: find a way to apply the policy only to this particular pod
		// TODO: only if the pod is located in this node - Add hostname check
		if pod.Status.Phase == corev1.PodRunning {
			logger.V(1).Info("Policy selected by policy pod selector", "pod Status", pod.Status.Phase)
			return true
		}
	}

	return false
}
