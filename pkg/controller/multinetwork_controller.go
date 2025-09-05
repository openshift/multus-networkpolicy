// Package controller provides Kubernetes controllers for managing multi-network policies
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/datastore"
	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/nftables"
)

// MultiNetworkReconciler reconciles a MultiNetworkPolicy object
type MultiNetworkReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	DS           *datastore.Datastore
	NFT          nftables.SyncInterface
	ValidPlugins []string
}

// Reconcile handles the reconciliation of MultiNetworkPolicy resources
func (m *MultiNetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("namespace", req.NamespacedName.Namespace, "name", req.NamespacedName.Name)

	logger.Info("Starting reconciliation of MultiNetworkPolicy")

	instance := &multiv1beta1.MultiNetworkPolicy{}
	err := m.Client.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if !errors.IsNotFound(err) {
			logger.Error(err, "Failed to get instance")
			return ctrl.Result{}, err
		}

		err = m.cleanUpPolicy(ctx, req.Name, req.Namespace, logger)
		if err != nil {
			logger.Error(err, "Failed to clean up policy")
			return ctrl.Result{}, err
		}

		// Ignore, not found
		logger.V(1).Info("MultiNetworkPolicy not found, it might have been deleted")
		return ctrl.Result{}, nil
	}

	return m.processPolicy(ctx, instance, logger)
}

// processPolicy validates and processes the MultiNetworkPolicy
func (m *MultiNetworkReconciler) processPolicy(ctx context.Context, instance *multiv1beta1.MultiNetworkPolicy, logger logr.Logger) (ctrl.Result, error) {
	policyForAnnotation, err := getPolicyForAnnotation(instance)
	if err != nil {
		logger.Info("Failed to validate policy-for annotation", "error", err.Error())
		err = m.cleanUpPolicy(ctx, instance.Name, instance.Namespace, logger)
		if err != nil {
			logger.Error(err, "Failed to clean up policy")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Get networks from policy-for annotation
	networks, err := getNetworksInPolicyForAnnotation(policyForAnnotation, instance.Namespace)
	if err != nil {
		logger.Info("Failed to get networks from policy-for annotation", "error", err.Error())
		err = m.cleanUpPolicy(ctx, instance.Name, instance.Namespace, logger)
		if err != nil {
			logger.Error(err, "Failed to clean up policy")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	logger.Info("Networks found in policy-for annotation", "networks", networks)

	// Verify that the networks are allowed by the valid plugins
	allowedNetworks, err := m.getAllowedNetworks(ctx, networks, m.ValidPlugins, logger)
	if err != nil {
		logger.Info("Failed to get allowed networks", "valid plugins", m.ValidPlugins, "error", err.Error())
		err = m.cleanUpPolicy(ctx, instance.Name, instance.Namespace, logger)
		if err != nil {
			logger.Error(err, "Failed to clean up policy")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	logger.Info("Allowed networks", "allowedNetworks", allowedNetworks)

	policy := &datastore.Policy{
		Name:      instance.Name,
		Namespace: instance.Namespace,
		Spec:      instance.Spec,
		Networks:  allowedNetworks,
	}

	err = m.NFT.SyncPolicy(ctx, policy, nftables.SyncOperationCreate, logger)
	if err != nil {
		logger.Error(err, "Failed to sync policies, requeuing")
		return ctrl.Result{}, err
	}

	m.DS.CreatePolicy(policy)

	logger.Info("MultiNetworkPolicy reconciled successfully")
	return ctrl.Result{}, nil
}

// cleanUpPolicy cleans up a policy from the datastore
func (m *MultiNetworkReconciler) cleanUpPolicy(ctx context.Context, name string, namespace string, logger logr.Logger) error {
	policy := m.DS.GetPolicy(types.NamespacedName{Namespace: namespace, Name: name})
	if policy == nil {
		return nil
	}

	err := m.NFT.SyncPolicy(ctx, policy, nftables.SyncOperationDelete, logger)
	if err != nil {
		return fmt.Errorf("failed to sync policy: %w", err)
	}

	m.DS.DeletePolicy(types.NamespacedName{Namespace: namespace, Name: name})
	logger.Info("Policy cleaned up successfully")
	return nil
}

// getPolicyForAnnotation gets the policy-for annotation from the MultiNetworkPolicy
func getPolicyForAnnotation(instance *multiv1beta1.MultiNetworkPolicy) (string, error) {
	annotations := instance.GetAnnotations()
	if annotations == nil {
		return "", fmt.Errorf("MultiNetworkPolicy has no annotations")
	}

	policyForAnnotation, hasAnnotation := annotations[datastore.PolicyForAnnotation]
	if !hasAnnotation {
		return "", fmt.Errorf("missing required annotation %s", datastore.PolicyForAnnotation)
	}

	// Validate PolicyForAnnotation is not empty
	trimmedAnnotation := strings.TrimSpace(policyForAnnotation)
	if trimmedAnnotation == "" {
		return "", fmt.Errorf("annotation %s is empty", datastore.PolicyForAnnotation)
	}

	return trimmedAnnotation, nil
}

// getNetworksInPolicyForAnnotation gets the networks from the policy-for annotation
func getNetworksInPolicyForAnnotation(policyForAnnotation string, namespace string) ([]string, error) {
	// Split by comma and check for at least one valid network name
	networkNames := strings.Split(policyForAnnotation, ",")

	networks := []string{}
	for _, networkName := range networkNames {
		trimmedNetwork := strings.TrimSpace(networkName)
		if trimmedNetwork == "" {
			continue
		}

		// Only allow formats: "name" or "namespace/name"
		if strings.Count(trimmedNetwork, "/") > 1 {
			continue
		}

		var ns string
		var name string

		parts := strings.Split(trimmedNetwork, "/")
		if len(parts) == 2 {
			ns = strings.TrimSpace(parts[0])
			name = strings.TrimSpace(parts[1])
		} else {
			ns = namespace
			name = strings.TrimSpace(parts[0])
		}

		if ns == "" || name == "" {
			continue
		}

		networks = append(networks, fmt.Sprintf("%s/%s", ns, name))
	}

	if len(networks) == 0 {
		return nil, fmt.Errorf("annotation %s contains no valid network names: %s", datastore.PolicyForAnnotation, policyForAnnotation)
	}

	return networks, nil
}

// getAllowedNetworks gets the allowed networks from the networks and the valid plugins
func (m *MultiNetworkReconciler) getAllowedNetworks(ctx context.Context, networks []string, validPlugins []string, logger logr.Logger) ([]string, error) {
	var allowedNetworks []string
	for _, network := range networks {
		parts := strings.Split(network, "/")
		if len(parts) != 2 {
			// Should not happen due to previous validation
			logger.Info("Invalid network format, skipping", "network", network)
			continue
		}

		// Get Network-Attachment-Definition
		var netAttachDef netdefv1.NetworkAttachmentDefinition
		err := m.Client.Get(ctx, types.NamespacedName{Namespace: parts[0], Name: parts[1]}, &netAttachDef)
		if err != nil {
			if errors.IsNotFound(err) {
				// Ignore, not found
				continue
			}

			return nil, fmt.Errorf("failed to get network attachment definition: %w", err)
		}

		networkType, err := getNetworkType(&netAttachDef)
		if err != nil {
			return nil, fmt.Errorf("failed to get network type: %w", err)
		}

		if slices.Contains(validPlugins, networkType) {
			logger.Info("Network type is supported", "network", network, "networkType", networkType)
			allowedNetworks = append(allowedNetworks, network)
		} else {
			logger.Info("Network type is not supported", "network", network, "networkType", networkType)
		}
	}

	if len(allowedNetworks) == 0 {
		return nil, fmt.Errorf("no allowed networks found")
	}

	return allowedNetworks, nil
}

// getNetworkType returns the type of a network
func getNetworkType(netAttachDef *netdefv1.NetworkAttachmentDefinition) (string, error) {
	if netAttachDef == nil {
		return "", fmt.Errorf("network attachment definition is nil")
	}

	var netType string

	confBytes, err := netdefutils.GetCNIConfigFromSpec(netAttachDef.Spec.Config, netAttachDef.Name)
	if err != nil {
		return "", err
	}

	netconfList := &cnitypes.NetConfList{}
	if err := json.Unmarshal(confBytes, netconfList); err != nil {
		return "", err
	}

	if len(netconfList.Plugins) == 0 {
		netconf := &cnitypes.NetConf{}
		if err := json.Unmarshal(confBytes, netconf); err != nil {
			return "", err
		}

		netType = netconf.Type
	} else {
		netType = netconfList.Plugins[0].Type
	}

	return netType, nil
}

// SetupWithManager sets up the controller with the Manager.
func (m *MultiNetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Ensure indexes are set up
	err := setupIndexes(mgr)
	if err != nil {
		return fmt.Errorf("failed to set up indexes: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&multiv1beta1.MultiNetworkPolicy{}).
		WithEventFilter(MultiNetworkPolicyPredicate).
		Watches(
			&corev1.Namespace{},
			// We will enqueue policies with selectors that match the namespace
			handler.EnqueueRequestsFromMapFunc(namespaceEnqueue(m.Client)),
			builder.WithPredicates(NamespacePredicate),
		).
		Watches(
			&corev1.Pod{},
			// We will enqueue policies with selectors that match the pod
			handler.EnqueueRequestsFromMapFunc(podEnqueue(m.Client)),
			builder.WithPredicates(PodPredicate),
		).
		Complete(m)
}
