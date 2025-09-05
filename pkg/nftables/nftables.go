// Package nftables provides the tools to apply nftables rules based on the MultiNetworkPolicy resource
package nftables

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/cri"
	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/datastore"
)

const (
	tableName = "multi_networkpolicy"

	inputChain         = "input"
	outputChain        = "output"
	ingressChain       = "ingress"
	egressChain        = "egress"
	commonIngressChain = "common-ingress"
	commonEgressChain  = "common-egress"

	dropRuleComment               = "Drop rule"
	connectionTrackingRuleComment = "Connection tracking"
	jumpCommonRuleComment         = "Jump to common"

	prefixManagedInterfacesSet = "smi-"
	prefixNetworkPolicyChain   = "cnp-"
	prefixNetworkPolicySet     = "snp-"

	PodHostnameIndex             = "pod.spec.nodeName"
	PodStatusIndex               = "pod.status.phase"
	PodHostNetworkIndex          = "pod.spec.hostNetwork"
	PodHasNetworkAnnotationIndex = "k8s.v1.cni.cncf.io/networks"
)

type SyncInterface interface {
	SyncPolicy(ctx context.Context, policy *datastore.Policy, operation SyncOperation, logger logr.Logger) error
}

var _ SyncInterface = &NFTables{}

// NFTables is the struct that contains the nftables client and the datastore
type NFTables struct {
	client.Client
	Hostname    string
	CriRuntime  *cri.Runtime
	CommonRules *CommonRules
}

type SyncError struct {
	message string
}

func (e *SyncError) Error() string {
	return e.message
}

func NewSyncError(format string, args ...interface{}) *SyncError {
	return &SyncError{message: fmt.Sprintf(format, args...)}
}

// CommonRules represents the common rules to be applied to all policies
type CommonRules struct {
	AcceptICMP   bool
	AcceptICMPv6 bool

	CustomIPv4IngressRules []string
	CustomIPv6IngressRules []string
	CustomIPv4EgressRules  []string
	CustomIPv6EgressRules  []string
}

// Interface represents a network interface
type Interface struct {
	Name    string
	Network string
	IPs     []string
}

type SyncOperation string

const (
	SyncOperationCreate SyncOperation = "create"
	SyncOperationDelete SyncOperation = "delete"
)

// SyncPolicy syncs the policy to the nftables
func (n *NFTables) SyncPolicy(ctx context.Context, policy *datastore.Policy, operation SyncOperation, logger logr.Logger) error {
	logger.Info("Syncing policy")

	pods := &corev1.PodList{}
	err := n.Client.List(ctx, pods,
		client.InNamespace(policy.Namespace),
		client.MatchingFields{
			PodHostnameIndex:             n.Hostname,
			PodStatusIndex:               string(corev1.PodRunning),
			PodHostNetworkIndex:          "false",
			PodHasNetworkAnnotationIndex: "true",
		})
	if err != nil {
		return fmt.Errorf("failed to list pods for hostname %s: %w", n.Hostname, err)
	}

	if len(pods.Items) == 0 {
		logger.Info("No pods found to enforce policy, skipping")
		return nil
	}

	logger.Info("Found pods to enforce policy", "hostname", n.Hostname, "count", len(pods.Items))

	// Generate nftables rules
	for _, pod := range pods.Items {
		logger := logger.WithValues("pod", pod.Name, "namespace", pod.Namespace)

		interfaces := getInterfaces(&pod)

		if len(interfaces) == 0 {
			logger.V(1).Info("No interfaces found, skipping")
			continue
		}

		netnsPath, err := n.CriRuntime.GetPodNetNSPath(ctx, &pod)
		if err != nil {
			return fmt.Errorf("failed to get network namespace path: %w", err)
		}

		netns, err := ns.GetNS(netnsPath)
		if err != nil {
			logger.V(1).Info("Failed to open network namespace, skipping")
			continue
		}

		// Use anonymous function to ensure netns is always closed for this iteration
		err = func() error {
			defer netns.Close()
			return netns.Do(func(_ ns.NetNS) error {
				var err error
				if operation == SyncOperationDelete {
					err = cleanUpPolicy(ctx, policy.Name, policy.Namespace, logger)
				}

				if operation == SyncOperationCreate {
					err = n.enforcePolicy(ctx, &pod, interfaces, policy, logger)
				}

				if err != nil {
					return NewSyncError("failed to enforce NFTables policies: %v", err)
				}

				return nil
			})
		}()
		if err != nil {
			// Check if this is an actual nftables error vs pod lifecycle error
			var syncError *SyncError
			if errors.As(err, &syncError) {
				return err
			}

			logger.Info("Pod lifecycle error, ignoring", "error", err)
		}
	}

	return nil
}

// getInterfaces gets the interfaces for a pod
func getInterfaces(pod *corev1.Pod) []Interface {
	networks, _ := netdefutils.ParsePodNetworkAnnotation(pod)

	networkNames := make([]string, 0, len(networks))
	for _, network := range networks {
		networkNames = append(networkNames, network.Name)
	}

	networkStatus, _ := netdefutils.GetNetworkStatus(pod)

	var interfaces []Interface
	for _, status := range networkStatus {
		var name string
		var namespace string

		// Parse name
		slashItems := strings.Split(status.Name, "/")
		if len(slashItems) == 2 {
			namespace = strings.TrimSpace(slashItems[0])
			name = strings.TrimSpace(slashItems[1])
		} else {
			namespace = pod.Namespace
			name = strings.TrimSpace(status.Name)
		}

		// Check if network is in the list of networks
		if !slices.Contains(networkNames, name) {
			continue
		}

		intf := Interface{
			Name:    status.Interface,
			Network: fmt.Sprintf("%s/%s", namespace, name),
			IPs:     status.IPs,
		}

		interfaces = append(interfaces, intf)
	}

	return interfaces
}

// getMatchedInterfaces returns the interfaces that match the given networks
func getMatchedInterfaces(interfaces []Interface, networks []string) []Interface {
	var matchedInterfaces []Interface
	for _, intf := range interfaces {
		if slices.Contains(networks, intf.Network) {
			matchedInterfaces = append(matchedInterfaces, intf)
		}
	}

	return matchedInterfaces
}

// checkPolicyTypes checks if the policy has ingress or egress enabled
func checkPolicyTypes(policy *datastore.Policy) (bool, bool) {
	// if no policy types are specified, ingress is always set
	if len(policy.Spec.PolicyTypes) == 0 {
		return true, len(policy.Spec.Egress) > 0
	}

	return slices.Contains(policy.Spec.PolicyTypes, multiv1beta1.PolicyTypeIngress), slices.Contains(policy.Spec.PolicyTypes, multiv1beta1.PolicyTypeEgress)
}
