package nftables

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/knftables"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/datastore"
	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/utils"
)

// enforcePolicy applies the NFTables policy for a pod
func (n *NFTables) enforcePolicy(ctx context.Context, pod *corev1.Pod, interfaces []Interface, policy *datastore.Policy, logger logr.Logger) error {
	logger.Info("Applying policy")

	nft, err := knftables.New(knftables.InetFamily, tableName)
	if err != nil {
		return fmt.Errorf("failed to create nftables client: %w", err)
	}

	// Clean up the policy even if the pod is not matched by the policy
	err = cleanUp(ctx, nft, policy.Name, policy.Namespace, logger)
	if err != nil {
		return fmt.Errorf("failed to clean up policy: %w", err)
	}

	if !utils.MatchesSelector(policy.Spec.PodSelector, pod.Labels) {
		logger.Info("Pod not matched by policy pod selector, skipping")
		return nil
	}

	// Find the interfaces on the pod that belong to the networks of the policy (Policy-for annotation)
	matchedInterfaces := getMatchedInterfaces(interfaces, policy.Networks)
	if len(matchedInterfaces) == 0 {
		logger.Info("No matched interfaces found, skipping")
		return nil
	}

	logger.Info("Found interfaces matched by policy", "matchedInterfaces", matchedInterfaces)

	// It creates the input, output chains and the common-ingress and common-egress chains
	// It also ensures the policy type structure for ingress and egress which is a connection tracking rule
	// and a jump rule to the common-ingress and common-egress chains, and a drop rule at the end of the chain
	err = ensureBasicStructure(ctx, nft, n.CommonRules, logger)
	if err != nil {
		return fmt.Errorf("failed to ensure basic structure: %w", err)
	}

	// Get the first 16 characters of the SHA256 hash of the namespace name of the policy to be used as nft object identifier
	hashName := utils.GetHashName(policy.Name, policy.Namespace)

	// We will apply all generated rules in a single transaction
	tx := nft.NewTransaction()

	// Create a set with the interfaces that are managed by the policy in the input and output chains
	createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

	// Check if the policy has ingress or egress enabled
	ingressEnabled, egressEnabled := checkPolicyTypes(policy)

	logger.Info("Policy types", "ingressEnabled", ingressEnabled, "egressEnabled", egressEnabled)

	mnpChainName := fmt.Sprintf("%s%s", prefixNetworkPolicyChain, hashName)

	if ingressEnabled {
		logger.V(1).Info("Enforcing ingress rules")

		dispatcherRuleComment := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
		createDispatcherRule(tx, hashName, inputChain, dispatcherRuleComment, logger)

		err = createPolicyChain(ctx, nft, tx, mnpChainName, ingressChain, policy.Namespace, policy.Name, logger)
		if err != nil {
			return fmt.Errorf("failed to create policy chain: %w", err)
		}

		err = n.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
		if err != nil {
			return fmt.Errorf("failed to apply ingress rules: %w", err)
		}

		logger.Info("Ingress rules applied")
	}

	if egressEnabled {
		logger.V(1).Info("Enforcing egress rules")

		dispatcherRuleComment := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
		createDispatcherRule(tx, hashName, outputChain, dispatcherRuleComment, logger)

		err = createPolicyChain(ctx, nft, tx, mnpChainName, egressChain, policy.Namespace, policy.Name, logger)
		if err != nil {
			return fmt.Errorf("failed to create policy chain: %w", err)
		}

		err = n.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
		if err != nil {
			return fmt.Errorf("failed to apply egress rules: %w", err)
		}

		logger.Info("Egress rules applied")
	}

	err = nft.Run(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to run transaction: %w", err)
	}

	return nil
}

// ensureBasicStructure ensures the basic NFTables structure
func ensureBasicStructure(ctx context.Context, nft knftables.Interface, commonRules *CommonRules, logger logr.Logger) error {
	logger.Info("Ensuring basic NFTables structure")

	tx := nft.NewTransaction()

	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("MultiNetworkPolicy"),
	})

	// Add the input chain
	tx.Add(&knftables.Chain{
		Name:     inputChain,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.InputHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
		Comment:  knftables.PtrTo("Input Dispatcher"),
	})

	// Add the output chain
	tx.Add(&knftables.Chain{
		Name:     outputChain,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.FilterPriority),
		Comment:  knftables.PtrTo("Output Dispatcher"),
	})

	// Ensure policy type structure for ingress
	err := policyTypeStructure(ctx, nft, tx, ingressChain, "Ingress Policies", commonIngressChain, logger)
	if err != nil {
		return fmt.Errorf("failed to ensure policy type structure for ingress: %w", err)
	}

	// Ensure policy type structure for egress
	err = policyTypeStructure(ctx, nft, tx, egressChain, "Egress Policies", commonEgressChain, logger)
	if err != nil {
		return fmt.Errorf("failed to ensure policy type structure for egress: %w", err)
	}

	// Create common rules
	createCommonRules(tx, commonRules, logger)

	err = nft.Run(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to run transaction: %w", err)
	}

	return nil
}

// policyTypeStructure ensures the basic NFTables structure for a policy type
func policyTypeStructure(ctx context.Context, nft knftables.Interface, tx *knftables.Transaction, chainName string, chainComment string, commonChainName string, logger logr.Logger) error {
	// Add ingress objects
	tx.Add(&knftables.Chain{
		Name:    chainName,
		Comment: knftables.PtrTo(chainComment),
	})

	tx.Add(&knftables.Chain{
		Name:    commonChainName,
		Comment: knftables.PtrTo("Common Policies"),
	})

	// Ensure connection tracking rule in chain
	connectionTrackingRule, err := findRuleInChain(ctx, nft, chainName, connectionTrackingRuleComment)
	if err != nil {
		return fmt.Errorf("failed to find connection tracking rule in %s chain: %w", chainName, err)
	}

	if connectionTrackingRule == nil {
		// First time we run, we need to add the connection tracking rule
		logger.V(1).Info("Adding connection tracking rule to chain", "chain", chainName)
		tx.Add(&knftables.Rule{
			Chain:   chainName,
			Rule:    knftables.Concat("ct state established,related accept"),
			Comment: knftables.PtrTo(connectionTrackingRuleComment),
		})
	}

	// Ensure jump rule to common chain
	jumpCommonRule, err := findRuleInChain(ctx, nft, chainName, jumpCommonRuleComment)
	if err != nil {
		return fmt.Errorf("failed to find jump rule to common in %s chain: %w", chainName, err)
	}

	if jumpCommonRule == nil {
		// First time we run, we need to add the jump rule
		logger.V(1).Info("Adding jump rule to common chain", "chain", chainName)
		tx.Add(&knftables.Rule{
			Chain:   chainName,
			Rule:    knftables.Concat("jump", commonChainName),
			Comment: knftables.PtrTo(jumpCommonRuleComment),
		})
	}

	// Ensure drop rule in chain
	dropRule, err := findRuleInChain(ctx, nft, chainName, dropRuleComment)
	if err != nil {
		return fmt.Errorf("failed to find drop rule in %s chain: %w", chainName, err)
	}

	if dropRule == nil {
		// First time we run, we need to add the drop rule
		logger.V(1).Info("Adding drop rule to chain", "chain", chainName)
		tx.Add(&knftables.Rule{
			Chain:   chainName,
			Rule:    knftables.Concat("drop"),
			Comment: knftables.PtrTo(dropRuleComment),
		})
	}

	return nil
}

// createCommonRules creates the common rules in the common chains
func createCommonRules(tx *knftables.Transaction, commonRules *CommonRules, logger logr.Logger) {
	logger.Info("Creating common rules")

	if commonRules == nil {
		logger.Info("No common rules specified, skipping")
		return
	}

	// Flush common chains to ensure no stale rules
	tx.Flush(&knftables.Chain{
		Name: commonIngressChain,
	})

	tx.Flush(&knftables.Chain{
		Name: commonEgressChain,
	})

	if commonRules.AcceptICMP {
		logger.Info("Adding rule to accept ICMP traffic in common ingress and egress chains")
		// Accept ICMP traffic in common ingress chain
		tx.Add(&knftables.Rule{
			Chain:   commonIngressChain,
			Rule:    knftables.Concat("meta l4proto icmp accept"),
			Comment: knftables.PtrTo("Accept ICMP"),
		})

		// Accept ICMP traffic in common egress chain
		tx.Add(&knftables.Rule{
			Chain:   commonEgressChain,
			Rule:    knftables.Concat("meta l4proto icmp accept"),
			Comment: knftables.PtrTo("Accept ICMP"),
		})
	}

	if commonRules.AcceptICMPv6 {
		logger.Info("Adding rule to accept ICMPv6 traffic in common ingress and egress chains")
		// Accept ICMPv6 traffic in common ingress chain
		tx.Add(&knftables.Rule{
			Chain:   commonIngressChain,
			Rule:    knftables.Concat("meta l4proto icmpv6 accept"),
			Comment: knftables.PtrTo("Accept ICMPv6"),
		})

		// Accept ICMPv6 traffic in common egress chain
		tx.Add(&knftables.Rule{
			Chain:   commonEgressChain,
			Rule:    knftables.Concat("meta l4proto icmpv6 accept"),
			Comment: knftables.PtrTo("Accept ICMPv6"),
		})
	}

	// Add custom rules to common ingress chain
	combined := commonRules.CustomIPv4IngressRules
	combined = append(combined, commonRules.CustomIPv6IngressRules...)
	for _, rule := range combined {
		logger.V(1).Info("Adding custom rule to common ingress chain", "rule", rule)
		tx.Add(&knftables.Rule{
			Chain:   commonIngressChain,
			Rule:    rule,
			Comment: knftables.PtrTo("Custom Rule"),
		})
	}

	// Add custom rules to common egress chain
	combined = commonRules.CustomIPv4EgressRules
	combined = append(combined, commonRules.CustomIPv6EgressRules...)
	for _, rule := range combined {
		logger.V(1).Info("Adding custom rule to common egress chain", "rule", rule)
		tx.Add(&knftables.Rule{
			Chain:   commonEgressChain,
			Rule:    rule,
			Comment: knftables.PtrTo("Custom Rule"),
		})
	}
}

// createManagedInterfacesSet creates the managed interfaces set
func createManagedInterfacesSet(tx *knftables.Transaction, matchedInterfaces []Interface, hashName string, policyNamespace string, policyName string, logger logr.Logger) {
	logger.Info("Creating managed interfaces set")

	name := fmt.Sprintf("%s%s", prefixManagedInterfacesSet, hashName)

	tx.Add(&knftables.Set{
		Name:    name,
		Type:    "ifname",
		Comment: knftables.PtrTo(fmt.Sprintf("Managed interfaces set for %s/%s", policyNamespace, policyName)),
	})

	// Add interfaces to the managed interfaces set
	for _, intf := range matchedInterfaces {
		logger.V(1).Info("Adding interface to managed interfaces set", "interface", intf.Name)
		tx.Add(&knftables.Element{
			Set: name,
			Key: []string{intf.Name},
		})
	}
}

// createDispatcherRule creates the dispatcher rule in the dispatcher chain
func createDispatcherRule(tx *knftables.Transaction, hashName string, dispatcherChainName string, comment string, logger logr.Logger) {
	logger.Info("Creating dispatcher rule in dispatcher chain", "dispatcherChainName", dispatcherChainName)

	managedInterfacesSetName := fmt.Sprintf("%s%s", prefixManagedInterfacesSet, hashName)

	trafficDirection := "iifname"
	policyTypeChainName := "ingress"
	if dispatcherChainName == outputChain {
		trafficDirection = "oifname"
		policyTypeChainName = "egress"
	}

	tx.Add(&knftables.Rule{
		Chain:   dispatcherChainName,
		Rule:    knftables.Concat(trafficDirection, fmt.Sprintf("@%s", managedInterfacesSetName), "jump", policyTypeChainName),
		Comment: knftables.PtrTo(comment),
	})
}

// createPolicyChain creates the policy chain and jump rule from policy type chain
func createPolicyChain(ctx context.Context, nft knftables.Interface, tx *knftables.Transaction, npChainName string, policyTypeChainName string, namespace string, name string, logger logr.Logger) error {
	logger.Info("Creating policy chain", "npChainName", npChainName)

	tx.Add(&knftables.Chain{
		Name:    npChainName,
		Comment: knftables.PtrTo(fmt.Sprintf("MultiNetworkPolicy %s/%s", namespace, name)),
	})

	// Find drop rule in policy chain
	dropRule, err := findRuleInChain(ctx, nft, policyTypeChainName, dropRuleComment)
	if err != nil || dropRule == nil {
		// Should never happen
		return fmt.Errorf("failed to find drop rule in %s chain: %w", policyTypeChainName, err)
	}

	// Insert jump rule before the drop rule
	tx.Insert(&knftables.Rule{
		Chain:   policyTypeChainName,
		Rule:    knftables.Concat("jump", npChainName),
		Comment: knftables.PtrTo(fmt.Sprintf("%s/%s", namespace, name)),
		Handle:  dropRule.Handle,
	})

	return nil
}

// createIngressRules creates the ingress rules for a policy
func (n *NFTables) createIngressRules(ctx context.Context, tx *knftables.Transaction, matchedInterfaces []Interface, policy *datastore.Policy, hashName string, logger logr.Logger) error {
	logger.Info("Creating ingress rules")

	npChainName := fmt.Sprintf("%s%s", prefixNetworkPolicyChain, hashName)

	// Reverse rules for IPv4 and IPv6 - hairpinning
	createReverseRules(tx, matchedInterfaces, npChainName, logger)

	if len(policy.Spec.Ingress) == 0 {
		logger.Info("No ingress rules specified, no rules will be created")
		return nil
	}

	for i, peer := range policy.Spec.Ingress {
		logger.V(1).Info("Processing ingress peer", "index", i)

		var portRuleSections []string
		if len(peer.Ports) > 0 {
			portRuleSections = getPortRuleSections(peer.Ports)
		}

		// Allow all traffic
		if len(peer.From) == 0 {
			logger.Info("No sources specified, accepting traffic from all sources")

			var ipRuleSections []string
			for _, intf := range matchedInterfaces {
				ipRuleSections = append(ipRuleSections, knftables.Concat("iifname", intf.Name))
			}

			createRules(tx, npChainName, ipRuleSections, portRuleSections, logger)
			continue
		}

		logger.V(1).Info("Processing ingress peer with sources specified")

		// Get the peer info which contains the pods, cidrs and excepts
		peerInfo, err := n.parsePeers(ctx, peer.From, policy.Namespace, logger)
		if err != nil {
			return fmt.Errorf("failed to parse peers: %w", err)
		}

		var ipRuleSections []string

		if len(peerInfo.pods) != 0 {
			logger.V(1).Info("Found pods selected by peer's selectors", "count", len(peerInfo.pods))

			podInterfacesMap := getPodInterfacesMap(peerInfo.pods, policy.Networks)

			// We need to process each interface individually
			for _, intf := range matchedInterfaces {
				// Create the IP addresses set for the interface.
				// Sets cannot be inet family, so we need to create separate sets for IPv4 and IPv6
				// Each ingress entry will have its own set for the interface
				ipv4SetName := fmt.Sprintf("%s%s_ingress_ipv4_%s_%d", prefixNetworkPolicySet, hashName, intf.Name, i)
				ipv6SetName := fmt.Sprintf("%s%s_ingress_ipv6_%s_%d", prefixNetworkPolicySet, hashName, intf.Name, i)
				setComment := fmt.Sprintf("Addresses for %s/%s", policy.Namespace, policy.Name)

				ipv4Addresses, ipv6Addresses := classifyAddresses(podInterfacesMap, intf.Network)

				if len(ipv4Addresses) > 0 {
					createAndPopulateIPSet(tx, ipv4SetName, "ipv4_addr", setComment, ipv4Addresses, false)
					ipRuleSections = append(ipRuleSections, knftables.Concat("iifname", intf.Name, "ip", "saddr", fmt.Sprintf("@%s", ipv4SetName)))
				}

				if len(ipv6Addresses) > 0 {
					createAndPopulateIPSet(tx, ipv6SetName, "ipv6_addr", setComment, ipv6Addresses, false)
					ipRuleSections = append(ipRuleSections, knftables.Concat("iifname", intf.Name, "ip6", "saddr", fmt.Sprintf("@%s", ipv6SetName)))
				}
			}
		}

		if len(peerInfo.cidrs) > 0 {
			logger.V(1).Info("Found IP blocks", "cidrs", len(peerInfo.cidrs), "excepts", len(peerInfo.excepts))

			ipv4CidrsSetName := fmt.Sprintf("%s%s_ingress_ipv4_cidr_%d", prefixNetworkPolicySet, hashName, i)
			ipv6CidrsSetName := fmt.Sprintf("%s%s_ingress_ipv6_cidr_%d", prefixNetworkPolicySet, hashName, i)
			cidrsSetComment := fmt.Sprintf("CIDRs for %s/%s", policy.Namespace, policy.Name)

			ipv4ExceptsSetName := fmt.Sprintf("%s%s_ingress_ipv4_except_%d", prefixNetworkPolicySet, hashName, i)
			ipv6ExceptsSetName := fmt.Sprintf("%s%s_ingress_ipv6_except_%d", prefixNetworkPolicySet, hashName, i)
			exceptsSetComment := fmt.Sprintf("Excepts for %s/%s", policy.Namespace, policy.Name)

			ipv4CIDRs, ipv6CIDRs := utils.SplitCIDRs(peerInfo.cidrs)
			ipv4Excepts, ipv6Excepts := utils.SplitCIDRs(peerInfo.excepts)

			if len(ipv4CIDRs) > 0 {
				createAndPopulateIPSet(tx, ipv4CidrsSetName, "ipv4_addr", cidrsSetComment, ipv4CIDRs, true)
				if len(ipv4Excepts) > 0 {
					createAndPopulateIPSet(tx, ipv4ExceptsSetName, "ipv4_addr", exceptsSetComment, ipv4Excepts, true)
				}
			}

			if len(ipv6CIDRs) > 0 {
				createAndPopulateIPSet(tx, ipv6CidrsSetName, "ipv6_addr", cidrsSetComment, ipv6CIDRs, true)
				if len(ipv6Excepts) > 0 {
					createAndPopulateIPSet(tx, ipv6ExceptsSetName, "ipv6_addr", exceptsSetComment, ipv6Excepts, true)
				}
			}

			managedInterfacesSetName := fmt.Sprintf("%s%s", prefixManagedInterfacesSet, hashName)
			if len(ipv4CIDRs) > 0 {
				rule := knftables.Concat("iifname", fmt.Sprintf("@%s", managedInterfacesSetName), "ip", "saddr", fmt.Sprintf("@%s", ipv4CidrsSetName))
				if len(ipv4Excepts) > 0 {
					rule = knftables.Concat(rule, "ip", "saddr", "!=", fmt.Sprintf("@%s", ipv4ExceptsSetName))
				}

				ipRuleSections = append(ipRuleSections, rule)
			}

			if len(ipv6CIDRs) > 0 {
				rule := knftables.Concat("iifname", fmt.Sprintf("@%s", managedInterfacesSetName), "ip6", "saddr", fmt.Sprintf("@%s", ipv6CidrsSetName))
				if len(ipv6Excepts) > 0 {
					rule = knftables.Concat(rule, "ip6", "saddr", "!=", fmt.Sprintf("@%s", ipv6ExceptsSetName))
				}

				ipRuleSections = append(ipRuleSections, rule)
			}
		}

		createRules(tx, npChainName, ipRuleSections, portRuleSections, logger)
	}

	return nil
}

// createEgressRules creates the egress rules for a policy
func (n *NFTables) createEgressRules(ctx context.Context, tx *knftables.Transaction, matchedInterfaces []Interface, policy *datastore.Policy, hashName string, logger logr.Logger) error {
	logger.Info("Creating egress rules")

	npChainName := fmt.Sprintf("%s%s", prefixNetworkPolicyChain, hashName)

	if len(policy.Spec.Egress) == 0 {
		logger.Info("No egress rules specified, no rules will be created")
		return nil
	}

	for i, peer := range policy.Spec.Egress {
		logger.V(1).Info("Processing egress peer", "index", i)

		var portRuleSections []string
		if len(peer.Ports) > 0 {
			portRuleSections = getPortRuleSections(peer.Ports)
		}

		// Allow all traffic
		if len(peer.To) == 0 {
			logger.Info("No destinations specified, accepting traffic to all destinations")

			var ipRuleSections []string
			for _, intf := range matchedInterfaces {
				ipRuleSections = append(ipRuleSections, knftables.Concat("oifname", intf.Name))
			}

			createRules(tx, npChainName, ipRuleSections, portRuleSections, logger)
			continue
		}

		logger.V(1).Info("Processing egress peer with destinations specified")

		// Get the peer info which contains the pods, cidrs and excepts
		peerInfo, err := n.parsePeers(ctx, peer.To, policy.Namespace, logger)
		if err != nil {
			return fmt.Errorf("failed to parse peers: %w", err)
		}

		var ipRuleSections []string

		if len(peerInfo.pods) != 0 {
			logger.V(1).Info("Found pods selected by peer's selectors", "count", len(peerInfo.pods))

			podInterfacesMap := getPodInterfacesMap(peerInfo.pods, policy.Networks)

			// We need to process each interface individually
			for _, intf := range matchedInterfaces {
				// Create the IP addresses set for the interface.
				// Sets cannot be inet family, so we need to create separate sets for IPv4 and IPv6
				// Each egress entry will have its own set for the interface
				ipv4SetName := fmt.Sprintf("%s%s_egress_ipv4_%s_%d", prefixNetworkPolicySet, hashName, intf.Name, i)
				ipv6SetName := fmt.Sprintf("%s%s_egress_ipv6_%s_%d", prefixNetworkPolicySet, hashName, intf.Name, i)
				setComment := fmt.Sprintf("Addresses for %s/%s", policy.Namespace, policy.Name)

				ipv4Addresses, ipv6Addresses := classifyAddresses(podInterfacesMap, intf.Network)

				if len(ipv4Addresses) > 0 {
					createAndPopulateIPSet(tx, ipv4SetName, "ipv4_addr", setComment, ipv4Addresses, false)
					ipRuleSections = append(ipRuleSections, knftables.Concat("oifname", intf.Name, "ip", "daddr", fmt.Sprintf("@%s", ipv4SetName)))
				}

				if len(ipv6Addresses) > 0 {
					createAndPopulateIPSet(tx, ipv6SetName, "ipv6_addr", setComment, ipv6Addresses, false)
					ipRuleSections = append(ipRuleSections, knftables.Concat("oifname", intf.Name, "ip6", "daddr", fmt.Sprintf("@%s", ipv6SetName)))
				}
			}
		}

		if len(peerInfo.cidrs) > 0 {
			logger.V(1).Info("Found IP blocks", "cidrs", len(peerInfo.cidrs), "excepts", len(peerInfo.excepts))

			ipv4CidrsSetName := fmt.Sprintf("%s%s_egress_ipv4_cidr_%d", prefixNetworkPolicySet, hashName, i)
			ipv6CidrsSetName := fmt.Sprintf("%s%s_egress_ipv6_cidr_%d", prefixNetworkPolicySet, hashName, i)
			cidrsSetComment := fmt.Sprintf("CIDRs for %s/%s", policy.Namespace, policy.Name)

			ipv4ExceptsSetName := fmt.Sprintf("%s%s_egress_ipv4_except_%d", prefixNetworkPolicySet, hashName, i)
			ipv6ExceptsSetName := fmt.Sprintf("%s%s_egress_ipv6_except_%d", prefixNetworkPolicySet, hashName, i)
			exceptsSetComment := fmt.Sprintf("Excepts for %s/%s", policy.Namespace, policy.Name)

			ipv4CIDRs, ipv6CIDRs := utils.SplitCIDRs(peerInfo.cidrs)
			ipv4Excepts, ipv6Excepts := utils.SplitCIDRs(peerInfo.excepts)

			if len(ipv4CIDRs) > 0 {
				createAndPopulateIPSet(tx, ipv4CidrsSetName, "ipv4_addr", cidrsSetComment, ipv4CIDRs, true)
				if len(ipv4Excepts) > 0 {
					createAndPopulateIPSet(tx, ipv4ExceptsSetName, "ipv4_addr", exceptsSetComment, ipv4Excepts, true)
				}
			}

			if len(ipv6CIDRs) > 0 {
				createAndPopulateIPSet(tx, ipv6CidrsSetName, "ipv6_addr", cidrsSetComment, ipv6CIDRs, true)
				if len(ipv6Excepts) > 0 {
					createAndPopulateIPSet(tx, ipv6ExceptsSetName, "ipv6_addr", exceptsSetComment, ipv6Excepts, true)
				}
			}

			managedInterfacesSetName := fmt.Sprintf("%s%s", prefixManagedInterfacesSet, hashName)
			if len(ipv4CIDRs) > 0 {
				rule := knftables.Concat("oifname", fmt.Sprintf("@%s", managedInterfacesSetName), "ip", "daddr", fmt.Sprintf("@%s", ipv4CidrsSetName))
				if len(ipv4Excepts) > 0 {
					rule = knftables.Concat(rule, "ip", "daddr", "!=", fmt.Sprintf("@%s", ipv4ExceptsSetName))
				}

				ipRuleSections = append(ipRuleSections, rule)
			}

			if len(ipv6CIDRs) > 0 {
				rule := knftables.Concat("oifname", fmt.Sprintf("@%s", managedInterfacesSetName), "ip6", "daddr", fmt.Sprintf("@%s", ipv6CidrsSetName))
				if len(ipv6Excepts) > 0 {
					rule = knftables.Concat(rule, "ip6", "daddr", "!=", fmt.Sprintf("@%s", ipv6ExceptsSetName))
				}

				ipRuleSections = append(ipRuleSections, rule)
			}
		}

		createRules(tx, npChainName, ipRuleSections, portRuleSections, logger)
	}

	return nil
}

// createReverseRules creates the reverse rules for the policy chain
func createReverseRules(tx *knftables.Transaction, matchedInterfaces []Interface, npChainName string, logger logr.Logger) {
	logger.Info("Creating reverse routes")

	for _, intf := range matchedInterfaces {
		for _, ip := range intf.IPs {
			// Validate IP address
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				logger.V(1).Info("Skipping invalid IP address", "ip", ip, "interface", intf.Name)
				continue
			}

			// Find ip version
			ipVersion := "ip"
			if parsedIP.To4() == nil {
				ipVersion = "ip6"
			}

			// Create the reverse route
			tx.Add(&knftables.Rule{
				Chain: npChainName,
				Rule:  knftables.Concat("iifname", intf.Name, ipVersion, "saddr", ip, "accept"),
			})
		}
	}
}

// findRuleInChain finds a rule in a chain by comment
func findRuleInChain(ctx context.Context, nft knftables.Interface, chain string, comment string) (*knftables.Rule, error) {
	rules, err := nft.ListRules(ctx, chain)
	if err != nil {
		// Ignore not found error
		if !knftables.IsNotFound(err) {
			return nil, fmt.Errorf("failed to list rules in chain %s: %w", chain, err)
		}
	}

	for _, rule := range rules {
		if rule.Comment != nil && *rule.Comment == comment {
			return rule, nil
		}
	}

	return nil, nil
}

// getPortRuleSections gets the port rule sections for a policy
func getPortRuleSections(ports []multiv1beta1.MultiNetworkPolicyPort) []string {
	protocolToPorts := make(map[string][]string)
	for _, port := range ports {
		p := corev1.ProtocolTCP
		if port.Protocol != nil {
			p = *port.Protocol
		}

		protocol := strings.ToLower(string(p))
		if port.Port != nil {
			if port.EndPort != nil {
				protocolToPorts[protocol] = append(protocolToPorts[protocol], fmt.Sprintf("%s-%d", port.Port.String(), *port.EndPort))
			} else {
				// Handle both integer and string ports
				if port.Port.Type == intstr.String {
					// For named ports (strings), convert to lowercase
					portStr := strings.ToLower(port.Port.StrVal)
					protocolToPorts[protocol] = append(protocolToPorts[protocol], portStr)
				} else {
					protocolToPorts[protocol] = append(protocolToPorts[protocol], port.Port.String())
				}
			}
		} else {
			if _, exists := protocolToPorts[protocol]; !exists {
				protocolToPorts[protocol] = nil
			}
		}
	}

	// Generate the rule sections for the ports
	var portRuleSections []string
	for protocol, ports := range protocolToPorts {
		if ports == nil {
			portRuleSections = append(portRuleSections, knftables.Concat("meta", "l4proto", protocol, "accept"))
		} else {
			// Anonymous set for the ports
			joinedPorts := strings.Join(ports, ",")
			portRuleSections = append(portRuleSections, knftables.Concat("meta", "l4proto", protocol, "th", "dport", "{", joinedPorts, "}", "accept"))
		}
	}

	return portRuleSections
}

// createRules creates the rules for the policy chain
func createRules(tx *knftables.Transaction, npChainName string, ipRuleSections []string, portRuleSections []string, logger logr.Logger) {
	if len(portRuleSections) == 0 {
		logger.V(1).Info("No port restrictions specified, creating rules with just IP restrictions", "ipRuleSections", ipRuleSections)
		for _, ipRuleSection := range ipRuleSections {
			tx.Add(&knftables.Rule{
				Chain: npChainName,
				Rule:  knftables.Concat(ipRuleSection, "accept"),
			})
		}
	} else {
		logger.V(1).Info("Port restrictions specified, creating rules with both IP and port restrictions", "ipRuleSections", ipRuleSections, "portRuleSections", portRuleSections)
		for _, ipRuleSection := range ipRuleSections {
			for _, portRuleSection := range portRuleSections {
				tx.Add(&knftables.Rule{
					Chain: npChainName,
					Rule:  knftables.Concat(ipRuleSection, portRuleSection),
				})
			}
		}
	}
}

// peerInfo contains the information for a peer
type peerInfo struct {
	pods    []corev1.Pod
	cidrs   []string
	excepts []string
}

// parsePeers parses the peers and returns the peer info
func (n *NFTables) parsePeers(ctx context.Context, peers []multiv1beta1.MultiNetworkPolicyPeer, policyNamespace string, logger logr.Logger) (*peerInfo, error) {
	logger.V(1).Info("Parsing peers", "peers", peers)

	var pods []corev1.Pod
	var cidrs []string
	var excepts []string

	// To avoid duplicates
	podMap := make(map[string]corev1.Pod)

	for _, peer := range peers {
		if peer.IPBlock != nil {
			cidrs = append(cidrs, peer.IPBlock.CIDR)
			excepts = append(excepts, peer.IPBlock.Except...)

			// When IPBlock is set, we don't need to check the other fields
			continue
		}

		switch {
		case peer.NamespaceSelector != nil && peer.PodSelector != nil:
			// When both namespace selector and pod selector are set, we first need to get the namespaces by namespace selector
			// and then get the pods from the namespaces by pod selector
			namespaces, err := n.getNamespacesByNamespaceSelector(ctx, peer.NamespaceSelector)
			if err != nil {
				return nil, fmt.Errorf("failed to get namespaces by namespace selector: %w", err)
			}

			for _, ns := range namespaces {
				namespacePods, err := n.getPodsByPodSelector(ctx, peer.PodSelector, ns.Name)
				if err != nil {
					return nil, fmt.Errorf("failed to get pods by pod selector: %w", err)
				}

				for _, pod := range namespacePods {
					podMap[pod.Namespace+"/"+pod.Name] = pod
				}
			}
		case peer.NamespaceSelector != nil:
			// When only namespace selector is set, we need to get the pods from the namespaces by namespace selector
			// and then get all pods from the namespaces
			namespaces, err := n.getNamespacesByNamespaceSelector(ctx, peer.NamespaceSelector)
			if err != nil {
				return nil, fmt.Errorf("failed to get namespaces by namespace selector: %w", err)
			}

			for _, ns := range namespaces {
				namespacePods, err := n.getPodsByNamespace(ctx, ns.Name)
				if err != nil {
					return nil, fmt.Errorf("failed to get pods by namespace: %w", err)
				}

				for _, pod := range namespacePods {
					podMap[pod.Namespace+"/"+pod.Name] = pod
				}
			}
		case peer.PodSelector != nil:
			// When only pod selector is set, we need to get the pods from the policy namespaces by pod selector
			filteredPods, err := n.getPodsByPodSelector(ctx, peer.PodSelector, policyNamespace)
			if err != nil {
				return nil, fmt.Errorf("failed to get pods by pod selector: %w", err)
			}

			for _, pod := range filteredPods {
				podMap[pod.Namespace+"/"+pod.Name] = pod
			}
		}
	}

	// Convert the map to a slice
	for _, pod := range podMap {
		pods = append(pods, pod)
	}

	return &peerInfo{
		pods:    pods,
		cidrs:   cidrs,
		excepts: excepts,
	}, nil
}

// getPodsByPodSelector gets the pods by pod selector
func (n *NFTables) getPodsByPodSelector(ctx context.Context, selector *metav1.LabelSelector, namespace string) ([]corev1.Pod, error) {
	pods := &corev1.PodList{}

	podSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		// Invalid selector, skip
		return nil, nil
	}

	listOptions := []client.ListOption{
		client.MatchingFields{
			PodStatusIndex:               string(corev1.PodRunning),
			PodHostNetworkIndex:          "false",
			PodHasNetworkAnnotationIndex: "true",
		},
		client.InNamespace(namespace),
	}

	if !podSelector.Empty() {
		listOptions = append(listOptions, client.MatchingLabelsSelector{Selector: podSelector})
	}

	err = n.Client.List(ctx, pods, listOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	return pods.Items, nil
}

// getPodsByNamespace gets the pods by namespace
func (n *NFTables) getPodsByNamespace(ctx context.Context, namespace string) ([]corev1.Pod, error) {
	pods := &corev1.PodList{}

	err := n.Client.List(ctx, pods, client.InNamespace(namespace), client.MatchingFields{
		PodStatusIndex:               string(corev1.PodRunning),
		PodHostNetworkIndex:          "false",
		PodHasNetworkAnnotationIndex: "true",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	return pods.Items, nil
}

// getNamespacesByNamespaceSelector gets the namespaces by namespace selector
func (n *NFTables) getNamespacesByNamespaceSelector(ctx context.Context, selector *metav1.LabelSelector) ([]corev1.Namespace, error) {
	namespaces := &corev1.NamespaceList{}

	namespaceSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		// Invalid selector, skip
		return nil, nil
	}

	listOptions := []client.ListOption{}

	if !namespaceSelector.Empty() {
		listOptions = append(listOptions, client.MatchingLabelsSelector{Selector: namespaceSelector})
	}

	err = n.Client.List(ctx, namespaces, listOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	return namespaces.Items, nil
}

// getPodInterfacesMap returns a map of valid interfaces per pod
func getPodInterfacesMap(pods []corev1.Pod, networks []string) map[string][]Interface {
	// Create a map of valid interfaces per pod
	podInterfacesMap := make(map[string][]Interface)
	for _, pod := range pods {
		podInterfacesMap[pod.Name+"/"+pod.Namespace] = getMatchedInterfaces(getInterfaces(&pod), networks)
	}

	return podInterfacesMap
}

// classifyAddresses classifies the IP addresses into IPv4 and IPv6
func classifyAddresses(interfacesPerPod map[string][]Interface, network string) ([]string, []string) {
	var ipv4Addresses []string
	var ipv6Addresses []string

	for _, interfaces := range interfacesPerPod {
		for _, intf := range interfaces {
			if intf.Network == network {
				for _, ip := range intf.IPs {
					// Parse the IP address to validate and classify it
					parsedIP := net.ParseIP(ip)
					if parsedIP == nil {
						// Invalid IP address, skip it
						continue
					}

					// Check if it's IPv4 (including IPv4-mapped IPv6)
					if parsedIP.To4() != nil {
						ipv4Addresses = append(ipv4Addresses, ip)
					} else {
						ipv6Addresses = append(ipv6Addresses, ip)
					}
				}
			}
		}
	}

	return ipv4Addresses, ipv6Addresses
}

// createAndPopulateIPSet creates and populates an IP set
func createAndPopulateIPSet(tx *knftables.Transaction, name string, setType string, setComment string, addresses []string, needsIntervalFlag bool) {
	// Create and populate the set

	set := &knftables.Set{
		Name:    name,
		Type:    setType,
		Comment: knftables.PtrTo(setComment),
	}

	if needsIntervalFlag {
		set.Flags = []knftables.SetFlag{knftables.IntervalFlag}
	}

	tx.Add(set)

	for _, address := range addresses {
		tx.Add(&knftables.Element{
			Set: name,
			Key: []string{address},
		})
	}
}
