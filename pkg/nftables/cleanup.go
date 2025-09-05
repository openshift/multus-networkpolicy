package nftables

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"sigs.k8s.io/knftables"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/utils"
)

// cleanUpPolicy cleans up the policy
func cleanUpPolicy(ctx context.Context, policyName string, policyNamespace string, logger logr.Logger) error {
	nft, err := knftables.New(knftables.InetFamily, tableName)
	if err != nil {
		return fmt.Errorf("failed to create nftables client: %w", err)
	}

	return cleanUp(ctx, nft, policyName, policyNamespace, logger)
}

// cleanUp cleans up the policy chains, rules and sets
func cleanUp(ctx context.Context, nft knftables.Interface, policyName string, policyNamespace string, logger logr.Logger) error {
	logger.Info("Cleaning up policy")

	tx := nft.NewTransaction()

	policyRuleComment := fmt.Sprintf("%s/%s", policyNamespace, policyName)

	// Delete rule in input chain
	rules, err := nft.ListRules(ctx, inputChain)
	if err != nil {
		if !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list rules in input chain: %w", err)
		}
	}

	for _, rule := range rules {
		if rule.Comment != nil && *rule.Comment == policyRuleComment {
			logger.V(1).Info("Deleting rule in input chain", "rule", rule.Comment)
			tx.Delete(rule)
		}
	}

	// Delete rule in output chain
	rules, err = nft.ListRules(ctx, outputChain)
	if err != nil {
		if !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list rules in output chain: %w", err)
		}
	}

	for _, rule := range rules {
		if rule.Comment != nil && *rule.Comment == policyRuleComment {
			logger.V(1).Info("Deleting rule in output chain", "rule", rule.Comment)
			tx.Delete(rule)
		}
	}

	// Delete rule in ingress chain
	rules, err = nft.ListRules(ctx, ingressChain)
	if err != nil {
		if !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list rules in ingress chain: %w", err)
		}
	}

	for _, rule := range rules {
		if rule.Comment != nil && *rule.Comment == policyRuleComment {
			logger.V(1).Info("Deleting rule in ingress chain", "rule", rule.Comment)
			tx.Delete(rule)
		}
	}

	// Delete rule in egress chain
	rules, err = nft.ListRules(ctx, egressChain)
	if err != nil {
		if !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list rules in egress chain: %w", err)
		}
	}

	for _, rule := range rules {
		if rule.Comment != nil && *rule.Comment == policyRuleComment {
			logger.V(1).Info("Deleting rule in egress chain", "rule", rule.Comment)
			tx.Delete(rule)
		}
	}

	hashName := utils.GetHashName(policyName, policyNamespace)

	// Delete policy chains
	chains, err := nft.List(ctx, "chains")
	if err != nil {
		if !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list chains: %w", err)
		}
	}

	for _, chain := range chains {
		if chain == fmt.Sprintf("%s%s", prefixNetworkPolicyChain, hashName) {
			logger.V(1).Info("Deleting policy chain", "chain", chain)
			tx.Flush(&knftables.Chain{
				Name: chain,
			})

			tx.Delete(&knftables.Chain{
				Name: chain,
			})
		}
	}

	// Delete policy sets
	policySetPrefix := fmt.Sprintf("%s%s", prefixNetworkPolicySet, hashName)
	managedInterfacesSetPrefix := fmt.Sprintf("%s%s", prefixManagedInterfacesSet, hashName)

	// Delete policy sets
	sets, err := nft.List(ctx, "sets")
	if err != nil {
		if !knftables.IsNotFound(err) {
			return fmt.Errorf("failed to list sets: %w", err)
		}
	}

	for _, set := range sets {
		if strings.HasPrefix(set, policySetPrefix) || strings.HasPrefix(set, managedInterfacesSetPrefix) {
			logger.V(1).Info("Deleting policy set", "set", set)
			tx.Flush(&knftables.Set{
				Name: set,
			})

			tx.Delete(&knftables.Set{
				Name: set,
			})
		}
	}

	err = nft.Run(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to run transaction: %w", err)
	}

	return nil
}
