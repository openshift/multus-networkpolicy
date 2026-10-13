package utils

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// ParseCommaSeparatedList parses a comma-separated string into a slice of non-empty strings.
func ParseCommaSeparatedList(input string) ([]string, error) {
	if input == "" {
		return nil, fmt.Errorf("input string cannot be empty")
	}

	elements := strings.Split(input, ",")
	result := make([]string, 0, len(elements))

	for _, element := range elements {
		trimmed := strings.TrimSpace(element)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid elements found in comma-separated list: %q", input)
	}

	return result, nil
}

// GetHashName returns the first 16 characters of the SHA256 hash of the namespace name
func GetHashName(name, namespace string) string {
	namespaceName := fmt.Sprintf("%s-%s", name, namespace)

	hash := sha256.Sum256([]byte(namespaceName))
	return fmt.Sprintf("%x", hash[:16])
}

// MatchesSelector checks if the pod labels match the given label selector
func MatchesSelector(selector metav1.LabelSelector, podLabels map[string]string) bool {
	// Convert the metav1.LabelSelector to a labels.Selector
	labelSelector, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		// If the selector is invalid, we don't match
		return false
	}

	if labelSelector.Empty() {
		return true
	}

	// Convert pod labels to a labels.Set and check if it matches
	podLabelSet := labels.Set(podLabels)
	return labelSelector.Matches(podLabelSet)
}

// SplitCIDRs splits the CIDRs into IPv4 and IPv6 CIDRs
func SplitCIDRs(cidrs []string) ([]string, []string) {
	var ipv4CIDRs []string
	var ipv6CIDRs []string

	for _, cidr := range cidrs {
		// Parse the CIDR to validate and classify it
		parsedIP, _, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		// Check if it's IPv4 (including IPv4-mapped IPv6)
		if parsedIP.To4() != nil {
			ipv4CIDRs = append(ipv4CIDRs, cidr)
		} else {
			ipv6CIDRs = append(ipv6CIDRs, cidr)
		}
	}

	return ipv4CIDRs, ipv6CIDRs
}

// ReadRulesFromFile reads rules from a file
func ReadRulesFromFile(filePath string) ([]string, error) {
	var rules []string

	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rule := scanner.Text()
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}

		rules = append(rules, rule)
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}
