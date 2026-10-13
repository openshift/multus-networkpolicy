package utils

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Utils Suite")
}

var _ = Describe("ParseCommaSeparatedList", func() {
	Context("with valid input", func() {
		It("should parse simple comma-separated list", func() {
			result, err := ParseCommaSeparatedList("a,b,c")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal([]string{"a", "b", "c"}))
		})

		It("should trim whitespace from elements", func() {
			result, err := ParseCommaSeparatedList(" a , b , c ")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal([]string{"a", "b", "c"}))
		})

		It("should filter out empty elements", func() {
			result, err := ParseCommaSeparatedList("a,,b,,,c")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal([]string{"a", "b", "c"}))
		})

		It("should handle single element", func() {
			result, err := ParseCommaSeparatedList("single")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal([]string{"single"}))
		})

		It("should handle single element with whitespace", func() {
			result, err := ParseCommaSeparatedList("  single  ")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal([]string{"single"}))
		})
	})

	Context("with invalid input", func() {
		It("should return error for empty string", func() {
			result, err := ParseCommaSeparatedList("")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("input string cannot be empty"))
			Expect(result).To(BeNil())
		})

		It("should return error for string with only commas", func() {
			result, err := ParseCommaSeparatedList(",,,")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no valid elements found"))
			Expect(result).To(BeNil())
		})

		It("should return error for string with only whitespace and commas", func() {
			result, err := ParseCommaSeparatedList("  ,  ,  ")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no valid elements found"))
			Expect(result).To(BeNil())
		})
	})

	Describe("GetHashName", func() {
		It("should return consistent hash for same input", func() {
			hash1 := GetHashName("test-policy", "test-namespace")
			hash2 := GetHashName("test-policy", "test-namespace")
			Expect(hash1).To(Equal(hash2))
		})

		It("should return different hashes for different inputs", func() {
			hash1 := GetHashName("policy1", "namespace1")
			hash2 := GetHashName("policy2", "namespace2")
			Expect(hash1).NotTo(Equal(hash2))
		})

		It("should return different hashes for same name but different namespace", func() {
			hash1 := GetHashName("test-policy", "namespace1")
			hash2 := GetHashName("test-policy", "namespace2")
			Expect(hash1).NotTo(Equal(hash2))
		})

		It("should return different hashes for different name but same namespace", func() {
			hash1 := GetHashName("policy1", "test-namespace")
			hash2 := GetHashName("policy2", "test-namespace")
			Expect(hash1).NotTo(Equal(hash2))
		})

		It("should return 32 character hex string", func() {
			hash := GetHashName("test-policy", "test-namespace")
			Expect(hash).To(HaveLen(32))
			Expect(hash).To(MatchRegexp("^[a-f0-9]{32}$"))
		})

		It("should handle empty strings", func() {
			hash1 := GetHashName("", "")
			hash2 := GetHashName("", "test")
			hash3 := GetHashName("test", "")

			Expect(hash1).To(HaveLen(32))
			Expect(hash2).To(HaveLen(32))
			Expect(hash3).To(HaveLen(32))

			// All should be different
			Expect(hash1).NotTo(Equal(hash2))
			Expect(hash1).NotTo(Equal(hash3))
			Expect(hash2).NotTo(Equal(hash3))
		})
	})

	Describe("MatchesPodSelector", func() {
		Context("when selector is empty", func() {
			It("should match any pod", func() {
				selector := metav1.LabelSelector{}
				podLabels := map[string]string{"app": "test", "version": "v1"}

				result := MatchesSelector(selector, podLabels)
				Expect(result).To(BeTrue())
			})
		})

		Context("when selector matches pod labels", func() {
			It("should return true", func() {
				selector := metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				}
				podLabels := map[string]string{"app": "test", "version": "v1"}

				result := MatchesSelector(selector, podLabels)
				Expect(result).To(BeTrue())
			})
		})

		Context("when selector does not match pod labels", func() {
			It("should return false", func() {
				selector := metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "different"},
				}
				podLabels := map[string]string{"app": "test", "version": "v1"}

				result := MatchesSelector(selector, podLabels)
				Expect(result).To(BeFalse())
			})
		})
	})

	Context("splitCIDRs", func() {
		It("should return empty slices for empty input", func() {
			cidrs := []string{}

			ipv4, ipv6 := SplitCIDRs(cidrs)
			Expect(ipv4).To(BeEmpty())
			Expect(ipv6).To(BeEmpty())
		})

		It("should split IPv4 and IPv6 CIDRs correctly", func() {
			cidrs := []string{
				"10.0.0.0/24",    // IPv4
				"192.168.1.0/24", // IPv4
				"2001:db8::/32",  // IPv6
				"fe80::/64",      // IPv6
				"172.16.0.0/16",  // IPv4
				"::1/128",        // IPv6 loopback
			}

			ipv4, ipv6 := SplitCIDRs(cidrs)

			Expect(ipv4).To(HaveLen(3))
			Expect(ipv4).To(ContainElements("10.0.0.0/24", "192.168.1.0/24", "172.16.0.0/16"))

			Expect(ipv6).To(HaveLen(3))
			Expect(ipv6).To(ContainElements("2001:db8::/32", "fe80::/64", "::1/128"))
		})

		It("should handle only IPv4 CIDRs", func() {
			cidrs := []string{
				"10.0.0.0/8",
				"192.168.0.0/16",
				"172.16.0.0/12",
				"127.0.0.0/8",
			}

			ipv4, ipv6 := SplitCIDRs(cidrs)

			Expect(ipv4).To(HaveLen(4))
			Expect(ipv4).To(ContainElements("10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "127.0.0.0/8"))
			Expect(ipv6).To(BeEmpty())
		})

		It("should handle only IPv6 CIDRs", func() {
			cidrs := []string{
				"2001:db8::/32",
				"fe80::/10",
				"::1/128",
				"2001:4860:4860::8888/128",
			}

			ipv4, ipv6 := SplitCIDRs(cidrs)

			Expect(ipv4).To(BeEmpty())
			Expect(ipv6).To(HaveLen(4))
			Expect(ipv6).To(ContainElements("2001:db8::/32", "fe80::/10", "::1/128", "2001:4860:4860::8888/128"))
		})

		It("should skip invalid CIDRs", func() {
			cidrs := []string{
				"10.0.0.0/24",        // Valid IPv4
				"invalid-cidr",       // Invalid
				"2001:db8::/32",      // Valid IPv6
				"300.400.500.600/24", // Invalid IPv4
				"192.168.1.0/33",     // Invalid prefix length for IPv4
				"fe80::/64",          // Valid IPv6
				"not-a-cidr",         // Invalid
				"2001:db8::/129",     // Invalid prefix length for IPv6
			}

			ipv4, ipv6 := SplitCIDRs(cidrs)

			// Only valid CIDRs should be included
			Expect(ipv4).To(HaveLen(1))
			Expect(ipv4).To(ContainElement("10.0.0.0/24"))

			Expect(ipv6).To(HaveLen(2))
			Expect(ipv6).To(ContainElements("2001:db8::/32", "fe80::/64"))
		})

		It("should handle IPv4-mapped IPv6 addresses as IPv4", func() {
			cidrs := []string{
				"::ffff:192.168.1.0/120", // IPv4-mapped IPv6
				"::ffff:10.0.0.0/120",    // IPv4-mapped IPv6
				"2001:db8::/32",          // Pure IPv6
				"192.168.1.0/24",         // Pure IPv4
			}

			ipv4, ipv6 := SplitCIDRs(cidrs)

			// IPv4-mapped IPv6 should be classified as IPv4
			Expect(ipv4).To(HaveLen(3))
			Expect(ipv4).To(ContainElements("::ffff:192.168.1.0/120", "::ffff:10.0.0.0/120", "192.168.1.0/24"))

			Expect(ipv6).To(HaveLen(1))
			Expect(ipv6).To(ContainElement("2001:db8::/32"))
		})

		It("should handle single host addresses with /32 and /128", func() {
			cidrs := []string{
				"192.168.1.1/32",  // Single IPv4 host
				"10.0.0.1/32",     // Single IPv4 host
				"2001:db8::1/128", // Single IPv6 host
				"fe80::1/128",     // Single IPv6 host
			}

			ipv4, ipv6 := SplitCIDRs(cidrs)

			Expect(ipv4).To(HaveLen(2))
			Expect(ipv4).To(ContainElements("192.168.1.1/32", "10.0.0.1/32"))

			Expect(ipv6).To(HaveLen(2))
			Expect(ipv6).To(ContainElements("2001:db8::1/128", "fe80::1/128"))
		})

		It("should handle edge case prefix lengths", func() {
			cidrs := []string{
				"0.0.0.0/0",       // IPv4 default route
				"192.168.1.0/32",  // IPv4 /32
				"::/0",            // IPv6 default route
				"2001:db8::1/128", // IPv6 /128
			}

			ipv4, ipv6 := SplitCIDRs(cidrs)

			Expect(ipv4).To(HaveLen(2))
			Expect(ipv4).To(ContainElements("0.0.0.0/0", "192.168.1.0/32"))

			Expect(ipv6).To(HaveLen(2))
			Expect(ipv6).To(ContainElements("::/0", "2001:db8::1/128"))
		})

		It("should handle mixed valid and invalid CIDRs preserving order", func() {
			cidrs := []string{
				"10.0.0.0/24",   // Valid IPv4 - should be first
				"invalid",       // Invalid - should be skipped
				"172.16.0.0/16", // Valid IPv4 - should be second
				"2001:db8::/32", // Valid IPv6 - should be first
				"bad-cidr",      // Invalid - should be skipped
				"fe80::/64",     // Valid IPv6 - should be second
			}

			ipv4, ipv6 := SplitCIDRs(cidrs)

			// Verify correct classification and order preservation
			Expect(ipv4).To(HaveLen(2))
			Expect(ipv4[0]).To(Equal("10.0.0.0/24"))
			Expect(ipv4[1]).To(Equal("172.16.0.0/16"))

			Expect(ipv6).To(HaveLen(2))
			Expect(ipv6[0]).To(Equal("2001:db8::/32"))
			Expect(ipv6[1]).To(Equal("fe80::/64"))
		})

		It("should handle nil input gracefully", func() {
			var cidrs []string // nil slice

			ipv4, ipv6 := SplitCIDRs(cidrs)
			Expect(ipv4).To(BeEmpty())
			Expect(ipv6).To(BeEmpty())
		})
	})
})
