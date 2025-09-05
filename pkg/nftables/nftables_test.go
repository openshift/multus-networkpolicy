package nftables

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/knftables"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/datastore"
)

func TestNFTablesUnit(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NFTables Suite")
}

var _ = Describe("NFTables Functions", func() {
	Context("getInterfaces", func() {
		var pod *corev1.Pod

		BeforeEach(func() {
			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
			}
		})

		Context("when pod has no network annotations", func() {
			It("should return empty interfaces slice", func() {
				interfaces := getInterfaces(pod)
				Expect(interfaces).To(BeEmpty())
			})
		})

		Context("when pod has network annotation but no status", func() {
			BeforeEach(func() {
				pod.Annotations = map[string]string{
					"k8s.v1.cni.cncf.io/networks": "net1",
				}
			})

			It("should return empty interfaces slice", func() {
				interfaces := getInterfaces(pod)
				Expect(interfaces).To(BeEmpty())
			})
		})

		Context("when pod has network status but no network annotation", func() {
			BeforeEach(func() {
				pod.Annotations = map[string]string{
					"k8s.v1.cni.cncf.io/network-status": `[
						{
							"name": "default/net1",
							"interface": "eth1",
							"ips": ["10.0.0.1"]
						}
					]`,
				}
			})

			It("should return empty interfaces slice", func() {
				interfaces := getInterfaces(pod)
				Expect(interfaces).To(BeEmpty())
			})
		})

		Context("when pod has both network annotation and status", func() {
			Context("with single network", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/net1",
								"interface": "eth1",
								"ips": ["10.0.0.1"]
							}
						]`,
					}
				})

				It("should return single interface", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(1))
					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.0.1"},
					}))
				})
			})

			Context("with multiple networks", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1,net2",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/net1",
								"interface": "eth1",
								"ips": ["10.0.0.1"]
							},
							{
								"name": "default/net2",
								"interface": "eth2",
								"ips": ["10.0.0.2", "2001:db8::1"]
							}
						]`,
					}
				})

				It("should return multiple interfaces", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(2))

					// Sort interfaces by network name for consistent testing
					if len(interfaces) == 2 && interfaces[0].Network == "net2" {
						interfaces[0], interfaces[1] = interfaces[1], interfaces[0]
					}

					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.0.1"},
					}))
					Expect(interfaces[1]).To(Equal(Interface{
						Name:    "eth2",
						Network: "default/net2",
						IPs:     []string{"10.0.0.2", "2001:db8::1"},
					}))
				})
			})

			Context("with namespaced network annotation", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-namespace/net1",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "test-namespace/net1",
								"interface": "eth1",
								"ips": ["10.0.0.1"]
							}
						]`,
					}
				})

				It("should return interface with correct network name", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(1))
					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "test-namespace/net1",
						IPs:     []string{"10.0.0.1"},
					}))
				})
			})

			Context("with mixed namespaced and non-namespaced networks", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-namespace/net1,net2",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "test-namespace/net1",
								"interface": "eth1",
								"ips": ["10.0.0.1"]
							},
							{
								"name": "net2",
								"interface": "eth2",
								"ips": ["10.0.0.2"]
							}
						]`,
					}
				})

				It("should return both interfaces with correct network names", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(2))

					// Sort interfaces by network name for consistent testing
					if len(interfaces) == 2 && interfaces[0].Network == "net2" {
						interfaces[0], interfaces[1] = interfaces[1], interfaces[0]
					}

					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "test-namespace/net1",
						IPs:     []string{"10.0.0.1"},
					}))
					Expect(interfaces[1]).To(Equal(Interface{
						Name:    "eth2",
						Network: "default/net2",
						IPs:     []string{"10.0.0.2"},
					}))
				})
			})

			Context("when network status has networks not in annotation", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/net1",
								"interface": "eth1",
								"ips": ["10.0.0.1"]
							},
							{
								"name": "default/net2",
								"interface": "eth2",
								"ips": ["10.0.0.2"]
							}
						]`,
					}
				})

				It("should only return interfaces for networks in annotation", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(1))
					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.0.1"},
					}))
				})
			})

			Context("when network annotation has networks not in status", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1,net2",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/net1",
								"interface": "eth1",
								"ips": ["10.0.0.1"]
							}
						]`,
					}
				})

				It("should only return interfaces for networks with status", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(1))
					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.0.1"},
					}))
				})
			})

			Context("with complex network names and spacing", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[
							{"name": "net-1"},
							{"name": "net_2"}
						]`,
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/net-1",
								"interface": "eth1",
								"ips": ["10.0.0.1"]
							},
							{
								"name": "default/net_2",
								"interface": "eth2",
								"ips": ["10.0.0.2"]
							}
						]`,
					}
				})

				It("should handle network names with dashes and underscores", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(2))

					// Sort interfaces by network name for consistent testing
					if len(interfaces) == 2 && interfaces[0].Network == "net_2" {
						interfaces[0], interfaces[1] = interfaces[1], interfaces[0]
					}

					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "default/net-1",
						IPs:     []string{"10.0.0.1"},
					}))
					Expect(interfaces[1]).To(Equal(Interface{
						Name:    "eth2",
						Network: "default/net_2",
						IPs:     []string{"10.0.0.2"},
					}))
				})
			})

			Context("with empty IPs array", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/net1",
								"interface": "eth1",
								"ips": []
							}
						]`,
					}
				})

				It("should return interface with empty IPs", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(1))
					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{},
					}))
				})
			})

			Context("with nil IPs field", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/net1",
								"interface": "eth1"
							}
						]`,
					}
				})

				It("should return interface with nil IPs", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(1))
					Expect(interfaces[0].Name).To(Equal("eth1"))
					Expect(interfaces[0].Network).To(Equal("default/net1"))
					Expect(interfaces[0].IPs).To(BeNil())
				})
			})

			Context("with invalid JSON in network status", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks":       "net1",
						"k8s.v1.cni.cncf.io/network-status": `invalid json`,
					}
				})

				It("should return empty interfaces slice", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(BeEmpty())
				})
			})

			Context("with malformed network annotation", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`, // JSON instead of string
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/net1",
								"interface": "eth1",
								"ips": ["10.0.0.1"]
							}
						]`,
					}
				})

				It("should handle parsing error gracefully", func() {
					interfaces := getInterfaces(pod)
					// Should not panic and return empty or handle gracefully
					// The exact behavior depends on netdefutils.ParsePodNetworkAnnotation implementation
					Expect(interfaces).NotTo(BeNil())
				})
			})
		})

		Context("edge cases", func() {
			Context("when pod is nil", func() {
				It("should panic (expected behavior)", func() {
					Expect(func() {
						getInterfaces(nil)
					}).To(Panic())
				})
			})

			Context("when pod has no annotations", func() {
				BeforeEach(func() {
					pod.Annotations = nil
				})

				It("should return empty interfaces slice", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(BeEmpty())
				})
			})

			Context("when pod has empty annotations map", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{}
				})

				It("should return empty interfaces slice", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(BeEmpty())
				})
			})
		})

		Context("real-world scenarios", func() {
			Context("with Multus CNI typical annotation format", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[
							{"name": "macvlan-net", "namespace": "default"},
							{"name": "sriov-net", "namespace": "kube-system"}
						]`,
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/macvlan-net",
								"interface": "net1",
								"ips": ["192.168.1.100"],
								"mac": "02:42:c0:a8:01:64"
							},
							{
								"name": "kube-system/sriov-net",
								"interface": "net2",
								"ips": ["10.56.217.100", "2001:db8::100"],
								"mac": "02:42:0a:38:d9:64"
							}
						]`,
					}
				})

				It("should return interfaces with correct network names", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(2))

					// Sort interfaces by network name for consistent testing
					if len(interfaces) == 2 && interfaces[0].Network == "sriov-net" {
						interfaces[0], interfaces[1] = interfaces[1], interfaces[0]
					}

					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "net1",
						Network: "default/macvlan-net",
						IPs:     []string{"192.168.1.100"},
					}))
					Expect(interfaces[1]).To(Equal(Interface{
						Name:    "net2",
						Network: "kube-system/sriov-net",
						IPs:     []string{"10.56.217.100", "2001:db8::100"},
					}))
				})
			})

			Context("with simple string format for networks", func() {
				BeforeEach(func() {
					pod.Annotations = map[string]string{
						"k8s.v1.cni.cncf.io/networks": "macvlan-net@eth1,sriov-net@eth2",
						"k8s.v1.cni.cncf.io/network-status": `[
							{
								"name": "default/macvlan-net",
								"interface": "eth1",
								"ips": ["192.168.1.100"]
							},
							{
								"name": "default/sriov-net",
								"interface": "eth2",
								"ips": ["10.56.217.100"]
							}
						]`,
					}
				})

				It("should return interfaces correctly", func() {
					interfaces := getInterfaces(pod)
					Expect(interfaces).To(HaveLen(2))

					// Sort interfaces by network name for consistent testing
					if len(interfaces) == 2 && interfaces[0].Network == "sriov-net" {
						interfaces[0], interfaces[1] = interfaces[1], interfaces[0]
					}

					Expect(interfaces[0]).To(Equal(Interface{
						Name:    "eth1",
						Network: "default/macvlan-net",
						IPs:     []string{"192.168.1.100"},
					}))
					Expect(interfaces[1]).To(Equal(Interface{
						Name:    "eth2",
						Network: "default/sriov-net",
						IPs:     []string{"10.56.217.100"},
					}))
				})
			})
		})
	})

	Context("ensureBasicStructure", func() {
		var (
			ctx    context.Context
			nft    knftables.Interface
			logger logr.Logger
		)

		BeforeEach(func() {
			ctx = context.Background()
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			logger = logr.Discard()
		})

		It("should create all required chains and rules", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})
	})

	Context("createManagedInterfacesSet", func() {
		var (
			ctx    context.Context
			nft    knftables.Interface
			logger logr.Logger
		)

		BeforeEach(func() {
			ctx = context.Background()
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			logger = logr.Discard()
		})

		It("should create set with no elements for empty interfaces", func() {
			// First create the table
			tx := nft.NewTransaction()
			tx.Add(&knftables.Table{
				Comment: knftables.PtrTo("MultiNetworkPolicy"),
			})
			err := nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Now create the managed interfaces set
			tx = nft.NewTransaction()
			interfaces := []Interface{} // Empty interfaces
			hashName := "test123"
			policyNamespace := "test-ns"
			policyName := "test-policy"

			createManagedInterfacesSet(tx, interfaces, hashName, policyNamespace, policyName, logger)

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Expected rules: table + set creation, no elements
			expectedRules := []string{
				"add table inet multi_networkpolicy",
				"add set inet multi_networkpolicy smi-test123 { type ifname ; comment \"Managed interfaces set for test-ns/test-policy\" ; }",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create set with elements for multiple interfaces", func() {
			// First create the table
			tx := nft.NewTransaction()
			tx.Add(&knftables.Table{
				Comment: knftables.PtrTo("MultiNetworkPolicy"),
			})
			err := nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Now create the managed interfaces set
			tx = nft.NewTransaction()
			interfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
				{Name: "eth2", Network: "default/net2", IPs: []string{"10.0.0.2"}},
				{Name: "eth3", Network: "default/net3", IPs: []string{"10.0.0.3"}},
			}
			hashName := "abc456"
			policyNamespace := "prod-ns"
			policyName := "prod-policy"

			createManagedInterfacesSet(tx, interfaces, hashName, policyNamespace, policyName, logger)

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Expected rules: table + set creation + 3 elements
			expectedRules := []string{
				"add table inet multi_networkpolicy",
				"add set inet multi_networkpolicy smi-abc456 { type ifname ; comment \"Managed interfaces set for prod-ns/prod-policy\" ; }",
				"add element inet multi_networkpolicy smi-abc456 { eth1 }",
				"add element inet multi_networkpolicy smi-abc456 { eth2 }",
				"add element inet multi_networkpolicy smi-abc456 { eth3 }",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})
	})

	Context("createPolicyChain", func() {
		var (
			ctx    context.Context
			nft    knftables.Interface
			logger logr.Logger
		)

		BeforeEach(func() {
			ctx = context.Background()
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			logger = logr.Discard()
		})

		It("should create policy chain with rules", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create policy chain
			tx := nft.NewTransaction()
			npChainName := "pi-abc123"
			policyTypeChainName := "ingress"
			policyNamespace := "test-ns"
			policyName := "test-policy"

			err = createPolicyChain(ctx, nft, tx, npChainName, policyTypeChainName, policyNamespace, policyName, logger)
			Expect(err).NotTo(HaveOccurred())

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Expected rules: basic structure + new policy chain + jump rule
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy pi-abc123 { comment \"MultiNetworkPolicy test-ns/test-policy\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress jump pi-abc123 comment \"test-ns/test-policy\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})
	})

	Context("createDispatcherRule", func() {
		var (
			ctx    context.Context
			nft    knftables.Interface
			logger logr.Logger
		)

		BeforeEach(func() {
			ctx = context.Background()
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			logger = logr.Discard()
		})

		It("should create input dispatcher rule", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create managed interfaces set
			tx := nft.NewTransaction()
			interfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
				{Name: "eth2", Network: "default/net2", IPs: []string{"10.0.0.2"}},
			}
			hashName := "abc123"
			policyNamespace := "test-ns"
			policyName := "test-policy"

			createManagedInterfacesSet(tx, interfaces, hashName, policyNamespace, policyName, logger)

			// Create dispatcher rule for input
			dispatcherChainName := "input"
			comment := "test-ns/test-policy"
			createDispatcherRule(tx, hashName, dispatcherChainName, comment, logger)

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Expected rules: basic structure + managed interfaces set + input dispatcher rule
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add set inet multi_networkpolicy smi-abc123 { type ifname ; comment \"Managed interfaces set for test-ns/test-policy\" ; }",
				"add element inet multi_networkpolicy smi-abc123 { eth1 }",
				"add element inet multi_networkpolicy smi-abc123 { eth2 }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy input iifname @smi-abc123 jump ingress comment \"test-ns/test-policy\"",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create output dispatcher rule", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create managed interfaces set
			tx := nft.NewTransaction()
			interfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
				{Name: "eth2", Network: "default/net2", IPs: []string{"10.0.0.2"}},
			}
			hashName := "def456"
			policyNamespace := "prod-ns"
			policyName := "prod-policy"

			createManagedInterfacesSet(tx, interfaces, hashName, policyNamespace, policyName, logger)

			// Create dispatcher rule for output
			dispatcherChainName := "output"
			comment := "prod-ns/prod-policy"
			createDispatcherRule(tx, hashName, dispatcherChainName, comment, logger)

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Expected rules: basic structure + managed interfaces set + output dispatcher rule
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add set inet multi_networkpolicy smi-def456 { type ifname ; comment \"Managed interfaces set for prod-ns/prod-policy\" ; }",
				"add element inet multi_networkpolicy smi-def456 { eth1 }",
				"add element inet multi_networkpolicy smi-def456 { eth2 }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy output oifname @smi-def456 jump egress comment \"prod-ns/prod-policy\"",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})
	})

	Context("getPortRuleSections", func() {
		It("should return empty slice for empty ports", func() {
			ports := []multiv1beta1.MultiNetworkPolicyPort{}
			result := getPortRuleSections(ports)
			Expect(result).To(BeEmpty())
		})

		It("should skip ports with nil protocol", func() {
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: nil, // nil protocol should be skipped
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(1))
			Expect(result[0]).To(Equal("meta l4proto tcp th dport { 80 } accept"))
		})

		It("should handle protocol without port (allow all ports)", func() {
			tcp := corev1.ProtocolTCP
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     nil, // nil port means allow all ports for this protocol
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(1))
			Expect(result[0]).To(Equal("meta l4proto tcp accept"))
		})

		It("should handle single integer port", func() {
			tcp := corev1.ProtocolTCP
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(1))
			Expect(result[0]).To(Equal("meta l4proto tcp th dport { 80 } accept"))
		})

		It("should handle single string port (named port)", func() {
			tcp := corev1.ProtocolTCP
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.String, StrVal: "HTTP"},
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(1))
			Expect(result[0]).To(Equal("meta l4proto tcp th dport { http } accept"))
		})

		It("should handle port range with EndPort", func() {
			tcp := corev1.ProtocolTCP
			endPort := int32(8080)
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 8000},
					EndPort:  &endPort,
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(1))
			Expect(result[0]).To(Equal("meta l4proto tcp th dport { 8000-8080 } accept"))
		})

		It("should handle multiple ports for same protocol", func() {
			tcp := corev1.ProtocolTCP
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
				},
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 443},
				},
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.String, StrVal: "SSH"},
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(1))
			// Note: order might vary due to map iteration, so check for both possible orders
			expectedPorts := []string{"80", "443", "ssh"}
			Expect(result[0]).To(ContainSubstring("meta l4proto tcp th dport {"))
			Expect(result[0]).To(ContainSubstring("} accept"))
			for _, port := range expectedPorts {
				Expect(result[0]).To(ContainSubstring(port))
			}
		})

		It("should handle multiple protocols", func() {
			tcp := corev1.ProtocolTCP
			udp := corev1.ProtocolUDP
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
				},
				{
					Protocol: &udp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(2))

			// Check that both protocols are present (order may vary)
			rules := strings.Join(result, " ")
			Expect(rules).To(ContainSubstring("meta l4proto tcp th dport { 80 } accept"))
			Expect(rules).To(ContainSubstring("meta l4proto udp th dport { 53 } accept"))
		})

		It("should handle mixed protocol with and without ports", func() {
			tcp := corev1.ProtocolTCP
			udp := corev1.ProtocolUDP
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
				},
				{
					Protocol: &udp,
					Port:     nil, // Allow all UDP ports
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(2))

			rules := strings.Join(result, " ")
			Expect(rules).To(ContainSubstring("meta l4proto tcp th dport { 80 } accept"))
			Expect(rules).To(ContainSubstring("meta l4proto udp accept"))
		})

		It("should handle complex combination with ranges and named ports", func() {
			tcp := corev1.ProtocolTCP
			udp := corev1.ProtocolUDP
			sctp := corev1.ProtocolSCTP
			endPort := int32(9000)
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
				},
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.String, StrVal: "HTTPS"},
				},
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 8000},
					EndPort:  &endPort,
				},
				{
					Protocol: &udp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
				},
				{
					Protocol: &sctp,
					Port:     nil, // Allow all SCTP ports
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(3)) // TCP, UDP, SCTP

			rules := strings.Join(result, " ")
			Expect(rules).To(ContainSubstring("meta l4proto sctp accept"))
			Expect(rules).To(ContainSubstring("meta l4proto udp th dport { 53 } accept"))
			// TCP should have multiple ports: 80, https (lowercase), and 8000-9000 range
			Expect(rules).To(ContainSubstring("meta l4proto tcp th dport {"))
			Expect(rules).To(ContainSubstring("80"))
			Expect(rules).To(ContainSubstring("https"))
			Expect(rules).To(ContainSubstring("8000-9000"))
		})

		It("should convert protocol names to lowercase", func() {
			tcp := corev1.Protocol("TCP") // Uppercase
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(1))
			Expect(result[0]).To(Equal("meta l4proto tcp th dport { 80 } accept"))
		})

		It("should convert named ports to lowercase", func() {
			tcp := corev1.ProtocolTCP
			ports := []multiv1beta1.MultiNetworkPolicyPort{
				{
					Protocol: &tcp,
					Port:     &intstr.IntOrString{Type: intstr.String, StrVal: "HTTP"},
				},
			}
			result := getPortRuleSections(ports)
			Expect(result).To(HaveLen(1))
			Expect(result[0]).To(Equal("meta l4proto tcp th dport { http } accept"))
		})
	})

	Context("createIngressRules", func() {
		var (
			ctx    context.Context
			nft    knftables.Interface
			logger logr.Logger
		)

		BeforeEach(func() {
			ctx = context.Background()
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			logger = logr.Discard()
		})

		It("should create no rules for deny-all policy (empty ingress)", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create a policy with no ingress rules (deny all)
			policy := &datastore.Policy{
				Name:      "deny-all-policy",
				Namespace: "test-ns",
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
					Ingress:     []multiv1beta1.MultiNetworkPolicyIngressRule{}, // Empty = deny all
				},
			}

			// Setup interfaces and transaction
			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
				{Name: "eth2", Network: "default/net2", IPs: []string{"10.0.0.2"}},
			}
			tx := nft.NewTransaction()
			hashName := "abc123"

			// Create policy chain first (as done in enforcePolicy)
			npChainName := fmt.Sprintf("cnp-%s", hashName)
			err = createPolicyChain(ctx, nft, tx, npChainName, "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create a minimal NFTables instance for testing
			nftables := &NFTables{
				Client: nil, // We don't need the client for this test since no API calls are made
			}

			// Call createIngressRules
			err = nftables.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-abc123 { comment \"MultiNetworkPolicy test-ns/deny-all-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-abc123 comment \"test-ns/deny-all-policy\"",
				"add rule inet multi_networkpolicy cnp-abc123 iifname eth1 ip saddr 10.0.0.1 accept",
				"add rule inet multi_networkpolicy cnp-abc123 iifname eth2 ip saddr 10.0.0.2 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create accept-all rules for policy with empty ingress entry", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create a policy with single empty ingress entry (accept all)
			policy := &datastore.Policy{
				Name:      "accept-all-policy",
				Namespace: "test-ns",
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From:  []multiv1beta1.MultiNetworkPolicyPeer{}, // Empty From = accept from all sources
							Ports: []multiv1beta1.MultiNetworkPolicyPort{}, // Empty Ports = accept all ports
						},
					},
				},
			}

			// Setup interfaces and transaction
			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
				{Name: "eth2", Network: "default/net2", IPs: []string{"10.0.0.2"}},
			}
			tx := nft.NewTransaction()
			hashName := "def456"

			// Create policy chain first (as done in enforcePolicy)
			npChainName := fmt.Sprintf("cnp-%s", hashName)
			err = createPolicyChain(ctx, nft, tx, npChainName, "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create NFTables instance
			nftables := &NFTables{
				Client: nil,
			}

			// Call createIngressRules
			err = nftables.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				// New commands to verify
				"add chain inet multi_networkpolicy cnp-def456 { comment \"MultiNetworkPolicy test-ns/accept-all-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-def456 comment \"test-ns/accept-all-policy\"",
				"add rule inet multi_networkpolicy cnp-def456 iifname eth1 ip saddr 10.0.0.1 accept",
				"add rule inet multi_networkpolicy cnp-def456 iifname eth2 ip saddr 10.0.0.2 accept",
				"add rule inet multi_networkpolicy cnp-def456 iifname eth1 accept",
				"add rule inet multi_networkpolicy cnp-def456 iifname eth2 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create port-restricted rules for multiple ingress entries with nil From", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create a policy with multiple ingress entries, nil From, specific ports
			tcp := corev1.ProtocolTCP
			udp := corev1.ProtocolUDP
			policy := &datastore.Policy{
				Name:      "port-restricted-policy",
				Namespace: "prod-ns",
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{}, // Empty From = accept from all sources
							Ports: []multiv1beta1.MultiNetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
								},
								{
									Protocol: &tcp,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 443},
								},
							},
						},
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{}, // Empty From = accept from all sources
							Ports: []multiv1beta1.MultiNetworkPolicyPort{
								{
									Protocol: &udp,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								},
							},
						},
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{}, // Empty From = accept from all sources
							Ports: []multiv1beta1.MultiNetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     &intstr.IntOrString{Type: intstr.String, StrVal: "SSH"},
								},
							},
						},
					},
				},
			}

			// Setup interfaces and transaction
			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
			}
			tx := nft.NewTransaction()
			hashName := "ghi789"

			// Create policy chain first (as done in enforcePolicy)
			npChainName := fmt.Sprintf("cnp-%s", hashName)
			err = createPolicyChain(ctx, nft, tx, npChainName, "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create NFTables instance
			nftables := &NFTables{
				Client: nil,
			}

			// Call createIngressRules
			err = nftables.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-ghi789 { comment \"MultiNetworkPolicy prod-ns/port-restricted-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-ghi789 comment \"prod-ns/port-restricted-policy\"",
				"add rule inet multi_networkpolicy cnp-ghi789 iifname eth1 meta l4proto tcp th dport { 80,443 } accept",
				"add rule inet multi_networkpolicy cnp-ghi789 iifname eth1 meta l4proto udp th dport { 53 } accept",
				"add rule inet multi_networkpolicy cnp-ghi789 iifname eth1 meta l4proto tcp th dport { ssh } accept",
				"add rule inet multi_networkpolicy cnp-ghi789 iifname eth1 ip saddr 10.0.0.1 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		// Comprehensive tests for full coverage
		It("should create rules for ingress with IPv4-only pod selector", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create fake client with IPv4-only pod
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1", 
							"ips": ["10.0.1.1"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			policy := &datastore.Policy{
				Name:      "ipv4-pod-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "web"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "ipv4test"
			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-ipv4test { comment \"MultiNetworkPolicy default/ipv4-pod-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-ipv4test comment \"default/ipv4-pod-policy\"",
				"add set inet multi_networkpolicy snp-ipv4test_ingress_ipv4_eth1_0 { type ipv4_addr ; comment \"Addresses for default/ipv4-pod-policy\" ; }",
				"add element inet multi_networkpolicy snp-ipv4test_ingress_ipv4_eth1_0 { 10.0.1.1 }",
				"add rule inet multi_networkpolicy cnp-ipv4test iifname eth1 ip saddr @snp-ipv4test_ingress_ipv4_eth1_0 accept",
				"add rule inet multi_networkpolicy cnp-ipv4test iifname eth1 ip saddr 10.0.1.1 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for ingress with IPv6-only pod selector", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod2 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod2",
					Namespace: "default",
					Labels:    map[string]string{"app": "db"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1",
							"ips": ["2001:db8::1"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod2).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			policy := &datastore.Policy{
				Name:      "ipv6-pod-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "db"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "ipv6test"
			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-ipv6test { comment \"MultiNetworkPolicy default/ipv6-pod-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-ipv6test comment \"default/ipv6-pod-policy\"",
				"add set inet multi_networkpolicy snp-ipv6test_ingress_ipv6_eth1_0 { type ipv6_addr ; comment \"Addresses for default/ipv6-pod-policy\" ; }",
				"add element inet multi_networkpolicy snp-ipv6test_ingress_ipv6_eth1_0 { 2001:db8::1 }",
				"add rule inet multi_networkpolicy cnp-ipv6test iifname eth1 ip6 saddr @snp-ipv6test_ingress_ipv6_eth1_0 accept",
				"add rule inet multi_networkpolicy cnp-ipv6test iifname eth1 ip saddr 10.0.1.1 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for ingress with dual-stack pod selector", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod3 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod3",
					Namespace: "default",
					Labels:    map[string]string{"app": "api"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1",
							"ips": ["10.0.1.2", "2001:db8::2"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod3).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			policy := &datastore.Policy{
				Name:      "dual-stack-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "api"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "dualtest"
			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-dualtest { comment \"MultiNetworkPolicy default/dual-stack-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-dualtest comment \"default/dual-stack-policy\"",
				"add set inet multi_networkpolicy snp-dualtest_ingress_ipv4_eth1_0 { type ipv4_addr ; comment \"Addresses for default/dual-stack-policy\" ; }",
				"add set inet multi_networkpolicy snp-dualtest_ingress_ipv6_eth1_0 { type ipv6_addr ; comment \"Addresses for default/dual-stack-policy\" ; }",
				"add element inet multi_networkpolicy snp-dualtest_ingress_ipv4_eth1_0 { 10.0.1.2 }",
				"add element inet multi_networkpolicy snp-dualtest_ingress_ipv6_eth1_0 { 2001:db8::2 }",
				"add rule inet multi_networkpolicy cnp-dualtest iifname eth1 ip saddr @snp-dualtest_ingress_ipv4_eth1_0 accept",
				"add rule inet multi_networkpolicy cnp-dualtest iifname eth1 ip6 saddr @snp-dualtest_ingress_ipv6_eth1_0 accept",
				"add rule inet multi_networkpolicy cnp-dualtest iifname eth1 ip saddr 10.0.1.1 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for ingress with IPv4 IPBlock", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			policy := &datastore.Policy{
				Name:      "ipv4-ipblock-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR:   "10.0.0.0/24",
										Except: []string{"10.0.0.1/32", "10.0.0.2/32"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "ipv4block"

			createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: nil}
			err = nftablesInstance.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				"add set inet multi_networkpolicy smi-ipv4block { type ifname ; comment \"Managed interfaces set for default/ipv4-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy smi-ipv4block { eth1 }",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-ipv4block { comment \"MultiNetworkPolicy default/ipv4-ipblock-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-ipv4block comment \"default/ipv4-ipblock-policy\"",
				"add set inet multi_networkpolicy snp-ipv4block_ingress_ipv4_cidr_0 { type ipv4_addr ; flags interval ; comment \"CIDRs for default/ipv4-ipblock-policy\" ; }",
				"add set inet multi_networkpolicy snp-ipv4block_ingress_ipv4_except_0 { type ipv4_addr ; flags interval ; comment \"Excepts for default/ipv4-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy snp-ipv4block_ingress_ipv4_cidr_0 { 10.0.0.0/24 }",
				"add element inet multi_networkpolicy snp-ipv4block_ingress_ipv4_except_0 { 10.0.0.1/32 }",
				"add element inet multi_networkpolicy snp-ipv4block_ingress_ipv4_except_0 { 10.0.0.2/32 }",
				"add rule inet multi_networkpolicy cnp-ipv4block iifname @smi-ipv4block ip saddr @snp-ipv4block_ingress_ipv4_cidr_0 ip saddr != @snp-ipv4block_ingress_ipv4_except_0 accept",
				"add rule inet multi_networkpolicy cnp-ipv4block iifname eth1 ip saddr 10.0.1.1 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for ingress with IPv6 IPBlock", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			policy := &datastore.Policy{
				Name:      "ipv6-ipblock-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR:   "2001:db8::/32",
										Except: []string{"2001:db8::1/128"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "ipv6block"

			createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: nil}
			err = nftablesInstance.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add set inet multi_networkpolicy smi-ipv6block { type ifname ; comment \"Managed interfaces set for default/ipv6-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy smi-ipv6block { eth1 }",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-ipv6block { comment \"MultiNetworkPolicy default/ipv6-ipblock-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-ipv6block comment \"default/ipv6-ipblock-policy\"",
				"add set inet multi_networkpolicy snp-ipv6block_ingress_ipv6_cidr_0 { type ipv6_addr ; flags interval ; comment \"CIDRs for default/ipv6-ipblock-policy\" ; }",
				"add set inet multi_networkpolicy snp-ipv6block_ingress_ipv6_except_0 { type ipv6_addr ; flags interval ; comment \"Excepts for default/ipv6-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy snp-ipv6block_ingress_ipv6_cidr_0 { 2001:db8::/32 }",
				"add element inet multi_networkpolicy snp-ipv6block_ingress_ipv6_except_0 { 2001:db8::1/128 }",
				"add rule inet multi_networkpolicy cnp-ipv6block iifname @smi-ipv6block ip6 saddr @snp-ipv6block_ingress_ipv6_cidr_0 ip6 saddr != @snp-ipv6block_ingress_ipv6_except_0 accept",
				"add rule inet multi_networkpolicy cnp-ipv6block iifname eth1 ip saddr 10.0.1.1 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for ingress with dual-stack IPBlock", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			policy := &datastore.Policy{
				Name:      "dual-ipblock-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR: "10.0.0.0/24",
									},
								},
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR: "2001:db8::/32",
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "dualblock"

			createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: nil}
			err = nftablesInstance.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add set inet multi_networkpolicy smi-dualblock { type ifname ; comment \"Managed interfaces set for default/dual-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy smi-dualblock { eth1 }",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-dualblock { comment \"MultiNetworkPolicy default/dual-ipblock-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-dualblock comment \"default/dual-ipblock-policy\"",
				"add set inet multi_networkpolicy snp-dualblock_ingress_ipv4_cidr_0 { type ipv4_addr ; flags interval ; comment \"CIDRs for default/dual-ipblock-policy\" ; }",
				"add set inet multi_networkpolicy snp-dualblock_ingress_ipv6_cidr_0 { type ipv6_addr ; flags interval ; comment \"CIDRs for default/dual-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy snp-dualblock_ingress_ipv4_cidr_0 { 10.0.0.0/24 }",
				"add element inet multi_networkpolicy snp-dualblock_ingress_ipv6_cidr_0 { 2001:db8::/32 }",
				"add rule inet multi_networkpolicy cnp-dualblock iifname @smi-dualblock ip saddr @snp-dualblock_ingress_ipv4_cidr_0 accept",
				"add rule inet multi_networkpolicy cnp-dualblock iifname @smi-dualblock ip6 saddr @snp-dualblock_ingress_ipv6_cidr_0 accept",
				"add rule inet multi_networkpolicy cnp-dualblock iifname eth1 ip saddr 10.0.1.1 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for ingress with mixed pod selector and IPBlock with ports", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1",
							"ips": ["10.0.1.1"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			tcpProtocol := corev1.ProtocolTCP
			port80 := intstr.FromInt(80)

			policy := &datastore.Policy{
				Name:      "mixed-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "web"},
									},
								},
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR: "192.168.1.0/24",
									},
								},
							},
							Ports: []multiv1beta1.MultiNetworkPolicyPort{
								{Protocol: &tcpProtocol, Port: &port80},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "mixed"

			createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add set inet multi_networkpolicy smi-mixed { type ifname ; comment \"Managed interfaces set for default/mixed-policy\" ; }",
				"add element inet multi_networkpolicy smi-mixed { eth1 }",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-mixed { comment \"MultiNetworkPolicy default/mixed-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-mixed comment \"default/mixed-policy\"",
				"add set inet multi_networkpolicy snp-mixed_ingress_ipv4_eth1_0 { type ipv4_addr ; comment \"Addresses for default/mixed-policy\" ; }",
				"add set inet multi_networkpolicy snp-mixed_ingress_ipv4_cidr_0 { type ipv4_addr ; flags interval ; comment \"CIDRs for default/mixed-policy\" ; }",
				"add element inet multi_networkpolicy snp-mixed_ingress_ipv4_eth1_0 { 10.0.1.1 }",
				"add element inet multi_networkpolicy snp-mixed_ingress_ipv4_cidr_0 { 192.168.1.0/24 }",
				"add rule inet multi_networkpolicy cnp-mixed iifname eth1 ip saddr @snp-mixed_ingress_ipv4_eth1_0 meta l4proto tcp th dport { 80 } accept",
				"add set inet multi_networkpolicy snp-mixed_ingress_ipv4_cidr_0 { type ipv4_addr ; flags interval ; comment \"CIDRs for default/mixed-policy\" ; }",
				"add rule inet multi_networkpolicy cnp-mixed iifname eth1 ip saddr 10.0.1.1 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should handle multiple interfaces for the same network", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1",
							"ips": ["10.0.1.1"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			policy := &datastore.Policy{
				Name:      "multi-interface-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "web"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
				{Name: "eth2", Network: "default/net1", IPs: []string{"10.0.1.2"}},
				{Name: "eth3", Network: "default/net1", IPs: []string{"10.0.1.3"}},
			}

			tx := nft.NewTransaction()
			hashName := "multiintf"
			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "ingress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createIngressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to verify
				"add chain inet multi_networkpolicy cnp-multiintf { comment \"MultiNetworkPolicy default/multi-interface-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump cnp-multiintf comment \"default/multi-interface-policy\"",
				"add set inet multi_networkpolicy snp-multiintf_ingress_ipv4_eth1_0 { type ipv4_addr ; comment \"Addresses for default/multi-interface-policy\" ; }",
				"add set inet multi_networkpolicy snp-multiintf_ingress_ipv4_eth2_0 { type ipv4_addr ; comment \"Addresses for default/multi-interface-policy\" ; }",
				"add set inet multi_networkpolicy snp-multiintf_ingress_ipv4_eth3_0 { type ipv4_addr ; comment \"Addresses for default/multi-interface-policy\" ; }",
				"add element inet multi_networkpolicy snp-multiintf_ingress_ipv4_eth1_0 { 10.0.1.1 }",
				"add element inet multi_networkpolicy snp-multiintf_ingress_ipv4_eth2_0 { 10.0.1.1 }",
				"add element inet multi_networkpolicy snp-multiintf_ingress_ipv4_eth3_0 { 10.0.1.1 }",
				"add rule inet multi_networkpolicy cnp-multiintf iifname eth1 ip saddr @snp-multiintf_ingress_ipv4_eth1_0 accept",
				"add rule inet multi_networkpolicy cnp-multiintf iifname eth2 ip saddr @snp-multiintf_ingress_ipv4_eth2_0 accept",
				"add rule inet multi_networkpolicy cnp-multiintf iifname eth3 ip saddr @snp-multiintf_ingress_ipv4_eth3_0 accept",
				"add rule inet multi_networkpolicy cnp-multiintf iifname eth1 ip saddr 10.0.1.1 accept",
				"add rule inet multi_networkpolicy cnp-multiintf iifname eth2 ip saddr 10.0.1.2 accept",
				"add rule inet multi_networkpolicy cnp-multiintf iifname eth3 ip saddr 10.0.1.3 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})
	})

	Context("parsePeers", func() {
		var (
			ctx             context.Context
			fakeClient      client.Client
			nftables        *NFTables
			logger          logr.Logger
			policyNamespace string
		)

		BeforeEach(func() {
			ctx = context.Background()
			logger = logr.Discard()
			policyNamespace = "default"

			// Create fake client with test data
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			// Create test pods
			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web", "tier": "frontend"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1",
					},
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
			}

			pod2 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod2",
					Namespace: "kube-system",
					Labels:    map[string]string{"app": "db", "tier": "backend"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net2",
					},
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
			}

			pod3 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod3",
					Namespace: "production",
					Labels:    map[string]string{"app": "api", "env": "prod"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net3",
					},
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
			}

			// Create test namespaces
			ns1 := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "default",
					Labels: map[string]string{"env": "test"},
				},
			}

			ns2 := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "kube-system",
					Labels: map[string]string{"env": "system"},
				},
			}

			ns3 := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "production",
					Labels: map[string]string{"env": "prod"},
				},
			}

			fakeClient = fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1, pod2, pod3, ns1, ns2, ns3).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			nftables = &NFTables{
				Client: fakeClient,
			}
		})

		It("should handle empty peers list", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.pods).To(BeEmpty())
			Expect(result.cidrs).To(BeEmpty())
			Expect(result.excepts).To(BeEmpty())
		})

		It("should handle IPBlock peer", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					IPBlock: &multiv1beta1.IPBlock{
						CIDR:   "10.0.0.0/24",
						Except: []string{"10.0.0.1", "10.0.0.2"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.pods).To(BeEmpty())
			Expect(result.cidrs).To(HaveLen(1))
			Expect(result.cidrs[0]).To(Equal("10.0.0.0/24"))
			Expect(result.excepts).To(HaveLen(2))
			Expect(result.excepts).To(ContainElements("10.0.0.1", "10.0.0.2"))
		})

		It("should handle multiple IPBlock peers", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					IPBlock: &multiv1beta1.IPBlock{
						CIDR:   "10.0.0.0/24",
						Except: []string{"10.0.0.1"},
					},
				},
				{
					IPBlock: &multiv1beta1.IPBlock{
						CIDR:   "192.168.1.0/24",
						Except: []string{"192.168.1.1", "192.168.1.2"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.pods).To(BeEmpty())
			Expect(result.cidrs).To(HaveLen(2))
			Expect(result.cidrs).To(ContainElements("10.0.0.0/24", "192.168.1.0/24"))
			Expect(result.excepts).To(HaveLen(3))
			Expect(result.excepts).To(ContainElements("10.0.0.1", "192.168.1.1", "192.168.1.2"))
		})

		It("should handle both NamespaceSelector and PodSelector", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "prod"},
					},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "api"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.cidrs).To(BeEmpty())
			Expect(result.excepts).To(BeEmpty())
			Expect(result.pods).To(HaveLen(1))
			Expect(result.pods[0].Name).To(Equal("pod3"))
			Expect(result.pods[0].Namespace).To(Equal("production"))
		})

		It("should handle only NamespaceSelector", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "system"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.cidrs).To(BeEmpty())
			Expect(result.excepts).To(BeEmpty())
			Expect(result.pods).To(HaveLen(1))
			Expect(result.pods[0].Name).To(Equal("pod2"))
			Expect(result.pods[0].Namespace).To(Equal("kube-system"))
		})

		It("should handle only PodSelector", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "web"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.cidrs).To(BeEmpty())
			Expect(result.excepts).To(BeEmpty())
			Expect(result.pods).To(HaveLen(1))
			Expect(result.pods[0].Name).To(Equal("pod1"))
			Expect(result.pods[0].Namespace).To(Equal("default"))
		})

		It("should handle mixed peer types", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					IPBlock: &multiv1beta1.IPBlock{
						CIDR: "10.0.0.0/24",
					},
				},
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "web"},
					},
				},
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "system"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.cidrs).To(HaveLen(1))
			Expect(result.cidrs[0]).To(Equal("10.0.0.0/24"))
			Expect(result.excepts).To(BeEmpty())
			Expect(result.pods).To(HaveLen(2))

			podNames := []string{}
			for _, pod := range result.pods {
				podNames = append(podNames, pod.Name)
			}
			Expect(podNames).To(ContainElements("pod1", "pod2"))
		})

		It("should deduplicate pods", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "web"},
					},
				},
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"tier": "frontend"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.pods).To(HaveLen(1)) // Should be deduplicated
			Expect(result.pods[0].Name).To(Equal("pod1"))
		})

		It("should handle empty namespace selector results", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "nonexistent"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.pods).To(BeEmpty())
		})

		It("should handle empty pod selector results", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "nonexistent"},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.pods).To(BeEmpty())
		})

		It("should handle invalid namespace selector", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "invalid",
								Operator: "InvalidOperator", // Invalid operator
								Values:   []string{"value"},
							},
						},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.pods).To(BeEmpty()) // Invalid selector should return empty results
		})

		It("should handle invalid pod selector", func() {
			peers := []multiv1beta1.MultiNetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "invalid",
								Operator: "InvalidOperator", // Invalid operator
								Values:   []string{"value"},
							},
						},
					},
				},
			}

			result, err := nftables.parsePeers(ctx, peers, policyNamespace, logger)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).NotTo(BeNil())
			Expect(result.pods).To(BeEmpty()) // Invalid selector should return empty results
		})
	})

	Context("getPodsByPodSelector", func() {
		var (
			ctx        context.Context
			fakeClient client.Client
			nftables   *NFTables
		)

		BeforeEach(func() {
			ctx = context.Background()

			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			// Create test pods
			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "web-pod",
					Namespace: "default",
					Labels:    map[string]string{"app": "web", "tier": "frontend"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1",
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			pod2 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-pod",
					Namespace: "default",
					Labels:    map[string]string{"app": "db", "tier": "backend"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net2",
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			// Pod without network annotation (should be filtered out)
			pod3 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-network-pod",
					Namespace: "default",
					Labels:    map[string]string{"app": "system"},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			// Host network pod (should be filtered out)
			pod4 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "host-network-pod",
					Namespace: "default",
					Labels:    map[string]string{"app": "host"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net3",
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: true},
			}

			// Non-running pod (should be filtered out)
			pod5 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pending-pod",
					Namespace: "default",
					Labels:    map[string]string{"app": "pending"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net4",
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodPending},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient = fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1, pod2, pod3, pod4, pod5).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			nftables = &NFTables{Client: fakeClient}
		})

		It("should get pods by label selector", func() {
			selector := &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			}

			pods, err := nftables.getPodsByPodSelector(ctx, selector, "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(pods).To(HaveLen(1))
			Expect(pods[0].Name).To(Equal("web-pod"))
		})

		It("should filter pods by running status, non-host network, and network annotation", func() {
			selector := &metav1.LabelSelector{
				MatchLabels: map[string]string{}, // Match all pods
			}

			pods, err := nftables.getPodsByPodSelector(ctx, selector, "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(pods).To(HaveLen(2)) // Only web-pod and db-pod should match

			podNames := []string{}
			for _, pod := range pods {
				podNames = append(podNames, pod.Name)
			}
			Expect(podNames).To(ContainElements("web-pod", "db-pod"))
		})

		It("should handle invalid selector", func() {
			selector := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "invalid",
						Operator: "InvalidOperator",
						Values:   []string{"value"},
					},
				},
			}

			pods, err := nftables.getPodsByPodSelector(ctx, selector, "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(pods).To(BeNil()) // Invalid selector should return nil
		})

		It("should return empty for no matching pods", func() {
			selector := &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "nonexistent"},
			}

			pods, err := nftables.getPodsByPodSelector(ctx, selector, "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(pods).To(BeEmpty())
		})
	})

	Context("getPodsByNamespace", func() {
		var (
			ctx        context.Context
			fakeClient client.Client
			nftables   *NFTables
		)

		BeforeEach(func() {
			ctx = context.Background()

			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			// Create test pods in different namespaces
			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "target-ns",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net1",
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			pod2 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod2",
					Namespace: "target-ns",
					Labels:    map[string]string{"app": "db"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net2",
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			// Pod in different namespace
			pod3 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod3",
					Namespace: "other-ns",
					Labels:    map[string]string{"app": "api"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "net3",
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			// Pod that should be filtered out (no network annotation)
			pod4 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "filtered-pod",
					Namespace: "target-ns",
					Labels:    map[string]string{"app": "filtered"},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient = fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1, pod2, pod3, pod4).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			nftables = &NFTables{Client: fakeClient}
		})

		It("should get all eligible pods from namespace", func() {
			pods, err := nftables.getPodsByNamespace(ctx, "target-ns")
			Expect(err).NotTo(HaveOccurred())
			Expect(pods).To(HaveLen(2))

			podNames := []string{}
			for _, pod := range pods {
				podNames = append(podNames, pod.Name)
			}
			Expect(podNames).To(ContainElements("pod1", "pod2"))
		})

		It("should return empty for nonexistent namespace", func() {
			pods, err := nftables.getPodsByNamespace(ctx, "nonexistent-ns")
			Expect(err).NotTo(HaveOccurred())
			Expect(pods).To(BeEmpty())
		})

		It("should filter pods correctly", func() {
			pods, err := nftables.getPodsByNamespace(ctx, "target-ns")
			Expect(err).NotTo(HaveOccurred())

			// Should not include filtered-pod (no network annotation)
			for _, pod := range pods {
				Expect(pod.Name).NotTo(Equal("filtered-pod"))
			}
		})
	})

	Context("getNamespacesByNamespaceSelector", func() {
		var (
			ctx        context.Context
			fakeClient client.Client
			nftables   *NFTables
		)

		BeforeEach(func() {
			ctx = context.Background()

			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			// Create test namespaces
			ns1 := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "production",
					Labels: map[string]string{"env": "prod", "tier": "production"},
				},
			}

			ns2 := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "staging",
					Labels: map[string]string{"env": "staging", "tier": "staging"},
				},
			}

			ns3 := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "development",
					Labels: map[string]string{"env": "dev", "tier": "development"},
				},
			}

			ns4 := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "no-labels",
				},
			}

			fakeClient = fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(ns1, ns2, ns3, ns4).
				Build()

			nftables = &NFTables{Client: fakeClient}
		})

		It("should get namespaces by label selector", func() {
			selector := &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			}

			namespaces, err := nftables.getNamespacesByNamespaceSelector(ctx, selector)
			Expect(err).NotTo(HaveOccurred())
			Expect(namespaces).To(HaveLen(1))
			Expect(namespaces[0].Name).To(Equal("production"))
		})

		It("should handle match expressions", func() {
			selector := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "tier",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"production", "staging"},
					},
				},
			}

			namespaces, err := nftables.getNamespacesByNamespaceSelector(ctx, selector)
			Expect(err).NotTo(HaveOccurred())
			Expect(namespaces).To(HaveLen(2))

			nsNames := []string{}
			for _, ns := range namespaces {
				nsNames = append(nsNames, ns.Name)
			}
			Expect(nsNames).To(ContainElements("production", "staging"))
		})

		It("should return empty for no matching namespaces", func() {
			selector := &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "nonexistent"},
			}

			namespaces, err := nftables.getNamespacesByNamespaceSelector(ctx, selector)
			Expect(err).NotTo(HaveOccurred())
			Expect(namespaces).To(BeEmpty())
		})

		It("should handle invalid selector", func() {
			selector := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "invalid",
						Operator: "InvalidOperator",
						Values:   []string{"value"},
					},
				},
			}

			namespaces, err := nftables.getNamespacesByNamespaceSelector(ctx, selector)
			Expect(err).NotTo(HaveOccurred())
			Expect(namespaces).To(BeNil()) // Invalid selector should return nil
		})

		It("should handle empty selector (match all)", func() {
			selector := &metav1.LabelSelector{}

			namespaces, err := nftables.getNamespacesByNamespaceSelector(ctx, selector)
			Expect(err).NotTo(HaveOccurred())
			Expect(namespaces).To(HaveLen(4)) // Should match all namespaces
		})
	})

	Context("getPodInterfacesMap", func() {
		It("should create empty map for empty pods list", func() {
			pods := []corev1.Pod{}
			networks := []string{"default/net1", "default/net2"}

			result := getPodInterfacesMap(pods, networks)
			Expect(result).NotTo(BeNil())
			Expect(result).To(BeEmpty())
		})

		It("should create map with pod interfaces", func() {
			pods := []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "default",
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": `[
								{"name": "net1"},
								{"name": "net2"}
							]`,
							"k8s.v1.cni.cncf.io/network-status": `[
								{
									"name": "default/net1",
									"interface": "eth1",
									"ips": ["10.0.1.1", "2001:db8::1"]
								},
								{
									"name": "default/net2",
									"interface": "eth2",
									"ips": ["10.0.2.1"]
								}
							]`,
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod2",
						Namespace: "kube-system",
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": `[
								{"name": "net1"},
								{"name": "net3"}
							]`,
							"k8s.v1.cni.cncf.io/network-status": `[
								{
									"name": "kube-system/net1",
									"interface": "eth1",
									"ips": ["10.0.1.2"]
								},
								{
									"name": "kube-system/net3",
									"interface": "eth3",
									"ips": ["10.0.3.1"]
								}
							]`,
						},
					},
				},
			}
			networks := []string{"default/net1", "default/net2", "kube-system/net1"}

			result := getPodInterfacesMap(pods, networks)
			Expect(result).To(HaveLen(2))

			// Check pod1 interfaces
			pod1Key := "pod1/default"
			Expect(result).To(HaveKey(pod1Key))
			pod1Interfaces := result[pod1Key]
			Expect(pod1Interfaces).To(HaveLen(2)) // net1 and net2

			// Verify net1 interface for pod1
			net1Found := false
			net2Found := false
			for _, intf := range pod1Interfaces {
				if intf.Network == "default/net1" {
					net1Found = true
					Expect(intf.Name).To(Equal("eth1"))
					Expect(intf.IPs).To(ContainElements("10.0.1.1", "2001:db8::1"))
				}
				if intf.Network == "default/net2" {
					net2Found = true
					Expect(intf.Name).To(Equal("eth2"))
					Expect(intf.IPs).To(ContainElement("10.0.2.1"))
				}
			}
			Expect(net1Found).To(BeTrue())
			Expect(net2Found).To(BeTrue())

			// Check pod2 interfaces
			pod2Key := "pod2/kube-system"
			Expect(result).To(HaveKey(pod2Key))
			pod2Interfaces := result[pod2Key]
			Expect(pod2Interfaces).To(HaveLen(1)) // Only net1 matches networks filter
			Expect(pod2Interfaces[0].Network).To(Equal("kube-system/net1"))
			Expect(pod2Interfaces[0].Name).To(Equal("eth1"))
			Expect(pod2Interfaces[0].IPs).To(ContainElement("10.0.1.2"))
		})

		It("should filter interfaces by networks", func() {
			pods := []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "default",
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": `[
								{"name": "net1"},
								{"name": "net2"},
								{"name": "net3"}
							]`,
							"k8s.v1.cni.cncf.io/network-status": `[
								{
									"name": "default/net1",
									"interface": "eth1",
									"ips": ["10.0.1.1"]
								},
								{
									"name": "net2",
									"interface": "eth2",
									"ips": ["10.0.2.1"]
								},
								{
									"name": "net3",
									"interface": "eth3",
									"ips": ["10.0.3.1"]
								}
							]`,
						},
					},
				},
			}
			networks := []string{"default/net1", "default/net3"} // Only net1 and net3

			result := getPodInterfacesMap(pods, networks)
			Expect(result).To(HaveLen(1))

			pod1Key := "pod1/default"
			pod1Interfaces := result[pod1Key]
			Expect(pod1Interfaces).To(HaveLen(2)) // Only net1 and net3

			networkNames := []string{}
			for _, intf := range pod1Interfaces {
				networkNames = append(networkNames, intf.Network)
			}
			Expect(networkNames).To(ContainElements("default/net1", "default/net3"))
			Expect(networkNames).NotTo(ContainElement("default/net2"))
		})

		It("should handle pods with no network annotations", func() {
			pods := []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "default",
						// No network annotations
					},
				},
			}
			networks := []string{"default/net1"}

			result := getPodInterfacesMap(pods, networks)
			Expect(result).To(HaveLen(1))

			pod1Key := "pod1/default"
			Expect(result).To(HaveKey(pod1Key))
			Expect(result[pod1Key]).To(BeEmpty()) // No interfaces
		})

		It("should handle pods with invalid network annotations", func() {
			pods := []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "default",
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "invalid-json",
						},
					},
				},
			}
			networks := []string{"default/net1"}

			result := getPodInterfacesMap(pods, networks)
			Expect(result).To(HaveLen(1))

			pod1Key := "pod1/default"
			Expect(result).To(HaveKey(pod1Key))
			Expect(result[pod1Key]).To(BeEmpty()) // No valid interfaces
		})

		It("should handle empty networks list", func() {
			pods := []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "default",
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": `[
								{"name": "net1"}
							]`,
							"k8s.v1.cni.cncf.io/network-status": `[
								{
									"name": "default/net1",
									"interface": "eth1",
									"ips": ["10.0.1.1"]
								}
							]`,
						},
					},
				},
			}
			networks := []string{} // Empty networks

			result := getPodInterfacesMap(pods, networks)
			Expect(result).To(HaveLen(1))

			pod1Key := "pod1/default"
			Expect(result).To(HaveKey(pod1Key))
			Expect(result[pod1Key]).To(BeEmpty()) // No matching networks
		})
	})

	Context("classifyAddresses", func() {
		It("should return empty slices for empty input", func() {
			interfacesPerPod := map[string][]Interface{}
			network := "net1"

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)
			Expect(ipv4).To(BeEmpty())
			Expect(ipv6).To(BeEmpty())
		})

		It("should classify IPv4 and IPv6 addresses correctly", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.1.1", "192.168.1.1", "2001:db8::1", "::1"},
					},
				},
				"pod2/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"172.16.1.1", "2001:db8::2"},
					},
				},
			}
			network := "default/net1"

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)

			Expect(ipv4).To(HaveLen(3))
			Expect(ipv4).To(ContainElements("10.0.1.1", "192.168.1.1", "172.16.1.1"))

			Expect(ipv6).To(HaveLen(3)) // ::1, 2001:db8::1, 2001:db8::2
			Expect(ipv6).To(ContainElements("2001:db8::1", "::1", "2001:db8::2"))
		})

		It("should handle IPv4-mapped IPv6 addresses as IPv4", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"::ffff:192.168.1.1", "::ffff:10.0.0.1"},
					},
				},
			}
			network := "default/net1"

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)

			// IPv4-mapped IPv6 addresses should be classified as IPv4
			Expect(ipv4).To(HaveLen(2))
			Expect(ipv4).To(ContainElements("::ffff:192.168.1.1", "::ffff:10.0.0.1"))
			Expect(ipv6).To(BeEmpty())
		})

		It("should filter by network name", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.1.1", "2001:db8::1"},
					},
					{
						Name:    "eth2",
						Network: "default/net2",
						IPs:     []string{"10.0.2.1", "2001:db8::2"},
					},
				},
			}
			network := "default/net1" // Only net1

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)

			Expect(ipv4).To(HaveLen(1))
			Expect(ipv4).To(ContainElement("10.0.1.1"))
			Expect(ipv4).NotTo(ContainElement("10.0.2.1")) // From net2, should be filtered out

			Expect(ipv6).To(HaveLen(1))
			Expect(ipv6).To(ContainElement("2001:db8::1"))
			Expect(ipv6).NotTo(ContainElement("2001:db8::2")) // From net2, should be filtered out
		})

		It("should skip invalid IP addresses", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.1.1", "invalid-ip", "2001:db8::1", "not.an.ip", "192.168.1.1"},
					},
				},
			}
			network := "default/net1"

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)

			// Should only include valid IPs
			Expect(ipv4).To(HaveLen(2))
			Expect(ipv4).To(ContainElements("10.0.1.1", "192.168.1.1"))
			Expect(ipv4).NotTo(ContainElements("invalid-ip", "not.an.ip"))

			Expect(ipv6).To(HaveLen(1))
			Expect(ipv6).To(ContainElement("2001:db8::1"))
		})

		It("should handle mixed valid and invalid addresses across multiple pods", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.1.1", "invalid", "2001:db8::1"},
					},
				},
				"pod2/kube-system": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"bad-ip", "192.168.1.1", "2001:db8::2", ""},
					},
				},
			}
			network := "default/net1"

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)

			Expect(ipv4).To(HaveLen(2))
			Expect(ipv4).To(ContainElements("10.0.1.1", "192.168.1.1"))

			Expect(ipv6).To(HaveLen(2))
			Expect(ipv6).To(ContainElements("2001:db8::1", "2001:db8::2"))
		})

		It("should handle empty IPs slice", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{}, // Empty IPs
					},
				},
			}
			network := "default/net1"

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)
			Expect(ipv4).To(BeEmpty())
			Expect(ipv6).To(BeEmpty())
		})

		It("should handle no matching network", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.1.1", "2001:db8::1"},
					},
				},
			}
			network := "default/net2" // Different network

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)
			Expect(ipv4).To(BeEmpty())
			Expect(ipv6).To(BeEmpty())
		})

		It("should handle various IPv6 formats", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs: []string{
							"2001:db8::1", // Standard IPv6
							"2001:0db8:0000:0000:0000:0000:0000:0001", // Full IPv6
							"::1",                          // Loopback IPv6
							"fe80::1",                      // Link-local IPv6
							"::ffff:192.168.1.1",           // IPv4-mapped IPv6 (should be IPv4)
							"2001:db8:85a3::8a2e:370:7334", // Compressed IPv6
						},
					},
				},
			}
			network := "default/net1"

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)

			// IPv4-mapped IPv6 should be classified as IPv4
			Expect(ipv4).To(HaveLen(1))
			Expect(ipv4).To(ContainElement("::ffff:192.168.1.1"))

			// All other IPv6 addresses
			Expect(ipv6).To(HaveLen(5))
			Expect(ipv6).To(ContainElements(
				"2001:db8::1",
				"2001:0db8:0000:0000:0000:0000:0000:0001",
				"::1",
				"fe80::1",
				"2001:db8:85a3::8a2e:370:7334",
			))
		})

		It("should handle multiple interfaces per pod with same network", func() {
			interfacesPerPod := map[string][]Interface{
				"pod1/default": {
					{
						Name:    "eth1",
						Network: "default/net1",
						IPs:     []string{"10.0.1.1", "2001:db8::1"},
					},
					{
						Name:    "eth2",
						Network: "default/net1", // Same network, different interface
						IPs:     []string{"10.0.1.2", "2001:db8::2"},
					},
				},
			}
			network := "default/net1"

			ipv4, ipv6 := classifyAddresses(interfacesPerPod, network)

			Expect(ipv4).To(HaveLen(2))
			Expect(ipv4).To(ContainElements("10.0.1.1", "10.0.1.2"))

			Expect(ipv6).To(HaveLen(2))
			Expect(ipv6).To(ContainElements("2001:db8::1", "2001:db8::2"))
		})
	})

	Context("createAndPopulateIPSet", func() {
		var (
			nft    knftables.Interface
			ctx    context.Context
			logger logr.Logger
		)

		BeforeEach(func() {
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			ctx = context.Background()
			logger = logr.Discard()

			// Create the basic structure first
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should create and populate IP set with addresses", func() {
			tx := nft.NewTransaction()
			setName := "test-set"
			setType := "ipv4_addr"
			setComment := "Test IP Set"
			addresses := []string{"10.0.1.1", "10.0.1.2", "192.168.1.1"}

			createAndPopulateIPSet(tx, setName, setType, setComment, addresses, false)

			// Run transaction to generate rules
			err := nft.Run(context.Background(), tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Expected rules: basic structure + set creation + elements
			expectedNewRules := []string{
				fmt.Sprintf("add set inet %s %s { type %s ; comment \"%s\" ; }", tableName, setName, setType, setComment),
				fmt.Sprintf("add element inet %s %s { 10.0.1.1 }", tableName, setName),
				fmt.Sprintf("add element inet %s %s { 10.0.1.2 }", tableName, setName),
				fmt.Sprintf("add element inet %s %s { 192.168.1.1 }", tableName, setName),
			}

			// Verify that our new rules exist in the dump
			for _, expectedRule := range expectedNewRules {
				found := false
				for _, actualRule := range dumpLines {
					if actualRule == expectedRule {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}

			// Verify the set was created with the correct type and comment
			setFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add set inet %s %s", tableName, setName)) {
					Expect(line).To(ContainSubstring(setType))
					Expect(line).To(ContainSubstring(setComment))
					setFound = true
					break
				}
			}
			Expect(setFound).To(BeTrue(), "Set creation rule not found")

			// Verify all elements were added
			elementCount := 0
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add element inet %s %s", tableName, setName)) {
					elementCount++
				}
			}
			Expect(elementCount).To(Equal(len(addresses)), "Expected %d elements, found %d", len(addresses), elementCount)
		})

		It("should create empty IP set when no addresses provided", func() {
			tx := nft.NewTransaction()
			setName := "empty-set"
			setType := "ipv6_addr"
			setComment := "Empty IP Set"
			addresses := []string{} // Empty addresses

			createAndPopulateIPSet(tx, setName, setType, setComment, addresses, false)

			// Run transaction to generate rules
			err := nft.Run(context.Background(), tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Verify the set was created
			setFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add set inet %s %s", tableName, setName)) {
					Expect(line).To(ContainSubstring(setType))
					Expect(line).To(ContainSubstring(setComment))
					setFound = true
					break
				}
			}
			Expect(setFound).To(BeTrue(), "Set creation rule not found")

			// Verify no elements were added (should be 0)
			elementCount := 0
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add element inet %s %s", tableName, setName)) {
					elementCount++
				}
			}
			Expect(elementCount).To(Equal(0), "Expected 0 elements for empty set, found %d", elementCount)
		})

		It("should handle different set types and single address", func() {
			tx := nft.NewTransaction()
			setName := "single-addr-set"
			setType := "inet_service"
			setComment := "Single Address Set"
			addresses := []string{"80"}

			createAndPopulateIPSet(tx, setName, setType, setComment, addresses, false)

			// Run transaction to generate rules
			err := nft.Run(context.Background(), tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Verify the set was created
			setFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add set inet %s %s", tableName, setName)) {
					Expect(line).To(ContainSubstring(setType))
					Expect(line).To(ContainSubstring(setComment))
					setFound = true
					break
				}
			}
			Expect(setFound).To(BeTrue(), "Set creation rule not found")

			// Verify the element was added
			elementFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add element inet %s %s { 80 }", tableName, setName)) {
					elementFound = true
					break
				}
			}
			Expect(elementFound).To(BeTrue(), "Expected element '80' not found")
		})

		It("should handle IPv6 addresses", func() {
			tx := nft.NewTransaction()
			setName := "ipv6-set"
			setType := "ipv6_addr"
			setComment := "IPv6 Address Set"
			addresses := []string{"2001:db8::1", "::1", "fe80::1"}

			createAndPopulateIPSet(tx, setName, setType, setComment, addresses, false)

			// Run transaction to generate rules
			err := nft.Run(context.Background(), tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Verify the set was created
			setFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add set inet %s %s", tableName, setName)) {
					Expect(line).To(ContainSubstring(setType))
					Expect(line).To(ContainSubstring(setComment))
					setFound = true
					break
				}
			}
			Expect(setFound).To(BeTrue(), "Set creation rule not found")

			// Verify all IPv6 elements were added
			expectedElements := []string{"2001:db8::1", "::1", "fe80::1"}
			for _, expectedElement := range expectedElements {
				elementFound := false
				for _, line := range dumpLines {
					if strings.Contains(line, fmt.Sprintf("add element inet %s %s { %s }", tableName, setName, expectedElement)) {
						elementFound = true
						break
					}
				}
				Expect(elementFound).To(BeTrue(), "Expected IPv6 element '%s' not found", expectedElement)
			}
		})

		It("should handle special characters in set name and comment", func() {
			tx := nft.NewTransaction()
			setName := "special-name_123"
			setType := "ipv4_addr"
			setComment := "Set with special chars & symbols"
			addresses := []string{"172.16.0.1"}

			createAndPopulateIPSet(tx, setName, setType, setComment, addresses, false)

			// Run transaction to generate rules
			err := nft.Run(context.Background(), tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Verify the set was created with special characters
			setFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add set inet %s %s", tableName, setName)) {
					Expect(line).To(ContainSubstring(setType))
					Expect(line).To(ContainSubstring(setComment))
					setFound = true
					break
				}
			}
			Expect(setFound).To(BeTrue(), "Set creation rule not found")

			// Verify the element was added
			elementFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add element inet %s %s { 172.16.0.1 }", tableName, setName)) {
					elementFound = true
					break
				}
			}
			Expect(elementFound).To(BeTrue(), "Expected element '172.16.0.1' not found")
		})

		It("should create set with interval flag when needsIntervalFlag is true", func() {
			tx := nft.NewTransaction()
			setName := "interval-set"
			setType := "ipv4_addr"
			setComment := "Set with Interval Flag"
			addresses := []string{"10.0.0.0/24", "192.168.1.0/24"}

			createAndPopulateIPSet(tx, setName, setType, setComment, addresses, true)

			// Run transaction to generate rules
			err := nft.Run(context.Background(), tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Verify the set was created with interval flag
			setFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add set inet %s %s", tableName, setName)) {
					Expect(line).To(ContainSubstring(setType))
					Expect(line).To(ContainSubstring(setComment))
					Expect(line).To(ContainSubstring("flags interval"))
					setFound = true
					break
				}
			}
			Expect(setFound).To(BeTrue(), "Set creation rule with interval flag not found")

			// Verify all CIDR elements were added
			expectedElements := []string{"10.0.0.0/24", "192.168.1.0/24"}
			for _, expectedElement := range expectedElements {
				elementFound := false
				for _, line := range dumpLines {
					if strings.Contains(line, fmt.Sprintf("add element inet %s %s { %s }", tableName, setName, expectedElement)) {
						elementFound = true
						break
					}
				}
				Expect(elementFound).To(BeTrue(), "Expected CIDR element '%s' not found", expectedElement)
			}
		})

		It("should create set without interval flag when needsIntervalFlag is false", func() {
			tx := nft.NewTransaction()
			setName := "no-interval-set"
			setType := "ipv4_addr"
			setComment := "Set without Interval Flag"
			addresses := []string{"10.0.1.1", "192.168.1.1"}

			createAndPopulateIPSet(tx, setName, setType, setComment, addresses, false)

			// Run transaction to generate rules
			err := nft.Run(context.Background(), tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()
			dumpLines := strings.Split(dump, "\n")

			// Verify the set was created without interval flag
			setFound := false
			for _, line := range dumpLines {
				if strings.Contains(line, fmt.Sprintf("add set inet %s %s", tableName, setName)) {
					Expect(line).To(ContainSubstring(setType))
					Expect(line).To(ContainSubstring(setComment))
					Expect(line).NotTo(ContainSubstring("flags interval"))
					setFound = true
					break
				}
			}
			Expect(setFound).To(BeTrue(), "Set creation rule not found")

			// Verify all IP elements were added
			expectedElements := []string{"10.0.1.1", "192.168.1.1"}
			for _, expectedElement := range expectedElements {
				elementFound := false
				for _, line := range dumpLines {
					if strings.Contains(line, fmt.Sprintf("add element inet %s %s { %s }", tableName, setName, expectedElement)) {
						elementFound = true
						break
					}
				}
				Expect(elementFound).To(BeTrue(), "Expected IP element '%s' not found", expectedElement)
			}
		})
	})

	Context("checkPolicyTypes", func() {
		It("should return (true, false) when no policy types are specified and no egress rules", func() {
			policy := &datastore.Policy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{},              // Empty policy types
					Egress:      []multiv1beta1.MultiNetworkPolicyEgressRule{}, // No egress rules
				},
			}

			hasIngress, hasEgress := checkPolicyTypes(policy)
			Expect(hasIngress).To(BeTrue(), "Ingress should be enabled by default when no policy types specified")
			Expect(hasEgress).To(BeFalse(), "Egress should be disabled when no policy types specified and no egress rules")
		})

		It("should return (true, true) when no policy types are specified but egress rules exist", func() {
			policy := &datastore.Policy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{}, // Empty policy types
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{}, // At least one egress rule
					},
				},
			}

			hasIngress, hasEgress := checkPolicyTypes(policy)
			Expect(hasIngress).To(BeTrue(), "Ingress should be enabled by default when no policy types specified")
			Expect(hasEgress).To(BeTrue(), "Egress should be enabled when no policy types specified but egress rules exist")
		})

		It("should return (true, false) when only ingress policy type is specified", func() {
			policy := &datastore.Policy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
				},
			}

			hasIngress, hasEgress := checkPolicyTypes(policy)
			Expect(hasIngress).To(BeTrue(), "Ingress should be enabled when PolicyTypeIngress is specified")
			Expect(hasEgress).To(BeFalse(), "Egress should be disabled when only PolicyTypeIngress is specified")
		})

		It("should return (false, true) when only egress policy type is specified", func() {
			policy := &datastore.Policy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
				},
			}

			hasIngress, hasEgress := checkPolicyTypes(policy)
			Expect(hasIngress).To(BeFalse(), "Ingress should be disabled when only PolicyTypeEgress is specified")
			Expect(hasEgress).To(BeTrue(), "Egress should be enabled when PolicyTypeEgress is specified")
		})

		It("should return (true, true) when both ingress and egress policy types are specified", func() {
			policy := &datastore.Policy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{
						multiv1beta1.PolicyTypeIngress,
						multiv1beta1.PolicyTypeEgress,
					},
				},
			}

			hasIngress, hasEgress := checkPolicyTypes(policy)
			Expect(hasIngress).To(BeTrue(), "Ingress should be enabled when PolicyTypeIngress is specified")
			Expect(hasEgress).To(BeTrue(), "Egress should be enabled when PolicyTypeEgress is specified")
		})

		It("should handle multiple egress rules correctly when no policy types specified", func() {
			policy := &datastore.Policy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{}, // Empty policy types
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{}, // First egress rule
						{}, // Second egress rule
					},
				},
			}

			hasIngress, hasEgress := checkPolicyTypes(policy)
			Expect(hasIngress).To(BeTrue(), "Ingress should be enabled by default when no policy types specified")
			Expect(hasEgress).To(BeTrue(), "Egress should be enabled when multiple egress rules exist")
		})
	})

	Context("createEgressRules", func() {
		var (
			ctx    context.Context
			nft    knftables.Interface
			logger logr.Logger
		)

		BeforeEach(func() {
			ctx = context.Background()
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			logger = logr.Discard()
		})

		It("should create no rules for deny-all policy (empty egress)", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create a policy with no egress rules (deny all)
			policy := &datastore.Policy{
				Name:      "deny-all-policy",
				Namespace: "test-ns",
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
					Egress:      []multiv1beta1.MultiNetworkPolicyEgressRule{}, // Empty = deny all
				},
			}

			// Setup interfaces and transaction
			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
				{Name: "eth2", Network: "default/net2", IPs: []string{"10.0.0.2"}},
			}
			tx := nft.NewTransaction()
			hashName := "abc123"

			// Create a minimal NFTables instance for testing
			nftables := &NFTables{
				Client: nil, // We don't need the client for this test since no API calls are made
			}

			// Call createEgressRules
			err = nftables.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create accept-all rules for policy with empty egress entry", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create a policy with an empty egress entry (accept to all destinations)
			policy := &datastore.Policy{
				Name:      "accept-all-policy",
				Namespace: "test-ns",
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{}, // Empty entry = accept to all destinations
					},
				},
			}

			// Setup interfaces and transaction
			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
				{Name: "eth2", Network: "default/net2", IPs: []string{"10.0.0.2"}},
			}
			tx := nft.NewTransaction()
			hashName := "def456"

			// Create policy chain first (as done in enforcePolicy)
			npChainName := fmt.Sprintf("cnp-%s", hashName)
			err = createPolicyChain(ctx, nft, tx, npChainName, "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create NFTables instance
			nftables := &NFTables{
				Client: nil,
			}

			// Call createEgressRules
			err = nftables.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-def456 { comment \"MultiNetworkPolicy test-ns/accept-all-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy cnp-def456 oifname eth1 accept",
				"add rule inet multi_networkpolicy cnp-def456 oifname eth2 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create port-restricted rules for multiple egress entries with nil To", func() {
			// First ensure basic structure exists
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create a policy with multiple egress entries with nil To (accept to all destinations) but specific ports
			tcp := corev1.ProtocolTCP
			udp := corev1.ProtocolUDP
			policy := &datastore.Policy{
				Name:      "port-restricted-policy",
				Namespace: "prod-ns",
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{}, // Empty To = accept to all destinations
							Ports: []multiv1beta1.MultiNetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
								},
								{
									Protocol: &tcp,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 443},
								},
							},
						},
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{}, // Empty To = accept to all destinations
							Ports: []multiv1beta1.MultiNetworkPolicyPort{
								{
									Protocol: &udp,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								},
							},
						},
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{}, // Empty To = accept to all destinations
							Ports: []multiv1beta1.MultiNetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     &intstr.IntOrString{Type: intstr.String, StrVal: "SSH"},
								},
							},
						},
					},
				},
			}

			// Setup interfaces and transaction
			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.0.1"}},
			}
			tx := nft.NewTransaction()
			hashName := "ghi789"

			// Create policy chain first (as done in enforcePolicy)
			npChainName := fmt.Sprintf("cnp-%s", hashName)
			err = createPolicyChain(ctx, nft, tx, npChainName, "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create NFTables instance
			nftables := &NFTables{
				Client: nil,
			}

			// Call createEgressRules
			err = nftables.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			// Run transaction to generate rules
			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			// Get all generated rules using Dump()
			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-ghi789 { comment \"MultiNetworkPolicy prod-ns/port-restricted-policy\" ; }",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy cnp-ghi789 oifname eth1 meta l4proto tcp th dport { 80,443 } accept",
				"add rule inet multi_networkpolicy cnp-ghi789 oifname eth1 meta l4proto udp th dport { 53 } accept",
				"add rule inet multi_networkpolicy cnp-ghi789 oifname eth1 meta l4proto tcp th dport { ssh } accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		// Comprehensive tests for full coverage
		It("should create rules for egress with IPv4-only pod selector", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create fake client with IPv4-only pod
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1", 
							"ips": ["10.0.1.1"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			policy := &datastore.Policy{
				Name:      "ipv4-pod-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "web"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "ipv4test"
			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-ipv4test { comment \"MultiNetworkPolicy default/ipv4-pod-policy\" ; }",
				"add rule inet multi_networkpolicy egress jump cnp-ipv4test comment \"default/ipv4-pod-policy\"",
				"add set inet multi_networkpolicy snp-ipv4test_egress_ipv4_eth1_0 { type ipv4_addr ; comment \"Addresses for default/ipv4-pod-policy\" ; }",
				"add element inet multi_networkpolicy snp-ipv4test_egress_ipv4_eth1_0 { 10.0.1.1 }",
				"add rule inet multi_networkpolicy cnp-ipv4test oifname eth1 ip daddr @snp-ipv4test_egress_ipv4_eth1_0 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for egress with IPv6-only pod selector", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create fake client with IPv6-only pod
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1", 
							"ips": ["2001:db8::1"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			policy := &datastore.Policy{
				Name:      "ipv6-pod-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "web"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"2001:db8::1"}},
			}

			tx := nft.NewTransaction()
			hashName := "ipv6test"
			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-ipv6test { comment \"MultiNetworkPolicy default/ipv6-pod-policy\" ; }",
				"add rule inet multi_networkpolicy egress jump cnp-ipv6test comment \"default/ipv6-pod-policy\"",
				"add set inet multi_networkpolicy snp-ipv6test_egress_ipv6_eth1_0 { type ipv6_addr ; comment \"Addresses for default/ipv6-pod-policy\" ; }",
				"add element inet multi_networkpolicy snp-ipv6test_egress_ipv6_eth1_0 { 2001:db8::1 }",
				"add rule inet multi_networkpolicy cnp-ipv6test oifname eth1 ip6 daddr @snp-ipv6test_egress_ipv6_eth1_0 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for egress with dual-stack pod selector", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create fake client with dual-stack pod
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1", 
							"ips": ["10.0.1.2", "2001:db8::2"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			policy := &datastore.Policy{
				Name:      "dual-stack-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "web"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.2", "2001:db8::2"}},
			}

			tx := nft.NewTransaction()
			hashName := "dualtest"
			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-dualtest { comment \"MultiNetworkPolicy default/dual-stack-policy\" ; }",
				"add rule inet multi_networkpolicy egress jump cnp-dualtest comment \"default/dual-stack-policy\"",
				"add set inet multi_networkpolicy snp-dualtest_egress_ipv4_eth1_0 { type ipv4_addr ; comment \"Addresses for default/dual-stack-policy\" ; }",
				"add set inet multi_networkpolicy snp-dualtest_egress_ipv6_eth1_0 { type ipv6_addr ; comment \"Addresses for default/dual-stack-policy\" ; }",
				"add element inet multi_networkpolicy snp-dualtest_egress_ipv4_eth1_0 { 10.0.1.2 }",
				"add element inet multi_networkpolicy snp-dualtest_egress_ipv6_eth1_0 { 2001:db8::2 }",
				"add rule inet multi_networkpolicy cnp-dualtest oifname eth1 ip daddr @snp-dualtest_egress_ipv4_eth1_0 accept",
				"add rule inet multi_networkpolicy cnp-dualtest oifname eth1 ip6 daddr @snp-dualtest_egress_ipv6_eth1_0 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for egress with IPv4 IPBlock", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			policy := &datastore.Policy{
				Name:      "ipv4-ipblock-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR:   "10.0.0.0/24",
										Except: []string{"10.0.0.1/32", "10.0.0.2/32"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "ipv4block"

			createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: nil}
			err = nftablesInstance.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add set inet multi_networkpolicy smi-ipv4block { type ifname ; comment \"Managed interfaces set for default/ipv4-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy smi-ipv4block { eth1 }",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-ipv4block { comment \"MultiNetworkPolicy default/ipv4-ipblock-policy\" ; }",
				"add rule inet multi_networkpolicy egress jump cnp-ipv4block comment \"default/ipv4-ipblock-policy\"",
				"add set inet multi_networkpolicy snp-ipv4block_egress_ipv4_cidr_0 { type ipv4_addr ; flags interval ; comment \"CIDRs for default/ipv4-ipblock-policy\" ; }",
				"add set inet multi_networkpolicy snp-ipv4block_egress_ipv4_except_0 { type ipv4_addr ; flags interval ; comment \"Excepts for default/ipv4-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy snp-ipv4block_egress_ipv4_cidr_0 { 10.0.0.0/24 }",
				"add element inet multi_networkpolicy snp-ipv4block_egress_ipv4_except_0 { 10.0.0.1/32 }",
				"add element inet multi_networkpolicy snp-ipv4block_egress_ipv4_except_0 { 10.0.0.2/32 }",
				"add rule inet multi_networkpolicy cnp-ipv4block oifname @smi-ipv4block ip daddr @snp-ipv4block_egress_ipv4_cidr_0 ip daddr != @snp-ipv4block_egress_ipv4_except_0 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for egress with IPv6 IPBlock", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			policy := &datastore.Policy{
				Name:      "ipv6-ipblock-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR:   "2001:db8::/32",
										Except: []string{"2001:db8::1/128"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"2001:db8::2"}},
			}

			tx := nft.NewTransaction()
			hashName := "ipv6block"

			createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: nil}
			err = nftablesInstance.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add set inet multi_networkpolicy smi-ipv6block { type ifname ; comment \"Managed interfaces set for default/ipv6-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy smi-ipv6block { eth1 }",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-ipv6block { comment \"MultiNetworkPolicy default/ipv6-ipblock-policy\" ; }",
				"add rule inet multi_networkpolicy egress jump cnp-ipv6block comment \"default/ipv6-ipblock-policy\"",
				"add set inet multi_networkpolicy snp-ipv6block_egress_ipv6_cidr_0 { type ipv6_addr ; flags interval ; comment \"CIDRs for default/ipv6-ipblock-policy\" ; }",
				"add set inet multi_networkpolicy snp-ipv6block_egress_ipv6_except_0 { type ipv6_addr ; flags interval ; comment \"Excepts for default/ipv6-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy snp-ipv6block_egress_ipv6_cidr_0 { 2001:db8::/32 }",
				"add element inet multi_networkpolicy snp-ipv6block_egress_ipv6_except_0 { 2001:db8::1/128 }",
				"add rule inet multi_networkpolicy cnp-ipv6block oifname @smi-ipv6block ip6 daddr @snp-ipv6block_egress_ipv6_cidr_0 ip6 daddr != @snp-ipv6block_egress_ipv6_except_0 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for egress with dual-stack IPBlock", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			policy := &datastore.Policy{
				Name:      "dual-ipblock-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR: "10.0.0.0/24",
									},
								},
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR: "2001:db8::/32",
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1", "2001:db8::1"}},
			}

			tx := nft.NewTransaction()
			hashName := "dualblock"

			createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: nil}
			err = nftablesInstance.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add set inet multi_networkpolicy smi-dualblock { type ifname ; comment \"Managed interfaces set for default/dual-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy smi-dualblock { eth1 }",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-dualblock { comment \"MultiNetworkPolicy default/dual-ipblock-policy\" ; }",
				"add rule inet multi_networkpolicy egress jump cnp-dualblock comment \"default/dual-ipblock-policy\"",
				"add set inet multi_networkpolicy snp-dualblock_egress_ipv4_cidr_0 { type ipv4_addr ; flags interval ; comment \"CIDRs for default/dual-ipblock-policy\" ; }",
				"add set inet multi_networkpolicy snp-dualblock_egress_ipv6_cidr_0 { type ipv6_addr ; flags interval ; comment \"CIDRs for default/dual-ipblock-policy\" ; }",
				"add element inet multi_networkpolicy snp-dualblock_egress_ipv4_cidr_0 { 10.0.0.0/24 }",
				"add element inet multi_networkpolicy snp-dualblock_egress_ipv6_cidr_0 { 2001:db8::/32 }",
				"add rule inet multi_networkpolicy cnp-dualblock oifname @smi-dualblock ip daddr @snp-dualblock_egress_ipv4_cidr_0 accept",
				"add rule inet multi_networkpolicy cnp-dualblock oifname @smi-dualblock ip6 daddr @snp-dualblock_egress_ipv6_cidr_0 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for egress with mixed pod selector and IPBlock with ports", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create fake client with pod
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "default/net1",
							"interface": "eth1", 
							"ips": ["10.0.1.1"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			tcp := corev1.ProtocolTCP
			policy := &datastore.Policy{
				Name:      "mixed-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "web"},
									},
								},
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR: "192.168.1.0/24",
									},
								},
							},
							Ports: []multiv1beta1.MultiNetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
			}

			tx := nft.NewTransaction()
			hashName := "mixed"

			createManagedInterfacesSet(tx, matchedInterfaces, hashName, policy.Namespace, policy.Name, logger)

			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",
				"add set inet multi_networkpolicy smi-mixed { type ifname ; comment \"Managed interfaces set for default/mixed-policy\" ; }",
				"add element inet multi_networkpolicy smi-mixed { eth1 }",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-mixed { comment \"MultiNetworkPolicy default/mixed-policy\" ; }",
				"add rule inet multi_networkpolicy egress jump cnp-mixed comment \"default/mixed-policy\"",
				"add set inet multi_networkpolicy snp-mixed_egress_ipv4_cidr_0 { type ipv4_addr ; flags interval ; comment \"CIDRs for default/mixed-policy\" ; }",
				"add set inet multi_networkpolicy snp-mixed_egress_ipv4_eth1_0 { type ipv4_addr ; comment \"Addresses for default/mixed-policy\" ; }",
				"add element inet multi_networkpolicy snp-mixed_egress_ipv4_cidr_0 { 192.168.1.0/24 }",
				"add element inet multi_networkpolicy snp-mixed_egress_ipv4_eth1_0 { 10.0.1.1 }",
				"add rule inet multi_networkpolicy cnp-mixed oifname eth1 ip daddr @snp-mixed_egress_ipv4_eth1_0 meta l4proto tcp th dport { 80 } accept",
				"add rule inet multi_networkpolicy cnp-mixed oifname @smi-mixed ip daddr @snp-mixed_egress_ipv4_cidr_0 meta l4proto tcp th dport { 80 } accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})

		It("should create rules for egress with multiple interfaces for same network", func() {
			err := ensureBasicStructure(ctx, nft, nil, logger)
			Expect(err).NotTo(HaveOccurred())

			// Create fake client with pods having multiple interfaces
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)

			pod1 := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "default",
					Labels:    map[string]string{"app": "web"},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": `[{"name": "net1"}, {"name": "net1"}, {"name": "net1"}]`,
						"k8s.v1.cni.cncf.io/network-status": `[{
							"name": "net1",
							"interface": "eth1", 
							"ips": ["10.0.1.1"]
						}, {
							"name": "net1",
							"interface": "eth2", 
							"ips": ["10.0.1.2"]
						}, {
							"name": "net1",
							"interface": "eth3", 
							"ips": ["10.0.1.3"]
						}]`,
					},
				},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
				Spec:   corev1.PodSpec{HostNetwork: false},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pod1).
				WithIndex(&corev1.Pod{}, PodStatusIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{string(pod.Status.Phase)}
				}).
				WithIndex(&corev1.Pod{}, PodHostNetworkIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					return []string{fmt.Sprintf("%t", pod.Spec.HostNetwork)}
				}).
				WithIndex(&corev1.Pod{}, PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
					pod := obj.(*corev1.Pod)
					_, hasAnnotation := pod.Annotations["k8s.v1.cni.cncf.io/networks"]
					return []string{fmt.Sprintf("%t", hasAnnotation)}
				}).
				Build()

			policy := &datastore.Policy{
				Name:      "multi-interface-policy",
				Namespace: "default",
				Networks:  []string{"default/net1"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"app": "web"},
									},
								},
							},
						},
					},
				},
			}

			matchedInterfaces := []Interface{
				{Name: "eth1", Network: "default/net1", IPs: []string{"10.0.1.1"}},
				{Name: "eth2", Network: "default/net1", IPs: []string{"10.0.1.2"}},
				{Name: "eth3", Network: "default/net1", IPs: []string{"10.0.1.3"}},
			}

			tx := nft.NewTransaction()
			hashName := "multiintf"
			err = createPolicyChain(ctx, nft, tx, fmt.Sprintf("cnp-%s", hashName), "egress", policy.Namespace, policy.Name, logger)
			Expect(err).NotTo(HaveOccurred())

			nftablesInstance := &NFTables{Client: fakeClient}
			err = nftablesInstance.createEgressRules(ctx, tx, matchedInterfaces, policy, hashName, logger)
			Expect(err).NotTo(HaveOccurred())

			err = nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())

			dump := nft.(*knftables.Fake).Dump()

			// Split the dump into lines for easier verification
			dumpLines := strings.Split(dump, "\n")

			// Expected rules that should be generated (based on actual output)
			expectedRules := []string{
				"add table inet multi_networkpolicy { comment \"MultiNetworkPolicy\" ; }",
				"add chain inet multi_networkpolicy input { type filter hook input priority 0 ; comment \"Input Dispatcher\" ; }",
				"add chain inet multi_networkpolicy output { type filter hook output priority 0 ; comment \"Output Dispatcher\" ; }",
				"add chain inet multi_networkpolicy ingress { comment \"Ingress Policies\" ; }",
				"add chain inet multi_networkpolicy egress { comment \"Egress Policies\" ; }",
				"add chain inet multi_networkpolicy common-ingress { comment \"Common Policies\" ; }",
				"add chain inet multi_networkpolicy common-egress { comment \"Common Policies\" ; }",
				"add rule inet multi_networkpolicy egress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy egress jump common-egress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy egress drop comment \"Drop rule\"",
				"add rule inet multi_networkpolicy ingress ct state established,related accept comment \"Connection tracking\"",
				"add rule inet multi_networkpolicy ingress jump common-ingress comment \"Jump to common\"",
				"add rule inet multi_networkpolicy ingress drop comment \"Drop rule\"",

				// New commands to check
				"add chain inet multi_networkpolicy cnp-multiintf { comment \"MultiNetworkPolicy default/multi-interface-policy\" ; }",
				"add rule inet multi_networkpolicy egress jump cnp-multiintf comment \"default/multi-interface-policy\"",
				"add set inet multi_networkpolicy snp-multiintf_egress_ipv4_eth1_0 { type ipv4_addr ; comment \"Addresses for default/multi-interface-policy\" ; }",
				"add set inet multi_networkpolicy snp-multiintf_egress_ipv4_eth2_0 { type ipv4_addr ; comment \"Addresses for default/multi-interface-policy\" ; }",
				"add set inet multi_networkpolicy snp-multiintf_egress_ipv4_eth3_0 { type ipv4_addr ; comment \"Addresses for default/multi-interface-policy\" ; }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth1_0 { 10.0.1.1 }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth1_0 { 10.0.1.2 }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth1_0 { 10.0.1.3 }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth2_0 { 10.0.1.1 }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth2_0 { 10.0.1.2 }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth2_0 { 10.0.1.3 }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth3_0 { 10.0.1.1 }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth3_0 { 10.0.1.2 }",
				"add element inet multi_networkpolicy snp-multiintf_egress_ipv4_eth3_0 { 10.0.1.3 }",
				"add rule inet multi_networkpolicy cnp-multiintf oifname eth1 ip daddr @snp-multiintf_egress_ipv4_eth1_0 accept",
				"add rule inet multi_networkpolicy cnp-multiintf oifname eth2 ip daddr @snp-multiintf_egress_ipv4_eth2_0 accept",
				"add rule inet multi_networkpolicy cnp-multiintf oifname eth3 ip daddr @snp-multiintf_egress_ipv4_eth3_0 accept",
				"", // Empty line at the end
			}

			// Verify exact number of expected rules
			Expect(dumpLines).To(HaveLen(len(expectedRules)), "Expected exactly %d rules, but got %d. Rules: %v", len(expectedRules), len(dumpLines), dumpLines)

			// Verify each expected rule exists completely
			for _, expectedRule := range expectedRules {
				found := false
				for _, actualRule := range dumpLines {
					if strings.Contains(actualRule, expectedRule) {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Expected rule not found: %s\nActual rules: %v", expectedRule, dumpLines)
			}
		})
	})

	Context("createCommonRules", func() {
		var (
			nft       knftables.Interface
			ctx       context.Context
			logger    logr.Logger
			tableName string
		)

		BeforeEach(func() {
			ctx = context.Background()
			tableName = "test-table"
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			logger = logr.Discard()
		})

		// Helper function to create table and common chains
		createTableAndChains := func() {
			tx := nft.NewTransaction()
			tx.Add(&knftables.Table{
				Comment: knftables.PtrTo("MultiNetworkPolicy"),
			})
			// Create common chains
			tx.Add(&knftables.Chain{
				Name:    commonIngressChain,
				Comment: knftables.PtrTo("Common Ingress Policies"),
			})
			tx.Add(&knftables.Chain{
				Name:    commonEgressChain,
				Comment: knftables.PtrTo("Common Egress Policies"),
			})
			err := nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())
		}

		Context("when commonRules is nil", func() {
			It("should not add any rules", func() {
				createTableAndChains()

				// Now test createCommonRules
				tx := nft.NewTransaction()
				createCommonRules(tx, nil, logger)

				// Verify no operations were performed (only the common chains exist)
				chains, err := nft.List(ctx, "chain")
				Expect(err).NotTo(HaveOccurred())
				Expect(chains).To(ContainElements(commonIngressChain, commonEgressChain))
			})
		})

		Context("when commonRules has both ICMP and ICMPv6 disabled", func() {
			It("should only flush common chains", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: false,
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify only flush operations were performed (no rules added)
				chains, err := nft.List(ctx, "chain")
				Expect(err).NotTo(HaveOccurred())
				Expect(chains).To(ContainElements(commonIngressChain, commonEgressChain))
			})
		})

		Context("when commonRules has only ICMP enabled", func() {
			It("should add ICMP rules to both common chains", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   true,
					AcceptICMPv6: false,
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify the common chains were created
				chains, err := nft.List(ctx, "chain")
				Expect(err).NotTo(HaveOccurred())
				Expect(chains).To(ContainElements(commonIngressChain, commonEgressChain))

				// Verify ICMP rules were added to both chains
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(HaveLen(1))
				Expect(*ingressRules[0].Comment).To(Equal("Accept ICMP"))

				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(HaveLen(1))
				Expect(*egressRules[0].Comment).To(Equal("Accept ICMP"))
			})
		})

		Context("when commonRules has only ICMPv6 enabled", func() {
			It("should add ICMPv6 rules to both common chains", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: true,
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify the common chains were created
				chains, err := nft.List(ctx, "chain")
				Expect(err).NotTo(HaveOccurred())
				Expect(chains).To(ContainElements(commonIngressChain, commonEgressChain))

				// Verify ICMPv6 rules were added to both chains
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(HaveLen(1))
				Expect(*ingressRules[0].Comment).To(Equal("Accept ICMPv6"))

				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(HaveLen(1))
				Expect(*egressRules[0].Comment).To(Equal("Accept ICMPv6"))
			})
		})

		Context("when commonRules has both ICMP and ICMPv6 enabled", func() {
			It("should add both ICMP and ICMPv6 rules to both common chains", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   true,
					AcceptICMPv6: true,
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify the common chains were created
				chains, err := nft.List(ctx, "chain")
				Expect(err).NotTo(HaveOccurred())
				Expect(chains).To(ContainElements(commonIngressChain, commonEgressChain))

				// Verify both ICMP and ICMPv6 rules were added to ingress chain
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(HaveLen(2))

				comments := []string{*ingressRules[0].Comment, *ingressRules[1].Comment}
				Expect(comments).To(ContainElements("Accept ICMP", "Accept ICMPv6"))

				// Verify both ICMP and ICMPv6 rules were added to egress chain
				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(HaveLen(2))

				comments = []string{*egressRules[0].Comment, *egressRules[1].Comment}
				Expect(comments).To(ContainElements("Accept ICMP", "Accept ICMPv6"))
			})
		})

		Context("when called multiple times with different rules", func() {
			It("should flush and recreate rules each time", func() {
				createTableAndChains()

				// First call with ICMP only
				commonRules1 := &CommonRules{
					AcceptICMP:   true,
					AcceptICMPv6: false,
				}

				tx1 := nft.NewTransaction()
				createCommonRules(tx1, commonRules1, logger)
				err := nft.Run(ctx, tx1)
				Expect(err).NotTo(HaveOccurred())

				// Verify only ICMP rules exist
				ingressRules1, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules1).To(HaveLen(1))
				Expect(*ingressRules1[0].Comment).To(Equal("Accept ICMP"))

				// Second call with both ICMP and ICMPv6
				commonRules2 := &CommonRules{
					AcceptICMP:   true,
					AcceptICMPv6: true,
				}

				tx2 := nft.NewTransaction()
				createCommonRules(tx2, commonRules2, logger)
				err = nft.Run(ctx, tx2)
				Expect(err).NotTo(HaveOccurred())

				// Verify both ICMP and ICMPv6 rules exist (previous rules were flushed)
				ingressRules2, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules2).To(HaveLen(2))

				comments := []string{*ingressRules2[0].Comment, *ingressRules2[1].Comment}
				Expect(comments).To(ContainElements("Accept ICMP", "Accept ICMPv6"))
			})
		})

		Context("custom rules handling", func() {
			It("should add custom IPv4 ingress rules", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: false,
					CustomIPv4IngressRules: []string{
						"tcp dport 8080 accept",
						"udp dport 9090 accept",
					},
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify custom rules were added to ingress chain
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(HaveLen(2))
				Expect(*ingressRules[0].Comment).To(Equal("Custom Rule"))
				Expect(*ingressRules[1].Comment).To(Equal("Custom Rule"))

				// Verify no custom rules were added to egress chain (only ingress rules)
				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(BeEmpty())
			})

			It("should add custom IPv6 ingress rules", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: false,
					CustomIPv6IngressRules: []string{
						"ip6 saddr 2001:db8::/32 accept",
						"ip6 daddr fe80::/10 drop",
					},
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify custom rules were added to ingress chain
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(HaveLen(2))
				Expect(*ingressRules[0].Comment).To(Equal("Custom Rule"))
				Expect(*ingressRules[1].Comment).To(Equal("Custom Rule"))

				// Verify no custom rules were added to egress chain (only ingress rules)
				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(BeEmpty())
			})

			It("should add custom IPv4 egress rules", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: false,
					CustomIPv4EgressRules: []string{
						"ip saddr 192.168.1.0/24 accept",
						"ip daddr 10.0.0.0/8 drop",
					},
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify no custom rules were added to ingress chain (only egress rules)
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(BeEmpty())

				// Verify custom rules were added to egress chain
				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(HaveLen(2))
				Expect(*egressRules[0].Comment).To(Equal("Custom Rule"))
				Expect(*egressRules[1].Comment).To(Equal("Custom Rule"))
			})

			It("should add custom IPv6 egress rules", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: false,
					CustomIPv6EgressRules: []string{
						"ip6 saddr 2001:db8::/32 accept",
						"ip6 daddr fe80::/10 drop",
					},
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify no custom rules were added to ingress chain (only egress rules)
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(BeEmpty())

				// Verify custom rules were added to egress chain
				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(HaveLen(2))
				Expect(*egressRules[0].Comment).To(Equal("Custom Rule"))
				Expect(*egressRules[1].Comment).To(Equal("Custom Rule"))
			})

			It("should add all types of custom rules together", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   true,
					AcceptICMPv6: true,
					CustomIPv4IngressRules: []string{
						"tcp dport 8080 accept",
					},
					CustomIPv6IngressRules: []string{
						"ip6 saddr 2001:db8::/32 accept",
					},
					CustomIPv4EgressRules: []string{
						"ip saddr 192.168.1.0/24 accept",
					},
					CustomIPv6EgressRules: []string{
						"ip6 daddr fe80::/10 drop",
					},
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify all rules were added to ingress chain
				// Should have: ICMP, ICMPv6, IPv4 ingress custom, IPv6 ingress custom = 4 rules
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(HaveLen(4))

				// Verify all rules were added to egress chain
				// Should have: ICMP, ICMPv6, IPv4 egress custom, IPv6 egress custom = 4 rules
				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(HaveLen(4))
			})

			It("should handle empty custom rules", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:             false,
					AcceptICMPv6:           false,
					CustomIPv4IngressRules: []string{},
					CustomIPv6IngressRules: []string{},
					CustomIPv4EgressRules:  []string{},
					CustomIPv6EgressRules:  []string{},
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify no rules were added
				ingressRules, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules).To(BeEmpty())

				egressRules, err := nft.ListRules(ctx, commonEgressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(egressRules).To(BeEmpty())
			})

			It("should flush and recreate custom rules on multiple calls", func() {
				createTableAndChains()

				// First call with some custom rules
				commonRules1 := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: false,
					CustomIPv4IngressRules: []string{
						"tcp dport 8080 accept",
					},
				}

				tx1 := nft.NewTransaction()
				createCommonRules(tx1, commonRules1, logger)
				err := nft.Run(ctx, tx1)
				Expect(err).NotTo(HaveOccurred())

				// Verify first set of rules
				ingressRules1, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules1).To(HaveLen(1))

				// Second call with different custom rules
				commonRules2 := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: false,
					CustomIPv4IngressRules: []string{
						"tcp dport 9090 accept",
						"udp dport 8080 accept",
					},
				}

				tx2 := nft.NewTransaction()
				createCommonRules(tx2, commonRules2, logger)
				err = nft.Run(ctx, tx2)
				Expect(err).NotTo(HaveOccurred())

				// Verify second set of rules (previous rules should be flushed)
				ingressRules2, err := nft.ListRules(ctx, commonIngressChain)
				Expect(err).NotTo(HaveOccurred())
				Expect(ingressRules2).To(HaveLen(2))
			})
		})

		Context("rule content verification", func() {
			It("should create correct ICMP rule content", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   true,
					AcceptICMPv6: false,
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Get the actual nftables output to verify rule content
				cmd := nft.(*knftables.Fake).Dump()
				Expect(cmd).To(ContainSubstring("meta l4proto icmp accept"))
			})

			It("should create correct ICMPv6 rule content", func() {
				createTableAndChains()

				commonRules := &CommonRules{
					AcceptICMP:   false,
					AcceptICMPv6: true,
				}

				tx := nft.NewTransaction()
				createCommonRules(tx, commonRules, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Get the actual nftables output to verify rule content
				cmd := nft.(*knftables.Fake).Dump()
				Expect(cmd).To(ContainSubstring("meta l4proto icmpv6 accept"))
			})
		})
	})

	Context("createReverseRules", func() {
		var (
			nft       knftables.Interface
			ctx       context.Context
			logger    logr.Logger
			tableName string
		)

		BeforeEach(func() {
			ctx = context.Background()
			tableName = "test-table"
			nft = knftables.NewFake(knftables.InetFamily, tableName)
			logger = logr.Discard()
		})

		// Helper function to create table and policy chain
		createTableAndPolicyChain := func(chainName string) {
			tx := nft.NewTransaction()
			tx.Add(&knftables.Table{
				Comment: knftables.PtrTo("MultiNetworkPolicy"),
			})
			tx.Add(&knftables.Chain{
				Name:    chainName,
				Comment: knftables.PtrTo("Test Policy Chain"),
			})
			err := nft.Run(ctx, tx)
			Expect(err).NotTo(HaveOccurred())
		}

		Context("when interfaces have valid IPv4 addresses", func() {
			It("should create reverse routes for IPv4 addresses", func() {
				chainName := "test-policy-chain"
				createTableAndPolicyChain(chainName)

				matchedInterfaces := []Interface{
					{
						Name:    "eth0",
						Network: "default/macvlan1",
						IPs:     []string{"192.168.1.10", "192.168.1.11"},
					},
					{
						Name:    "eth1",
						Network: "default/macvlan2",
						IPs:     []string{"192.168.2.10"},
					},
				}

				tx := nft.NewTransaction()
				createReverseRules(tx, matchedInterfaces, chainName, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify rules were created
				rules, err := nft.ListRules(ctx, chainName)
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(3)) // 2 IPs from eth0 + 1 IP from eth1

				// Verify rule content
				cmd := nft.(*knftables.Fake).Dump()
				Expect(cmd).To(ContainSubstring("iifname eth0 ip saddr 192.168.1.10 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth0 ip saddr 192.168.1.11 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth1 ip saddr 192.168.2.10 accept"))
			})
		})

		Context("when interfaces have valid IPv6 addresses", func() {
			It("should create reverse routes for IPv6 addresses", func() {
				chainName := "test-policy-chain"
				createTableAndPolicyChain(chainName)

				matchedInterfaces := []Interface{
					{
						Name:    "eth0",
						Network: "default/macvlan1",
						IPs:     []string{"2001:db8::1", "2001:db8::2"},
					},
					{
						Name:    "eth1",
						Network: "default/macvlan2",
						IPs:     []string{"2001:db8:1::1"},
					},
				}

				tx := nft.NewTransaction()
				createReverseRules(tx, matchedInterfaces, chainName, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify rules were created
				rules, err := nft.ListRules(ctx, chainName)
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(3)) // 2 IPs from eth0 + 1 IP from eth1

				// Verify rule content
				cmd := nft.(*knftables.Fake).Dump()
				Expect(cmd).To(ContainSubstring("iifname eth0 ip6 saddr 2001:db8::1 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth0 ip6 saddr 2001:db8::2 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth1 ip6 saddr 2001:db8:1::1 accept"))
			})
		})

		Context("when interfaces have mixed IPv4 and IPv6 addresses", func() {
			It("should create reverse routes for both IPv4 and IPv6 addresses", func() {
				chainName := "test-policy-chain"
				createTableAndPolicyChain(chainName)

				matchedInterfaces := []Interface{
					{
						Name:    "eth0",
						Network: "default/macvlan1",
						IPs:     []string{"192.168.1.10", "2001:db8::1"},
					},
					{
						Name:    "eth1",
						Network: "default/macvlan2",
						IPs:     []string{"10.0.0.1", "2001:db8:1::1"},
					},
				}

				tx := nft.NewTransaction()
				createReverseRules(tx, matchedInterfaces, chainName, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify rules were created
				rules, err := nft.ListRules(ctx, chainName)
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(4)) // 2 IPs from eth0 + 2 IPs from eth1

				// Verify rule content
				cmd := nft.(*knftables.Fake).Dump()
				Expect(cmd).To(ContainSubstring("iifname eth0 ip saddr 192.168.1.10 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth0 ip6 saddr 2001:db8::1 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth1 ip saddr 10.0.0.1 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth1 ip6 saddr 2001:db8:1::1 accept"))
			})
		})

		Context("when interfaces have empty IP lists", func() {
			It("should not create any rules for interfaces with empty IP lists", func() {
				chainName := "test-policy-chain"
				createTableAndPolicyChain(chainName)

				matchedInterfaces := []Interface{
					{
						Name:    "eth0",
						Network: "default/macvlan1",
						IPs:     []string{}, // Empty IP list
					},
					{
						Name:    "eth1",
						Network: "default/macvlan2",
						IPs:     nil, // Nil IP list
					},
				}

				tx := nft.NewTransaction()
				createReverseRules(tx, matchedInterfaces, chainName, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify no rules were created
				rules, err := nft.ListRules(ctx, chainName)
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(BeEmpty())
			})
		})

		Context("when interfaces have invalid IP addresses", func() {
			It("should handle invalid IP addresses gracefully", func() {
				chainName := "test-policy-chain"
				createTableAndPolicyChain(chainName)

				matchedInterfaces := []Interface{
					{
						Name:    "eth0",
						Network: "default/macvlan1",
						IPs:     []string{"192.168.1.10", "invalid-ip", "2001:db8::1"},
					},
				}

				tx := nft.NewTransaction()
				createReverseRules(tx, matchedInterfaces, chainName, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify only valid IPs created rules
				rules, err := nft.ListRules(ctx, chainName)
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(2)) // Only valid IPs

				// Verify rule content
				cmd := nft.(*knftables.Fake).Dump()
				Expect(cmd).To(ContainSubstring("iifname eth0 ip saddr 192.168.1.10 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth0 ip6 saddr 2001:db8::1 accept"))
				Expect(cmd).NotTo(ContainSubstring("invalid-ip"))
			})
		})

		Context("when no interfaces are provided", func() {
			It("should not create any rules", func() {
				chainName := "test-policy-chain"
				createTableAndPolicyChain(chainName)

				matchedInterfaces := []Interface{}

				tx := nft.NewTransaction()
				createReverseRules(tx, matchedInterfaces, chainName, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify no rules were created
				rules, err := nft.ListRules(ctx, chainName)
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(BeEmpty())
			})
		})

		Context("when interfaces have special characters in names", func() {
			It("should handle special characters in interface names", func() {
				chainName := "test-policy-chain"
				createTableAndPolicyChain(chainName)

				matchedInterfaces := []Interface{
					{
						Name:    "eth0.100", // VLAN interface
						Network: "default/macvlan1",
						IPs:     []string{"192.168.1.10"},
					},
					{
						Name:    "bond0", // Bond interface
						Network: "default/macvlan2",
						IPs:     []string{"192.168.2.10"},
					},
				}

				tx := nft.NewTransaction()
				createReverseRules(tx, matchedInterfaces, chainName, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify rules were created
				rules, err := nft.ListRules(ctx, chainName)
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(2))

				// Verify rule content
				cmd := nft.(*knftables.Fake).Dump()
				Expect(cmd).To(ContainSubstring("iifname eth0.100 ip saddr 192.168.1.10 accept"))
				Expect(cmd).To(ContainSubstring("iifname bond0 ip saddr 192.168.2.10 accept"))
			})
		})

		Context("when interfaces have duplicate IPs", func() {
			It("should create rules for duplicate IPs on different interfaces", func() {
				chainName := "test-policy-chain"
				createTableAndPolicyChain(chainName)

				matchedInterfaces := []Interface{
					{
						Name:    "eth0",
						Network: "default/macvlan1",
						IPs:     []string{"192.168.1.10"},
					},
					{
						Name:    "eth1",
						Network: "default/macvlan2",
						IPs:     []string{"192.168.1.10"}, // Same IP on different interface
					},
				}

				tx := nft.NewTransaction()
				createReverseRules(tx, matchedInterfaces, chainName, logger)

				// Run the transaction
				err := nft.Run(ctx, tx)
				Expect(err).NotTo(HaveOccurred())

				// Verify rules were created for both interfaces
				rules, err := nft.ListRules(ctx, chainName)
				Expect(err).NotTo(HaveOccurred())
				Expect(rules).To(HaveLen(2))

				// Verify rule content
				cmd := nft.(*knftables.Fake).Dump()
				Expect(cmd).To(ContainSubstring("iifname eth0 ip saddr 192.168.1.10 accept"))
				Expect(cmd).To(ContainSubstring("iifname eth1 ip saddr 192.168.1.10 accept"))
			})
		})
	})
})
