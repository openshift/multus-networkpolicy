package nftables

import (
	"context"
	"fmt"
	"runtime"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/knftables"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/datastore"
	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/utils"
)

var _ = Describe("NFTables Simple Integration Tests", func() {
	var (
		ctx               context.Context
		logger            logr.Logger
		targetPod         *corev1.Pod
		matchedInterfaces []Interface
		actualHashName    string

		// Test pods for comprehensive test
		backendPod   *corev1.Pod
		frontendPod1 *corev1.Pod
		frontendPod2 *corev1.Pod
		databasePod  *corev1.Pod

		// Test namespaces
		prodNamespace *corev1.Namespace
		devNamespace  *corev1.Namespace
	)

	BeforeEach(func() {
		ctx = context.Background()
		logger = logr.Discard()

		// Create target pod (the one policies apply to)
		targetPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "target-pod",
				Namespace: "test-ns",
				Labels:    map[string]string{"app": "web"},
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/networks":       "net1,net2",
					"k8s.v1.cni.cncf.io/network-status": `[{"name":"test-ns/net1","interface":"eth1","ips":["10.0.1.1","2001:db8:1::1"],"dns":{}},{"name":"test-ns/net2","interface":"eth2","ips":["10.0.2.1","2001:db8:2::1"],"dns":{}}]`,
				},
			},
			Spec:   corev1.PodSpec{HostNetwork: false},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}

		matchedInterfaces = []Interface{
			{Name: "eth1", Network: "test-ns/net1", IPs: []string{"10.0.1.1", "2001:db8:1::1"}},
			{Name: "eth2", Network: "test-ns/net2", IPs: []string{"10.0.2.1", "2001:db8:2::1"}},
		}

		// Create test pods for comprehensive test
		backendPod = createDualStackPod("backend-pod", "test-ns",
			map[string]string{"app": "backend", "tier": "api"},
			"10.0.1.10", "10.0.2.10", "2001:db8:1::10", "2001:db8:2::10")

		frontendPod1 = createDualStackPod("frontend-pod1", "production",
			map[string]string{"app": "frontend", "role": "web"},
			"10.0.1.20", "10.0.2.20", "2001:db8:1::20", "2001:db8:2::20")

		frontendPod2 = createDualStackPod("frontend-pod2", "production",
			map[string]string{"app": "frontend", "role": "logs"},
			"10.0.1.21", "10.0.2.21", "2001:db8:1::21", "2001:db8:2::21")

		databasePod = createDualStackPod("database-pod", "development",
			map[string]string{"app": "database", "tier": "data"},
			"10.0.1.30", "10.0.2.30", "2001:db8:1::30", "2001:db8:2::30")

		// Create test namespaces
		prodNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "production",
				Labels: map[string]string{"env": "prod"},
			},
		}
		devNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "development",
				Labels: map[string]string{"env": "dev"},
			},
		}
	})

	It("should handle deny-all policy", func() {
		defer GinkgoRecover()

		netNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer netNS.Close()

		err = netNS.Do(func(_ ns.NetNS) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			nft, err := knftables.New(knftables.InetFamily, "multi_networkpolicy")
			if err != nil {
				return err
			}

			nftablesWithPods := &NFTables{
				Client: createFakeClient([]*corev1.Pod{targetPod}),
			}

			policy := createDenyAllPolicy("deny-all", "test-ns")
			actualHashName = utils.GetHashName(policy.Name, policy.Namespace)

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			// Verify basic structures exist
			expectedSetElements := map[string]int{"smi-" + actualHashName: 2}
			expectedPolicyRules := 4 // Deny-all has 4 reverse rules in ingress

			err = verifyChainAndRules(ctx, nft, actualHashName, expectedPolicyRules)
			if err != nil {
				return err
			}
			return verifySetAndElements(ctx, nft, expectedSetElements)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle accept-all policy", func() {
		defer GinkgoRecover()

		netNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer netNS.Close()

		err = netNS.Do(func(_ ns.NetNS) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			nft, err := knftables.New(knftables.InetFamily, "multi_networkpolicy")
			if err != nil {
				return err
			}

			nftablesWithPods := &NFTables{
				Client: createFakeClient([]*corev1.Pod{targetPod}),
			}

			policy := createAcceptAllPolicy("accept-all", "test-ns")
			actualHashName = utils.GetHashName(policy.Name, policy.Namespace)

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			// Verify basic structures exist
			expectedSetElements := map[string]int{"smi-" + actualHashName: 2}
			expectedPolicyRules := 8 // 2 ingress + 2 egress (1 per interface each) + 4 reverse rules in ingress

			err = verifyChainAndRules(ctx, nft, actualHashName, expectedPolicyRules)
			if err != nil {
				return err
			}
			return verifySetAndElements(ctx, nft, expectedSetElements)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle accept-all with port restrictions", func() {
		defer GinkgoRecover()

		netNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer netNS.Close()

		err = netNS.Do(func(_ ns.NetNS) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			nft, err := knftables.New(knftables.InetFamily, "multi_networkpolicy")
			if err != nil {
				return err
			}

			nftablesWithPods := &NFTables{
				Client: createFakeClient([]*corev1.Pod{targetPod}),
			}

			policy := createAcceptAllWithPortsPolicy("accept-ports", "test-ns")
			actualHashName = utils.GetHashName(policy.Name, policy.Namespace)

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			// Verify basic structures exist - ports create anonymous sets, so just count rules
			expectedSetElements := map[string]int{"smi-" + actualHashName: 2}
			expectedPolicyRules := 8 // Port restrictions create grouped rules + 4 reverse rules in ingress

			err = verifyChainAndRules(ctx, nft, actualHashName, expectedPolicyRules)
			if err != nil {
				return err
			}
			return verifySetAndElements(ctx, nft, expectedSetElements)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle comprehensive stacked policy", func() {
		defer GinkgoRecover()

		netNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer netNS.Close()

		err = netNS.Do(func(_ ns.NetNS) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			nft, err := knftables.New(knftables.InetFamily, "multi_networkpolicy")
			if err != nil {
				return err
			}

			nftablesWithPods := &NFTables{
				Client: createFakeClientWithNamespaces([]*corev1.Pod{targetPod, backendPod, frontendPod1, frontendPod2, databasePod},
					[]*corev1.Namespace{prodNamespace, devNamespace}),
			}

			policy := createComprehensivePolicy("comprehensive", "test-ns")
			actualHashName = utils.GetHashName(policy.Name, policy.Namespace)

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			// Verify set and its elements exist
			expectedSetElements := map[string]int{
				"smi-" + actualHashName: 2, // eth1, eth2
				// Just verify some key sets have elements
				"snp-" + actualHashName + "_ingress_ipv4_eth1_0": 1, // backendPod ipv4
				"snp-" + actualHashName + "_ingress_ipv6_eth1_0": 1, // backendpod ipv6
				"snp-" + actualHashName + "_ingress_ipv4_eth2_0": 1, // backendPod ipv4
				"snp-" + actualHashName + "_ingress_ipv6_eth2_0": 1, // backendpod ipv6

				"snp-" + actualHashName + "_ingress_ipv4_eth1_1": 2, // frontend1, frontend2 ipv4
				"snp-" + actualHashName + "_ingress_ipv6_eth1_1": 2, // frontend1, frontend2 ipv6
				"snp-" + actualHashName + "_ingress_ipv4_eth2_1": 2, // frontend1, frontend2 ipv4
				"snp-" + actualHashName + "_ingress_ipv6_eth2_1": 2, // frontend1, frontend2 ipv6

				"snp-" + actualHashName + "_ingress_ipv4_cidr_2":   1, // cidr ipv4
				"snp-" + actualHashName + "_ingress_ipv4_except_2": 1, // except ipv4
				"snp-" + actualHashName + "_ingress_ipv6_cidr_2":   1, // cidr ipv4
				"snp-" + actualHashName + "_ingress_ipv6_except_2": 1, // except ipv4

				"snp-" + actualHashName + "_egress_ipv4_eth1_0": 1, // frontend2 ipv4
				"snp-" + actualHashName + "_egress_ipv6_eth1_0": 1, // frontend2 ipv6
				"snp-" + actualHashName + "_egress_ipv4_eth2_0": 1, // frontend2 ipv4
				"snp-" + actualHashName + "_egress_ipv6_eth2_0": 1, // frontend2 ipv6
			}

			// 10 ingres + 4 egress + 4 reverse rules in ingress
			expectedRules := 18

			err = verifyChainAndRules(ctx, nft, actualHashName, expectedRules)
			if err != nil {
				return err
			}
			return verifySetAndElements(ctx, nft, expectedSetElements)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle full livecycle", func() {
		defer GinkgoRecover()

		netNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer netNS.Close()

		err = netNS.Do(func(_ ns.NetNS) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			nft, err := knftables.New(knftables.InetFamily, "multi_networkpolicy")
			if err != nil {
				return err
			}

			nftablesWithPods := &NFTables{
				Client: createFakeClientWithNamespaces([]*corev1.Pod{targetPod, backendPod, frontendPod1, frontendPod2, databasePod},
					[]*corev1.Namespace{prodNamespace, devNamespace}),
			}

			// Add deny all policy
			policy := createDenyAllPolicy("deny-all", "test-ns")
			actualHashNameDeny := utils.GetHashName(policy.Name, policy.Namespace)

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			// Verify basic structures exist
			expectedSetElements := map[string]int{"smi-" + actualHashNameDeny: 2}
			expectedPolicyRules := 4 // Deny-all has 4 reverse rules in ingress

			err = verifyChainAndRules(ctx, nft, actualHashNameDeny, expectedPolicyRules)
			if err != nil {
				return err
			}
			err = verifySetAndElements(ctx, nft, expectedSetElements)
			if err != nil {
				return err
			}

			// Add comprehensive policy
			policy = createComprehensivePolicy("comprehensive", "test-ns")
			actualHashName = utils.GetHashName(policy.Name, policy.Namespace)

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			// Verify set and its elements exist
			expectedSetElements = map[string]int{
				"smi-" + actualHashNameDeny: 2,
				"smi-" + actualHashName:     2, // eth1, eth2
				// Just verify some key sets have elements
				"snp-" + actualHashName + "_ingress_ipv4_eth1_0": 1, // backendPod ipv4
				"snp-" + actualHashName + "_ingress_ipv6_eth1_0": 1, // backendpod ipv6
				"snp-" + actualHashName + "_ingress_ipv4_eth2_0": 1, // backendPod ipv4
				"snp-" + actualHashName + "_ingress_ipv6_eth2_0": 1, // backendpod ipv6

				"snp-" + actualHashName + "_ingress_ipv4_eth1_1": 2, // frontend1, frontend2 ipv4
				"snp-" + actualHashName + "_ingress_ipv6_eth1_1": 2, // frontend1, frontend2 ipv6
				"snp-" + actualHashName + "_ingress_ipv4_eth2_1": 2, // frontend1, frontend2 ipv4
				"snp-" + actualHashName + "_ingress_ipv6_eth2_1": 2, // frontend1, frontend2 ipv6

				"snp-" + actualHashName + "_ingress_ipv4_cidr_2":   1, // cidr ipv4
				"snp-" + actualHashName + "_ingress_ipv4_except_2": 1, // except ipv4
				"snp-" + actualHashName + "_ingress_ipv6_cidr_2":   1, // cidr ipv4
				"snp-" + actualHashName + "_ingress_ipv6_except_2": 1, // except ipv4

				"snp-" + actualHashName + "_egress_ipv4_eth1_0": 1, // frontend2 ipv4
				"snp-" + actualHashName + "_egress_ipv6_eth1_0": 1, // frontend2 ipv6
				"snp-" + actualHashName + "_egress_ipv4_eth2_0": 1, // frontend2 ipv4
				"snp-" + actualHashName + "_egress_ipv6_eth2_0": 1, // frontend2 ipv6
			}

			// 10 ingres + 4 egress + 4 reverse rules in ingress
			expectedRules := 18

			err = verifySetAndElements(ctx, nft, expectedSetElements)
			if err != nil {
				return err
			}

			// Comprehensive policy should be in effect
			err = verifyChainAndRules(ctx, nft, actualHashName, expectedRules)
			if err != nil {
				return err
			}

			// Clean up comprehensive policy
			err = cleanUpPolicy(ctx, policy.Name, policy.Namespace, logger)
			if err != nil {
				return err
			}

			// Verify basic structures exist
			expectedSetElements = map[string]int{"smi-" + actualHashNameDeny: 2}
			expectedPolicyRules = 4 // Deny-all has 4 reverse rules in ingress

			err = verifySetAndElements(ctx, nft, expectedSetElements)
			if err != nil {
				return err
			}

			err = verifyChainAndRules(ctx, nft, actualHashName, 14)
			if err == nil {
				return err
			}

			return verifyChainAndRules(ctx, nft, actualHashNameDeny, expectedPolicyRules)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be able to clean up on a pod without nft objects", func() {
		defer GinkgoRecover()

		netNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer netNS.Close()

		err = netNS.Do(func(_ ns.NetNS) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// Clean up comprehensive policy
			return cleanUpPolicy(ctx, "policy-test", "namespace", logger)
		})
		Expect(err).NotTo(HaveOccurred())
	})
})

// Helper function to create a dual-stack pod
func createDualStackPod(name, namespace string, labels map[string]string, ipv4Net1, ipv4Net2, ipv6Net1, ipv6Net2 string) *corev1.Pod {
	// We assume that the network attachment definition is common. There is no restriction per namespace
	networkStatus := `[{"name":"test-ns/net1","interface":"eth1","ips":["` + ipv4Net1 + `","` + ipv6Net1 + `"],"dns":{}},{"name":"test-ns/net2","interface":"eth2","ips":["` + ipv4Net2 + `","` + ipv6Net2 + `"],"dns":{}}]`

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/networks":       "net1,net2",
				"k8s.v1.cni.cncf.io/network-status": networkStatus,
			},
		},
		Spec:   corev1.PodSpec{HostNetwork: false},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// Helper function to create a fake client with pods
func createFakeClient(pods []*corev1.Pod) client.Client {
	scheme := k8sruntime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	objects := make([]client.Object, len(pods))
	for i, pod := range pods {
		objects[i] = pod
	}

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithIndex(&corev1.Pod{}, PodHostnameIndex, func(obj client.Object) []string {
			pod := obj.(*corev1.Pod)
			return []string{pod.Spec.NodeName}
		}).
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
}

// Helper function to create a fake client with pods and namespaces
func createFakeClientWithNamespaces(pods []*corev1.Pod, namespaces []*corev1.Namespace) client.Client {
	scheme := k8sruntime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	objects := make([]client.Object, len(pods)+len(namespaces))
	for i, pod := range pods {
		objects[i] = pod
	}
	for i, ns := range namespaces {
		objects[len(pods)+i] = ns
	}

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithIndex(&corev1.Pod{}, PodHostnameIndex, func(obj client.Object) []string {
			pod := obj.(*corev1.Pod)
			return []string{pod.Spec.NodeName}
		}).
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
}

// Policy creation helpers
func createDenyAllPolicy(name, namespace string) *datastore.Policy {
	return &datastore.Policy{
		Name:      name,
		Namespace: namespace,
		Networks:  []string{"test-ns/net1", "test-ns/net2"},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeIngress,
				multiv1beta1.PolicyTypeEgress,
			},
			// Empty Ingress and Egress = deny all
		},
	}
}

func createAcceptAllPolicy(name, namespace string) *datastore.Policy {
	return &datastore.Policy{
		Name:      name,
		Namespace: namespace,
		Networks:  []string{"test-ns/net1", "test-ns/net2"},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeIngress,
				multiv1beta1.PolicyTypeEgress,
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{}, // Empty From = accept all
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{}, // Empty To = accept all
			},
		},
	}
}

func createAcceptAllWithPortsPolicy(name, namespace string) *datastore.Policy {
	endPort := int32(8010)
	return &datastore.Policy{
		Name:      name,
		Namespace: namespace,
		Networks:  []string{"test-ns/net1", "test-ns/net2"},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeIngress,
				multiv1beta1.PolicyTypeEgress,
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 80}},                      // Specific port
						{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "https"}},              // Named port
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8000}, EndPort: &endPort}, // Port range
					},
				},
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 443}}, // HTTPS egress
					},
				},
			},
		},
	}
}

func createComprehensivePolicy(name, namespace string) *datastore.Policy {
	endPort := int32(8010)
	return &datastore.Policy{
		Name:      name,
		Namespace: namespace,
		Networks:  []string{"test-ns/net1", "test-ns/net2"},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeIngress,
				multiv1beta1.PolicyTypeEgress,
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					// Rule 0: Pod selector
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "backend"},
							},
						},
					},
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 80}},                      // Specific port
						{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "https"}},              // Named port
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8000}, EndPort: &endPort}, // Port range
					},
				},
				{
					// Rule 1: Namespace selector
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"env": "prod"},
							},
						},
					},
				},
				{
					// Rule 2: IPBlock with exceptions
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR:   "10.0.0.0/8",
								Except: []string{"10.1.0.0/16"},
							},
						},
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR:   "2001:db8::/32",
								Except: []string{"2001:db8:1::/48"},
							},
						},
					},
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 80}},                      // Specific port
						{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "https"}},              // Named port
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 8000}, EndPort: &endPort}, // Port range
					},
				},
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					// Egress to database pods
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"env": "prod"},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "frontend", "role": "logs"},
							},
						},
					},
				},
			},
		},
	}
}

// verifyChainAndRules verifies the chain and rule count for a given policy
func verifyChainAndRules(ctx context.Context, nft knftables.Interface, hashName string, expectedRules int) error {
	// Get policy chain
	chainName := fmt.Sprintf("cnp-%s", hashName)
	rules, err := nft.ListRules(ctx, chainName)
	if err != nil {
		return err
	}

	// Verify rule count
	if len(rules) != expectedRules {
		return fmt.Errorf("expected %d rules in policy chain, got %d", expectedRules, len(rules))
	}

	return nil
}

// verifySetAndElements verifies the sets and their element counts
func verifySetAndElements(ctx context.Context, nft knftables.Interface, expectedSetElements map[string]int) error {
	// Get all sets
	sets, err := nft.List(ctx, "sets")
	if err != nil {
		return err
	}

	// Verify set count
	if len(sets) != len(expectedSetElements) {
		return fmt.Errorf("expected %d sets, got %d", len(expectedSetElements), len(sets))
	}

	// Verify expected sets exist
	for expectedSet, expectedElements := range expectedSetElements {
		found := false
		for _, set := range sets {
			if set == expectedSet {
				found = true
				// Verify element count
				elements, err := nft.ListElements(ctx, "set", expectedSet)
				if err != nil {
					return err
				}
				if len(elements) != expectedElements {
					return fmt.Errorf("expected %d elements in set %s, got %d", expectedElements, expectedSet, len(elements))
				}
				break
			}
		}
		if !found {
			return fmt.Errorf("expected set %s not found", expectedSet)
		}
	}

	return nil
}
