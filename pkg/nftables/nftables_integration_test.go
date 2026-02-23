package nftables

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/k8snetworkplumbingwg/multi-network-policy-nftables/pkg/datastore"
)

var logger logr.Logger = funcr.New(func(prefix, args string) {
	GinkgoWriter.Printf("%s %s\n", prefix, args)
}, funcr.Options{Verbosity: 6})

var _ = Describe("NFTables Simple Integration Tests", func() {
	var (
		ctx               context.Context
		targetPod         *corev1.Pod
		matchedInterfaces []Interface

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

			nftablesWithPods := &NFTables{
				Client: createFakeClient([]*corev1.Pod{targetPod}),
			}

			policy := createDenyAllPolicy("deny-all", "test-ns")

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			// Verify using golden file
			return verifyNFTablesGoldenFile("deny-all-policy.nft")
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

			nftablesWithPods := &NFTables{
				Client: createFakeClient([]*corev1.Pod{targetPod}),
			}

			policy := createAcceptAllPolicy("accept-all", "test-ns")

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			return verifyNFTablesGoldenFile("accept-all-policy.nft")
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

			nftablesWithPods := &NFTables{
				Client: createFakeClient([]*corev1.Pod{targetPod}),
			}

			policy := createAcceptAllWithPortsPolicy("accept-ports", "test-ns")

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			return verifyNFTablesGoldenFile("accept-all-with-ports-policy.nft")
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

			nftablesWithPods := &NFTables{
				Client: createFakeClientWithNamespaces([]*corev1.Pod{targetPod, backendPod, frontendPod1, frontendPod2, databasePod},
					[]*corev1.Namespace{prodNamespace, devNamespace}),
			}

			policy := createComprehensivePolicy("comprehensive", "test-ns")

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			return verifyNFTablesGoldenFile("comprehensive-policy.nft")
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

			nftablesWithPods := &NFTables{
				Client: createFakeClientWithNamespaces([]*corev1.Pod{targetPod, backendPod, frontendPod1, frontendPod2, databasePod},
					[]*corev1.Namespace{prodNamespace, devNamespace}),
			}

			// Add deny all policy
			policy := createDenyAllPolicy("deny-all", "test-ns")

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			err = verifyNFTablesGoldenFile("lifecycle-deny-all.nft")
			if err != nil {
				return err
			}

			// Add comprehensive policy
			policy = createComprehensivePolicy("comprehensive", "test-ns")

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, matchedInterfaces, policy, logger)
			if err != nil {
				return err
			}

			err = verifyNFTablesGoldenFile("lifecycle-stacked.nft")
			if err != nil {
				return err
			}

			// Clean up comprehensive policy
			err = cleanUpPolicy(ctx, policy.Name, policy.Namespace, logger)
			if err != nil {
				return err
			}

			// Verify cleanup using golden file - should be back to deny-all only
			return verifyNFTablesGoldenFile("lifecycle-after-cleanup.nft")
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

var _ = Describe("Multiple NetworkAttachmentDefinitions Integration Tests", func() {
	/*
		                   ┌─────────────┐        ┌─────────────┐
		                   │  << NAD >>  │        │  << NAD >>  │
		                   │ RedNetwork  │        │ BlueNetwork │
		                   │             │        │             │
		                   └─────────────┘        └─────────────┘

		┌────────────┐     ┌─────────────┐        ┌─────────────┐     ┌────────────┐
		│            │     │             │        │             │     │            │
		│ red-pod-a  ├──┐  │  << MNP >>  │        │  << MNP >>  │  ┌──┼ blue-pod-a │
		│            │  │  │  RedPolicy  │        │ BluePolicy  │  │  │            │
		└────────────┘  │  │             │        │             │  │  └────────────┘
		                │  └─────────────┘        └─────────────┘  │
		┌────────────┐  │                                          │  ┌────────────┐
		│            │  │ 10.0.1.0/24                  10.0.2.0/24 │  │            │
		│ red-pod-b  ├──┴───────────┐                   ┌──────────┴──┤ blue-pod-b │
		│            │        ┌──┬──┴─────┬──────┬──────┴──┬──┐       │            │
		└────────────┘        │  │ ethred │      │ ethblue │  │       └────────────┘
		                      │  └────────┘      └─────────┘  │
		                      │                               │
		                      │          TargetPod            │
		                      │                               │
		                      └───────────────────────────────┘
	*/
	var (
		targetPod      *corev1.Pod
		redPodA        *corev1.Pod
		redPodB        *corev1.Pod
		bluePodA       *corev1.Pod
		bluePodB       *corev1.Pod
		redInterfaces  []Interface
		blueInterfaces []Interface
	)

	BeforeEach(func() {
		// Create target pod (the one policies apply to)
		targetPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "target-pod",
				Namespace: "test-ns",
				Labels:    map[string]string{"app": "target-pod"},
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/networks":       "red-net,blue-net",
					"k8s.v1.cni.cncf.io/network-status": `[{"name":"test-ns/red-net","interface":"ethred","ips":["10.0.1.1","2001:db8:1::1"],"dns":{}},{"name":"test-ns/blue-net","interface":"ethblue","ips":["10.0.2.1","2001:db8:2::1"],"dns":{}}]`,
				},
			},
			Spec:   corev1.PodSpec{HostNetwork: false},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}

		redInterfaces = []Interface{{Name: "ethred", Network: "test-ns/red-net", IPs: []string{"10.0.1.1", "2001:db8:1::1"}}}
		blueInterfaces = []Interface{{Name: "ethblue", Network: "test-ns/blue-net", IPs: []string{"10.0.2.1", "2001:db8:2::1"}}}

		// Create test pods for comprehensive test
		redPodA = createPodSingleInterface("red-pod-a", "test-ns/red-net",
			map[string]string{"app": "red-pod-a"},
			"10.0.1.10", "2001:db8:1::10")

		redPodB = createPodSingleInterface("red-pod-b", "test-ns/red-net",
			map[string]string{"app": "red-pod-b"},
			"10.0.1.11", "2001:db8:1::11")

		bluePodA = createPodSingleInterface("blue-pod-a", "test-ns/blue-net",
			map[string]string{"app": "blue-pod-a"},
			"10.0.2.10", "2001:db8:2::10")

		bluePodB = createPodSingleInterface("blue-pod-b", "test-ns/blue-net",
			map[string]string{"app": "blue-pod-b"},
			"10.0.2.11", "2001:db8:2::11")
	})

	It("should handle policies on different networks", func(ctx context.Context) {
		defer GinkgoRecover()

		netNS, err := testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		defer netNS.Close()

		err = netNS.Do(func(_ ns.NetNS) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			nftablesWithPods := &NFTables{
				Client: createFakeClient([]*corev1.Pod{targetPod, redPodA, redPodB, bluePodA, bluePodB}),
			}

			redPolicy := &datastore.Policy{
				Name:      "red-policy",
				Namespace: "test-ns",
				Networks:  []string{"test-ns/red-net"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "target-pod"},
					},
					PolicyTypes: []multiv1beta1.MultiPolicyType{
						multiv1beta1.PolicyTypeIngress,
						multiv1beta1.PolicyTypeEgress,
					},
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
						From: []multiv1beta1.MultiNetworkPolicyPeer{createPolicyPeer(map[string]string{"app": "red-pod-a"})},
					}},
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{{
						To: []multiv1beta1.MultiNetworkPolicyPeer{createPolicyPeer(map[string]string{"app": "red-pod-b"})},
					}},
				},
			}

			bluePolicy := &datastore.Policy{
				Name:      "blue-policy",
				Namespace: "test-ns",
				Networks:  []string{"test-ns/blue-net"},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "target-pod"},
					},
					PolicyTypes: []multiv1beta1.MultiPolicyType{
						multiv1beta1.PolicyTypeIngress,
						multiv1beta1.PolicyTypeEgress,
					},
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
						From: []multiv1beta1.MultiNetworkPolicyPeer{createPolicyPeer(map[string]string{"app": "blue-pod-a"})},
					}},
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{{
						To: []multiv1beta1.MultiNetworkPolicyPeer{createPolicyPeer(map[string]string{"app": "blue-pod-b"})},
					}},
				},
			}

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, redInterfaces, redPolicy, logger)
			if err != nil {
				return err
			}

			err = nftablesWithPods.enforcePolicy(ctx, targetPod, blueInterfaces, bluePolicy, logger)
			if err != nil {
				return err
			}

			err = verifyNFTablesGoldenFile("multiple-networks-policy.nft")
			if err != nil {
				return err
			}

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})
})

func createPolicyPeer(matchLabels map[string]string) multiv1beta1.MultiNetworkPolicyPeer {
	return multiv1beta1.MultiNetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: matchLabels,
		},
	}
}

func createPodSingleInterface(name, network string, labels map[string]string, ipv4Net, ipv6Net string) *corev1.Pod {
	networkStatus := fmt.Sprintf(`[{"name":"%s","interface":"eth1","ips":["%s","%s"],"dns":{}}]`, network, ipv4Net, ipv6Net)

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "test-ns",
			Labels:    labels,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/networks":       network,
				"k8s.v1.cni.cncf.io/network-status": networkStatus,
			},
		},
		Spec:   corev1.PodSpec{HostNetwork: false},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

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

// verifyNFTablesGoldenFile compares the nftables dump with a golden file
func verifyNFTablesGoldenFile(goldenFileName string) error {
	actualDump, err := dumpNFTRules()
	if err != nil {
		return fmt.Errorf("failed to dump nftables: %w", err)
	}

	// Determine the golden file path relative to the test file
	_, testFile, _, _ := runtime.Caller(0)
	testDir := filepath.Dir(testFile)
	goldenDir := filepath.Join(testDir, "testdata", "golden")
	goldenFilePath := filepath.Join(goldenDir, goldenFileName)

	// Read the golden file
	expectedDump, err := os.ReadFile(goldenFilePath)

	// If the file is missing, create it
	if err != nil && os.IsNotExist(err) {
		// Create golden directory if it doesn't exist
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			return fmt.Errorf("failed to create golden directory: %w", err)
		}

		// Write the actual dump to the golden file
		if err := os.WriteFile(goldenFilePath, []byte(actualDump), 0o644); err != nil {
			return fmt.Errorf("failed to write golden file: %w", err)
		}

		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to read golden file: %w", err)
	}

	// Compare the dumps
	if actualDump != string(expectedDump) {
		return fmt.Errorf("nftables dump does not match golden file %s\n\nExpected:\n%s\n\nActual:\n%s",
			goldenFileName, string(expectedDump), actualDump)
	}

	return nil
}

func dumpNFTRules() (string, error) {
	cmd := exec.Command("nft", "list", "ruleset")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute command [%s]: %w: %s", cmd.String(), err, string(out))
	}
	return string(out), nil
}
