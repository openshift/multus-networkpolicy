package controller_test

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/datastore"
	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/nftables"
)

type SyncPolicyCall struct {
	Policy    *datastore.Policy
	Operation string
	Trigger   string // What triggered this call
}

var _ = Describe("MultiNetworkController Integration Tests", func() {
	var (
		ctx                    context.Context
		syncPolicyCalls        []SyncPolicyCall
		initialSyncPolicyCalls int
	)

	BeforeEach(func() {
		ctx = context.Background()
		syncPolicyCalls = []SyncPolicyCall{}
		initialSyncPolicyCalls = 0

		// Reset the mock NFT to track calls
		mockNFT.SyncPolicyFunc = func(_ context.Context, policy *datastore.Policy, operation nftables.SyncOperation, _ logr.Logger) error {
			syncPolicyCalls = append(syncPolicyCalls, SyncPolicyCall{
				Policy:    policy,
				Operation: string(operation),
				Trigger:   "unknown", // Will be updated by specific tests
			})
			return nil
		}
	})

	// Helper functions for creating test resources
	createTestNamespace := func(name string, labels map[string]string) *corev1.Namespace {
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: labels,
			},
		}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() {
			k8sClient.Delete(ctx, ns)
		})
		return ns
	}

	createNetworkAttachmentDefinition := func(name, namespace, config string) *netdefv1.NetworkAttachmentDefinition {
		nad := &netdefv1.NetworkAttachmentDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: netdefv1.NetworkAttachmentDefinitionSpec{
				Config: config,
			},
		}
		Expect(k8sClient.Create(ctx, nad)).To(Succeed())
		DeferCleanup(func() {
			k8sClient.Delete(ctx, nad)
		})
		return nad
	}

	createMultiNetworkPolicy := func(name, namespace string, annotations map[string]string, spec multiv1beta1.MultiNetworkPolicySpec) *multiv1beta1.MultiNetworkPolicy {
		policy := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   namespace,
				Annotations: annotations,
			},
			Spec: spec,
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		DeferCleanup(func() {
			k8sClient.Delete(ctx, policy)
		})
		return policy
	}

	createPod := func(name, namespace string, labels map[string]string, annotations map[string]string) *corev1.Pod {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   namespace,
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "test-container",
						Image: "nginx:latest",
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() {
			k8sClient.Delete(ctx, pod)
		})
		return pod
	}

	waitForPolicyInDatastore := func(namespace, name string) *datastore.Policy {
		var storedPolicy *datastore.Policy
		Eventually(func() bool {
			storedPolicy = datastoreInstance.GetPolicy(types.NamespacedName{
				Namespace: namespace,
				Name:      name,
			})
			return storedPolicy != nil
		}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
		return storedPolicy
	}

	// Helper to record the initial sync calls (when policy is first created)
	recordInitialSyncCalls := func() {
		initialSyncPolicyCalls = len(syncPolicyCalls)
	}

	// Helper to wait for any reconciliation activity (sync or cleanup)
	waitForReconciliationActivity := func(trigger string) {
		Eventually(func() bool {
			// Update the trigger for new calls
			for i := initialSyncPolicyCalls; i < len(syncPolicyCalls); i++ {
				syncPolicyCalls[i].Trigger = trigger
			}
			// Check if there was any reconciliation activity (either sync or cleanup)
			return len(syncPolicyCalls) > initialSyncPolicyCalls
		}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
	}

	// Helper to verify that reconciliation was triggered (either sync or cleanup)
	verifyReconciliationWasTriggered := func(trigger string, policyName string) {
		// For now, we'll just verify that there was some reconciliation activity
		// The actual verification of what triggered it would require more sophisticated tracking
		Expect(len(syncPolicyCalls)).To(BeNumerically(">", initialSyncPolicyCalls),
			"Expected reconciliation activity to be triggered by %s for policy %s", trigger, policyName)
	}

	Context("MultiNetworkPolicy CRUD Operations", func() {
		It("should create a policy successfully", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-create", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-create/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
					multiv1beta1.PolicyTypeEgress,
				},
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "allowed-app",
									},
								},
							},
						},
					},
				},
			})

			// Wait for policy to be stored in datastore
			storedPolicy := waitForPolicyInDatastore(policy.Namespace, policy.Name)
			Expect(storedPolicy).NotTo(BeNil())
			Expect(storedPolicy.Name).To(Equal(policy.Name))
			Expect(storedPolicy.Namespace).To(Equal(policy.Namespace))
			Expect(storedPolicy.Networks).To(ContainElement("test-ns-create/macvlan-net"))
		})

		It("should update a policy when spec changes", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-update", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create initial policy
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-update/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for initial policy to be stored
			waitForPolicyInDatastore(policy.Namespace, policy.Name)

			// Update policy spec
			policy.Spec.PodSelector.MatchLabels["version"] = "v2"
			Expect(k8sClient.Update(ctx, policy)).To(Succeed())

			// Wait for updated policy to be stored
			Eventually(func() bool {
				storedPolicy := datastoreInstance.GetPolicy(types.NamespacedName{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				})
				return storedPolicy != nil && storedPolicy.Spec.PodSelector.MatchLabels["version"] == "v2"
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
		})

		It("should update a policy when policy-for annotation changes", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-annotation", map[string]string{"environment": "test"})

			// Create network attachment definitions
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)
			createNetworkAttachmentDefinition("ipvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "ipvlan-net",
				"type": "ipvlan",
				"master": "eth0",
				"mode": "l2"
			}`)

			// Create policy with single network
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-annotation/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for initial policy to be stored
			waitForPolicyInDatastore(policy.Namespace, policy.Name)

			// Update policy annotation to include both networks
			policy.Annotations[datastore.PolicyForAnnotation] = "test-ns-annotation/macvlan-net,test-ns-annotation/ipvlan-net"
			Expect(k8sClient.Update(ctx, policy)).To(Succeed())

			// Wait for updated policy to be stored with both networks
			Eventually(func() bool {
				storedPolicy := datastoreInstance.GetPolicy(types.NamespacedName{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				})
				return storedPolicy != nil && len(storedPolicy.Networks) == 2
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
		})

		It("should delete a policy successfully", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-delete", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-delete/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for policy to be stored
			waitForPolicyInDatastore(policy.Namespace, policy.Name)

			// Delete policy
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			// Wait for policy to be removed from datastore
			Eventually(func() bool {
				storedPolicy := datastoreInstance.GetPolicy(types.NamespacedName{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				})
				return storedPolicy == nil
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
		})

		It("should handle policy with missing policy-for annotation", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-missing-annotation", map[string]string{"environment": "test"})

			// Create policy without policy-for annotation
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait and verify policy is not stored in datastore
			Eventually(func() bool {
				storedPolicy := datastoreInstance.GetPolicy(types.NamespacedName{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				})
				return storedPolicy == nil
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
		})

		It("should handle policy with invalid network references", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-invalid-networks", map[string]string{"environment": "test"})

			// Create policy with invalid network reference
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "nonexistent-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait and verify policy is not stored in datastore
			Eventually(func() bool {
				storedPolicy := datastoreInstance.GetPolicy(types.NamespacedName{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				})
				return storedPolicy == nil
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
		})

		It("should handle policy with unsupported network types", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-unsupported", map[string]string{"environment": "test"})

			// Create unsupported network attachment definition
			createNetworkAttachmentDefinition("unsupported-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "unsupported-net",
				"type": "unsupported",
				"master": "eth0"
			}`)

			// Create policy with unsupported network
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-unsupported/unsupported-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait and verify policy is not stored in datastore
			Eventually(func() bool {
				storedPolicy := datastoreInstance.GetPolicy(types.NamespacedName{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				})
				return storedPolicy == nil
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
		})
	})

	Context("Namespace Change Triggers", func() {
		It("should reconcile policies when namespace labels change", func() {
			// Create test namespaces
			testNs1 := createTestNamespace("test-ns-labels-1", map[string]string{"environment": "test"})
			_ = createTestNamespace("test-ns-labels-2", map[string]string{"environment": "production"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs1.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy manually (without DeferCleanup to avoid timing issues)
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: testNs1.Name,
					Annotations: map[string]string{
						datastore.PolicyForAnnotation: "test-ns-labels-1/macvlan-net",
					},
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test-app",
						},
					},
					PolicyTypes: []multiv1beta1.MultiPolicyType{
						multiv1beta1.PolicyTypeIngress,
					},
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "test",
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Manually clean up the policy at the end
			DeferCleanup(func() {
				k8sClient.Delete(ctx, policy)
			})

			// Wait for policy to be stored and record initial sync calls
			waitForPolicyInDatastore(policy.Namespace, policy.Name)
			recordInitialSyncCalls()

			// Update namespace labels - this should trigger reconciliation
			testNs1.Labels["environment"] = "production"
			Expect(k8sClient.Update(ctx, testNs1)).To(Succeed())

			// Wait for reconciliation activity due to namespace change
			waitForReconciliationActivity("namespace-change")

			// Verify that reconciliation was triggered by namespace change
			verifyReconciliationWasTriggered("namespace-change", policy.Name)
		})

		It("should reconcile policies when new namespace is created", func() {
			// Create test namespace
			testNs1 := createTestNamespace("test-ns-new-1", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs1.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy manually (without DeferCleanup to avoid timing issues)
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: testNs1.Name,
					Annotations: map[string]string{
						datastore.PolicyForAnnotation: "test-ns-new-1/macvlan-net",
					},
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test-app",
						},
					},
					PolicyTypes: []multiv1beta1.MultiPolicyType{
						multiv1beta1.PolicyTypeIngress,
					},
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "test",
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Manually clean up the policy at the end
			DeferCleanup(func() {
				k8sClient.Delete(ctx, policy)
			})

			// Wait for policy to be stored and record initial sync calls
			waitForPolicyInDatastore(policy.Namespace, policy.Name)
			recordInitialSyncCalls()

			// Create new namespace with matching labels - this should trigger reconciliation
			_ = createTestNamespace("test-ns-new-2", map[string]string{"environment": "test"})

			// Wait for reconciliation activity due to namespace creation
			waitForReconciliationActivity("namespace-creation")

			// Verify that reconciliation was triggered by namespace creation
			verifyReconciliationWasTriggered("namespace-creation", policy.Name)
		})
	})

	Context("Pod Change Triggers", func() {
		It("should reconcile policies when pod labels change", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-pod-labels", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy manually (without DeferCleanup to avoid timing issues)
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: testNs.Name,
					Annotations: map[string]string{
						datastore.PolicyForAnnotation: "test-ns-pod-labels/macvlan-net",
					},
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test-app",
						},
					},
					PolicyTypes: []multiv1beta1.MultiPolicyType{
						multiv1beta1.PolicyTypeIngress,
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Manually clean up the policy at the end
			DeferCleanup(func() {
				k8sClient.Delete(ctx, policy)
			})

			// Wait for policy to be stored and record initial sync calls
			waitForPolicyInDatastore(policy.Namespace, policy.Name)
			recordInitialSyncCalls()

			// Create pod with matching labels
			pod := createPod("test-pod", testNs.Name, map[string]string{
				"app": "test-app",
			}, map[string]string{
				"k8s.v1.cni.cncf.io/networks": "test-ns-pod-labels/macvlan-net",
			})

			// Set pod status to Running to ensure it matches the policy selector
			pod.Status.Phase = corev1.PodRunning
			Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

			// Update pod labels - this should trigger reconciliation
			pod.Labels["version"] = "v2"
			Expect(k8sClient.Update(ctx, pod)).To(Succeed())

			// Wait for reconciliation activity due to pod change
			waitForReconciliationActivity("pod-change")

			// Verify that reconciliation was triggered by pod change
			verifyReconciliationWasTriggered("pod-change", policy.Name)
		})

		It("should reconcile policies when pod becomes ineligible", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-pod-ineligible", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-pod-ineligible/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for policy to be stored and record initial sync calls
			waitForPolicyInDatastore(policy.Namespace, policy.Name)
			recordInitialSyncCalls()

			// Create pod with matching labels
			pod := createPod("test-pod", testNs.Name, map[string]string{
				"app": "test-app",
			}, map[string]string{
				"k8s.v1.cni.cncf.io/networks": "test-ns-pod-ineligible/macvlan-net",
			})

			// Set pod status to Running to ensure it matches the policy selector
			pod.Status.Phase = corev1.PodRunning
			Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

			// Remove network annotation to make pod ineligible - this should trigger reconciliation
			delete(pod.Annotations, "k8s.v1.cni.cncf.io/networks")
			Expect(k8sClient.Update(ctx, pod)).To(Succeed())

			// Wait for reconciliation activity due to pod becoming ineligible
			waitForReconciliationActivity("pod-ineligible")

			// Verify that reconciliation was triggered by pod becoming ineligible
			verifyReconciliationWasTriggered("pod-ineligible", policy.Name)
		})

		It("should reconcile policies when pod is deleted", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-pod-delete", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-pod-delete/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for policy to be stored and record initial sync calls
			waitForPolicyInDatastore(policy.Namespace, policy.Name)
			recordInitialSyncCalls()

			// Create pod with matching labels
			pod := createPod("test-pod", testNs.Name, map[string]string{
				"app": "test-app",
			}, map[string]string{
				"k8s.v1.cni.cncf.io/networks": "test-ns-pod-delete/macvlan-net",
			})

			// Set pod status to Running to ensure it matches the policy selector
			pod.Status.Phase = corev1.PodRunning
			Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

			// Delete pod - this should trigger reconciliation
			Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

			// Wait for reconciliation activity due to pod deletion
			waitForReconciliationActivity("pod-deletion")

			// Verify that reconciliation was triggered by pod deletion
			verifyReconciliationWasTriggered("pod-deletion", policy.Name)
		})

		It("should not reconcile policies for non-eligible pods", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-pod-non-eligible", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-pod-non-eligible/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for policy to be stored and record initial sync calls
			waitForPolicyInDatastore(policy.Namespace, policy.Name)
			recordInitialSyncCalls()

			// Create pod without network annotation (non-eligible)
			pod := createPod("test-pod", testNs.Name, map[string]string{
				"app": "test-app",
			}, map[string]string{})

			// Update pod labels - this should NOT trigger reconciliation for non-eligible pods
			pod.Labels["version"] = "v2"
			Expect(k8sClient.Update(ctx, pod)).To(Succeed())

			// Wait a bit to ensure no additional sync calls are made
			time.Sleep(2 * time.Second)

			// Verify that no additional sync calls were made
			Expect(syncPolicyCalls).To(HaveLen(initialSyncPolicyCalls), "Expected no additional sync calls for non-eligible pods")
		})
	})

	Context("Complex Policy Scenarios", func() {
		It("should handle policy with multiple ingress rules", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-complex-ingress", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy with multiple ingress rules
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-complex-ingress/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "allowed-app",
									},
								},
							},
						},
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
								Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
							},
						},
					},
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"tier": "database",
									},
								},
							},
						},
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
								Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 5432},
							},
						},
					},
				},
			})

			// Wait for policy to be stored
			storedPolicy := waitForPolicyInDatastore(policy.Namespace, policy.Name)
			Expect(storedPolicy).NotTo(BeNil())
			Expect(storedPolicy.Spec.Ingress).To(HaveLen(2))
		})

		It("should handle policy with egress rules", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-complex-egress", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy with egress rules
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-complex-egress/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeEgress,
				},
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "database",
									},
								},
							},
						},
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &[]corev1.Protocol{corev1.ProtocolTCP}[0],
								Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 5432},
							},
						},
					},
				},
			})

			// Wait for policy to be stored
			storedPolicy := waitForPolicyInDatastore(policy.Namespace, policy.Name)
			Expect(storedPolicy).NotTo(BeNil())
			Expect(storedPolicy.Spec.Egress).To(HaveLen(1))
		})

		It("should handle policy with cross-namespace network reference", func() {
			// Create test namespaces
			testNs1 := createTestNamespace("test-ns-cross-1", map[string]string{"environment": "test"})
			testNs2 := createTestNamespace("test-ns-cross-2", map[string]string{"environment": "test"})

			// Create network attachment definition in first namespace
			createNetworkAttachmentDefinition("macvlan-net", testNs1.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy in second namespace referencing first namespace's network
			policy := createMultiNetworkPolicy("test-policy", testNs2.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-cross-1/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app-2",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for policy to be stored
			storedPolicy := waitForPolicyInDatastore(policy.Namespace, policy.Name)
			Expect(storedPolicy).NotTo(BeNil())
			Expect(storedPolicy.Networks).To(ContainElement("test-ns-cross-1/macvlan-net"))
		})

		It("should handle pod with host network", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-host-network", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-host-network/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for policy to be stored
			waitForPolicyInDatastore(policy.Namespace, policy.Name)

			// Create pod with host network
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: testNs.Name,
					Labels: map[string]string{
						"app": "test-app",
					},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-ns-host-network/macvlan-net",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:latest",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			DeferCleanup(func() {
				k8sClient.Delete(ctx, pod)
			})

			// Wait for reconciliation to complete
			Eventually(func() bool {
				storedPolicy := datastoreInstance.GetPolicy(types.NamespacedName{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				})
				return storedPolicy != nil
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
		})

		It("should handle pod without network annotation", func() {
			// Create test namespace
			testNs := createTestNamespace("test-ns-no-annotation", map[string]string{"environment": "test"})

			// Create network attachment definition
			createNetworkAttachmentDefinition("macvlan-net", testNs.Name, `{
				"cniVersion": "0.3.1",
				"name": "macvlan-net",
				"type": "macvlan",
				"master": "eth0",
				"mode": "bridge"
			}`)

			// Create policy
			policy := createMultiNetworkPolicy("test-policy", testNs.Name, map[string]string{
				datastore.PolicyForAnnotation: "test-ns-no-annotation/macvlan-net",
			}, multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
				PolicyTypes: []multiv1beta1.MultiPolicyType{
					multiv1beta1.PolicyTypeIngress,
				},
			})

			// Wait for policy to be stored
			waitForPolicyInDatastore(policy.Namespace, policy.Name)

			// Create pod without network annotation
			_ = createPod("test-pod", testNs.Name, map[string]string{
				"app": "test-app",
			}, map[string]string{})

			// Wait for reconciliation to complete
			Eventually(func() bool {
				storedPolicy := datastoreInstance.GetPolicy(types.NamespacedName{
					Namespace: policy.Namespace,
					Name:      policy.Name,
				})
				return storedPolicy != nil
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
		})
	})
})
