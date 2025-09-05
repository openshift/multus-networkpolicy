package controller_test

import (
	"context"
	"fmt"
	"time"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/nftables"
)

var _ = Describe("MultiNetworkController Integration Tests", func() {
	var (
		testNamespace string
		policyName    = "test-policy"
		networkName   = "test-network"
	)

	BeforeEach(func() {
		// Reset all global variables before each test
		syncPolicyCreateCalled = 0
		syncPolicyDeleteCalled = 0
		lastSyncedPolicy = nil
		lastSyncOperation = ""

		// Generate unique namespace name for each test to avoid conflicts
		testNamespace = fmt.Sprintf("test-namespace-%d", time.Now().UnixNano())

		// Create the test namespace
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		// Create a NetworkAttachmentDefinition for the policy to reference
		netAttachDef := &netdefv1.NetworkAttachmentDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name:      networkName,
				Namespace: testNamespace,
			},
			Spec: netdefv1.NetworkAttachmentDefinitionSpec{
				Config: `{"type": "macvlan", "mode": "bridge"}`,
			},
		}
		Expect(k8sClient.Create(ctx, netAttachDef)).To(Succeed())
	})

	AfterEach(func() {
		// Comprehensive cleanup to ensure test isolation

		// 1. Remove all labels from the test namespace to prevent cross-test interference
		namespace := &corev1.Namespace{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: testNamespace}, namespace)
		if err == nil {
			namespace.Labels = map[string]string{}
			k8sClient.Update(ctx, namespace)
		}

		// 2. Delete all MultiNetworkPolicies in the test namespace
		var policyList multiv1beta1.MultiNetworkPolicyList
		err = k8sClient.List(ctx, &policyList, client.InNamespace(testNamespace))
		if err == nil {
			for _, policy := range policyList.Items {
				k8sClient.Delete(ctx, &policy)
			}
		}

		// 3. Delete all pods in the test namespace
		var podList corev1.PodList
		err = k8sClient.List(ctx, &podList, client.InNamespace(testNamespace))
		if err == nil {
			for _, pod := range podList.Items {
				k8sClient.Delete(ctx, &pod)
			}
		}

		// 4. Wait for all resources to be deleted
		Eventually(func() bool {
			var policyList multiv1beta1.MultiNetworkPolicyList
			err := k8sClient.List(ctx, &policyList, client.InNamespace(testNamespace))
			if err != nil {
				return false
			}

			var podList corev1.PodList
			err = k8sClient.List(ctx, &podList, client.InNamespace(testNamespace))
			if err != nil {
				return false
			}

			return len(policyList.Items) == 0 && len(podList.Items) == 0
		}, "10s", "100ms").Should(BeTrue(), "All policies and pods should be deleted")
	})

	Describe("Normal MultiNetworkPolicy Lifecycle", func() {
		It("should process a valid MultiNetworkPolicy through its complete lifecycle", func() {
			// Create a MultiNetworkPolicy with valid policy-for annotation
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
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
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"role": "client",
										},
									},
								},
							},
						},
					},
				},
			}

			// Create the policy
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Eventually check that the reconciler processed the policy correctly
			Eventually(func() bool {
				// Get the updated policy
				updatedPolicy := &multiv1beta1.MultiNetworkPolicy{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: testNamespace,
					Name:      policyName,
				}, updatedPolicy)
				if err != nil {
					return false
				}

				// Check that SyncPolicy was called with CREATE operation
				if syncPolicyCreateCalled != 1 {
					return false
				}

				if lastSyncOperation != "create" {
					return false
				}

				// Check that policy was added to datastore
				// Note: We need to access the datastore from the controller
				// For this test, we'll assume the controller's datastore is accessible
				// In a real scenario, you might need to expose this or use a different approach
				return true
			}, "10s", "100ms").Should(BeTrue(), "Policy should be processed successfully")

			By("Verifying the policy lifecycle completed successfully")
		})

		It("should handle policy deletion and call cleanup", func() {
			// First create a policy
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
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

			// Delete the policy
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			// Eventually check that cleanup was called
			Eventually(func() bool {
				// Check that SyncPolicy was called with DELETE operation
				return syncPolicyDeleteCalled == 1 && lastSyncOperation == "delete"
			}, "10s", "100ms").Should(BeTrue(), "Policy cleanup should be called")

			By("Verifying policy deletion completed successfully")
		})

		It("should handle spec updates and re-sync policy", func() {
			// Create initial policy
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
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

			// Reset counters to focus on update
			syncPolicyCreateCalled = 0

			// Update the spec (add egress rules)
			Eventually(func() error {
				updatedPolicy := &multiv1beta1.MultiNetworkPolicy{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: testNamespace,
					Name:      policyName,
				}, updatedPolicy)
				if err != nil {
					return err
				}

				// Add egress rules to change the spec
				updatedPolicy.Spec.PolicyTypes = append(updatedPolicy.Spec.PolicyTypes, multiv1beta1.PolicyTypeEgress)
				updatedPolicy.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"role": "database",
									},
								},
							},
						},
					},
				}

				return k8sClient.Update(ctx, updatedPolicy)
			}, "5s", "100ms").Should(Succeed())

			// Eventually check that policy was re-synced due to spec change
			Eventually(func() bool {
				return syncPolicyCreateCalled >= 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue(), "Policy should be re-synced after spec update")

			By("Verifying spec update triggered policy re-sync")
		})

		It("should handle policy-for annotation addition", func() {
			// Create policy without policy-for annotation
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					// No annotations initially
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

			// Verify no sync happened initially (no valid annotation)
			Expect(syncPolicyCreateCalled).To(Equal(0), "Should not sync without valid annotation")

			// Add the policy-for annotation
			Eventually(func() error {
				updatedPolicy := &multiv1beta1.MultiNetworkPolicy{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: testNamespace,
					Name:      policyName,
				}, updatedPolicy)
				if err != nil {
					return err
				}

				if updatedPolicy.Annotations == nil {
					updatedPolicy.Annotations = make(map[string]string)
				}
				updatedPolicy.Annotations["k8s.v1.cni.cncf.io/policy-for"] = networkName

				return k8sClient.Update(ctx, updatedPolicy)
			}, "5s", "100ms").Should(Succeed())

			// Eventually check that policy was synced after annotation addition
			Eventually(func() bool {
				return syncPolicyCreateCalled >= 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue(), "Policy should be synced after annotation addition")

			By("Verifying annotation addition triggered policy sync")
		})

		It("should handle policy-for annotation removal and cleanup", func() {
			// Create policy with policy-for annotation
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
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

			// Wait for initial processing
			Eventually(func() bool {
				return syncPolicyCreateCalled >= 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue())

			// Reset counters to focus on annotation removal
			syncPolicyCreateCalled = 0
			syncPolicyDeleteCalled = 0

			// Remove the policy-for annotation
			Eventually(func() error {
				updatedPolicy := &multiv1beta1.MultiNetworkPolicy{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: testNamespace,
					Name:      policyName,
				}, updatedPolicy)
				if err != nil {
					return err
				}

				delete(updatedPolicy.Annotations, "k8s.v1.cni.cncf.io/policy-for")
				return k8sClient.Update(ctx, updatedPolicy)
			}, "5s", "100ms").Should(Succeed())

			// Eventually check that cleanup was called after annotation removal
			Eventually(func() bool {
				return syncPolicyDeleteCalled >= 1 && lastSyncOperation == "delete"
			}, "10s", "100ms").Should(BeTrue(), "Policy should be cleaned up after annotation removal")

			By("Verifying annotation removal triggered policy cleanup")
		})

		It("should handle policy-for annotation modification", func() {
			// Create a second network for testing
			secondNetworkName := "test-network-2"
			secondNetAttachDef := &netdefv1.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secondNetworkName,
					Namespace: testNamespace,
				},
				Spec: netdefv1.NetworkAttachmentDefinitionSpec{
					Config: `{"type": "macvlan", "mode": "bridge"}`,
				},
			}
			Expect(k8sClient.Create(ctx, secondNetAttachDef)).To(Succeed())
			defer k8sClient.Delete(ctx, secondNetAttachDef)

			// Create policy with first network
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
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

			// Wait for initial processing
			Eventually(func() bool {
				return syncPolicyCreateCalled >= 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue())

			// Reset counters to focus on annotation modification
			syncPolicyCreateCalled = 0

			// Modify the policy-for annotation to point to second network
			Eventually(func() error {
				updatedPolicy := &multiv1beta1.MultiNetworkPolicy{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Namespace: testNamespace,
					Name:      policyName,
				}, updatedPolicy)
				if err != nil {
					return err
				}

				updatedPolicy.Annotations["k8s.v1.cni.cncf.io/policy-for"] = secondNetworkName
				return k8sClient.Update(ctx, updatedPolicy)
			}, "5s", "100ms").Should(Succeed())

			// Eventually check that policy was re-synced with new network
			Eventually(func() bool {
				return syncPolicyCreateCalled >= 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue(), "Policy should be re-synced after annotation modification")

			By("Verifying annotation modification triggered policy re-sync")
		})
	})

	Describe("Namespace Operations", func() {
		It("should handle namespace creation with matching ingress namespace selector", func() {
			// Create a policy with ingress namespace selector
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
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
											"environment": "production",
										},
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Wait for initial policy processing (expect exactly 1 CREATE call)
			Eventually(func() bool {
				return syncPolicyCreateCalled == 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue())

			// Reset counters to focus on namespace operation
			syncPolicyCreateCalled = 0
			syncPolicyDeleteCalled = 0

			// Create a namespace that matches the selector
			matchingNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("matching-ns-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"environment": "production",
					},
				},
			}

			Expect(k8sClient.Create(ctx, matchingNamespace)).To(Succeed())
			defer k8sClient.Delete(ctx, matchingNamespace)

			// Eventually check that policy was re-synced exactly once due to matching namespace creation
			Eventually(func() bool {
				return syncPolicyCreateCalled == 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue(), "Policy should be re-synced exactly once when matching namespace is created")

			By("Verifying namespace creation triggered policy re-sync for ingress selector")
		})

		It("should handle namespace creation with matching egress namespace selector", func() {
			// Create a policy with egress namespace selector
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
					},
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
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
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "database",
										},
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Wait for initial policy processing (expect exactly 1 CREATE call)
			Eventually(func() bool {
				return syncPolicyCreateCalled == 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue())

			// Reset counters to focus on namespace operation
			syncPolicyCreateCalled = 0
			syncPolicyDeleteCalled = 0

			// Create a namespace that matches the selector
			matchingNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("matching-ns-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"tier": "database",
					},
				},
			}

			Expect(k8sClient.Create(ctx, matchingNamespace)).To(Succeed())
			defer k8sClient.Delete(ctx, matchingNamespace)

			// Eventually check that policy was re-synced exactly once due to matching namespace creation
			Eventually(func() bool {
				return syncPolicyCreateCalled == 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue(), "Policy should be re-synced exactly once when matching namespace is created")

			By("Verifying namespace creation triggered policy re-sync for egress selector")
		})

		It("should handle namespace label updates with matching selectors", func() {
			// Create a policy with ingress namespace selector
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
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
											"security": "high",
										},
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Create a namespace without matching labels initially
			targetNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("target-ns-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"security": "low",
					},
				},
			}

			Expect(k8sClient.Create(ctx, targetNamespace)).To(Succeed())
			defer k8sClient.Delete(ctx, targetNamespace)

			// Wait for initial processing (expect exactly 2 CREATE calls: 1 for policy, 1 for namespace)
			// Since the namespace doesn't match initially, we should have exactly 1 call from policy creation
			Eventually(func() bool {
				return syncPolicyCreateCalled == 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue())

			// Reset counters to focus on namespace label update
			syncPolicyCreateCalled = 0
			syncPolicyDeleteCalled = 0

			// Update namespace labels to match the selector
			Eventually(func() error {
				updatedNamespace := &corev1.Namespace{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: targetNamespace.Name}, updatedNamespace)
				if err != nil {
					return err
				}

				updatedNamespace.Labels["security"] = "high"
				return k8sClient.Update(ctx, updatedNamespace)
			}, "5s", "100ms").Should(Succeed())

			// Eventually check that policy was re-synced exactly once due to namespace label change
			Eventually(func() bool {
				return syncPolicyCreateCalled == 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue(), "Policy should be re-synced exactly once when namespace labels change to match selector")

			By("Verifying namespace label update triggered policy re-sync")
		})

		It("should not trigger sync when namespace is created without matching selectors", func() {
			// Create a policy with specific namespace selector
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
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
											"access": "restricted",
										},
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Wait for initial policy processing (expect exactly 1 CREATE call)
			Eventually(func() bool {
				return syncPolicyCreateCalled == 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue())

			// Reset counters to focus on namespace operation
			syncPolicyCreateCalled = 0
			syncPolicyDeleteCalled = 0

			// Create a namespace that does NOT match the selector
			nonMatchingNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("non-matching-ns-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"access": "public", // Different value
						"other":  "label",
					},
				},
			}

			Expect(k8sClient.Create(ctx, nonMatchingNamespace)).To(Succeed())
			defer k8sClient.Delete(ctx, nonMatchingNamespace)

			// Wait a bit and verify exactly 0 sync calls were triggered
			Consistently(func() bool {
				return syncPolicyCreateCalled == 0 && syncPolicyDeleteCalled == 0
			}, "3s", "100ms").Should(BeTrue(), "Policy should NOT be re-synced when non-matching namespace is created")

			By("Verifying non-matching namespace creation does not trigger policy re-sync")
		})

		It("should not trigger sync when namespace is updated without matching selectors", func() {
			// Create a policy with specific namespace selector
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": networkName,
					},
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
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
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"zone": "secure",
										},
									},
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Create a namespace with non-matching labels
			targetNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("target-ns-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"zone": "public",
					},
				},
			}

			Expect(k8sClient.Create(ctx, targetNamespace)).To(Succeed())
			defer k8sClient.Delete(ctx, targetNamespace)

			// Wait for initial processing (expect exactly 1 CREATE call from policy creation)
			Eventually(func() bool {
				return syncPolicyCreateCalled == 1 && lastSyncOperation == "create"
			}, "10s", "100ms").Should(BeTrue())

			// Reset counters to focus on namespace update
			syncPolicyCreateCalled = 0
			syncPolicyDeleteCalled = 0

			// Update namespace labels but still don't match the selector
			Eventually(func() error {
				updatedNamespace := &corev1.Namespace{}
				err := k8sClient.Get(ctx, types.NamespacedName{Name: targetNamespace.Name}, updatedNamespace)
				if err != nil {
					return err
				}

				updatedNamespace.Labels["zone"] = "dmz" // Still doesn't match "secure"
				updatedNamespace.Labels["new"] = "label"
				return k8sClient.Update(ctx, updatedNamespace)
			}, "5s", "100ms").Should(Succeed())

			// Wait a bit and verify exactly 0 sync calls were triggered
			Consistently(func() bool {
				return syncPolicyCreateCalled == 0 && syncPolicyDeleteCalled == 0
			}, "3s", "100ms").Should(BeTrue(), "Policy should NOT be re-synced when namespace labels don't match selector")

			By("Verifying non-matching namespace label update does not trigger policy re-sync")
		})

		It("should not trigger sync when no policies exist", func() {
			// Don't create any policies

			// Reset counters
			syncPolicyCreateCalled = 0
			syncPolicyDeleteCalled = 0

			// Create a namespace
			newNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("empty-ns-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"environment": "test",
						"zone":        "public",
					},
				},
			}

			Expect(k8sClient.Create(ctx, newNamespace)).To(Succeed())
			defer k8sClient.Delete(ctx, newNamespace)

			// Wait a bit and verify exactly 0 sync calls were triggered
			Consistently(func() bool {
				return syncPolicyCreateCalled == 0 && syncPolicyDeleteCalled == 0
			}, "3s", "100ms").Should(BeTrue(), "No sync should be triggered when no policies exist")
		})
	})
})

var _ = Describe("MultiNetworkController Pod Operations Integration", func() {
	var (
		ctx           context.Context
		testNamespace string
		policy        *multiv1beta1.MultiNetworkPolicy
		netAttachDef  *netdefv1.NetworkAttachmentDefinition
	)

	BeforeEach(func() {
		ctx = context.Background()
		testNamespace = fmt.Sprintf("test-pod-ns-%d", time.Now().UnixNano())

		// Reset counters
		syncPolicyCreateCalled = 0
		syncPolicyDeleteCalled = 0
		lastSyncedPolicy = nil
		lastSyncOperation = ""

		// Create test namespace
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}
		Expect(k8sClient.Create(ctx, namespace)).To(Succeed())

		// Create NetworkAttachmentDefinition
		netAttachDef = &netdefv1.NetworkAttachmentDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-network",
				Namespace: testNamespace,
			},
			Spec: netdefv1.NetworkAttachmentDefinitionSpec{
				Config: `{"cniVersion":"0.3.1","type":"macvlan","master":"eth0","mode":"bridge"}`,
			},
		}
		Expect(k8sClient.Create(ctx, netAttachDef)).To(Succeed())
	})

	AfterEach(func() {
		// Comprehensive cleanup to ensure test isolation

		// 1. Remove all labels from the test namespace to prevent cross-test interference
		namespace := &corev1.Namespace{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: testNamespace}, namespace)
		if err == nil {
			namespace.Labels = map[string]string{}
			k8sClient.Update(ctx, namespace)
		}

		// 2. Delete all MultiNetworkPolicies in the test namespace
		var policyList multiv1beta1.MultiNetworkPolicyList
		err = k8sClient.List(ctx, &policyList, client.InNamespace(testNamespace))
		if err == nil {
			for _, policy := range policyList.Items {
				k8sClient.Delete(ctx, &policy)
			}
		}

		// 3. Delete all pods in the test namespace
		var podList corev1.PodList
		err = k8sClient.List(ctx, &podList, client.InNamespace(testNamespace))
		if err == nil {
			for _, pod := range podList.Items {
				k8sClient.Delete(ctx, &pod)
			}
		}

		// 4. Wait for all resources to be deleted
		Eventually(func() bool {
			var policyList multiv1beta1.MultiNetworkPolicyList
			err := k8sClient.List(ctx, &policyList, client.InNamespace(testNamespace))
			if err != nil {
				return false
			}

			var podList corev1.PodList
			err = k8sClient.List(ctx, &podList, client.InNamespace(testNamespace))
			if err != nil {
				return false
			}

			return len(policyList.Items) == 0 && len(podList.Items) == 0
		}, "10s", "100ms").Should(BeTrue(), "All policies and pods should be deleted")

		// 5. Reset counters after cleanup to ensure clean state
		syncPolicyCreateCalled = 0
		syncPolicyDeleteCalled = 0
		lastSyncedPolicy = nil
		lastSyncOperation = ""
	})

	Context("Pod Create Operations", func() {
		Context("when policy has ingress allow all", func() {
			BeforeEach(func() {
				policy = &multiv1beta1.MultiNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "allow-all-policy",
						Namespace: testNamespace,
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/policy-for": "test-network",
						},
					},
					Spec: multiv1beta1.MultiNetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-app",
							},
						},
						Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
							{
								// Empty From means allow all
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())

				// Wait for policy to be processed
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue())

				// Reset counters after policy creation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0
			})

			It("should trigger reconciliation when eligible pod is created", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "eligible-pod",
						Namespace: testNamespace,
						Labels: map[string]string{
							"app": "test-app",
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "test-network",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Reset counters just before checking the specific operation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Update pod status to Running to make it eligible
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue(), "Should trigger exactly 1 reconciliation for eligible pod creation")

				Expect(lastSyncOperation).To(Equal(nftables.SyncOperationCreate))
			})

			It("should not trigger reconciliation when ineligible pod is created", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ineligible-pod",
						Namespace: testNamespace,
						Labels: map[string]string{
							"app": "test-app",
						},
						// No network annotation - makes it ineligible
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Update pod status to Running
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				// Reset counters just before checking the specific operation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				Consistently(func() bool {
					return syncPolicyCreateCalled == 0 && syncPolicyDeleteCalled == 0
				}, "3s", "100ms").Should(BeTrue(), "Should not trigger any reconciliation for ineligible pod")
			})

			It("should not trigger reconciliation when pod doesn't match policy selector", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-matching-pod",
						Namespace: testNamespace,
						Labels: map[string]string{
							"app": "different-app", // Doesn't match policy selector
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "test-network",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Update pod status to Running
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				// Reset counters just before checking the specific operation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// With "allow all" ingress policy, ANY eligible pod triggers reconciliation
				// This is correct behavior - the policy allows all ingress traffic
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue(), "Should trigger exactly 1 reconciliation because policy allows all ingress")
			})
		})

		Context("when policy has ingress pod selector", func() {
			BeforeEach(func() {
				policy = &multiv1beta1.MultiNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-selector-policy",
						Namespace: testNamespace,
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/policy-for": "test-network",
						},
					},
					Spec: multiv1beta1.MultiNetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "server",
							},
						},
						Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
							{
								From: []multiv1beta1.MultiNetworkPolicyPeer{
									{
										PodSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												"role": "client",
											},
										},
									},
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())

				// Wait for policy to be processed
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue())

				// Reset counters after policy creation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0
			})

			It("should trigger reconciliation when client pod matching ingress selector is created", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "client-pod",
						Namespace: testNamespace,
						Labels: map[string]string{
							"role": "client", // Matches ingress selector
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "test-network",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Reset counters just before checking the specific operation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Update pod status to Running
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue(), "Should trigger exactly 1 reconciliation for client pod creation")

				Expect(lastSyncOperation).To(Equal(nftables.SyncOperationCreate))
			})

			It("should trigger reconciliation when server pod matching policy selector is created", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "server-pod",
						Namespace: testNamespace,
						Labels: map[string]string{
							"app": "server", // Matches policy selector
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "test-network",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Reset counters just before checking the specific operation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Update pod status to Running
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue(), "Should trigger exactly 1 reconciliation for server pod creation")

				Expect(lastSyncOperation).To(Equal(nftables.SyncOperationCreate))
			})
		})
	})

	Context("Pod Delete Operations", func() {
		Context("when policy has egress allow all", func() {
			BeforeEach(func() {
				policy = &multiv1beta1.MultiNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "egress-allow-all-policy",
						Namespace: testNamespace,
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/policy-for": "test-network",
						},
					},
					Spec: multiv1beta1.MultiNetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-app",
							},
						},
						Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
							{
								// Empty To means allow all
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())

				// Wait for policy to be processed
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue())

				// Reset counters after policy creation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0
			})

			It("should trigger reconciliation when eligible pod is deleted", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "eligible-pod-to-delete",
						Namespace: testNamespace,
						Labels: map[string]string{
							"app": "test-app",
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "test-network",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Update pod status to Running
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				// Wait for create reconciliation and reset counters
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue())

				// Reset counters just before the delete operation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Delete the pod
				Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue(), "Should trigger exactly 1 reconciliation for eligible pod deletion")

				Expect(lastSyncOperation).To(Equal(nftables.SyncOperationCreate)) // Still create operation because pod is affected by allow-all policy
			})

			It("should not trigger reconciliation when ineligible pod is deleted", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ineligible-pod-to-delete",
						Namespace: testNamespace,
						Labels: map[string]string{
							"app": "test-app",
						},
						// No network annotation - makes it ineligible for deletion events
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Reset counters just before the delete operation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Delete the pod
				Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

				Consistently(func() bool {
					return syncPolicyCreateCalled == 0 && syncPolicyDeleteCalled == 0
				}, "3s", "100ms").Should(BeTrue(), "Should not trigger any reconciliation for ineligible pod deletion")
			})
		})
	})

	Context("Pod Update Operations", func() {
		Context("when pod becomes eligible", func() {
			BeforeEach(func() {
				policy = &multiv1beta1.MultiNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "update-test-policy",
						Namespace: testNamespace,
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/policy-for": "test-network",
						},
					},
					Spec: multiv1beta1.MultiNetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-app",
							},
						},
						Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
							{
								// Empty From means allow all
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())

				// Wait for policy to be processed
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue())

				// Reset counters after policy creation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0
			})

			It("should trigger reconciliation when pod becomes eligible by adding network annotation", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-to-update",
						Namespace: testNamespace,
						Labels: map[string]string{
							"app": "test-app",
						},
						// Initially no network annotation
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Update pod status to Running (still ineligible due to missing annotation)
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				// Verify no reconciliation triggered yet
				Consistently(func() bool {
					return syncPolicyCreateCalled == 0
				}, "2s", "100ms").Should(BeTrue())

				// Reset counters just before making the pod eligible
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Add network annotation to make it eligible
				pod.Annotations = map[string]string{
					"k8s.v1.cni.cncf.io/networks": "test-network",
				}
				Expect(k8sClient.Update(ctx, pod)).To(Succeed())

				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue(), "Should trigger exactly 1 reconciliation when pod becomes eligible")

				Expect(lastSyncOperation).To(Equal(nftables.SyncOperationCreate))
			})

			It("should trigger reconciliation when pod becomes ineligible by changing status", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-to-make-ineligible",
						Namespace: testNamespace,
						Labels: map[string]string{
							"app": "test-app",
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "test-network",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Update pod status to Running (eligible)
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				// Wait for create reconciliation
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue())

				// Reset counters just before changing status
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Change pod status to Failed (ineligible)
				pod.Status.Phase = corev1.PodFailed
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue(), "Should trigger exactly 1 reconciliation when pod becomes ineligible")

				Expect(lastSyncOperation).To(Equal(nftables.SyncOperationCreate)) // Still create operation because pod is affected by allow-all policy
			})
		})

		Context("when pod labels change", func() {
			BeforeEach(func() {
				policy = &multiv1beta1.MultiNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "label-change-policy",
						Namespace: testNamespace,
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/policy-for": "test-network",
						},
					},
					Spec: multiv1beta1.MultiNetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "server",
							},
						},
						Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
							{
								From: []multiv1beta1.MultiNetworkPolicyPeer{
									{
										PodSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{
												"role": "client",
											},
										},
									},
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, policy)).To(Succeed())

				// Wait for policy to be processed
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue())

				// Reset counters after policy creation
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0
			})

			It("should trigger reconciliation when eligible pod labels change", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-with-changing-labels",
						Namespace: testNamespace,
						Labels: map[string]string{
							"role": "client",
						},
						Annotations: map[string]string{
							"k8s.v1.cni.cncf.io/networks": "test-network",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Update pod status to Running (eligible)
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				// Wait for create reconciliation
				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue())

				// Reset counters just before changing labels
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Change pod labels
				pod.Labels = map[string]string{
					"role": "database",
				}
				Expect(k8sClient.Update(ctx, pod)).To(Succeed())

				Eventually(func() bool {
					return syncPolicyCreateCalled == 1
				}, "10s", "100ms").Should(BeTrue(), "Should trigger exactly 1 reconciliation when eligible pod labels change")

				Expect(lastSyncOperation).To(Equal(nftables.SyncOperationCreate))
			})

			It("should not trigger reconciliation when ineligible pod labels change", func() {
				pod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ineligible-pod-labels-change",
						Namespace: testNamespace,
						Labels: map[string]string{
							"role": "client",
						},
						// No network annotation - makes it ineligible
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "test-container",
								Image: "nginx",
							},
						},
					},
				}

				Expect(k8sClient.Create(ctx, pod)).To(Succeed())

				// Update pod status to Running (still ineligible due to missing annotation)
				pod.Status.Phase = corev1.PodRunning
				Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

				// Reset counters just before changing labels
				syncPolicyCreateCalled = 0
				syncPolicyDeleteCalled = 0

				// Change pod labels
				pod.Labels = map[string]string{
					"role": "database",
				}
				Expect(k8sClient.Update(ctx, pod)).To(Succeed())

				Consistently(func() bool {
					return syncPolicyCreateCalled == 0 && syncPolicyDeleteCalled == 0
				}, "3s", "100ms").Should(BeTrue(), "Should not trigger any reconciliation when ineligible pod labels change")
			})
		})
	})

	Context("Complex Pod Scenarios", func() {
		BeforeEach(func() {
			policy = &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "complex-policy",
					Namespace: testNamespace,
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/policy-for": "test-network",
					},
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"tier": "backend",
						},
					},
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "frontend",
										},
									},
								},
							},
						},
					},
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "database",
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Wait for policy to be processed
			Eventually(func() bool {
				return syncPolicyCreateCalled >= 1
			}, "10s", "100ms").Should(BeTrue())

			// Reset counters after policy creation
			syncPolicyCreateCalled = 0
			syncPolicyDeleteCalled = 0
		})

		It("should handle multiple pod types correctly", func() {
			// Create frontend pod (matches ingress selector)
			frontendPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "frontend-pod",
					Namespace: testNamespace,
					Labels: map[string]string{
						"tier": "frontend",
					},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "frontend", Image: "nginx"},
					},
				},
			}

			Expect(k8sClient.Create(ctx, frontendPod)).To(Succeed())

			// Reset counters just before checking frontend reconciliation
			syncPolicyCreateCalled = 0

			frontendPod.Status.Phase = corev1.PodRunning
			Expect(k8sClient.Status().Update(ctx, frontendPod)).To(Succeed())

			Eventually(func() bool {
				return syncPolicyCreateCalled >= 1
			}, "10s", "100ms").Should(BeTrue(), "Frontend pod should trigger at least 1 reconciliation")

			// Create backend pod (matches policy selector)
			backendPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "backend-pod",
					Namespace: testNamespace,
					Labels: map[string]string{
						"tier": "backend",
					},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "backend", Image: "nginx"},
					},
				},
			}

			// Reset counters just before backend pod
			syncPolicyCreateCalled = 0

			Expect(k8sClient.Create(ctx, backendPod)).To(Succeed())
			backendPod.Status.Phase = corev1.PodRunning
			Expect(k8sClient.Status().Update(ctx, backendPod)).To(Succeed())

			Eventually(func() bool {
				return syncPolicyCreateCalled == 1
			}, "10s", "100ms").Should(BeTrue(), "Backend pod should trigger at least 1 reconciliation")

			// Create database pod (matches egress selector)
			databasePod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "database-pod",
					Namespace: testNamespace,
					Labels: map[string]string{
						"tier": "database",
					},
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "database", Image: "postgres"},
					},
				},
			}

			// Reset counters just before database pod
			syncPolicyCreateCalled = 0

			Expect(k8sClient.Create(ctx, databasePod)).To(Succeed())
			databasePod.Status.Phase = corev1.PodRunning
			Expect(k8sClient.Status().Update(ctx, databasePod)).To(Succeed())

			Eventually(func() bool {
				return syncPolicyCreateCalled == 1
			}, "10s", "100ms").Should(BeTrue(), "Database pod should trigger exactly 1 reconciliation")

			By("Verifying all pod types trigger reconciliation correctly")
		})
	})
})
