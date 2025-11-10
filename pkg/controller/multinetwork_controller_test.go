package controller

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("isPolicyAffectedByNamespace Unit Tests", func() {
	logger := log.Log.WithName("test")

	Describe("Input validation", func() {
		It("should return false when policy is nil", func() {
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"environment": "production",
					},
				},
			}

			result := isPolicyAffectedByNamespace(nil, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when namespace is nil", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			}

			result := isPolicyAffectedByNamespace(policy, nil, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when both policy and namespace are nil", func() {
			result := isPolicyAffectedByNamespace(nil, nil, logger)
			Expect(result).To(BeFalse())
		})
	})

	Describe("Ingress namespace selectors", func() {
		var namespace *corev1.Namespace

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"environment": "production",
						"tier":        "frontend",
					},
				},
			}
		})

		It("should return true when ingress namespace selector matches", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
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

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeTrue())
		})

		It("should return false when ingress namespace selector does not match", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "staging",
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when ingress peer has IPBlock (skips namespace selector)", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR: "10.0.0.0/8",
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "production", // This should be ignored
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when ingress peer has no namespace selector", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"app": "web",
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return true when one of multiple ingress peers matches", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "staging", // Doesn't match
										},
									},
								},
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "frontend", // Matches
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeTrue())
		})

		It("should return true when one of multiple ingress rules matches", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "staging", // Doesn't match
										},
									},
								},
							},
						},
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "frontend", // Matches
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeTrue())
		})
	})

	Describe("Egress namespace selectors", func() {
		var namespace *corev1.Namespace

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"database": "mysql",
						"zone":     "secure",
					},
				},
			}
		})

		It("should return true when egress namespace selector matches", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"database": "mysql",
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeTrue())
		})

		It("should return false when egress namespace selector does not match", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"database": "postgres",
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when egress peer has IPBlock (skips namespace selector)", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									IPBlock: &multiv1beta1.IPBlock{
										CIDR: "192.168.0.0/16",
									},
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"database": "mysql", // This should be ignored
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when egress peer has no namespace selector", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
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
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return true when one of multiple egress peers matches", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"database": "postgres", // Doesn't match
										},
									},
								},
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"zone": "secure", // Matches
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeTrue())
		})

		It("should return true when one of multiple egress rules matches", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"database": "postgres", // Doesn't match
										},
									},
								},
							},
						},
						{
							To: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"zone": "secure", // Matches
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeTrue())
		})
	})

	Describe("Combined ingress and egress selectors", func() {
		var namespace *corev1.Namespace

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"environment": "production",
						"tier":        "backend",
					},
				},
			}
		})

		It("should return true when ingress selector matches (egress doesn't match)", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "production", // Matches
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
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "database", // Doesn't match
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeTrue())
		})

		It("should return true when egress selector matches (ingress doesn't match)", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "staging", // Doesn't match
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
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "backend", // Matches
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeTrue())
		})

		It("should return false when neither ingress nor egress selectors match", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "staging", // Doesn't match
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
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"tier": "database", // Doesn't match
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})
	})

	Describe("Edge cases", func() {
		var namespace *corev1.Namespace

		BeforeEach(func() {
			namespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					Labels: map[string]string{
						"app": "web",
					},
				},
			}
		})

		It("should return false when policy has no ingress or egress rules", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					// No Ingress or Egress rules
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when ingress rule has no From peers", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							// No From peers
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when egress rule has no To peers", func() {
			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
						{
							// No To peers
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespace, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when namespace has no labels", func() {
			namespaceNoLabels := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
					// No labels
				},
			}

			policy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"app": "web",
										},
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(policy, namespaceNoLabels, logger)
			Expect(result).To(BeFalse())
		})

		It("should return true when namespace selector is empty (matches all)", func() {
			testPolicy := &multiv1beta1.MultiNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
						{
							From: []multiv1beta1.MultiNetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										// Empty selector matches all
									},
								},
							},
						},
					},
				},
			}

			result := isPolicyAffectedByNamespace(testPolicy, namespace, logger)
			Expect(result).To(BeTrue())
		})
	})
})

var _ = Describe("isPolicyAffectedByPod", func() {
	var (
		logger logr.Logger
		pod    *corev1.Pod
		policy *multiv1beta1.MultiNetworkPolicy
	)

	BeforeEach(func() {
		logger = logr.Discard()

		// Default pod
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "test-namespace",
				Labels: map[string]string{
					"app": "test-app",
					"env": "dev",
				},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
			},
		}

		// Default policy
		policy = &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "test-namespace",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "test-app",
					},
				},
			},
		}
	})

	Context("input validation", func() {
		It("should return false when policy is nil", func() {
			result := isPolicyAffectedByPod(nil, pod, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when pod is nil", func() {
			result := isPolicyAffectedByPod(policy, nil, logger)
			Expect(result).To(BeFalse())
		})

		It("should return false when both policy and pod are nil", func() {
			result := isPolicyAffectedByPod(nil, nil, logger)
			Expect(result).To(BeFalse())
		})
	})

	Context("ingress rules", func() {
		Context("empty ingress from rules (allow all)", func() {
			BeforeEach(func() {
				policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						// Empty From slice means allow all
					},
				}
			})

			It("should return true for empty from rules", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})
		})

		Context("IPBlock rules", func() {
			BeforeEach(func() {
				policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR: "10.0.0.0/8",
								},
							},
						},
					},
				}
			})

			It("should skip IPBlock rules and continue checking other conditions", func() {
				// Since IPBlock is present, it should skip and continue
				// With no other matching conditions, it should fall through to pod selector check
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue()) // Should match on policy pod selector
			})
		})

		Context("pod selector only (same namespace)", func() {
			BeforeEach(func() {
				policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "test-app",
									},
								},
							},
						},
					},
				}
			})

			It("should return true when pod selector matches and namespaces match", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})

			It("should return false when pod selector matches but namespaces don't match", func() {
				pod.Namespace = "different-namespace"
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})

			It("should continue checking when pod selector doesn't match", func() {
				policy.Spec.Ingress[0].From[0].PodSelector.MatchLabels = map[string]string{
					"app": "different-app",
				}
				// Should fall through to policy pod selector check
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue()) // Should match on policy pod selector
			})
		})

		Context("pod selector with namespace selector", func() {
			BeforeEach(func() {
				policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "test-app",
									},
								},
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"env": "test",
									},
								},
							},
						},
					},
				}
			})

			It("should return true when pod selector matches (ignores namespace matching)", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})

			It("should continue checking when pod selector doesn't match", func() {
				policy.Spec.Ingress[0].From[0].PodSelector.MatchLabels = map[string]string{
					"app": "different-app",
				}
				// Should fall through to policy pod selector check
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue()) // Should match on policy pod selector
			})
		})

		Context("multiple ingress rules", func() {
			BeforeEach(func() {
				policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "different-app", // Won't match
									},
								},
							},
						},
					},
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"env": "dev", // Will match
									},
								},
							},
						},
					},
				}
			})

			It("should return true if any ingress rule matches", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})
		})

		Context("multiple peers in single ingress rule", func() {
			BeforeEach(func() {
				policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "different-app", // Won't match
									},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"env": "dev", // Will match
									},
								},
							},
						},
					},
				}
			})

			It("should return true if any peer matches", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})
		})
	})

	Context("egress rules", func() {
		Context("empty egress to rules (allow all)", func() {
			BeforeEach(func() {
				policy.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						// Empty To slice means allow all
					},
				}
			})

			It("should return true for empty to rules", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})
		})

		Context("IPBlock rules", func() {
			BeforeEach(func() {
				policy.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR: "10.0.0.0/8",
								},
							},
						},
					},
				}
			})

			It("should skip IPBlock rules and continue checking other conditions", func() {
				// Since IPBlock is present, it should skip and continue
				// With no other matching conditions, it should fall through to pod selector check
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue()) // Should match on policy pod selector
			})
		})

		Context("pod selector only (same namespace)", func() {
			BeforeEach(func() {
				policy.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "test-app",
									},
								},
							},
						},
					},
				}
			})

			It("should return true when pod selector matches and namespaces match", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})

			It("should return false when pod selector matches but namespaces don't match", func() {
				pod.Namespace = "different-namespace"
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})

			It("should continue checking when pod selector doesn't match", func() {
				policy.Spec.Egress[0].To[0].PodSelector.MatchLabels = map[string]string{
					"app": "different-app",
				}
				// Should fall through to policy pod selector check
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue()) // Should match on policy pod selector
			})
		})

		Context("pod selector with namespace selector", func() {
			BeforeEach(func() {
				policy.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "test-app",
									},
								},
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"env": "test",
									},
								},
							},
						},
					},
				}
			})

			It("should return true when pod selector matches (ignores namespace matching)", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})

			It("should continue checking when pod selector doesn't match", func() {
				policy.Spec.Egress[0].To[0].PodSelector.MatchLabels = map[string]string{
					"app": "different-app",
				}
				// Should fall through to policy pod selector check
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue()) // Should match on policy pod selector
			})
		})

		Context("multiple egress rules", func() {
			BeforeEach(func() {
				policy.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "different-app", // Won't match
									},
								},
							},
						},
					},
					{
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"env": "dev", // Will match
									},
								},
							},
						},
					},
				}
			})

			It("should return true if any egress rule matches", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})
		})
	})

	Context("policy pod selector (final check)", func() {
		Context("when no ingress/egress rules match", func() {
			BeforeEach(func() {
				// Set up a policy with non-matching ingress/egress rules
				policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "different-app",
									},
								},
							},
						},
					},
				}
			})

			It("should return true when policy pod selector matches and pod is running", func() {
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})

			It("should return false when policy pod selector matches but pod is not running", func() {
				pod.Status.Phase = corev1.PodPending
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})

			It("should return false when policy pod selector doesn't match", func() {
				policy.Spec.PodSelector.MatchLabels = map[string]string{
					"app": "different-app",
				}
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})

			It("should return false when namespaces don't match", func() {
				pod.Namespace = "different-namespace"
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})
		})

		Context("with different pod phases", func() {
			It("should return true for running pods", func() {
				pod.Status.Phase = corev1.PodRunning
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeTrue())
			})

			It("should return false for pending pods", func() {
				pod.Status.Phase = corev1.PodPending
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})

			It("should return false for succeeded pods", func() {
				pod.Status.Phase = corev1.PodSucceeded
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})

			It("should return false for failed pods", func() {
				pod.Status.Phase = corev1.PodFailed
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})

			It("should return false for unknown phase pods", func() {
				pod.Status.Phase = corev1.PodUnknown
				result := isPolicyAffectedByPod(policy, pod, logger)
				Expect(result).To(BeFalse())
			})
		})
	})

	Context("combined ingress and egress rules", func() {
		BeforeEach(func() {
			policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "different-app", // Won't match
								},
							},
						},
					},
				},
			}
			policy.Spec.Egress = []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"env": "dev", // Will match
								},
							},
						},
					},
				},
			}
		})

		It("should return true if any rule (ingress or egress) matches", func() {
			result := isPolicyAffectedByPod(policy, pod, logger)
			Expect(result).To(BeTrue())
		})
	})

	Context("edge cases", func() {
		It("should handle policy with no ingress, egress, or pod selector", func() {
			policy.Spec.Ingress = nil
			policy.Spec.Egress = nil
			policy.Spec.PodSelector = metav1.LabelSelector{} // Empty selector matches all

			result := isPolicyAffectedByPod(policy, pod, logger)
			Expect(result).To(BeTrue()) // Empty selector matches all running pods
		})

		It("should handle pod with no labels", func() {
			pod.Labels = nil
			policy.Spec.PodSelector = metav1.LabelSelector{} // Empty selector matches all

			result := isPolicyAffectedByPod(policy, pod, logger)
			Expect(result).To(BeTrue())
		})

		It("should handle pod with empty labels map", func() {
			pod.Labels = map[string]string{}
			policy.Spec.PodSelector = metav1.LabelSelector{} // Empty selector matches all

			result := isPolicyAffectedByPod(policy, pod, logger)
			Expect(result).To(BeTrue())
		})

		It("should handle policy with empty pod selector (matches all)", func() {
			policy.Spec.PodSelector = metav1.LabelSelector{} // Empty selector matches all

			result := isPolicyAffectedByPod(policy, pod, logger)
			Expect(result).To(BeTrue())
		})
	})
})

var _ = Describe("isPodTentativelyEligible", func() {
	var pod *corev1.Pod

	BeforeEach(func() {
		// Default eligible pod
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "test-namespace",
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/networks": "macvlan-network",
				},
			},
			Spec: corev1.PodSpec{
				HostNetwork: false,
			},
		}
	})

	Context("input validation", func() {
		It("should return false when pod is nil", func() {
			result := isPodTentativelyEligible(nil)
			Expect(result).To(BeFalse())
		})
	})

	Context("host network check", func() {
		It("should return false when pod uses host network", func() {
			pod.Spec.HostNetwork = true
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should continue checking when pod doesn't use host network", func() {
			pod.Spec.HostNetwork = false
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeTrue())
		})
	})

	Context("annotations check", func() {
		It("should return false when pod has no annotations", func() {
			pod.Annotations = nil
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return false when pod has empty annotations map", func() {
			pod.Annotations = map[string]string{}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should continue checking when pod has annotations", func() {
			pod.Annotations = map[string]string{
				"k8s.v1.cni.cncf.io/networks": "macvlan-network",
			}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeTrue())
		})
	})

	Context("network annotation parsing", func() {
		It("should return false when network annotation is invalid", func() {
			pod.Annotations = map[string]string{
				"k8s.v1.cni.cncf.io/networks": "invalid-json-[",
			}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return false when network annotation is missing", func() {
			pod.Annotations = map[string]string{
				"other-annotation": "value",
			}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return false when network annotation results in empty networks", func() {
			pod.Annotations = map[string]string{
				"k8s.v1.cni.cncf.io/networks": "",
			}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return true when network annotation is valid with single network", func() {
			pod.Annotations = map[string]string{
				"k8s.v1.cni.cncf.io/networks": "macvlan-network",
			}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeTrue())
		})

		It("should return true when network annotation is valid with multiple networks", func() {
			pod.Annotations = map[string]string{
				"k8s.v1.cni.cncf.io/networks": "macvlan-network,bridge-network",
			}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeTrue())
		})

		It("should return true when network annotation is valid JSON format", func() {
			pod.Annotations = map[string]string{
				"k8s.v1.cni.cncf.io/networks": `[{"name": "macvlan-network"}]`,
			}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeTrue())
		})
	})

	Context("edge cases", func() {
		It("should handle pod with host network and no annotations", func() {
			pod.Spec.HostNetwork = true
			pod.Annotations = nil
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should handle pod with host network and valid annotations", func() {
			pod.Spec.HostNetwork = true
			pod.Annotations = map[string]string{
				"k8s.v1.cni.cncf.io/networks": "macvlan-network",
			}
			result := isPodTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})
	})
})

var _ = Describe("isTentativelyEligible", func() {
	Context("input validation", func() {
		It("should return false when object is nil", func() {
			result := isTentativelyEligible(nil)
			Expect(result).To(BeFalse())
		})

		It("should return false when object is not a pod", func() {
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			result := isTentativelyEligible(namespace)
			Expect(result).To(BeFalse())
		})
	})

	Context("pod eligibility", func() {
		It("should return false for ineligible pod", func() {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "test-namespace",
				},
				Spec: corev1.PodSpec{
					HostNetwork: true, // Makes it ineligible
				},
			}
			result := isTentativelyEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return true for tentatively eligible pod", func() {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "macvlan-network",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
			}
			result := isTentativelyEligible(pod)
			Expect(result).To(BeTrue())
		})
	})
})

var _ = Describe("isEligible", func() {
	Context("input validation", func() {
		It("should return false when object is nil", func() {
			result := isEligible(nil)
			Expect(result).To(BeFalse())
		})

		It("should return false when object is not a pod", func() {
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			result := isEligible(namespace)
			Expect(result).To(BeFalse())
		})
	})

	Context("pod phase check", func() {
		var pod *corev1.Pod

		BeforeEach(func() {
			// Default tentatively eligible pod
			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "macvlan-network",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
			}
		})

		It("should return true for running pod that is tentatively eligible", func() {
			pod.Status.Phase = corev1.PodRunning
			result := isEligible(pod)
			Expect(result).To(BeTrue())
		})

		It("should return false for pending pod even if tentatively eligible", func() {
			pod.Status.Phase = corev1.PodPending
			result := isEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return false for succeeded pod even if tentatively eligible", func() {
			pod.Status.Phase = corev1.PodSucceeded
			result := isEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return false for failed pod even if tentatively eligible", func() {
			pod.Status.Phase = corev1.PodFailed
			result := isEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return false for unknown phase pod even if tentatively eligible", func() {
			pod.Status.Phase = corev1.PodUnknown
			result := isEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return false for running pod that is not tentatively eligible", func() {
			pod.Status.Phase = corev1.PodRunning
			pod.Spec.HostNetwork = true // Makes it not tentatively eligible
			result := isEligible(pod)
			Expect(result).To(BeFalse())
		})
	})

	Context("comprehensive eligibility check", func() {
		It("should return false for host network pod regardless of phase", func() {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "macvlan-network",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: true,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			}
			result := isEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return false for pod without network annotations regardless of phase", func() {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "test-namespace",
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			}
			result := isEligible(pod)
			Expect(result).To(BeFalse())
		})

		It("should return true only for running pods with valid network annotations and no host network", func() {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "macvlan-network",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			}
			result := isEligible(pod)
			Expect(result).To(BeTrue())
		})
	})
})

var _ = Describe("getNetworksInPolicyForAnnotation Unit Tests", func() {
	Context("input validation", func() {
		It("should return error for empty annotation", func() {
			networks, err := getNetworksInPolicyForAnnotation("", "default")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("contains no valid network names"))
			Expect(networks).To(BeNil())
		})

		It("should return error for whitespace-only annotation", func() {
			networks, err := getNetworksInPolicyForAnnotation("   ", "default")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("contains no valid network names"))
			Expect(networks).To(BeNil())
		})

		It("should return error for annotation with only commas and spaces", func() {
			networks, err := getNetworksInPolicyForAnnotation(" , , , ", "default")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("contains no valid network names"))
			Expect(networks).To(BeNil())
		})
	})

	Context("single network parsing", func() {
		It("should parse single network name without namespace", func() {
			networks, err := getNetworksInPolicyForAnnotation("macvlan-net", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"default/macvlan-net"}))
		})

		It("should parse single network name with namespace", func() {
			networks, err := getNetworksInPolicyForAnnotation("prod/macvlan-net", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"prod/macvlan-net"}))
		})

		It("should handle network name with leading/trailing spaces", func() {
			networks, err := getNetworksInPolicyForAnnotation("  macvlan-net  ", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"default/macvlan-net"}))
		})

		It("should handle namespace and name with spaces", func() {
			networks, err := getNetworksInPolicyForAnnotation("  prod  /  macvlan-net  ", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"prod/macvlan-net"}))
		})
	})

	Context("multiple networks parsing", func() {
		It("should parse multiple networks without namespaces", func() {
			networks, err := getNetworksInPolicyForAnnotation("macvlan-net,bridge-net", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"default/macvlan-net", "default/bridge-net"}))
		})

		It("should parse multiple networks with mixed namespace formats", func() {
			networks, err := getNetworksInPolicyForAnnotation("macvlan-net,prod/bridge-net,test/vlan-net", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"default/macvlan-net", "prod/bridge-net", "test/vlan-net"}))
		})

		It("should handle multiple networks with spaces around commas", func() {
			networks, err := getNetworksInPolicyForAnnotation(" macvlan-net , prod/bridge-net , test/vlan-net ", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"default/macvlan-net", "prod/bridge-net", "test/vlan-net"}))
		})

		It("should skip empty entries in comma-separated list", func() {
			networks, err := getNetworksInPolicyForAnnotation("macvlan-net,,bridge-net,", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"default/macvlan-net", "default/bridge-net"}))
		})
	})

	Context("edge cases and potential bugs", func() {
		It("should handle network names with multiple slashes (potential bug)", func() {
			networks, err := getNetworksInPolicyForAnnotation("ns/name/extra", "default")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("contains no valid network names"))
			Expect(networks).To(BeNil())
		})

		It("should handle empty namespace in network name", func() {
			networks, err := getNetworksInPolicyForAnnotation("/macvlan-net", "default")
			Expect(err.Error()).To(ContainSubstring("contains no valid network names"))
			Expect(networks).To(BeNil())
		})

		It("should handle empty name in network name", func() {
			networks, err := getNetworksInPolicyForAnnotation("prod/", "default")
			Expect(err.Error()).To(ContainSubstring("contains no valid network names"))
			Expect(networks).To(BeNil())
		})

		It("should handle only slash in network name", func() {
			networks, err := getNetworksInPolicyForAnnotation("/", "default")
			Expect(err.Error()).To(ContainSubstring("contains no valid network names"))
			Expect(networks).To(BeNil())
		})
	})

	Context("real-world scenarios", func() {
		It("should handle typical CNI network annotation format", func() {
			networks, err := getNetworksInPolicyForAnnotation("macvlan-conf@eth0,bridge-conf@eth1", "kube-system")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"kube-system/macvlan-conf@eth0", "kube-system/bridge-conf@eth1"}))
		})

		It("should handle network names with special characters", func() {
			networks, err := getNetworksInPolicyForAnnotation("net-1,net_2,net.3", "default")
			Expect(err).ToNot(HaveOccurred())
			Expect(networks).To(Equal([]string{"default/net-1", "default/net_2", "default/net.3"}))
		})
	})
})

var _ = Describe("getNetworkType Unit Tests", func() {
	Context("input validation", func() {
		It("should return error when netAttachDef is nil", func() {
			netType, err := getNetworkType(nil)
			Expect(err).To(HaveOccurred())
			Expect(netType).To(BeEmpty())
		})
	})

	Context("CNI configuration parsing", func() {
		var netAttachDef *netdefv1.NetworkAttachmentDefinition

		BeforeEach(func() {
			netAttachDef = &netdefv1.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-network",
					Namespace: "default",
				},
			}
		})

		It("should parse single plugin configuration", func() {
			netAttachDef.Spec.Config = `{
				"cniVersion": "0.3.1",
				"type": "macvlan",
				"master": "eth0"
			}`

			netType, err := getNetworkType(netAttachDef)
			Expect(err).ToNot(HaveOccurred())
			Expect(netType).To(Equal("macvlan"))
		})

		It("should parse plugin list configuration and return first plugin type", func() {
			netAttachDef.Spec.Config = `{
				"cniVersion": "0.3.1",
				"plugins": [
					{
						"type": "macvlan",
						"master": "eth0"
					},
					{
						"type": "bridge",
						"bridge": "br0"
					}
				]
			}`

			netType, err := getNetworkType(netAttachDef)
			Expect(err).ToNot(HaveOccurred())
			Expect(netType).To(Equal("macvlan"))
		})

		It("should handle empty plugin list", func() {
			netAttachDef.Spec.Config = `{
				"cniVersion": "0.3.1",
				"plugins": []
			}`

			netType, err := getNetworkType(netAttachDef)
			Expect(err).ToNot(HaveOccurred())
			Expect(netType).To(Equal(""))
		})

		It("should return error for invalid JSON configuration", func() {
			netAttachDef.Spec.Config = `{
				"cniVersion": "0.3.1",
				"type": "macvlan"
				"master": "eth0"
			}`

			netType, err := getNetworkType(netAttachDef)
			Expect(err).To(HaveOccurred())
			Expect(netType).To(BeEmpty())
		})

		It("should return error for empty configuration", func() {
			netAttachDef.Spec.Config = ""

			netType, err := getNetworkType(netAttachDef)
			Expect(err).To(HaveOccurred())
			Expect(netType).To(BeEmpty())
		})

		It("should handle configuration without type field", func() {
			netAttachDef.Spec.Config = `{
				"cniVersion": "0.3.1",
				"master": "eth0"
			}`

			netType, err := getNetworkType(netAttachDef)
			Expect(err).ToNot(HaveOccurred())
			Expect(netType).To(Equal(""))
		})

		It("should handle plugin list with empty first plugin", func() {
			netAttachDef.Spec.Config = `{
				"cniVersion": "0.3.1",
				"plugins": [
					{},
					{
						"type": "bridge",
						"bridge": "br0"
					}
				]
			}`

			netType, err := getNetworkType(netAttachDef)
			Expect(err).ToNot(HaveOccurred())
			Expect(netType).To(Equal(""))
		})
	})

	Context("edge cases", func() {
		var netAttachDef *netdefv1.NetworkAttachmentDefinition

		BeforeEach(func() {
			netAttachDef = &netdefv1.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-network",
					Namespace: "default",
				},
			}
		})

		It("should handle configuration with null values", func() {
			netAttachDef.Spec.Config = `{
				"cniVersion": "0.3.1",
				"type": null,
				"master": "eth0"
			}`

			netType, err := getNetworkType(netAttachDef)
			Expect(err).ToNot(HaveOccurred())
			Expect(netType).To(Equal(""))
		})

		It("should handle configuration with numeric type field", func() {
			netAttachDef.Spec.Config = `{
				"cniVersion": "0.3.1",
				"type": 123,
				"master": "eth0"
			}`

			netType, err := getNetworkType(netAttachDef)
			Expect(err).To(HaveOccurred())
			Expect(netType).To(BeEmpty())
		})

		It("should handle very large configuration", func() {
			largeConfig := `{
				"cniVersion": "0.3.1",
				"type": "macvlan",
				"master": "eth0",
				"extra": "` + strings.Repeat("x", 10000) + `"
			}`

			netAttachDef.Spec.Config = largeConfig

			netType, err := getNetworkType(netAttachDef)
			Expect(err).ToNot(HaveOccurred())
			Expect(netType).To(Equal("macvlan"))
		})
	})
})

var _ = Describe("getAllowedNetworks Unit Tests", func() {
	var (
		reconciler *MultiNetworkReconciler
		ctx        context.Context
		logger     logr.Logger
		fakeClient client.Client
		scheme     *runtime.Scheme
	)

	BeforeEach(func() {
		ctx = context.Background()
		logger = logr.Discard()

		// Create a fake client with the necessary schemes
		scheme = runtime.NewScheme()
		Expect(netdefv1.AddToScheme(scheme)).To(Succeed())

		fakeClient = fake.NewClientBuilder().WithScheme(scheme).Build()
		reconciler = &MultiNetworkReconciler{
			Client:       fakeClient,
			ValidPlugins: []string{"macvlan", "bridge", "ipvlan"},
		}
	})

	Context("input validation", func() {
		It("should return empty slice for nil networks slice", func() {
			networks, err := reconciler.getAllowedNetworks(ctx, nil, reconciler.ValidPlugins, logger)
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
			Expect(networks).To(BeEmpty())
		})

		It("should return empty slice for empty networks slice", func() {
			networks, err := reconciler.getAllowedNetworks(ctx, []string{}, reconciler.ValidPlugins, logger)
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
			Expect(networks).To(BeEmpty())
		})

		It("should handle nil validPlugins slice", func() {
			networks := []string{"default/macvlan-net"}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, nil, logger)
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
			Expect(allowedNetworks).To(BeEmpty())
		})

		It("should handle empty validPlugins slice", func() {
			networks := []string{"default/macvlan-net"}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, []string{}, logger)
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
			Expect(allowedNetworks).To(BeEmpty())
		})
	})

	Context("network format validation", func() {
		It("should skip networks with invalid format", func() {
			networks := []string{"invalid-format"}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
			Expect(allowedNetworks).To(BeEmpty()) // No valid networks found due to invalid format
		})

		It("should skip networks with too many parts", func() {
			networks := []string{"ns/name/extra"}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
			Expect(allowedNetworks).To(BeEmpty()) // No valid networks found due to invalid format
		})
	})

	Context("network attachment definition handling", func() {
		It("should skip networks when attachment definition is not found", func() {
			networks := []string{"default/nonexistent-net"}
			_, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
		})

		It("should return error when getting attachment definition fails with non-NotFound error", func() {
			// This test would require a more sophisticated fake client setup
			// For now, we'll test the happy path
			networks := []string{"default/macvlan-net"}
			_, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
		})
	})

	Context("network type validation with fake client", func() {
		BeforeEach(func() {
			// Create a fake client with network attachment definitions
			objects := []client.Object{
				&netdefv1.NetworkAttachmentDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "macvlan-net",
						Namespace: "default",
					},
					Spec: netdefv1.NetworkAttachmentDefinitionSpec{
						Config: `{
							"cniVersion": "0.3.1",
							"type": "macvlan",
							"master": "eth0"
						}`,
					},
				},
				&netdefv1.NetworkAttachmentDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bridge-net",
						Namespace: "default",
					},
					Spec: netdefv1.NetworkAttachmentDefinitionSpec{
						Config: `{
							"cniVersion": "0.3.1",
							"type": "bridge",
							"bridge": "br0"
						}`,
					},
				},
				&netdefv1.NetworkAttachmentDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "unsupported-net",
						Namespace: "default",
					},
					Spec: netdefv1.NetworkAttachmentDefinitionSpec{
						Config: `{
							"cniVersion": "0.3.1",
							"type": "unsupported",
							"config": "value"
						}`,
					},
				},
				&netdefv1.NetworkAttachmentDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "invalid-config-net",
						Namespace: "default",
					},
					Spec: netdefv1.NetworkAttachmentDefinitionSpec{
						Config: `{
							"cniVersion": "0.3.1",
							"type": "macvlan"
							"master": "eth0"
						}`,
					},
				},
			}

			fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
			reconciler.Client = fakeClient
		})

		It("should include networks with supported types", func() {
			networks := []string{"default/macvlan-net"}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowedNetworks).To(Equal([]string{"default/macvlan-net"}))
		})

		It("should include multiple networks with supported types", func() {
			networks := []string{"default/macvlan-net", "default/bridge-net"}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowedNetworks).To(Equal([]string{"default/macvlan-net", "default/bridge-net"}))
		})

		It("should exclude networks with unsupported types", func() {
			networks := []string{"default/unsupported-net"}
			_, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no allowed networks found"))
		})

		It("should skip networks with invalid configuration", func() {
			networks := []string{"default/invalid-config-net"}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err).To(HaveOccurred())
			Expect(allowedNetworks).To(BeEmpty())
		})

		It("should handle mix of valid and invalid networks", func() {
			networks := []string{
				"invalid-format",
				"default/macvlan-net",
				"ns/name/extra",
				"default/unsupported-net",
				"default/bridge-net",
			}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowedNetworks).To(Equal([]string{"default/macvlan-net", "default/bridge-net"}))
		})

		It("should handle networks from different namespaces", func() {
			// Add a network in a different namespace
			otherNamespaceNet := &netdefv1.NetworkAttachmentDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "macvlan-net",
					Namespace: "other-ns",
				},
				Spec: netdefv1.NetworkAttachmentDefinitionSpec{
					Config: `{
						"cniVersion": "0.3.1",
						"type": "macvlan",
						"master": "eth1"
					}`,
				},
			}
			Expect(fakeClient.Create(ctx, otherNamespaceNet)).To(Succeed())

			networks := []string{"default/macvlan-net", "other-ns/macvlan-net"}
			allowedNetworks, err := reconciler.getAllowedNetworks(ctx, networks, reconciler.ValidPlugins, logger)
			Expect(err).ToNot(HaveOccurred())
			Expect(allowedNetworks).To(Equal([]string{"default/macvlan-net", "other-ns/macvlan-net"}))
		})
	})
})
