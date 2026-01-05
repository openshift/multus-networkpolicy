package datastore

import (
	"testing"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestDatastore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Datastore Suite")
}

var _ = Describe("Datastore", func() {
	var ds *Datastore

	BeforeEach(func() {
		ds = &Datastore{
			Policies: make(map[types.NamespacedName]*Policy),
		}
	})

	Describe("Policy Management", func() {
		Context("when creating a policy", func() {
			It("should store the policy correctly", func() {
				policy := &Policy{
					Name:      "test-policy",
					Namespace: "test-ns",
					Networks:  []string{"network1"},
					Spec: multiv1beta1.MultiNetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "test"},
						},
					},
				}

				ds.CreatePolicy(policy)

				key := types.NamespacedName{Namespace: "test-ns", Name: "test-policy"}
				retrievedPolicy := ds.GetPolicy(key)
				Expect(retrievedPolicy).NotTo(BeNil())
				Expect(retrievedPolicy.Name).To(Equal("test-policy"))
				Expect(retrievedPolicy.Namespace).To(Equal("test-ns"))
				Expect(retrievedPolicy.Networks).To(Equal([]string{"network1"}))
			})

			It("should overwrite existing policy with same key", func() {
				key := types.NamespacedName{Namespace: "test-ns", Name: "test-policy"}

				policy1 := &Policy{
					Name:      "test-policy",
					Namespace: "test-ns",
					Networks:  []string{"network1"},
				}

				policy2 := &Policy{
					Name:      "test-policy",
					Namespace: "test-ns",
					Networks:  []string{"network2"},
				}

				ds.CreatePolicy(policy1)
				ds.CreatePolicy(policy2)

				retrievedPolicy := ds.GetPolicy(key)
				Expect(retrievedPolicy).NotTo(BeNil())
				Expect(retrievedPolicy.Networks).To(Equal([]string{"network2"}))
			})
		})

		Context("when getting a policy", func() {
			It("should return the policy if it exists", func() {
				policy := &Policy{
					Name:      "existing-policy",
					Namespace: "test-ns",
					Networks:  []string{"network1"},
				}

				ds.CreatePolicy(policy)

				key := types.NamespacedName{Namespace: "test-ns", Name: "existing-policy"}
				retrievedPolicy := ds.GetPolicy(key)
				Expect(retrievedPolicy).NotTo(BeNil())
				Expect(retrievedPolicy.Name).To(Equal("existing-policy"))
			})

			It("should return nil if policy doesn't exist", func() {
				key := types.NamespacedName{Namespace: "test-ns", Name: "non-existent"}
				retrievedPolicy := ds.GetPolicy(key)
				Expect(retrievedPolicy).To(BeNil())
			})
		})

		Context("when deleting a policy", func() {
			It("should remove the policy from the datastore", func() {
				policy := &Policy{
					Name:      "to-delete",
					Namespace: "test-ns",
					Networks:  []string{"network1"},
				}

				ds.CreatePolicy(policy)

				key := types.NamespacedName{Namespace: "test-ns", Name: "to-delete"}
				// Verify policy exists
				Expect(ds.GetPolicy(key)).NotTo(BeNil())

				// Delete policy
				ds.DeletePolicy(key)

				// Verify policy is gone
				Expect(ds.GetPolicy(key)).To(BeNil())
			})

			It("should handle deletion of non-existent policy gracefully", func() {
				key := types.NamespacedName{Namespace: "test-ns", Name: "non-existent"}

				// Should not panic
				Expect(func() {
					ds.DeletePolicy(key)
				}).NotTo(Panic())
			})
		})
	})

	Describe("Concurrent Access", func() {
		It("should handle concurrent reads and writes safely", func() {
			done := make(chan bool, 3)

			// Concurrent writer
			go func() {
				defer GinkgoRecover()
				for i := 0; i < 100; i++ {
					policy := &Policy{
						Name:      "concurrent-policy",
						Namespace: "test-ns",
						Networks:  []string{"network1"},
					}
					ds.CreatePolicy(policy)
				}
				done <- true
			}()

			// Concurrent reader
			go func() {
				defer GinkgoRecover()
				for i := 0; i < 100; i++ {
					key := types.NamespacedName{Namespace: "test-ns", Name: "concurrent-policy"}
					ds.GetPolicy(key) // May return nil or the policy
				}
				done <- true
			}()

			// Concurrent deleter
			go func() {
				defer GinkgoRecover()
				for i := 0; i < 100; i++ {
					key := types.NamespacedName{Namespace: "test-ns", Name: "concurrent-policy"}
					ds.DeletePolicy(key)
				}
				done <- true
			}()

			// Wait for all goroutines to complete
			for i := 0; i < 3; i++ {
				Eventually(done).Should(Receive())
			}
		})
	})
})
