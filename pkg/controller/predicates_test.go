package controller

import (
	"testing"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// TestPodPredicateNetworkStatusChange verifies that the PodPredicate triggers
// reconciliation when the network-status annotation changes
func TestPodPredicateNetworkStatusChange(t *testing.T) {
	tests := []struct {
		name           string
		oldPod         *corev1.Pod
		newPod         *corev1.Pod
		expectedResult bool
		expectedReason string
	}{
		{
			name: "network-status annotation added",
			oldPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			newPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
						netdefv1.NetworkStatusAnnot:   `[{"name":"test-network","interface":"net1","ips":["2001:db8::1"]}]`,
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			expectedResult: true,
			expectedReason: "Network status changed",
		},
		{
			name: "network-status annotation modified (IPv6 address added)",
			oldPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
						netdefv1.NetworkStatusAnnot:   `[{"name":"test-network","interface":"net1","ips":["192.0.2.1"]}]`,
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			newPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
						netdefv1.NetworkStatusAnnot:   `[{"name":"test-network","interface":"net1","ips":["192.0.2.1","2001:db8::1"]}]`,
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			expectedResult: true,
			expectedReason: "Network status changed",
		},
		{
			name: "network-status annotation unchanged",
			oldPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
						netdefv1.NetworkStatusAnnot:   `[{"name":"test-network","interface":"net1","ips":["192.0.2.1"]}]`,
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			newPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
						netdefv1.NetworkStatusAnnot:   `[{"name":"test-network","interface":"net1","ips":["192.0.2.1"]}]`,
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			expectedResult: false,
			expectedReason: "No changes",
		},
		{
			name: "pod not eligible - host network",
			oldPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: true,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			newPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
						netdefv1.NetworkStatusAnnot:   `[{"name":"test-network","interface":"net1","ips":["192.0.2.1"]}]`,
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: true,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			expectedResult: false,
			expectedReason: "Pod not eligible",
		},
		{
			name: "other annotation changed but not network-status",
			oldPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
						netdefv1.NetworkStatusAnnot:   `[{"name":"test-network","interface":"net1","ips":["192.0.2.1"]}]`,
						"other-annotation":            "value1",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			newPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
					Annotations: map[string]string{
						"k8s.v1.cni.cncf.io/networks": "test-network",
						netdefv1.NetworkStatusAnnot:   `[{"name":"test-network","interface":"net1","ips":["192.0.2.1"]}]`,
						"other-annotation":            "value2",
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: false,
				},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
				},
			},
			expectedResult: false,
			expectedReason: "Only other annotations changed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := event.UpdateEvent{
				ObjectOld: tt.oldPod,
				ObjectNew: tt.newPod,
			}

			result := PodPredicate.Update(e)
			if result != tt.expectedResult {
				t.Errorf("PodPredicate.Update() = %v, want %v (reason: %s)", result, tt.expectedResult, tt.expectedReason)
			}
		})
	}
}
