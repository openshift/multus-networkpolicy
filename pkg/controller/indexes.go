package controller

import (
	"context"
	"strconv"

	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/nftables"
)

func setupIndexes(mgr ctrl.Manager) error {
	// Pod Hostname index
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, nftables.PodHostnameIndex, func(obj client.Object) []string {
		pod := obj.(*corev1.Pod)

		if pod.Spec.NodeName == "" {
			return nil
		}

		return []string{pod.Spec.NodeName}
	}); err != nil {
		return err
	}

	// Pod Status Phase index
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, nftables.PodStatusIndex, func(obj client.Object) []string {
		pod := obj.(*corev1.Pod)
		return []string{string(pod.Status.Phase)}
	}); err != nil {
		return err
	}

	// Pod Host Network index
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, nftables.PodHostNetworkIndex, func(obj client.Object) []string {
		pod := obj.(*corev1.Pod)
		return []string{strconv.FormatBool(pod.Spec.HostNetwork)}
	}); err != nil {
		return err
	}

	// Pod Has Network Annotation index
	return mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, nftables.PodHasNetworkAnnotationIndex, func(obj client.Object) []string {
		pod := obj.(*corev1.Pod)

		if pod.GetAnnotations() == nil {
			return []string{"false"}
		}

		networks, err := netdefutils.ParsePodNetworkAnnotation(pod)
		if err != nil {
			return []string{"false"}
		}

		if len(networks) == 0 {
			return []string{"false"}
		}

		return []string{"true"}
	})
}
