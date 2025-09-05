package controller

import (
	"reflect"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/datastore"
)

// MultiNetworkPolicyPredicate is a predicate that checks if a policy is eligible for reconciliation
// This predicate is set with WithEventFilter which means that the predicate will be added to all watched resources.
// We will let through events for pods and namespaces which will be handled by their respective predicates.
var MultiNetworkPolicyPredicate = predicate.Funcs{
	CreateFunc: func(e event.CreateEvent) bool {
		// Always when creating a policy, we need to reconcile it
		if _, ok := e.Object.(*multiv1beta1.MultiNetworkPolicy); ok {
			log.Log.V(2).Info("MultiNetworkPolicyPredicate CreateFunc", "namespace", e.Object.GetNamespace(), "name", e.Object.GetName())
			return true
		}

		return true
	},
	UpdateFunc: func(e event.UpdateEvent) bool {
		// Pod and Namespace events will be handled by their respective predicates
		if _, ok := e.ObjectOld.(*corev1.Pod); ok {
			return true
		}
		if _, ok := e.ObjectNew.(*corev1.Namespace); ok {
			return true
		}

		// Mark for deletion
		if e.ObjectOld.GetDeletionTimestamp() == nil && e.ObjectNew.GetDeletionTimestamp() != nil {
			log.Log.V(2).Info("MultiNetworkPolicyPredicate UpdateFunc", "reason", "Marked for deletion", "namespace", e.ObjectOld.GetNamespace(), "name", e.ObjectOld.GetName())
			return true
		}

		// Spec Changes
		if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
			log.Log.V(2).Info("MultiNetworkPolicyPredicate UpdateFunc", "reason", "Spec changed", "namespace", e.ObjectOld.GetNamespace(), "name", e.ObjectOld.GetName())
			return true
		}

		// Policy-for Annotation Changes
		oldAnnotations := e.ObjectOld.GetAnnotations()
		newAnnotations := e.ObjectNew.GetAnnotations()

		var oldAnnotationValue, newAnnotationValue string
		if oldAnnotations != nil {
			oldAnnotationValue = oldAnnotations[datastore.PolicyForAnnotation]
		}
		if newAnnotations != nil {
			newAnnotationValue = newAnnotations[datastore.PolicyForAnnotation]
		}

		if oldAnnotationValue != newAnnotationValue {
			log.Log.V(2).Info("MultiNetworkPolicyPredicate UpdateFunc", "reason", "Policy-for annotation changed", "namespace", e.ObjectOld.GetNamespace(), "name", e.ObjectOld.GetName())
			return true
		}

		return false
	},
	DeleteFunc: func(e event.DeleteEvent) bool {
		// Always when deleting a policy, we need to reconcile it
		if _, ok := e.Object.(*multiv1beta1.MultiNetworkPolicy); ok {
			log.Log.V(2).Info("MultiNetworkPolicyPredicate DeleteFunc", "namespace", e.Object.GetNamespace(), "name", e.Object.GetName())
			return true
		}

		return true
	},
	GenericFunc: func(_ event.GenericEvent) bool {
		return false
	},
}

// NamespacePredicate is a predicate that will only allow to create events, and updates when the namespace labels change.
var NamespacePredicate = predicate.Funcs{
	CreateFunc: func(e event.CreateEvent) bool {
		// Always when creating a namespace, we need to reconcile it
		log.Log.V(2).Info("NamespacePredicate CreateFunc", "name", e.Object.GetName())
		return true
	},
	UpdateFunc: func(e event.UpdateEvent) bool {
		// Only when the namespace labels change, we need to reconcile it
		if !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) {
			log.Log.V(2).Info("NamespacePredicate UpdateFunc", "reason", "Labels changed", "name", e.ObjectNew.GetName())
			return true
		}

		return false
	},
	DeleteFunc: func(_ event.DeleteEvent) bool {
		// We don't want to process namespace deletion events. Pods are gone for sure.
		return false
	},
	GenericFunc: func(_ event.GenericEvent) bool {
		return false
	},
}

// PodPredicate is a predicate that checks if a pod is eligible for reconciliation
// All events will check if the pod is eligible, except the delete event given that the pod might not be running.
// This pod might be matched by a peer selector, so we need to reconcile it.
// No need to reconcile when old and new are eligible on update events. Changes on secondary interfaces need a Pod restart.
// And containerID of first container is always parsed by demand to get the netns path.
var PodPredicate = predicate.Funcs{
	CreateFunc: func(e event.CreateEvent) bool {
		// Always when creating a pod, we need to reconcile it
		if isEligible(e.Object) {
			log.Log.V(2).Info("PodPredicate CreateFunc", "namespace", e.Object.GetNamespace(), "name", e.Object.GetName())
			return true
		}

		return false
	},
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldEligible := isEligible(e.ObjectOld)
		newEligible := isEligible(e.ObjectNew)

		// When pod becomes eligible
		if !oldEligible && newEligible {
			log.Log.V(2).Info("PodPredicate UpdateFunc", "reason", "Pod became eligible", "namespace", e.ObjectNew.GetNamespace(), "name", e.ObjectNew.GetName())
			return true
		}

		// When pod becomes ineligible
		if oldEligible && !newEligible {
			log.Log.V(2).Info("PodPredicate UpdateFunc", "reason", "Pod became ineligible", "namespace", e.ObjectNew.GetNamespace(), "name", e.ObjectNew.GetName())
			return true
		}

		// When both pods are eligible but labels changed
		if oldEligible && newEligible {
			if !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) {
				log.Log.V(2).Info("PodPredicate UpdateFunc", "reason", "Pod labels changed", "namespace", e.ObjectNew.GetNamespace(), "name", e.ObjectNew.GetName())
				return true
			}
		}

		return false
	},
	DeleteFunc: func(e event.DeleteEvent) bool {
		// Always when deleting a pod, we need to reconcile it
		if isTentativelyEligible(e.Object) {
			log.Log.V(2).Info("PodPredicate DeleteFunc", "namespace", e.Object.GetNamespace(), "name", e.Object.GetName())
			return true
		}

		return false
	},
	GenericFunc: func(_ event.GenericEvent) bool {
		return false
	},
}

// isEligible checks if the object is eligible for reconciliation
func isEligible(obj client.Object) bool {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return false
	}

	if pod.Status.Phase != corev1.PodRunning {
		return false
	}

	return isPodTentativelyEligible(pod)
}

// isTentativelyEligible checks if the object is tentatively eligible for reconciliation
func isTentativelyEligible(obj client.Object) bool {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return false
	}

	return isPodTentativelyEligible(pod)
}

// isPodTentativelyEligible checks if a pod is tentatively eligible for reconciliation
// Pod status phase check is missing to be fully eligible.
func isPodTentativelyEligible(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}

	if pod.Spec.HostNetwork {
		return false
	}

	if pod.GetAnnotations() == nil {
		return false
	}

	networks, err := netdefutils.ParsePodNetworkAnnotation(pod)
	if err != nil {
		return false
	}

	if len(networks) == 0 {
		return false
	}

	return true
}
