package controller

import (
	"log/slog"
	"time"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// isRotationNeeded checks if the SealedSecret needs to be rotated based on its policy.
func isRotationNeeded(ssecret *ssv1alpha1.SealedSecret) bool {
	if ssecret.Spec.Rotation == nil || !ssecret.Spec.Rotation.Enabled {
		return false
	}

	// 1. Get the last time it was successfully unsealed/updated.
	lastUnsealTime := getLastUnsealTime(ssecret)
	if lastUnsealTime.IsZero() {
		// If never unsealed, or status unknown, assume it's fresh enough or not ready.
		// Fallback to creation timestamp
		lastUnsealTime = ssecret.CreationTimestamp.Time
	}

	// 2. Parse Schedule (Simplistic implementation for coursework)
	// Supports: "0 0 1 * *" (Monthly -> 30 days)
	//           "@monthly" (Monthly -> 30 days)
	//           "30d" (30 days)
	schedule := ssecret.Spec.Rotation.Schedule
	var period time.Duration

	switch schedule {
	case "0 0 1 * *", "@monthly", "monthly":
		period = 30 * 24 * time.Hour
	case "7d", "@weekly":
		period = 7 * 24 * time.Hour
	// Add more simplified cases if needed
	default:
		// Default to 30 days if unknown string, or log warning
		// For safety in this demo, we can just return false if we don't understand the schedule
		slog.Warn("Unknown rotation schedule string, ignoring", "schedule", schedule, "name", ssecret.Name)
		return false
	}

	// 3. Check if time has passed
	cutoff := lastUnsealTime.Add(period)
	if time.Now().After(cutoff) {
		slog.Info("Rotation needed", "name", ssecret.Name, "lastUnseal", lastUnsealTime, "schedule", schedule)
		return true
	}

	return false
}

func getLastUnsealTime(ssecret *ssv1alpha1.SealedSecret) time.Time {
	if ssecret.Status == nil {
		return time.Time{}
	}
	for _, cond := range ssecret.Status.Conditions {
		if cond.Type == ssv1alpha1.SealedSecretSynced && cond.Status == corev1.ConditionTrue {
			return cond.LastTransitionTime.Time
		}
	}
	return time.Time{}
}

// updateRotationCondition updates the RotationNeeded condition in the status
func updateRotationCondition(st *ssv1alpha1.SealedSecretStatus, needed bool) bool {
	var updateRequired bool
	cond := func() *ssv1alpha1.SealedSecretCondition {
		for i := range st.Conditions {
			if st.Conditions[i].Type == ssv1alpha1.SealedSecretRotationNeeded {
				return &st.Conditions[i]
			}
		}
		st.Conditions = append(st.Conditions, ssv1alpha1.SealedSecretCondition{
			Type: ssv1alpha1.SealedSecretRotationNeeded,
		})
		return &st.Conditions[len(st.Conditions)-1]
	}()

	var status corev1.ConditionStatus
	var msg string
	if needed {
		status = corev1.ConditionTrue
		msg = "Secret is stale and should be rotated (re-encrypted)"
	} else {
		status = corev1.ConditionFalse
		msg = "Secret is fresh"
	}

	// If status changed, update timestamp
	if cond.Status != status {
		cond.Status = status
		cond.Message = msg
		cond.LastTransitionTime = metav1.Now()
		cond.LastUpdateTime = metav1.Now()
		updateRequired = true
	} else if cond.Message != msg {
		// Update message if different but status same (rare case)
		cond.Message = msg
		cond.LastUpdateTime = metav1.Now()
		updateRequired = true
	}

	return updateRequired
}
