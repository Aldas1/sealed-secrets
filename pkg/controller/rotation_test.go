package controller

import (
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeSSWithRotation(schedule string, enabled bool, age time.Duration) *ssv1alpha1.SealedSecret {
	ss := &ssv1alpha1.SealedSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
	}
	if schedule != "" || enabled {
		ss.Spec.Rotation = &ssv1alpha1.SealedSecretRotationPolicySpec{
			Enabled:  enabled,
			Schedule: schedule,
		}
	}
	ss.Status = &ssv1alpha1.SealedSecretStatus{
		Conditions: []ssv1alpha1.SealedSecretCondition{
			{
				Type:               ssv1alpha1.SealedSecretSynced,
				Status:             corev1.ConditionTrue,
				LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
			},
		},
	}
	return ss
}

func TestIsRotationNeeded(t *testing.T) {
	tests := []struct {
		name     string
		ss       *ssv1alpha1.SealedSecret
		expected bool
	}{
		{
			name:     "rotation_nil",
			ss:       &ssv1alpha1.SealedSecret{},
			expected: false,
		},
		{
			name:     "rotation_disabled",
			ss:       makeSSWithRotation("@monthly", false, 31*24*time.Hour),
			expected: false,
		},
		{
			name:     "monthly_expired",
			ss:       makeSSWithRotation("@monthly", true, 31*24*time.Hour),
			expected: true,
		},
		{
			name:     "monthly_fresh",
			ss:       makeSSWithRotation("@monthly", true, 1*24*time.Hour),
			expected: false,
		},
		{
			name:     "weekly_expired",
			ss:       makeSSWithRotation("@weekly", true, 8*24*time.Hour),
			expected: true,
		},
		{
			name:     "weekly_fresh",
			ss:       makeSSWithRotation("@weekly", true, 30*time.Second),
			expected: false,
		},
		{
			name:     "daily_expired",
			ss:       makeSSWithRotation("@daily", true, 48*time.Hour),
			expected: true,
		},
		{
			name:     "daily_fresh",
			ss:       makeSSWithRotation("@daily", true, 1*time.Hour),
			expected: false,
		},
		{
			name:     "custom_cron_expired",
			ss:       makeSSWithRotation("0 0 * * *", true, 48*time.Hour),
			expected: true,
		},
		{
			name:     "custom_cron_fresh",
			ss:       makeSSWithRotation("0 0 * * *", true, 1*time.Hour),
			expected: false,
		},
		{
			name:     "unknown_schedule",
			ss:       makeSSWithRotation("not-a-cron", true, 31*24*time.Hour),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRotationNeeded(tt.ss)
			if got != tt.expected {
				t.Errorf("isRotationNeeded() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestUpdateRotationCondition(t *testing.T) {
	t.Run("creates_condition_when_absent", func(t *testing.T) {
		st := &ssv1alpha1.SealedSecretStatus{}
		changed := updateRotationCondition(st, true)
		if !changed {
			t.Error("expected changed=true on first creation")
		}
		if len(st.Conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(st.Conditions))
		}
		c := st.Conditions[0]
		if c.Type != ssv1alpha1.SealedSecretRotationNeeded {
			t.Errorf("unexpected condition type: %s", c.Type)
		}
		if c.Status != corev1.ConditionTrue {
			t.Errorf("expected ConditionTrue, got %s", c.Status)
		}
	})

	t.Run("false_to_true_transition", func(t *testing.T) {
		st := &ssv1alpha1.SealedSecretStatus{
			Conditions: []ssv1alpha1.SealedSecretCondition{
				{Type: ssv1alpha1.SealedSecretRotationNeeded, Status: corev1.ConditionFalse, Message: "Secret is fresh"},
			},
		}
		changed := updateRotationCondition(st, true)
		if !changed {
			t.Error("expected changed=true on status transition")
		}
		if st.Conditions[0].Status != corev1.ConditionTrue {
			t.Errorf("expected ConditionTrue after transition")
		}
	})

	t.Run("true_to_false_transition", func(t *testing.T) {
		st := &ssv1alpha1.SealedSecretStatus{
			Conditions: []ssv1alpha1.SealedSecretCondition{
				{Type: ssv1alpha1.SealedSecretRotationNeeded, Status: corev1.ConditionTrue, Message: "Secret is stale and should be rotated (re-encrypted)"},
			},
		}
		changed := updateRotationCondition(st, false)
		if !changed {
			t.Error("expected changed=true on status transition")
		}
		if st.Conditions[0].Status != corev1.ConditionFalse {
			t.Errorf("expected ConditionFalse after transition")
		}
	})

	t.Run("no_change_returns_false", func(t *testing.T) {
		st := &ssv1alpha1.SealedSecretStatus{
			Conditions: []ssv1alpha1.SealedSecretCondition{
				{Type: ssv1alpha1.SealedSecretRotationNeeded, Status: corev1.ConditionFalse, Message: "Secret is fresh"},
			},
		}
		changed := updateRotationCondition(st, false)
		if changed {
			t.Error("expected changed=false when state is already ConditionFalse")
		}
	})
}
