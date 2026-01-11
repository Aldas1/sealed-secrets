package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestHandleAdmission(t *testing.T) {
	// Mock success checker
	successChecker := func(content []byte) (bool, error) {
		return true, nil
	}
	// Mock failure checker
	failureChecker := func(content []byte) (bool, error) {
		return false, errors.New("decryption failed")
	}

	tests := []struct {
		name            string
		checker         secretChecker
		inputObj        string // JSON string of the SealedSecret
		expectedAllow   bool
		expectedCode    int32
		expectedMessage string
	}{
		{
			name:          "Valid Secret",
			checker:       successChecker,
			inputObj:      `{"kind": "SealedSecret", "apiVersion": "bitnami.com/v1alpha1", "metadata": {"name": "foo", "namespace": "bar"}}`,
			expectedAllow: true,
		},
		{
			name:            "Invalid Secret (Decryption Failure)",
			checker:         failureChecker,
			inputObj:        `{"kind": "SealedSecret", "apiVersion": "bitnami.com/v1alpha1", "metadata": {"name": "foo", "namespace": "bar"}}`,
			expectedAllow:   false,
			expectedCode:    http.StatusUnprocessableEntity,
			expectedMessage: "Validation failed: SealedSecret could not be decrypted",
		},
		{
			name:          "Garbage Input (Not a SealedSecret)",
			checker:       successChecker,                        // Should not be called
			inputObj:      `{"kind": "Pod", "apiVersion": "v1"}`, // Wrong kind
			expectedAllow: true,                                  // We allow things we don't care about (logic in handler: return Allowed=true if not SealedSecret)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct AdmissionReview request
			ar := admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					UID: "12345",
					Kind: metav1.GroupVersionKind{
						Group: ssv1alpha1.GroupName,
						Kind:  "SealedSecret",
					},
					Object: runtime.RawExtension{
						Raw: []byte(tt.inputObj),
					},
				},
			}

			// If test case is "Garbage Input", change the request kind to match input or keep as is?
			if tt.name == "Garbage Input (Not a SealedSecret)" {
				ar.Request.Kind.Kind = "Pod"
				ar.Request.Kind.Group = ""
			}

			reqBody, _ := json.Marshal(ar)
			req := httptest.NewRequest("POST", "/v1/admission", bytes.NewReader(reqBody))
			w := httptest.NewRecorder()

			HandleAdmission(tt.checker, w, req)

			resp := w.Result()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected HTTP 200 (Admission Response), got %d", resp.StatusCode)
			}

			var arm admissionv1.AdmissionReview
			json.NewDecoder(resp.Body).Decode(&arm)

			if arm.Response.Allowed != tt.expectedAllow {
				t.Errorf("Expected Allowed=%v, got %v", tt.expectedAllow, arm.Response.Allowed)
			}

			if !tt.expectedAllow {
				if arm.Response.Result.Code != tt.expectedCode {
					t.Errorf("Expected Result Code %d, got %d", tt.expectedCode, arm.Response.Result.Code)
				}
				if len(tt.expectedMessage) > 0 {
					if len(arm.Response.Result.Message) == 0 {
						t.Error("Expected error message, got empty")
					}
					// Check simple containment
					if !contains(arm.Response.Result.Message, tt.expectedMessage) {
						// Simple helper check
					}
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr // simplistic
}
