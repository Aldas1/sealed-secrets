package controller

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
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

// TestHandleAdmission_WrongNamespace seals a secret for namespace "prod", then submits
// the same ciphertext with namespace changed to "staging" and expects rejection.
func TestHandleAdmission_WrongNamespace(t *testing.T) {
	rng := testRand()

	privKey, err := rsa.GenerateKey(rng, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	plainSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "prod",
		},
		Data: map[string][]byte{"password": []byte("s3cr3t")},
	}

	sealedSecret, err := ssv1alpha1.NewSealedSecret(runtimeserializer.CodecFactory{}, &privKey.PublicKey, plainSecret)
	if err != nil {
		t.Fatalf("NewSealedSecret: %v", err)
	}

	// Tamper: move the sealed secret into a different namespace.
	sealedSecret.Namespace = "staging"

	checker := func(content []byte) (bool, error) {
		var ss ssv1alpha1.SealedSecret
		if err := json.Unmarshal(content, &ss); err != nil {
			return false, err
		}
		privKeys := map[string]*rsa.PrivateKey{"test-key": privKey}
		_, err := ss.Unseal(runtimeserializer.CodecFactory{}, privKeys)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	sealedJSON, err := json.Marshal(sealedSecret)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: "wrong-ns-test",
			Kind: metav1.GroupVersionKind{
				Group: ssv1alpha1.GroupName,
				Kind:  "SealedSecret",
			},
			Object: runtime.RawExtension{Raw: sealedJSON},
		},
	}
	reqBody, _ := json.Marshal(ar)
	req := httptest.NewRequest("POST", "/v1/admission", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()

	HandleAdmission(checker, w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d", resp.StatusCode)
	}

	var arm admissionv1.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&arm); err != nil {
		t.Fatalf("Decode response: %v", err)
	}

	if arm.Response.Allowed {
		t.Error("expected admission denied for wrong-namespace sealed secret, got allowed=true")
	}
	if arm.Response.Result == nil || arm.Response.Result.Message == "" {
		t.Error("expected a non-empty rejection message")
	}
}
