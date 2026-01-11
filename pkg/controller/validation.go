package controller

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	universalDeserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

// HandleAdmission handles Validation Webhook requests.
// It attempts to unseal the SealedSecret. If unsealing fails, it rejects the request.
func HandleAdmission(checker secretChecker, w http.ResponseWriter, r *http.Request) {
	// 1. Read byte slice from body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("Error reading admission request", "error", err)
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return
	}

	// 2. Decode AdmissionReview
	// We need to handle both v1 and v1beta1, but for simplicity let's stick to v1 (K8s 1.16+)
	// UniversalDeserializer can help if we registered the types, but manual JSON unmarshal is often safer for simple structs
	admissionReview := admissionv1.AdmissionReview{}
	if err := json.Unmarshal(body, &admissionReview); err != nil {
		slog.Error("Error unmarshalling admission request", "error", err)
		http.Error(w, "could not unmarshal request body", http.StatusBadRequest)
		return
	}

	if admissionReview.Request == nil {
		slog.Error("Admission request is nil")
		http.Error(w, "admission request is nil", http.StatusBadRequest)
		return
	}

	req := admissionReview.Request
	resp := admissionv1.AdmissionResponse{
		UID: req.UID,
	}

	// 3. Process only SealedSecrets
	// (The webhook configuration should filter this, but double checking is good)
	if req.Kind.Kind != "SealedSecret" || req.Kind.Group != ssv1alpha1.GroupName {
		resp.Allowed = true
		writeAdmissionResponse(w, &admissionReview, &resp)
		return
	}

	// 4. Decode SealedSecret object
	var sealedSecret ssv1alpha1.SealedSecret
	if err := json.Unmarshal(req.Object.Raw, &sealedSecret); err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{
			Message: fmt.Sprintf("could not unmarshal SealedSecret: %v", err),
		}
		writeAdmissionResponse(w, &admissionReview, &resp)
		return
	}

	// 5. Check if we can unseal it
	// We re-encode it to bytes because `checker` (AttemptUnseal) expects raw bytes to decode again.
	// Optimization: We could refactor AttemptUnseal to take the struct, but reusing existing interface is safer.
	content := req.Object.Raw

	// Note: Checker (AttemptUnseal) will return true/nil if unseal works, or false/err if it fails.
	ok, err := checker(content)
	if err != nil {
		slog.Info("Refusing SealedSecret admission due to decryption failure", "namespace", sealedSecret.Namespace, "name", sealedSecret.Name, "error", err)
		resp.Allowed = false
		resp.Result = &metav1.Status{
			Status:  metav1.StatusFailure,
			Reason:  metav1.StatusReasonInvalid, // "NotAcceptable" might be better but K8s expects specific reasons
			Message: fmt.Sprintf("Validation failed: SealedSecret could not be decrypted (likely wrong scope/namespace/name or invalid key): %v", err),
			Code:    http.StatusUnprocessableEntity,
		}
	} else if !ok {
		// Should not happen if err is nil, but handle strictly
		resp.Allowed = false
		resp.Result = &metav1.Status{
			Message: "Validation failed: Unknown error during decryption check",
		}
	} else {
		resp.Allowed = true
	}

	writeAdmissionResponse(w, &admissionReview, &resp)
}

func writeAdmissionResponse(w http.ResponseWriter, ar *admissionv1.AdmissionReview, resp *admissionv1.AdmissionResponse) {
	// Construct the final response
	finalReview := admissionv1.AdmissionReview{
		TypeMeta: ar.TypeMeta,
		Response: resp,
	}
	// If TypeMeta was empty (JSON unmarshal doesn't fill it), set it
	finalReview.APIVersion = "admission.k8s.io/v1"
	finalReview.Kind = "AdmissionReview"

	respBytes, err := json.Marshal(finalReview)
	if err != nil {
		slog.Error("Error marshalling admission response", "error", err)
		http.Error(w, "could not marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}
