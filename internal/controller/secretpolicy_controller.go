/*
Copyright 2025 Kishore.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	compliancev1alpha1 "github.com/Kisor-S/secret-policy-operator/api/v1alpha1"
	internalpolicy "github.com/Kisor-S/secret-policy-operator/internal/policy"
)

// SecretPolicyReconciler reconciles a SecretPolicy object
type SecretPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

const SecretPolicyFinalizer = "finalizer.secretpolicy.compliance.security.local"

// +kubebuilder:rbac:groups=compliance.security.local,resources=secretpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=compliance.security.local,resources=secretpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=compliance.security.local,resources=secretpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SecretPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/reconcile
// func (r *SecretPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
// 	_ = logf.FromContext(ctx)

// 	// TODO(user): your logic here

// 	return ctrl.Result{}, nil
// }

// SetupWithManager sets up the controller with the Manager.
func (r *SecretPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize Kubernetes event recorder (client-go style)
	r.Recorder = mgr.GetEventRecorderFor("secretpolicy-controller")

	// Register controller with the manager
	return ctrl.NewControllerManagedBy(mgr).
		For(&compliancev1alpha1.SecretPolicy{}). // primary resource
		Watches(
			&corev1.Secret{},                   // secondary resource
			&handler.EnqueueRequestForObject{}, // enqueue Secret events
		).
		Named("secretpolicy"). // controller name
		Complete(r)            // finalize
}

// Reconcile logic that handles both SecretPolicy and Secret resources
func (r *SecretPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// First: Try to fetch SecretPolicy
	var policy compliancev1alpha1.SecretPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err == nil {
		logger.Info("Reconciling SecretPolicy", "policy", req.NamespacedName)
		return r.reconcileSecretPolicy(ctx, &policy)
	}

	// Second: Try to fetch Secret
	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err == nil {
		logger.Info("Reconciling Secret", "secret", req.NamespacedName)
		return r.reconcileSecret(ctx, &secret)
	}

	// Not a SecretPolicy or Secret — ignore
	return ctrl.Result{}, nil
}

// 1. Reconcile SecretPolicy (policy-scoped scan of ALL secrets)
func (r *SecretPolicyReconciler) reconcileSecretPolicy(ctx context.Context, policy *compliancev1alpha1.SecretPolicy) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	//  Handle deletion + finalizer
	if !policy.DeletionTimestamp.IsZero() {
		// Resource is being deleted
		if controllerutil.ContainsFinalizer(policy, SecretPolicyFinalizer) {
			logger.Info("Running finalizer: cleaning up policy side-effects")

			// Perform cleanup
			if err := r.cleanupPolicyEffects(ctx, policy); err != nil {
				return ctrl.Result{}, err
			}

			// Remove finalizer
			controllerutil.RemoveFinalizer(policy, SecretPolicyFinalizer)
			if err := r.Update(ctx, policy); err != nil {
				return ctrl.Result{}, err
			}

			logger.Info("Finalizer completed and removed")
		}
		return ctrl.Result{}, nil
	}

	//  Ensure finalizer exists (on create)
	if !controllerutil.ContainsFinalizer(policy, SecretPolicyFinalizer) {
		logger.Info("Adding finalizer to SecretPolicy")
		controllerutil.AddFinalizer(policy, SecretPolicyFinalizer)
		if err := r.Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Fetch all Secrets
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets); err != nil {
		return ctrl.Result{}, err
	}

	totalViolations := 0
	var violationSummary []compliancev1alpha1.SecretViolationStatus

	for _, s := range secrets.Items {
		errs := internalpolicy.CheckSecretAgainstPolicy(&s, policy)
		if len(errs) > 0 {
			totalViolations += len(errs)

			// Convert errors to string list
			var msgs []string
			for _, e := range errs {
				msgs = append(msgs, e.Error())
			}

			violationSummary = append(violationSummary, compliancev1alpha1.SecretViolationStatus{
				Name:       s.Name,
				Namespace:  s.Namespace,
				Violations: msgs,
			})

			// Emit Kubernetes Events
			r.emitViolationEvents(policy, &s, errs)
		}
	}

	// Update status fields
	now := metav1.Now()
	policy.Status.LastScanTime = &now
	policy.Status.EnforcedSecrets = len(secrets.Items)
	policy.Status.Violations = totalViolations
	policy.Status.SecretViolations = violationSummary

	// Update Conditions
	if totalViolations > 0 {
		policy.Status.SetCondition(metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "PolicyViolations",
			Message: fmt.Sprintf("%d violations detected", totalViolations),
		})
	} else {
		policy.Status.SetCondition(metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionTrue,
			Reason:  "PolicyClean",
			Message: "No violations found",
		})
	}

	// Persist status updates
	if err := r.Status().Update(ctx, policy); err != nil {
		logger.Error(err, "Failed to update policy status")
	}

	// Requeue after rotation interval (if enabled)
	if policy.Spec.Rotation.Enabled && policy.Spec.Rotation.IntervalDays > 0 {
		return ctrl.Result{
			RequeueAfter: time.Duration(policy.Spec.Rotation.IntervalDays) * 24 * time.Hour,
		}, nil
	}

	return ctrl.Result{}, nil
}

// 2. Reconcile Secret (evaluate single secret against all policies)
func (r *SecretPolicyReconciler) reconcileSecret(ctx context.Context, secret *corev1.Secret) (ctrl.Result, error) {

	// List all SecretPolicies
	var policies compliancev1alpha1.SecretPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return ctrl.Result{}, err
	}

	for _, p := range policies.Items {
		// errs := internalpolicy.checkSecretAgainstPolicy(secret, &p)
		errs := internalpolicy.CheckSecretAgainstPolicy(secret, &p)
		if len(errs) > 0 {
			r.emitViolationEvents(&p, secret, errs)
		}
	}

	return ctrl.Result{}, nil
}

// // 3. The Policy Evaluation Engine. This function performs ALL checks on a Secret.
// func (r *SecretPolicyReconciler) checkSecretAgainstPolicy(secret *corev1.Secret, policy *compliancev1alpha1.SecretPolicy) []error {
// 	var errs []error

// 	// 1. Allowed types
// 	if !isIn(secret.Type, policy.Spec.AllowedTypes) {
// 		errs = append(errs, fmt.Errorf("secret type %s not allowed", secret.Type))
// 	}

// 	// 2. Disallowed keys
// 	for key := range secret.Data {
// 		if contains(policy.Spec.DisallowedKeys, key) {
// 			errs = append(errs, fmt.Errorf("key %s is disallowed", key))
// 		}
// 	}

// 	// 3. Base64 enforcement
// 	if policy.Spec.Encryption.EnforceBase64 {
// 		for key, val := range secret.Data {
// 			if !isValidBase64(val) {
// 				errs = append(errs, fmt.Errorf("key %s is not valid base64", key))
// 			}
// 		}
// 	}

// 	// 4. KMS enforcement
// 	if policy.Spec.Encryption.ExternalKMS {
// 		if secret.Annotations["kms-encrypted"] != "true" {
// 			errs = append(errs, fmt.Errorf("secret is not encrypted via external KMS"))
// 		}
// 	}

// 	// 5. Namespace rules
// 	if !contains(policy.Spec.AccessRules.AllowedNamespaces, secret.Namespace) {
// 		errs = append(errs, fmt.Errorf("namespace %s is not allowed", secret.Namespace))
// 	}

// 	// 6. Rotation rules
// 	if policy.Spec.Rotation.Enabled {
// 		if isRotationExpired(secret, policy.Spec.Rotation.IntervalDays) {
// 			errs = append(errs, fmt.Errorf("secret rotation interval exceeded"))
// 		}
// 	}

// 	return errs
// }

// // Helper Functions
// func isIn(value corev1.SecretType, list []string) bool {
// 	for _, v := range list {
// 		if string(value) == v {
// 			return true
// 		}
// 	}
// 	return false
// }

// func contains(list []string, v string) bool {
// 	for _, item := range list {
// 		if item == v {
// 			return true
// 		}
// 	}
// 	return false
// }

// func isValidBase64(data []byte) bool {
// 	_, err := base64.StdEncoding.DecodeString(string(data))
// 	return err == nil
// }

// func isRotationExpired(secret *corev1.Secret, interval int) bool {
// 	last := secret.Annotations["lastRotated"]
// 	if last == "" {
// 		return true // no rotation timestamp means expired
// 	}
// 	t, err := time.Parse(time.RFC3339, last)
// 	if err != nil {
// 		return true
// 	}
// 	return time.Since(t).Hours() > float64(interval*24)
// }

func (r *SecretPolicyReconciler) cleanupPolicyEffects(ctx context.Context, policy *compliancev1alpha1.SecretPolicy) error {
	logger := log.FromContext(ctx)

	// List all Secrets
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets); err != nil {
		return err
	}

	for _, s := range secrets.Items {
		// Remove rotation tracking annotation if present
		changed := false

		if s.Annotations != nil {
			if _, exists := s.Annotations["lastRotated"]; exists {
				delete(s.Annotations, "lastRotated")
				changed = true
			}
		}

		if changed {
			logger.Info("Cleaning up secret annotation from finalizer", "secret", s.Name)
			if err := r.Update(ctx, &s); err != nil {
				return err
			}
		}
	}

	// Clear status fields
	policy.Status.EnforcedSecrets = 0
	policy.Status.Violations = 0
	policy.Status.SecretViolations = nil
	policy.Status.LastScanTime = nil
	policy.Status.MarkReady()

	if err := r.Status().Update(ctx, policy); err != nil {
		return err
	}

	// Emit final event
	r.Recorder.Eventf(
		policy,
		corev1.EventTypeNormal,
		"PolicyFinalizerComplete",
		"Cleanup completed for SecretPolicy %s", policy.Name,
	)

	return nil
}

// Violation Event Emitter
func (r *SecretPolicyReconciler) emitViolationEvents(policy *compliancev1alpha1.SecretPolicy, secret *corev1.Secret, errs []error) {
	for _, err := range errs {
		r.Recorder.Eventf(
			policy,
			corev1.EventTypeWarning,
			"SecretPolicyViolation",
			"Secret %s/%s: %s",
			secret.Namespace, secret.Name, err.Error(),
		)
	}
}
