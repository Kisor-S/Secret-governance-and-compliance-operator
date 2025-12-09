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

package v1alpha1

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	compliancev1alpha1 "github.com/Kisor-S/secret-policy-operator/api/v1alpha1"
	internalpolicy "github.com/Kisor-S/secret-policy-operator/internal/policy"
	corev1 "k8s.io/api/core/v1"
)

// nolint:unused
// log is for logging in this package.
var secretpolicylog = logf.Log.WithName("secretpolicy-resource")

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-compliance-security-local-v1alpha1-secretpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=compliance.security.local,resources=secretpolicies,verbs=create;update,versions=v1alpha1,name=vsecretpolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// SecretPolicyCustomValidator struct is responsible for validating the SecretPolicy resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.

// -----------------------------------------------------------------------------
// SecretPolicyValidator – validates CRD objects (SecretPolicy)
// -----------------------------------------------------------------------------

type SecretPolicyValidator struct {
	Client client.Client
}

func (v *SecretPolicyValidator) InjectClient(c client.Client) error {
	v.Client = c
	return nil
}

var _ webhook.CustomValidator = &SecretPolicyValidator{}

// SetupSecretPolicyWebhookWithManager registers the webhook for SecretPolicy in the manager.
func SetupSecretPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&compliancev1alpha1.SecretPolicy{}).
		WithValidator(&SecretPolicyValidator{}).
		Complete()
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type SecretPolicy.
func (v *SecretPolicyValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	secretpolicy, ok := obj.(*compliancev1alpha1.SecretPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a SecretPolicy object but got %T", obj)
	}
	secretpolicylog.Info("Validation for SecretPolicy upon creation", "name", secretpolicy.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type SecretPolicy.
func (v *SecretPolicyValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	secretpolicy, ok := newObj.(*compliancev1alpha1.SecretPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a SecretPolicy object for the newObj but got %T", newObj)
	}
	secretpolicylog.Info("Validation for SecretPolicy upon update", "name", secretpolicy.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type SecretPolicy.
func (v *SecretPolicyValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	secretpolicy, ok := obj.(*compliancev1alpha1.SecretPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a SecretPolicy object but got %T", obj)
	}
	secretpolicylog.Info("Validation for SecretPolicy upon deletion", "name", secretpolicy.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}

// -----------------------------------------------------------------------------
// SecretValidator – admission webhook for corev1.Secrets
// -----------------------------------------------------------------------------

// +kubebuilder:webhook:path=/validate-v1-secret,mutating=false,failurePolicy=fail,sideEffects=None,groups="",resources=secrets,verbs=create;update,versions=v1,name=secret.validator.kishore.dev,admissionReviewVersions=v1

type SecretValidator struct {
	Client  client.Client
	Decoder admission.Decoder
}

var _ admission.Handler = &SecretValidator{}

// var _ admission.DecoderInjector = &SecretValidator{}
// var _ client.Injector = &SecretValidator{}

// Note: compile-time assertions for admission.DecoderInjector and client.Injector
// were removed because the controller-runtime version in use does not
// export those exact interface names. These assertions are optional
// static checks — the webhook still works at runtime as long as the
// InjectClient/InjectDecoder methods are present on the type.

func (v *SecretValidator) InjectClient(c client.Client) error {
	v.Client = c
	return nil
}

func (v *SecretValidator) InjectDecoder(decoder admission.Decoder) error {
	v.Decoder = decoder
	return nil
}

// Register webhook with the manager
// func (v *SecretValidator) SetupWebhookWithManager(mgr ctrl.Manager) {
// 	mgr.GetWebhookServer().Register("/validate-v1-secret", &admission.Webhook{Handler: v})
// }

func SetupSecretWebhookWithManager(mgr ctrl.Manager) error {
	validator := &SecretValidator{}
	// Inject client
	if err := validator.InjectClient(mgr.GetClient()); err != nil {
		return fmt.Errorf("failed to inject client: %w", err)
	}

	// Create and inject decoder
	dec := admission.NewDecoder(mgr.GetScheme())
	if err := validator.InjectDecoder(dec); err != nil {
		return fmt.Errorf("failed to inject decoder: %w", err)
	}

	mgr.GetWebhookServer().Register("/validate-v1-secret",
		&admission.Webhook{Handler: validator})
	return nil
}

func (v *SecretValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	secret := &corev1.Secret{}
	if err := v.Decoder.Decode(req, secret); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Skip system namespaces + empty
	if secret.Namespace == "" ||
		secret.Namespace == "kube-system" ||
		secret.Namespace == "cert-manager" ||
		secret.Namespace == "secret-policy-operator-system" {

		return admission.Allowed("skipping validation for system namespace")
	}

	// List policies
	var policies compliancev1alpha1.SecretPolicyList
	if err := v.Client.List(ctx, &policies); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	var violations []string
	for i := range policies.Items {
		p := &policies.Items[i]
		errs := internalpolicy.CheckSecretAgainstPolicy(secret, p)
		for _, e := range errs {
			violations = append(violations, e.Error())
		}
	}

	if len(violations) > 0 {
		return admission.Denied(
			"Secret violates policy:\n - " + strings.Join(violations, "\n - "),
		)
	}

	return admission.Allowed("valid secret")
}
