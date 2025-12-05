package policy

import (
	"encoding/base64"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"

	compliancev1alpha1 "github.com/Kisor-S/secret-policy-operator/api/v1alpha1"
)

func CheckSecretAgainstPolicy(secret *corev1.Secret, policy *compliancev1alpha1.SecretPolicy) []error {
	var errs []error

	if !isIn(secret.Type, policy.Spec.AllowedTypes) {
		errs = append(errs, fmt.Errorf("secret type %s not allowed", secret.Type))
	}

	for key := range secret.Data {
		if contains(policy.Spec.DisallowedKeys, key) {
			errs = append(errs, fmt.Errorf("key %s is disallowed", key))
		}
	}

	if policy.Spec.Encryption.EnforceBase64 {
		for key, val := range secret.Data {
			if !isValidBase64(val) {
				errs = append(errs, fmt.Errorf("key %s is not valid base64", key))
			}
		}
	}

	if policy.Spec.Encryption.ExternalKMS {
		if secret.Annotations["kms-encrypted"] != "true" {
			errs = append(errs, fmt.Errorf("secret is not encrypted via external KMS"))
		}
	}

	if !contains(policy.Spec.AccessRules.AllowedNamespaces, secret.Namespace) {
		errs = append(errs, fmt.Errorf("namespace %s is not allowed", secret.Namespace))
	}

	if policy.Spec.Rotation.Enabled {
		if isRotationExpired(secret, policy.Spec.Rotation.IntervalDays) {
			errs = append(errs, fmt.Errorf("secret rotation interval exceeded"))
		}
	}

	return errs
}

func isIn(value corev1.SecretType, list []string) bool {
	for _, v := range list {
		if string(value) == v {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func isValidBase64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

func isRotationExpired(secret *corev1.Secret, intervalDays int) bool {
	last := secret.Annotations["lastRotated"]
	if last == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, last)
	if err != nil {
		return true
	}
	return time.Since(t).Hours() > float64(intervalDays*24)
}
