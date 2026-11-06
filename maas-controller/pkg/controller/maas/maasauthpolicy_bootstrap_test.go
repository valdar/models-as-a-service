package maas

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gatewayapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	maasv1alpha1 "github.com/opendatahub-io/models-as-a-service/maas-controller/api/maas/v1alpha1"
	"github.com/opendatahub-io/models-as-a-service/maas-controller/pkg/platform/tenantreconcile"
)

func TestTenantGatewayManagementAuth_ReconcilesOIDCWithoutModelPolicies(t *testing.T) {
	const defaultTenant = "models-as-a-service"
	for _, tc := range []struct {
		name, tenantName, tenantNamespace, gatewayName string
	}{
		{"default tenant", defaultTenant, defaultTenant, "maas-default-gateway"},
		{"dedicated gateway", "team-a", "ai-tenant-team-a", "team-a-gateway"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			gateway := &gatewayapiv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: tc.gatewayName, Namespace: "openshift-ingress"}}
			aitenant := &maasv1alpha1.AITenant{
				ObjectMeta: metav1.ObjectMeta{Name: tc.tenantName, Namespace: tenantreconcile.DefaultAITenantNamespace},
				Status:     maasv1alpha1.AITenantStatus{GatewayRef: maasv1alpha1.TenantGatewayRef{Name: gateway.Name, Namespace: gateway.Namespace}},
			}
			tenant := &maasv1alpha1.MaasTenantConfig{ObjectMeta: metav1.ObjectMeta{
				Name: maasv1alpha1.MaasTenantConfigInstanceName, Namespace: tc.tenantNamespace,
				Labels: map[string]string{
					tenantreconcile.LabelManagedByAITenant: "true",
					tenantreconcile.LabelTenantName:        tc.tenantName,
					tenantreconcile.LabelTenantNamespace:   tc.tenantNamespace,
				},
				Annotations: map[string]string{
					tenantreconcile.AnnotationAITenantName:      aitenant.Name,
					tenantreconcile.AnnotationAITenantNamespace: aitenant.Namespace,
				},
			}}
			cl := fake.NewClientBuilder().WithScheme(scheme).WithRESTMapper(testRESTMapper()).WithObjects(gateway, aitenant, tenant).Build()
			r := &TenantReconciler{
				Client: cl, Scheme: scheme, TenantNamespace: defaultTenant,
				GatewayName: "maas-default-gateway", GatewayNamespace: gateway.Namespace,
			}
			authR := &MaaSAuthPolicyReconciler{GatewayName: r.GatewayName, GatewayNamespace: r.GatewayNamespace}
			policy := &unstructured.Unstructured{}
			policy.SetGroupVersionKind(tenantreconcile.GVKAuthPolicy)
			policyKey := client.ObjectKey{Name: authR.gatewayAuthPolicyName(gateway.Namespace, gateway.Name), Namespace: gateway.Namespace}

			// Bootstrap before OIDC is configured, matching a fresh MaaS install.
			require.NoError(t, r.ensureGatewayManagementAuth(ctx, logr.Discard(), tenant))
			for _, step := range []struct {
				name string
				oidc *maasv1alpha1.TenantExternalOIDCConfig
			}{
				{"enable", &maasv1alpha1.TenantExternalOIDCConfig{
					IssuerURL: "https://issuer.example.com/realms/a", ClientID: "client-a", Audience: "maas-a",
					AccessTokenPurposeClaim: "token_use", AccessTokenPurpose: "access", TTL: 60,
				}},
				{"change", &maasv1alpha1.TenantExternalOIDCConfig{
					IssuerURL: "https://issuer.example.com/realms/b", ClientID: "client-b", Audience: "maas-b",
					AccessTokenPurposeClaim: "purpose", AccessTokenPurpose: "api", TTL: 120,
				}},
				{"disable", nil},
			} {
				t.Run(step.name, func(t *testing.T) {
					aitenant.Spec.OIDC = step.oidc
					require.NoError(t, cl.Update(ctx, aitenant))
					requests := r.enqueueTenantForAITenant(ctx, aitenant)
					require.Equal(t, []ctrl.Request{{NamespacedName: client.ObjectKeyFromObject(tenant)}}, requests)
					require.NoError(t, r.ensureGatewayManagementAuth(ctx, logr.Discard(), tenant))
					require.NoError(t, cl.Get(ctx, policyKey, policy))
					authentication := nestedMapRequired(t, policy, "spec", "defaults", "rules", "authentication")
					authorization := nestedMapRequired(t, policy, "spec", "defaults", "rules", "authorization")
					if step.oidc == nil {
						assert.NotContains(t, authentication, "oidc-identities")
						assert.NotContains(t, authorization, "oidc-client-bound")
						return
					}
					jwt := nestedMapRequired(t, policy, "spec", "defaults", "rules", "authentication", "oidc-identities", "jwt")
					assert.Equal(t, step.oidc.IssuerURL, jwt["issuerUrl"])
					assert.Equal(t, int64(step.oidc.TTL), jwt["ttl"])
					patterns, found, err := unstructured.NestedSlice(policy.Object, "spec", "defaults", "rules", "authorization", "oidc-client-bound", "patternMatching", "patterns")
					require.NoError(t, err)
					require.True(t, found)
					assert.Contains(t, patterns, map[string]any{"selector": "auth.identity.iss", "operator": "eq", "value": step.oidc.IssuerURL})
					assert.Contains(t, patterns, map[string]any{"selector": "auth.identity.azp", "operator": "eq", "value": step.oidc.ClientID})
					assert.Contains(t, patterns, map[string]any{"selector": "auth.identity." + step.oidc.AccessTokenPurposeClaim, "operator": "eq", "value": step.oidc.AccessTokenPurpose})
					require.Len(t, patterns, 4)
					audiencePattern, ok := patterns[2].(map[string]any)
					require.True(t, ok)
					assert.Contains(t, audiencePattern["predicate"], `"`+step.oidc.Audience+`"`)
				})
			}
		})
	}
}

func TestEnsureBaseGatewayAuthPolicy_ExistingPolicyOwnership(t *testing.T) {
	const tenantNamespace = "models-as-a-service"
	listErr := errors.New("cannot list model policies")
	for _, tc := range []struct {
		name       string
		modelNS    string
		deleting   bool
		unmanaged  bool
		listError  bool
		wantUpdate bool
	}{
		{name: "no model policies", wantUpdate: true},
		{name: "model policies in another tenant", modelNS: "other-tenant", wantUpdate: true},
		{name: "only terminating model policies", modelNS: tenantNamespace, deleting: true, wantUpdate: true},
		{name: "active model policy owns gateway", modelNS: tenantNamespace},
		{name: "management opted out", unmanaged: true},
		{name: "model policy lookup fails closed", listError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			policy := newPreexistingAuthPolicy(maasGatewayAuthPolicyName, "openshift-ingress", "", nil)
			if tc.unmanaged {
				policy.SetAnnotations(map[string]string{ManagedByODHOperator: "false"})
			}
			original := policy.DeepCopy()
			builder := fake.NewClientBuilder().WithScheme(scheme).WithRESTMapper(testRESTMapper()).WithObjects(policy)
			if tc.modelNS != "" {
				modelPolicy := newMaaSAuthPolicy("model-access", tc.modelNS, "users", maasv1alpha1.ModelRef{Name: "model", Namespace: "models"})
				if tc.deleting {
					now := metav1.Now()
					modelPolicy.DeletionTimestamp = &now
					modelPolicy.Finalizers = []string{maasAuthPolicyFinalizer}
				}
				builder.WithObjects(modelPolicy)
			}
			if tc.listError {
				builder.WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						if _, ok := list.(*maasv1alpha1.MaaSAuthPolicyList); ok {
							return listErr
						}
						return cl.List(ctx, list, opts...)
					},
				})
			}
			cl := builder.Build()
			r := &MaaSAuthPolicyReconciler{Client: cl, Scheme: scheme, TenantNamespace: tenantNamespace,
				GatewayName: "maas-default-gateway", GatewayNamespace: policy.GetNamespace()}
			err := r.ensureBaseGatewayAuthPolicy(ctx, logr.Discard(), &oidcConfig{IssuerURL: "https://issuer.example.com", ClientID: "client", TTL: 60},
				false, tenantNamespace, "", r.GatewayNamespace, r.GatewayName)
			if tc.listError {
				require.ErrorIs(t, err, listErr)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, cl.Get(ctx, client.ObjectKeyFromObject(policy), policy))
			if tc.wantUpdate {
				authentication := nestedMapRequired(t, policy, "spec", "defaults", "rules", "authentication")
				assert.Contains(t, authentication, "oidc-identities")
			} else {
				assert.Equal(t, original.Object["spec"], policy.Object["spec"], "preserve existing gateway rules")
			}
		})
	}
}
