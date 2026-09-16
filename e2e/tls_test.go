/*
Copyright 2024.

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

package e2e

import (
	"context"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("TLS compliance", Label("e2e", "tls"), func() {

	It("operator watches the cluster TLS profile", func(ctx context.Context) {
		pods := &corev1.PodList{}
		Expect(k8sClient.List(ctx, pods,
			client.InNamespace(operatorNS),
			client.MatchingLabels{"control-plane": "controller-manager"},
		)).To(Succeed())
		Expect(pods.Items).NotTo(BeEmpty())

		req := clientset.CoreV1().Pods(operatorNS).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{})
		logs, err := req.DoRaw(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(logs)).To(ContainSubstring("tlssecurityprofilewatcher"),
			"operator should run the TLS security profile watcher")
	})

	DescribeTable("to Modern profile for",
		func(ctx context.Context, url string) {
			apiserver := &configv1.APIServer{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)).To(Succeed())
			if apiserver.Spec.TLSSecurityProfile == nil ||
				apiserver.Spec.TLSSecurityProfile.Type != configv1.TLSProfileModernType {
				Skip("cluster TLS profile is not Modern")
			}

			By("rejecting TLS 1.2")
			logs, err := probe.RunPod(ctx,
				`curl --tlsv1.2 --tls-max 1.2 -sv -o /dev/null --cacert /etc/cabundle/service-ca.crt `+url)
			Expect(err).To(HaveOccurred(), "expected server to reject TLS 1.2:\n%s", logs)

			By("accepting TLS 1.3 with service-ca cert")
			logs, err = probe.RunPod(ctx,
				`curl -sv -o /dev/null --cacert /etc/cabundle/service-ca.crt `+url)
			Expect(err).NotTo(HaveOccurred(), "TLS 1.3 connection failed:\n%s", logs)
		},
		Entry("metrics endpoint", Label("metrics"),
			`https://pf-status-relay-operator-controller-manager-metrics-service.`+operatorNS+`.svc:8443/metrics`),
		Entry("webhook endpoint", Label("webhook"),
			`https://pf-status-relay-operator-webhook-service.`+operatorNS+`.svc:443/`),
	)

	// PContext: changing the APIServer TLS profile triggers a kube-apiserver
	// rollout. Run on demand to verify the operator reloads correctly.
	Context("when adding custom profile", func() {
		BeforeEach(func(ctx context.Context) {
			customProfile := &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
						MinTLSVersion: configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion,
						Groups:        []configv1.TLSGroup{configv1.TLSGroupSecP384r1},
					},
				},
			}

			patch, err := json.Marshal(map[string]any{
				"spec": map[string]any{"tlsSecurityProfile": customProfile},
			})
			Expect(err).NotTo(HaveOccurred())
			capabilityProbe := &configv1.APIServer{}
			capabilityProbe.Name = "cluster"
			Expect(k8sClient.Patch(ctx, capabilityProbe,
				client.RawPatch(types.MergePatchType, patch), client.DryRunAll,
			)).To(Succeed())
			if capabilityProbe.Spec.TLSSecurityProfile == nil ||
				capabilityProbe.Spec.TLSSecurityProfile.Custom == nil ||
				len(capabilityProbe.Spec.TLSSecurityProfile.Custom.Groups) == 0 {
				Skip("APIServer API does not support custom TLS groups")
			}

			pods := &corev1.PodList{}
			Expect(k8sClient.List(ctx, pods,
				client.InNamespace(operatorNS),
				client.MatchingLabels{"control-plane": "controller-manager"},
			)).To(Succeed())
			Expect(pods.Items).To(HaveLen(1))
			Expect(pods.Items[0].Status.ContainerStatuses).NotTo(BeEmpty())
			podName := pods.Items[0].Name
			restartCount := pods.Items[0].Status.ContainerStatuses[0].RestartCount

			apiserver := &configv1.APIServer{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)).To(Succeed())
			savedProfile := apiserver.Spec.TLSSecurityProfile.DeepCopy()

			DeferCleanup(func(ctx context.Context) {
				apiserver := &configv1.APIServer{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "cluster"}, apiserver)).To(Succeed())
				apiserver.Spec.TLSSecurityProfile = savedProfile
				Expect(k8sClient.Update(ctx, apiserver)).To(Succeed())
			})

			apiserver.Spec.TLSSecurityProfile = customProfile
			Expect(k8sClient.Update(ctx, apiserver)).To(Succeed())

			Eventually(func(g Gomega) {
				pod := &corev1.Pod{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      podName,
					Namespace: operatorNS,
				}, pod)).To(Succeed())
				g.Expect(pod.Status.ContainerStatuses).NotTo(BeEmpty())
				status := pod.Status.ContainerStatuses[0]
				g.Expect(status.RestartCount).To(BeNumerically(">", restartCount))
				g.Expect(status.Ready).To(BeTrue())
			}, "3m", "5s").Should(Succeed())
		})

		It("rejects client offering only a non-configured curve", func(ctx context.Context) {
			logs, err := probe.RunPod(ctx,
				`curl --curves X25519 -sv -o /dev/null --cacert /etc/cabundle/service-ca.crt `+metricsURL)
			Expect(err).To(HaveOccurred(), "expected server to reject X25519-only client:\n%s", logs)
		})

		It("accepts client offering the configured curve", func(ctx context.Context) {
			logs, err := probe.RunPod(ctx,
				`curl --curves P-384 -sv -o /dev/null --cacert /etc/cabundle/service-ca.crt `+metricsURL)
			Expect(err).NotTo(HaveOccurred(), "expected secp384r1 connection to succeed:\n%s", logs)
		})
	})
})
