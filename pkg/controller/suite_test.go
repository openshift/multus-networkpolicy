package controller_test

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-logr/logr"
	multinetworkscheme "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned/scheme"
	netdefscheme "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/scheme"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/controller"
	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/datastore"
	"github.com/mlguerrero12/multi-network-policy-nftables/pkg/nftables"
)

var (
	cfg               *rest.Config
	k8sClient         client.Client
	testEnv           *envtest.Environment
	ctx               context.Context
	cancel            context.CancelFunc
	datastoreInstance *datastore.Datastore
	mockNFT           *MockNFT
)

// MockNFT is a mock implementation of the NFT interface for testing
type MockNFT struct {
	SyncPolicyFunc func(ctx context.Context, policy *datastore.Policy, operation nftables.SyncOperation, logger logr.Logger) error
}

func (m *MockNFT) SyncPolicy(ctx context.Context, policy *datastore.Policy, operation nftables.SyncOperation, logger logr.Logger) error {
	if m.SyncPolicyFunc != nil {
		return m.SyncPolicyFunc(ctx, policy, operation, logger)
	}
	return nil
}

func TestMultiNetworkController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	ctx, cancel = context.WithCancel(context.TODO())

	// Set up logger
	ctrl.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(GinkgoWriter)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("config", "crd")},
		ErrorIfCRDPathMissing: false,

		// The BinaryAssetsDirectory is only required if you want to run the tests directly
		// without call the makefile target test. If not informed it will look for the
		// default path defined in controller-runtime which is /usr/local/kubebuilder/.
		// Note that you must have the required binaries setup under the bin directory to perform
		// the tests directly. When we run make test it will be setup and used automatically.
		BinaryAssetsDirectory: filepath.Join("..", "..", "bin", "k8s",
			fmt.Sprintf("1.30.0-%s-%s", runtime.GOOS, runtime.GOARCH)),
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	// Add custom scheme
	Expect(multinetworkscheme.AddToScheme(scheme.Scheme)).To(Succeed())
	Expect(netdefscheme.AddToScheme(scheme.Scheme)).To(Succeed())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	datastoreInstance = &datastore.Datastore{
		Policies: make(map[types.NamespacedName]*datastore.Policy),
	}

	mockNFT = &MockNFT{
		SyncPolicyFunc: func(_ context.Context, _ *datastore.Policy, _ nftables.SyncOperation, _ logr.Logger) error {
			// Mock successful sync by default
			return nil
		},
	}

	err = (&controller.MultiNetworkReconciler{
		Client:       k8sManager.GetClient(),
		Scheme:       k8sManager.GetScheme(),
		DS:           datastoreInstance,
		NFT:          mockNFT,
		ValidPlugins: []string{"macvlan", "ipvlan"},
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
