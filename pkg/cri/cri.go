package cri

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	runtimeDialTimeout = 10 * time.Second
)

type Runtime struct {
	CriEndpoint string
	HostPrefix  string

	sync.RWMutex
	RuntimeClient pb.RuntimeServiceClient
	Conn          *grpc.ClientConn
}

// New creates a new CriRuntime instance.
func New(criEndpoint, hostPrefix string) *Runtime {
	return &Runtime{
		CriEndpoint: criEndpoint,
		HostPrefix:  hostPrefix,
	}
}

// Connect connects to the CRI runtime.
func (c *Runtime) Connect(ctx context.Context) error {
	c.Lock()
	defer c.Unlock()

	return c.connect(ctx)
}

func (c *Runtime) connect(ctx context.Context) error {
	logger := log.FromContext(ctx)

	// Close the connection if it exists
	if c.Conn != nil {
		c.Conn.Close()
	}

	conn, err := c.getRuntimeClientConnection(ctx)
	if err != nil {
		return fmt.Errorf("failed to get runtime client connection: %w", err)
	}

	c.Conn = conn
	c.RuntimeClient = pb.NewRuntimeServiceClient(conn)

	logger.Info("Successfully connected to CRI runtime")
	return nil
}

// Close closes the connection to the CRI runtime.
func (c *Runtime) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

// getRuntimeClientConnection establishes a gRPC connection to the CRI Unix socket
func (c *Runtime) getRuntimeClientConnection(ctx context.Context) (*grpc.ClientConn, error) {
	target := fmt.Sprintf("unix://%s%s", c.HostPrefix, c.CriEndpoint)

	// Custom dialer for Unix sockets
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", addr)
	}

	// Set timeout for the dial
	timeout, cancel := context.WithTimeout(ctx, runtimeDialTimeout)
	defer cancel()

	trimmedTarget := strings.TrimPrefix(target, "unix://")
	if trimmedTarget == "" {
		return nil, fmt.Errorf("invalid target: %s", target)
	}

	// Dial the CRI runtime
	//nolint:staticcheck
	conn, err := grpc.DialContext(timeout, trimmedTarget, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(dialer))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CRI runtime %s: %w", target, err)
	}

	return conn, nil
}

// containerInfoJSON is the JSON structure for the container info
type containerInfoJSON struct {
	PID int `json:"pid"`
}

// GetPodNetNSPath gets the network namespace path for a pod
func (c *Runtime) GetPodNetNSPath(ctx context.Context, pod *corev1.Pod) (string, error) {
	logger := log.FromContext(ctx).WithValues("pod", pod.Name, "namespace", pod.Namespace)

	c.Lock()
	defer c.Unlock()

	// Connect if we are not connected
	if c.Conn == nil {
		err := c.connect(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to connect to CRI runtime: %w", err)
		}
	}

	// Get the container ID from the pod status
	if len(pod.Status.ContainerStatuses) == 0 {
		return "", fmt.Errorf("no container statuses found for pod %s", pod.Name)
	}

	splitContainerID := strings.Split(pod.Status.ContainerStatuses[0].ContainerID, "://")
	if len(splitContainerID) != 2 {
		return "", fmt.Errorf("invalid container ID for pod %s", pod.Name)
	}

	containerID := splitContainerID[1]
	if containerID == "" {
		return "", fmt.Errorf("empty container ID for pod %s", pod.Name)
	}

	// Send request to get container status
	req := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	resp, err := c.RuntimeClient.ContainerStatus(ctx, req)
	if err != nil {
		// Check if the error is a gRPC status error.
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.Unavailable {
			// The connection is dead. Log it and try to reconnect.
			logger.Info("CRI connection is unavailable, attempting to reconnect...")

			if reconnErr := c.connect(ctx); reconnErr != nil {
				return "", fmt.Errorf("failed to reconnect to CRI: %w", reconnErr)
			}

			// After reconnecting, retry the RPC call one more time.
			logger.Info("Reconnected. Retrying ContainerStatus call...")
			resp, err = c.RuntimeClient.ContainerStatus(ctx, req)
			if err != nil {
				return "", fmt.Errorf("failed to get container status on retry for pod %s: %w", pod.Name, err)
			}
		} else {
			// It was a different kind of error
			return "", fmt.Errorf("failed to get container status for pod %s: %w", pod.Name, err)
		}
	}

	// Get the PID from the info map
	info := resp.GetInfo()
	if info == nil {
		return "", fmt.Errorf("no info map found for container %s", containerID)
	}

	infoJSONString, ok := info["info"]
	if !ok {
		return "", fmt.Errorf("key 'info' not found in container status info map for %s", containerID)
	}

	var parsedInfo containerInfoJSON
	if err := json.Unmarshal([]byte(infoJSONString), &parsedInfo); err != nil {
		return "", fmt.Errorf("failed to unmarshal container info JSON for %s: %w", containerID, err)
	}

	if parsedInfo.PID <= 0 {
		return "", fmt.Errorf("invalid PID '%d' found for container %s", parsedInfo.PID, containerID)
	}

	netnsPath := fmt.Sprintf("%s/proc/%d/ns/net", c.HostPrefix, parsedInfo.PID)
	logger.Info("Found netns path", "netnsPath", netnsPath)
	return netnsPath, nil
}
