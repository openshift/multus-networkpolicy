# Multi-Network Policy for NFTables

A Kubernetes controller that enforces MultiNetworkPolicy resources using nftables on Linux nodes. This project enables fine-grained, declarative network security for pods with multiple network interfaces.

## The Problem: A Security Gap in Multi-Network Pods

Standard Kubernetes Network Policies provide essential firewall capabilities for pod-to-pod communication on the primary cluster network.

However, when you use Network Attachment Definitions (net-attach-def) to connect pods to additional, specialized networks (e.g., for telco, storage, or high-speed data), a security gap emerges. Because these attachments are Custom Resource Definitions (CRDs), the native Kubernetes Network Policy controller is unaware of them, leaving traffic on these secondary interfaces unprotected.

## The Solution: MultiNetworkPolicy

multi-networkpolicy-nftables bridges this gap. It introduces the MultiNetworkPolicy Custom Resource Definition and a controller that enforces these policies specifically for secondary networks. By leveraging the modern nftables framework on each node, it protects traffic that standard policies cannot see.

## How It Works

The controller operates as a Kubernetes DaemonSet, running an agent on every node in the cluster. This agent:

- Watches for MultiNetworkPolicy objects defined in the cluster.
- Identifies the target net-attach-def for each policy via the `k8s.v1.cni.cncf.io/policy-for` annotation.
- Generates the corresponding nftables rules based on the policy specification.
- Injects these rules directly into the target pod's network namespace, ensuring policies are isolated and do not interfere with the host or other pods.

## Key Features

- **Declarative, Namespace-Scoped Policies**: Manage security for secondary networks using the same familiar Kubernetes-style declarative model.
- **High-Performance Packet Filtering**: Utilizes the modern and efficient nftables kernel subsystem.
- **Seamless Integration**: Works with popular CNI plugins used for creating secondary networks.
- **CRD-Based**: Extends the Kubernetes API without modifying core components.

## Getting Started

### 1. Prerequisites

This controller requires the `nf_tables` kernel module to be loaded on all container hosts (nodes).

```bash
# Verify the module is loaded
lsmod | grep nf_tables

# If not loaded, load it now
sudo modprobe nf_tables
```

### 2. Install the MultiNetworkPolicy CRD

First, apply the scheme to your cluster to create the MultiNetworkPolicy resource type.

```bash
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy/master/scheme.yml
```

Expected Output:

```
customresourcedefinition.apiextensions.k8s.io/multinetworkpolicies.k8s.cni.cncf.io created
```

### 3. Deploy the Controller

Next, deploy the multi-networkpolicy-nftables DaemonSet, which will run the controller on each node.

```bash
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy-nftables/master/deploy.yaml
```

Expected Output:

```
clusterrole.rbac.authorization.k8s.io/multi-networkpolicy-nftables created
clusterrolebinding.rbac.authorization.k8s.io/multi-networkpolicy-nftables created
serviceaccount/multi-networkpolicy-nftables created
daemonset.apps/multi-networkpolicy-nftables created
```

### 4. Apply an Example Policy

Save the following YAML to a file named `web-policy.yaml`. This policy targets pods with the label `app: web` on the `macvlan-network` secondary interface.

```yaml
apiVersion: k8s.cni.cncf.io/v1beta1
kind: MultiNetworkPolicy
metadata:
  name: web-policy
  namespace: default
  annotations:
    k8s.v1.cni.cncf.io/policy-for: "macvlan-network"
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    - ipBlock:
        cidr: 10.0.0.0/8
        except:
        - 10.0.1.0/24
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
    ports:
    - protocol: TCP
      port: 5432
```

Apply it to your cluster:

```bash
kubectl apply -f web-policy.yaml
```

## Configuration

### Supported CNI Plugins

The controller validates that the target net-attach-def uses one of the following supported CNI plugins:

- `macvlan`
- `ipvlan`
- `sriov`

### Controller Flags

The controller supports the following command-line flags for customization:

- `--hostname-override`: The hostname to use for the node. If not set, it's determined automatically.
- `--network-plugins`: Comma-separated list of CNI plugins to be considered for policies (default: "macvlan").
- `--container-runtime-endpoint`: Path to the CRI socket (e.g., `/run/containerd/containerd.sock`). This is a required flag.
- `--host-prefix`: If non-empty, prefixes filesystem paths for chroot environments.
- `--accept-icmp`: If true, allows all ICMP traffic (default: false).
- `--accept-icmpv6`: If true, allows all ICMPv6 traffic (default: false).
- `--custom-v4-ingress-rule-file`: Path to a custom rule file for IPv4 ingress.
- `--custom-v4-egress-rule-file`: Path to a custom rule file for IPv4 egress.
- `--custom-v6-ingress-rule-file`: Path to a custom rule file for IPv6 ingress.
- `--custom-v6-egress-rule-file`: Path to a custom rule file for IPv6 egress.

## Documentation

For a more detailed technical design, please see the [NFTables Design Document](./docs/nftables.md).

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

## Acknowledgments

- Built on top of the excellent [knftables](https://github.com/kubernetes-sigs/knftables) library.
- Inspired by the [multi-networkpolicy-iptables](https://github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables) project.
