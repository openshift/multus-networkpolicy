# NFTables Implementation

## Overview

This document details how Kubernetes `MultiNetworkPolicy` resources are translated into NFTables rules and applied within pod network namespaces.

## NFTables Structure

### Table and Chain Hierarchy

```
Table: multi_networkpolicy (inet family)
├── Chain: input (netfilter hook, filter priority)
├── Chain: output (netfilter hook, filter priority)  
├── Chain: ingress (regular chain)
│   ├── Connection tracking rule
│   ├── Jump to common-ingress
│   ├── Jump to policy chains (cnp-<hash>)
│   └── Drop rule
├── Chain: egress (regular chain)
│   ├── Connection tracking rule
│   ├── Jump to common-egress
│   ├── Jump to policy chains (cnp-<hash>)
│   └── Drop rule
├── Chain: common-ingress (shared rules)
│   ├── Optional: Accept ICMP
│   ├── Optional: Accept ICMPv6
│   └── Custom ingress rules (IPv4/IPv6)
├── Chain: common-egress (shared rules)
│   ├── Optional: Accept ICMP
│   ├── Optional: Accept ICMPv6
│   └── Custom egress rules (IPv4/IPv6)
└── Policy-specific chains (cnp-<hash>)
    ├── Reverse rules (hairpinning support)
    ├── Source/destination filtering
    ├── Port/protocol rules
    └── Accept rules
```

### Naming Conventions

- **Table**: `multi_networkpolicy`
- **Policy chains**: `cnp-<16-char-hash>` (where hash = SHA256(policy.namespace/policy.name)[:16])
- **Interface sets**: `smi-<16-char-hash>` (managed interfaces for policy)
- **IP sets**: `snp-<16-char-hash>_<direction>_<family>_<interface>_<index>`
  - Direction: `ingress` or `egress`
  - Family: `ipv4` or `ipv6`
  - Interface: interface name (e.g., `eth1`)
  - Index: rule index number

## Rule Generation Process

### 1. Basic Structure Creation

When the first policy is applied to a pod, the basic NFTables structure is created:

```nftables
# Create table
table inet multi_networkpolicy {
    # Input dispatcher chain
    chain input {
        type filter hook input priority filter; policy accept;
        comment "Input Dispatcher"
    }
    
    # Output dispatcher chain  
    chain output {
        type filter hook output priority filter; policy accept;
        comment "Output Dispatcher"
    }
    
    # Ingress policy chain
    chain ingress {
        comment "Ingress Policies"
        ct state established,related accept comment "Connection tracking"
        jump common-ingress comment "Jump to common"
        drop comment "Drop rule"
    }
    
    # Egress policy chain
    chain egress {
        comment "Egress Policies" 
        ct state established,related accept comment "Connection tracking"
        jump common-egress comment "Jump to common"
        drop comment "Drop rule"
    }
    
    # Common ingress chain
    chain common-ingress {
        comment "Common Policies"
        # Optional: ICMP rules
        meta l4proto icmp accept comment "Accept ICMP"
        meta l4proto icmpv6 accept comment "Accept ICMPv6"
        # Custom ingress rules from ConfigMaps
        tcp dport 9999 accept comment "Custom Rule"
        ip saddr 192.168.100.0/24 accept comment "Custom Rule"
    }
    
    # Common egress chain
    chain common-egress {
        comment "Common Policies"
        # Optional: ICMP rules
        meta l4proto icmp accept comment "Accept ICMP"
        meta l4proto icmpv6 accept comment "Accept ICMPv6"
        # Custom egress rules from ConfigMaps
        tcp dport 9999 accept comment "Custom Rule"
        ip saddr 192.168.100.0/24 accept comment "Custom Rule"
    }
}
```

### 2. Common Rules Configuration

Common rules are applied to all policies through the `common-ingress` and `common-egress` chains. These are configured via the controller's command-line flags:

- **ICMP Support**: Enable/disable ICMP and ICMPv6 traffic globally
  - `--accept-icmp`: Accept ICMP (IPv4) traffic
  - `--accept-icmpv6`: Accept ICMPv6 (IPv6) traffic

- **Custom Rules**: Load custom nftables rules from files
  - `--custom-v4-ingress-rule-file`: Custom IPv4 ingress rules
  - `--custom-v4-egress-rule-file`: Custom IPv4 egress rules
  - `--custom-v6-ingress-rule-file`: Custom IPv6 ingress rules
  - `--custom-v6-egress-rule-file`: Custom IPv6 egress rules

Custom rules are typically provided via ConfigMaps mounted into the controller pod. These rules allow cluster administrators to define global network policies without modifying individual MultiNetworkPolicy resources.

Example custom rules:
```nftables
# Allow traffic on specific port
tcp dport 9999 accept

# Allow traffic from specific IP range
ip saddr 192.168.100.0/24 accept
ip6 saddr 2001:db8:100::/64 accept

# Drop traffic from specific sources
ip saddr 10.0.0.0/8 drop
```

### 3. Interface Set Creation

For each policy, a set of managed interfaces is created:

```nftables
# Managed interfaces set for policy
set smi-365f0b66bf7ef65c {
    type ifname
    comment "Managed interfaces set for default/web-policy"
    elements = { "net1", "net2" }
}
```

### 4. Policy Chain Creation

Each policy gets its own chain:

```nftables
chain cnp-365f0b66bf7ef65c {
    comment "MultiNetworkPolicy default/web-policy"
    
    # Reverse rules for hairpinning (added first)
    iifname net1 ip saddr 10.244.1.5 accept
    iifname net2 ip saddr 10.244.1.6 accept
    
    # Policy-specific rules follow...
}
```

### 5. Dispatcher Rules

Rules in the input/output chains dispatch traffic to appropriate policy type chains:

```nftables
# In input chain - for ingress traffic
iifname @smi-365f0b66bf7ef65c jump ingress comment "Policy default/web-policy"

# In output chain - for egress traffic  
oifname @smi-365f0b66bf7ef65c jump egress comment "Policy default/web-policy"
```

### 6. Ingress Chain Flow

The ingress chain contains jumps to policy-specific chains:

```nftables
# In ingress chain
jump cnp-365f0b66bf7ef65c comment "default/web-policy"
```

### 7. Reverse Rules (Hairpinning Support)

Reverse rules are automatically generated at the beginning of each policy chain to support pod-to-pod communication within the same host (hairpinning). These rules allow traffic from the pod's own IP addresses to return:

```nftables
# In cnp-365f0b66bf7ef65c chain - reverse rules for each interface
iifname net1 ip saddr 10.244.1.5 accept
iifname net1 ip6 saddr 2001:db8::5 accept
iifname net2 ip saddr 10.244.1.6 accept
iifname net2 ip6 saddr 2001:db8::6 accept
```

These rules are crucial for allowing pods to communicate with themselves or other pods on the same node through secondary network interfaces.

### 8. Policy-Specific Rules

Following the reverse rules, the policy chain contains the actual filtering logic:

```nftables
# In cnp-365f0b66bf7ef65c chain - the actual policy rules
iifname "net1" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_net1_0 tcp dport { 8080 } accept
iifname "net1" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_cidr_0 tcp dport { 8080 } accept
iifname "net2" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_net1_0 tcp dport { 8080 } accept
iifname "net2" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_cidr_0 tcp dport { 8080 } accept
```

## Rule Types

### 1. Allow All Rules

When no `from`/`to` or `ports` are specified:

```nftables
iifname "net1" accept
```

### 2. Port-Only Rules

When only `ports` are specified:

```nftables
iifname "net1" tcp dport { 8080, 8443 } accept
iifname "net1" udp dport { 53 } accept
```

### 3. IP Block Rules

For CIDR-based rules with sets:

```nftables
# Create CIDR set
set snp-365f0b66bf7ef65c_ingress_ipv4_cidr_0 {
    type ipv4_addr
    flags interval
    comment "CIDRs for default/web-policy"
    elements = { 10.0.0.0/8, 192.168.0.0/16 }
}

# Use set in rule
iifname "net1" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_cidr_0 tcp dport { 8080 } accept
```

### 4. Pod Selector Rules

For pod-based rules:

```nftables
# Create pod IP set
set snp-365f0b66bf7ef65c_ingress_ipv4_net1_0 {
    type ipv4_addr  
    comment "Addresses for default/web-policy"
    elements = { 10.244.1.5, 10.244.1.8 }
}

# Use set in rule
iifname "net1" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_net1_0 tcp dport { 8080 } accept
```

### 5. Namespace Selector Rules

Similar to pod selector, but IPs are gathered from all pods in matching namespaces:

```nftables
set snp-365f0b66bf7ef65c_ingress_ipv4_net1_0 {
    type ipv4_addr
    comment "Addresses for default/web-policy"
    elements = { 10.244.2.10, 10.244.2.15, 10.244.2.20 }
}
```

## Complete Example

Given this `MultiNetworkPolicy`:

```yaml
apiVersion: k8s.cni.cncf.io/v1beta1
kind: MultiNetworkPolicy
metadata:
  name: web-policy
  namespace: default
  annotations:
    k8s.v1.cni.cncf.io/policy-for: "macvlan-net1,macvlan-net2"
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

And assuming the web pod has these interfaces:
- `net1` with IP `10.244.1.5`
- `net2` with IP `10.244.1.6`

The generated NFTables rules would be:

```nftables
table inet multi_networkpolicy {
    # Managed interfaces set
    set smi-365f0b66bf7ef65c {
        type ifname
        comment "Managed interfaces set for default/web-policy"
        elements = { "net1", "net2" }
    }
    
    # Pod selector IPs
    set snp-365f0b66bf7ef65c_ingress_ipv4_net1_0 {
        type ipv4_addr
        comment "Addresses for default/web-policy"
        elements = { 10.244.1.5, 10.244.1.8 }
    }
    
    # IP block CIDRs (with exceptions)
    set snp-365f0b66bf7ef65c_ingress_ipv4_cidr_0 {
        type ipv4_addr
        flags interval
        comment "CIDRs for default/web-policy"
        elements = { 10.0.0.0/24, 10.0.2.0/23, 10.0.4.0/22, ... }
    }
    
    # Namespace selector IPs  
    set snp-365f0b66bf7ef65c_egress_ipv4_net1_0 {
        type ipv4_addr
        comment "Addresses for default/web-policy"
        elements = { 10.244.3.10, 10.244.3.15 }
    }
    
    # Basic chains
    chain input {
        type filter hook input priority filter; policy accept;
        comment "Input Dispatcher"
        iifname @smi-365f0b66bf7ef65c jump ingress comment "default/web-policy"
    }
    
    chain output {
        type filter hook output priority filter; policy accept;
        comment "Output Dispatcher"
        oifname @smi-365f0b66bf7ef65c jump egress comment "default/web-policy"
    }
    
    chain ingress {
        comment "Ingress Policies"
        ct state established,related accept comment "Connection tracking"
        jump common-ingress comment "Jump to common"
        jump cnp-365f0b66bf7ef65c comment "default/web-policy"
        drop comment "Drop rule"
    }
    
    chain egress {
        comment "Egress Policies"
        ct state established,related accept comment "Connection tracking"
        jump common-egress comment "Jump to common"
        jump cnp-365f0b66bf7ef65c comment "default/web-policy"
        drop comment "Drop rule"
    }
    
    chain common-ingress {
        comment "Common Policies"
        meta l4proto icmp accept comment "Accept ICMP"
        meta l4proto icmpv6 accept comment "Accept ICMPv6"
        tcp dport 9999 accept comment "Custom Rule"
        ip saddr 192.168.100.0/24 accept comment "Custom Rule"
    }
    
    chain common-egress {
        comment "Common Policies"
        meta l4proto icmp accept comment "Accept ICMP"
        meta l4proto icmpv6 accept comment "Accept ICMPv6"
        tcp dport 9999 accept comment "Custom Rule"
        ip saddr 192.168.100.0/24 accept comment "Custom Rule"
    }
    
    # Policy-specific chain
    chain cnp-365f0b66bf7ef65c {
        comment "MultiNetworkPolicy default/web-policy"
        
        # Reverse rules for hairpinning (always first)
        iifname net1 ip saddr 10.244.1.5 accept
        iifname net2 ip saddr 10.244.1.6 accept
        
        # Ingress rules (for each interface)
        iifname "net1" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_net1_0 tcp dport { 8080 } accept
        iifname "net1" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_cidr_0 tcp dport { 8080 } accept
        iifname "net2" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_net1_0 tcp dport { 8080 } accept
        iifname "net2" ip saddr @snp-365f0b66bf7ef65c_ingress_ipv4_cidr_0 tcp dport { 8080 } accept
        
        # Egress rules (for each interface)
        oifname "net1" ip daddr @snp-365f0b66bf7ef65c_egress_ipv4_net1_0 tcp dport { 5432 } accept
        oifname "net2" ip daddr @snp-365f0b66bf7ef65c_egress_ipv4_net1_0 tcp dport { 5432 } accept
    }
}
```

## Advanced Features

### 1. Hairpinning Support

Reverse rules enable pod-to-pod communication on the same host through secondary network interfaces. Without these rules, traffic from a pod to another pod on the same host would be blocked by the policy's default drop rule.

Example scenario:
- Pod A (IP: 10.244.1.5 on net1) sends traffic to Pod B (IP: 10.244.1.6 on net1)
- Both pods are on the same Kubernetes node
- The reverse rule `iifname net1 ip saddr 10.244.1.5 accept` allows the traffic to flow

### 2. IPv6 Support

The system automatically handles IPv6 addresses and creates separate sets:

```nftables
set snp-365f0b66bf7ef65c_ingress_ipv6_net1_0 {
    type ipv6_addr
    flags interval
    elements = { 2001:db8::/32 }
}

# Reverse rule for IPv6
iifname net1 ip6 saddr 2001:db8::5 accept
```

### 3. CIDR Exception Handling

IP blocks with exceptions are processed to create precise interval sets:

```yaml
ipBlock:
  cidr: 10.0.0.0/8
  except:
  - 10.0.1.0/24
```

Becomes:
```nftables
elements = { 
    10.0.0.0/24,      # 10.0.0.0 - 10.0.0.255
    10.0.2.0/23,      # 10.0.2.0 - 10.0.3.255  
    10.0.4.0/22,      # 10.0.4.0 - 10.0.7.255
    # ... continues to cover 10.0.0.0/8 except 10.0.1.0/24
}
```

### 4. Connection Tracking

All policies include stateful connection tracking in the policy type chains (ingress/egress):

```nftables
ct state established,related accept
```

This allows return traffic for established connections without explicit rules.

### 5. Multiple Interface Support

Policies can apply to multiple network interfaces, with rules generated for each:

```nftables
# Rules duplicated for each managed interface
iifname "net1" ip saddr @source_set tcp dport { 8080 } accept
iifname "net2" ip saddr @source_set tcp dport { 8080 } accept

# Reverse rules for each interface
iifname net1 ip saddr 10.244.1.5 accept
iifname net2 ip saddr 10.244.1.6 accept
```

## Traffic Flow

### Ingress Traffic Flow

1. Packet arrives at input hook
2. Input chain checks if interface is managed (`iifname @smi-<hash>`)
3. If matched, jumps to `ingress` chain
4. Ingress chain checks connection state (established/related)
5. If new connection, jumps to `common-ingress` chain
   - ICMP/ICMPv6 rules checked
   - Custom ingress rules checked
6. Back to ingress chain, jumps to policy-specific chain (`cnp-<hash>`)
7. Policy chain checks reverse rules first (hairpinning)
8. If not matched, checks policy-specific rules
9. If no rule matches, falls through to ingress chain's drop rule

### Egress Traffic Flow

1. Packet arrives at output hook
2. Output chain checks if interface is managed (`oifname @smi-<hash>`)
3. If matched, jumps to `egress` chain
4. Egress chain checks connection state (established/related)
5. If new connection, jumps to `common-egress` chain
   - ICMP/ICMPv6 rules checked
   - Custom egress rules checked
6. Back to egress chain, jumps to policy-specific chain (`cnp-<hash>`)
7. Policy chain checks reverse rules first (hairpinning)
8. If not matched, checks policy-specific rules
9. If no rule matches, falls through to egress chain's drop rule

## Performance Optimizations

1. **Set-Based Matching**: Uses NFTables sets for O(1) IP address lookups
2. **Connection Tracking**: Reduces per-packet processing for established flows
3. **Interface Sets**: Efficient interface matching using sets
4. **Rule Consolidation**: Combines similar rules where possible
5. **Interval Sets**: Efficient CIDR range matching with interval flag
6. **Early Exit**: Reverse rules placed first for quick hairpinning decision
7. **Common Rules**: Shared rules (ICMP, custom rules) evaluated once per packet

## Cleanup Process

When policies are deleted or updated:

1. **Chain Removal**: Policy-specific chains are deleted
2. **Set Cleanup**: All associated sets are removed
3. **Rule Removal**: Dispatcher rules are removed
4. **Reference Cleanup**: All references to the policy are cleaned up
5. **Common Chains**: Preserved across policy changes, rebuilt on structure updates

The cleanup process ensures no orphaned rules or sets remain in the NFTables configuration.

## Configuration Files

Custom rules can be loaded from ConfigMaps:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: multi-networkpolicy-custom-v4-rules
  namespace: kube-system
data:
  custom-v4-rules.txt: |
    # Custom IPv4 ingress/egress rules
    tcp dport 9999 accept
    ip saddr 192.168.100.0/24 accept
```

Mount this ConfigMap to the controller pod and reference it with:
```
--custom-v4-ingress-rule-file=/path/to/custom-v4-rules.txt
```

The controller reads these files on startup and applies the rules to all pods.
