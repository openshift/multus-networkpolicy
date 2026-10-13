#!/usr/bin/env bats

# Note:
# These test cases verify mixed selector policies combining pod selectors and namespace selectors.
# 
# Test Setup:
# - Policy 1 (AND): role=allowed-client AND environment=staging (ingress only)
# - Policy 2 (OR): role=allowed-client OR environment=staging (ingress only)  
# - Policy 3 (AND): role=allowed-client AND environment=staging (egress only)
#
# Pods:
# - client-a: role=allowed-client, production namespace (should succeed ingress via OR policy)
# - client-b: role=blocked-client, production namespace (should fail ingress)
# - client-c: role=allowed-client, staging namespace (should succeed ingress via both policies)
# - client-d: role=blocked-client, staging namespace (should succeed ingress via OR policy)
# - client-e: role=other-client, staging namespace (should succeed ingress via OR policy)
#
# Egress only allows: role=allowed-client AND environment=staging (client-c only)

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-mixed-selectors" "pod-server")
	client_a_net1=$(get_net1_ip "test-mixed-selectors" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-mixed-selectors" "pod-client-b")
	client_c_net1=$(get_net1_ip "test-mixed-selectors-blue" "pod-client-c")
	client_d_net1=$(get_net1_ip "test-mixed-selectors-blue" "pod-client-d")
	client_e_net1=$(get_net1_ip "test-mixed-selectors-blue" "pod-client-e")
}

@test "setup mixed selector test environments" {
	# create test manifests
	kubectl create -f mixed-selector-policies.yml

	# verify all pods are available
	run kubectl -n test-mixed-selectors wait --for=condition=ready -l app=test-mixed-selectors pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	run kubectl -n test-mixed-selectors-blue wait --for=condition=ready -l app=test-mixed-selectors pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 5
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

	run has_nftables_table "test-mixed-selectors" "pod-server"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-mixed-selectors" "pod-client-a"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-mixed-selectors" "pod-client-b"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-mixed-selectors-blue" "pod-client-c"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-mixed-selectors-blue" "pod-client-d"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-mixed-selectors-blue" "pod-client-e"
	[ "$status" -eq  "1" ]
}

# Test Policy 1 (AND condition): role=allowed-client AND environment=staging
@test "mixed-selectors check client-a (allowed role, production namespace) -> server" {
	# Should succeed - client-a has allowed role (OR policy allows this)
	run kubectl -n test-mixed-selectors exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "mixed-selectors check client-b (blocked role, production namespace) -> server" {
	# Should fail - client-b has blocked role and is in production namespace
	run kubectl -n test-mixed-selectors exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "mixed-selectors check client-c (allowed role, staging namespace) -> server" {
	# Should succeed - client-c has allowed role AND is in staging namespace (both policies allow this)
	run kubectl -n test-mixed-selectors-blue exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "mixed-selectors check client-d (blocked role, staging namespace) -> server" {
	# Should succeed - client-d is in staging namespace (OR policy allows this)
	run kubectl -n test-mixed-selectors-blue exec pod-client-d -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "mixed-selectors check client-e (other role, staging namespace) -> server" {
	# Should succeed - client-e is in staging namespace (OR policy allows this)
	run kubectl -n test-mixed-selectors-blue exec pod-client-e -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

# Egress tests - only AND policy applies (role=allowed-client AND environment=staging)
@test "mixed-selectors check server -> client-a egress (allowed role, production namespace)" {
	# Should fail - egress to client-a is in production namespace, not staging
	run kubectl -n test-mixed-selectors exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "mixed-selectors check server -> client-b egress (blocked role, production namespace)" {
	# Should fail - egress to client-b is in production namespace, not staging
	run kubectl -n test-mixed-selectors exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "mixed-selectors check server -> client-c egress (allowed role, staging namespace)" {
	# Should succeed - egress to client-c has correct role AND is in staging namespace
	run kubectl -n test-mixed-selectors exec pod-server -- sh -c "echo x | nc -w 1 ${client_c_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "mixed-selectors check server -> client-d egress (blocked role, staging namespace)" {
	# Should fail - egress to client-d is in staging namespace but wrong role
	run kubectl -n test-mixed-selectors exec pod-server -- sh -c "echo x | nc -w 1 ${client_d_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "mixed-selectors check server -> client-e egress (other role, staging namespace)" {
	# Should fail - egress to client-e is in staging namespace but wrong role
	run kubectl -n test-mixed-selectors exec pod-server -- sh -c "echo x | nc -w 1 ${client_e_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f mixed-selector-policies.yml
	run kubectl -n test-mixed-selectors wait --for=delete -l app=test-mixed-selectors pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
	run kubectl -n test-mixed-selectors-blue wait --for=delete -l app=test-mixed-selectors pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
