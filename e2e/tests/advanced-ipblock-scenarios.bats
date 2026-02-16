#!/usr/bin/env bats

# Note:
# These test cases verify advanced IP block scenarios including except blocks,
# complex CIDR combinations, and edge cases with IP ranges.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-advanced-ipblock" "pod-server")
	client_a_net1=$(get_net1_ip "test-advanced-ipblock" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-advanced-ipblock" "pod-client-b")
	client_c_net1=$(get_net1_ip "test-advanced-ipblock" "pod-client-c")
	client_d_net1=$(get_net1_ip "test-advanced-ipblock" "pod-client-d")
}

@test "setup advanced ipblock test environments" {
	# create test manifests
	kubectl create -f advanced-ipblock-scenarios.yml

	# verify all pods are available
	run kubectl -n test-advanced-ipblock wait --for=condition=ready -l app=test-advanced-ipblock pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 5
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

	run has_nftables_table "test-advanced-ipblock" "pod-server"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-advanced-ipblock" "pod-client-a"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-advanced-ipblock" "pod-client-b"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-advanced-ipblock" "pod-client-c"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-advanced-ipblock" "pod-client-d"
	[ "$status" -eq  "1" ]
}

@test "advanced-ipblock check client-a (2.2.8.11) -> server" {
	# Should succeed - client-a is in allowed subnet
	run kubectl -n test-advanced-ipblock exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "advanced-ipblock check client-b (2.2.8.12) -> server" {
	# Should succeed - client-b is in allowed subnet
	run kubectl -n test-advanced-ipblock exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "advanced-ipblock check client-c (2.2.8.13) -> server" {
	# Should fail - client-c is in excepted range
	run kubectl -n test-advanced-ipblock exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "advanced-ipblock check client-d (2.2.8.20) -> server" {
	# Should succeed - client-d is in allowed subnet but not in excepted range
	run kubectl -n test-advanced-ipblock exec pod-client-d -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "advanced-ipblock check server -> client-a egress" {
	# Should succeed - egress to allowed subnet
	run kubectl -n test-advanced-ipblock exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "advanced-ipblock check server -> client-c egress" {
	# Should fail - egress to excepted range
	run kubectl -n test-advanced-ipblock exec pod-server -- sh -c "echo x | nc -w 1 ${client_c_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f advanced-ipblock-scenarios.yml
	run kubectl -n test-advanced-ipblock wait --for=delete -l app=test-advanced-ipblock pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
