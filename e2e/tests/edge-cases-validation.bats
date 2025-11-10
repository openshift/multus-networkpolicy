#!/usr/bin/env bats

# Note:
# These test cases verify edge cases and validation scenarios including
# empty selectors, invalid configurations, and boundary conditions.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-edge-cases" "pod-server")
	client_a_net1=$(get_net1_ip "test-edge-cases" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-edge-cases" "pod-client-b")
}

@test "setup edge cases test environments" {
	# create test manifests
	kubectl create -f edge-cases-validation.yml

	# verify all pods are available
	run kubectl -n test-edge-cases wait --for=condition=ready -l app=test-edge-cases pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 5
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

	run has_nftables_table "test-edge-cases" "pod-server"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-edge-cases" "pod-client-a"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-edge-cases" "pod-client-b"
	[ "$status" -eq  "1" ]
}

@test "edge-cases check empty pod selector -> server" {
	# Should fail - empty pod selector should block all traffic
	run kubectl -n test-edge-cases exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "edge-cases check empty namespace selector -> server" {
	# Should fail - empty namespace selector should block all traffic
	run kubectl -n test-edge-cases exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "edge-cases check server -> client-a egress" {
	# Should fail - empty egress selector should block all traffic
	run kubectl -n test-edge-cases exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "edge-cases check server -> client-b egress" {
	# Should fail - empty egress selector should block all traffic
	run kubectl -n test-edge-cases exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "edge-cases check invalid port range -> server" {
	# Should fail - invalid port range should be rejected
	run kubectl -n test-edge-cases exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 9999"
	[ "$status" -eq  "1" ]
}

@test "edge-cases check invalid protocol -> server" {
	# Should fail - invalid protocol should be rejected
	run kubectl -n test-edge-cases exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f edge-cases-validation.yml
	run kubectl -n test-edge-cases wait --for=delete -l app=test-edge-cases pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
