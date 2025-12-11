#!/usr/bin/env bats

# Note:
# This test verifies that an accept-all policy works alongside a specific allow policy.
# The test shows that traffic that doesn't match the specific allow policy still succeeds
# due to the accept-all policy, demonstrating the additive nature of network policies.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-accept-all" "pod-server")
	client_a_net1=$(get_net1_ip "test-accept-all" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-accept-all" "pod-client-b")
	client_c_net1=$(get_net1_ip "test-accept-all" "pod-client-c")
}

@test "setup accept-all with specific allow test environment" {
	# create test manifests
	kubectl create -f accept-all-with-specific-allow.yml

	# verify all pods are available
	run kubectl -n test-accept-all wait --for=condition=ready -l app=test-accept-all pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	# wait for sync
	sleep 5
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

	run has_nftables_table "test-accept-all" "pod-server"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-accept-all" "pod-client-a"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-accept-all" "pod-client-b"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-accept-all" "pod-client-c"
	[ "$status" -eq  "1" ]
}

# Test accept-all policy behavior
@test "accept-all check client-a -> server on port 80 (should succeed - specific allow policy allows)" {
	# Should succeed - specific allow policy allows client-a on port 80
	run kubectl -n test-accept-all exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "0" ]
}

@test "accept-all check client-a -> server on port 8080 (should succeed - accept-all policy allows)" {
	# Should succeed - accept-all policy allows all traffic
	run kubectl -n test-accept-all exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "0" ]
}

@test "accept-all check client-b -> server on port 80 (should succeed - accept-all policy allows)" {
	# Should succeed - accept-all policy allows all traffic
	run kubectl -n test-accept-all exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "0" ]
}

@test "accept-all check client-b -> server on port 8080 (should succeed - accept-all policy allows)" {
	# Should succeed - accept-all policy allows all traffic
	run kubectl -n test-accept-all exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "0" ]
}

@test "accept-all check client-c -> server on port 80 (should succeed - accept-all policy allows)" {
	# Should succeed - accept-all policy allows all traffic
	run kubectl -n test-accept-all exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "0" ]
}

@test "accept-all check client-c -> server on port 8080 (should succeed - accept-all policy allows)" {
	# Should succeed - accept-all policy allows all traffic
	run kubectl -n test-accept-all exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "0" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f accept-all-with-specific-allow.yml
	run kubectl -n test-accept-all wait --for=delete -l app=test-accept-all pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
