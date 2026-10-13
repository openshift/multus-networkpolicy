#!/usr/bin/env bats

# Note:
# This test verifies that a deny-all policy can be overridden by a specific allow policy.
# The test shows that even though there's a deny-all policy, traffic succeeds due to
# the specific allow policy, demonstrating the additive nature of network policies.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-deny-all" "pod-server")
	client_a_net1=$(get_net1_ip "test-deny-all" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-deny-all" "pod-client-b")
	client_c_net1=$(get_net1_ip "test-deny-all" "pod-client-c")
}

@test "setup deny-all with specific allow test environment" {
	# create test manifests
	kubectl create -f deny-all-with-specific-allow.yml

	# verify all pods are available
	run kubectl -n test-deny-all wait --for=condition=ready -l app=test-deny-all pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	# wait for sync
	sleep 5
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

	run has_nftables_table "test-deny-all" "pod-server"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-deny-all" "pod-client-a"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-deny-all" "pod-client-b"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-deny-all" "pod-client-c"
	[ "$status" -eq  "1" ]
}

# Test deny-all policy behavior
@test "deny-all check client-a -> server on port 80 (should succeed - specific allow policy overrides deny-all)" {
	# Should succeed - specific allow policy allows client-a on port 80
	run kubectl -n test-deny-all exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "0" ]
}

@test "deny-all check client-a -> server on port 8080 (should fail - specific allow policy only allows port 80)" {
	# Should fail - specific allow policy only allows port 80
	run kubectl -n test-deny-all exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "1" ]
}

@test "deny-all check client-b -> server on port 80 (should fail - specific allow policy only allows client-a)" {
	# Should fail - specific allow policy only allows client-a
	run kubectl -n test-deny-all exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "deny-all check client-b -> server on port 8080 (should fail - specific allow policy only allows client-a)" {
	# Should fail - specific allow policy only allows client-a
	run kubectl -n test-deny-all exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "1" ]
}

@test "deny-all check client-c -> server on port 80 (should fail - specific allow policy only allows client-a)" {
	# Should fail - specific allow policy only allows client-a
	run kubectl -n test-deny-all exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "deny-all check client-c -> server on port 8080 (should fail - specific allow policy only allows client-a)" {
	# Should fail - specific allow policy only allows client-a
	run kubectl -n test-deny-all exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f deny-all-with-specific-allow.yml
	run kubectl -n test-deny-all wait --for=delete -l app=test-deny-all pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
