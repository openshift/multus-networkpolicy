#!/usr/bin/env bats

# Note:
# This test verifies that custom rules from config maps are properly applied.
# The custom rules allow traffic on port 9999 and from specific IP ranges.
# This test ensures that custom rules work alongside regular network policies.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-custom-rules" "pod-server")
	client_a_net1=$(get_net1_ip "test-custom-rules" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-custom-rules" "pod-client-b")
}

@test "setup custom rules test environment" {
	# create test manifests
	kubectl create -f custom-rules.yml

	# verify all pods are available
	run kubectl -n test-custom-rules wait --for=condition=ready -l app=test-custom-rules pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	# wait for sync
	sleep 5
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

	run has_nftables_table "test-custom-rules" "pod-server"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-custom-rules" "pod-client-a"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-custom-rules" "pod-client-b"
	[ "$status" -eq  "1" ]
}

# Test custom rules functionality
@test "custom-rules check client-a -> server on port 80 (should fail - regular policy blocks)" {
	# Should fail - regular policy only allows port 8080
	run kubectl -n test-custom-rules exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "custom-rules check client-a -> server on port 8080 (should succeed - regular policy allows)" {
	# Should succeed - regular policy allows port 8080
	run kubectl -n test-custom-rules exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "0" ]
}

@test "custom-rules check client-a -> server on port 9999 (should succeed - custom rule allows)" {
	# Should succeed - custom rule allows port 9999
	run kubectl -n test-custom-rules exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 9999"
	[ "$status" -eq  "0" ]
}

@test "custom-rules check client-b -> server on port 80 (should fail - regular policy blocks)" {
	# Should fail - regular policy only allows port 8080
	run kubectl -n test-custom-rules exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "custom-rules check client-b -> server on port 8080 (should fail - regular policy blocks client-b)" {
	# Should fail - regular policy only allows client-a
	run kubectl -n test-custom-rules exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "1" ]
}

@test "custom-rules check client-b -> server on port 9999 (should succeed - custom rule allows)" {
	# Should succeed - custom rule allows port 9999 regardless of regular policy
	run kubectl -n test-custom-rules exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 9999"
	[ "$status" -eq  "0" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f custom-rules.yml
	run kubectl -n test-custom-rules wait --for=delete -l app=test-custom-rules pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
