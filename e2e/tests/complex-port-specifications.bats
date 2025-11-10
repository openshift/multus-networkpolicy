#!/usr/bin/env bats

# Note:
# These test cases verify complex port specifications including named ports,
# port ranges with specific protocols, and mixed port configurations.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-complex-ports" "pod-server")
	client_a_net1=$(get_net1_ip "test-complex-ports" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-complex-ports" "pod-client-b")
	client_c_net1=$(get_net1_ip "test-complex-ports" "pod-client-c")
}

@test "setup complex port specifications test environments" {
	# create test manifests
	kubectl create -f complex-port-specifications.yml

	# verify all pods are available
	run kubectl -n test-complex-ports wait --for=condition=ready -l app=test-complex-ports pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 5
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

	run has_nftables_table "test-complex-ports" "pod-server"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-complex-ports" "pod-client-a"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-complex-ports" "pod-client-b"
	[ "$status" -eq  "1" ]

	run has_nftables_table "test-complex-ports" "pod-client-c"
	[ "$status" -eq  "1" ]
}

@test "complex-ports check client-a -> server HTTP (80)" {
	# Should succeed - HTTP port is allowed
	run kubectl -n test-complex-ports exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "0" ]
}

@test "complex-ports check client-a -> server HTTPS (443)" {
	# Should succeed - HTTPS port is allowed
	run kubectl -n test-complex-ports exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 443"
	[ "$status" -eq  "0" ]
}

@test "complex-ports check client-a -> server SSH (22)" {
	# Should succeed - SSH port is allowed
	run kubectl -n test-complex-ports exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 22"
	[ "$status" -eq  "0" ]
}

@test "complex-ports check client-a -> server DNS (53)" {
	# Should succeed - DNS port is allowed
	run kubectl -n test-complex-ports exec pod-client-a -- sh -c "echo x | nc -u -w 1 ${server_net1} 53"
	[ "$status" -eq  "0" ]
}

@test "complex-ports check client-a -> server blocked port (8080)" {
	# Should fail - port 8080 is not allowed
	run kubectl -n test-complex-ports exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 8080"
	[ "$status" -eq  "1" ]
}

@test "complex-ports check client-b -> server HTTP (80)" {
	# Should fail - client-b is not allowed
	run kubectl -n test-complex-ports exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "complex-ports check client-c -> server HTTP (80)" {
	# Should succeed - client-c is allowed
	run kubectl -n test-complex-ports exec pod-client-c -- sh -c "echo x | nc -w 1 ${server_net1} 80"
	[ "$status" -eq  "0" ]
}

@test "complex-ports check server -> client-a egress" {
	# Should succeed - egress to client-a is allowed
	run kubectl -n test-complex-ports exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 80"
	[ "$status" -eq  "0" ]
}

@test "complex-ports check server -> client-b egress" {
	# Should fail - egress to client-b is not allowed
	run kubectl -n test-complex-ports exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f complex-port-specifications.yml
	run kubectl -n test-complex-ports wait --for=delete -l app=test-complex-ports pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
