#!/usr/bin/env bats

# Note:
# These test cases, simple, will create simple (one policy for ingress) and test the 
# traffic policying by ncat (nc) command.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(get_net1_ip "test-simple-v4-egress" "pod-server")
	client_a_net1=$(get_net1_ip "test-simple-v4-egress" "pod-client-a")
	client_b_net1=$(get_net1_ip "test-simple-v4-egress" "pod-client-b")
}

@test "setup simple test environments" {
	# create test manifests
	kubectl create -f simple-v4-egress.yml

	# verify all pods are available
	run kubectl -n test-simple-v4-egress wait --for=condition=ready -l app=test-simple-v4-egress pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

  run has_nftables_table "test-simple-v4-egress" "pod-server"
  [ "$status" -eq  "0" ]

  run has_nftables_table "test-simple-v4-egress" "pod-client-a"
  [ "$status" -eq  "1" ]

  run has_nftables_table "test-simple-v4-egress" "pod-client-b"
  [ "$status" -eq  "1" ]
}


@test "test-simple-v4-egress check client-a -> server" {
	# nc should succeed from client-a to server by no policy definition for the direction
	run kubectl -n test-simple-v4-egress exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-egress check client-b -> server" {
	# nc should succeed from client-b to server by no policy definition for the direction
	run kubectl -n test-simple-v4-egress exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-egress check server -> client-a" {
	# nc should succeed from server to client-a by policy definition
	run kubectl -n test-simple-v4-egress exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v4-egress check server -> client-b" {
	# nc should NOT succeed from server to client-b by policy definition
	run kubectl -n test-simple-v4-egress exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f simple-v4-egress.yml
	run kubectl -n test-simple-v4-egress wait --for=delete -l app=test-simple-v4-egress pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
