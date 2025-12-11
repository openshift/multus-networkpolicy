#!/usr/bin/env bats

# Note:
# These test cases verify production-like scenarios with complex real-world
# network policies that combine multiple features and edge cases.
#
# Test Setup:
# - Frontend Policy: Allows HTTP/HTTPS from production namespace, egress to backend
# - Backend Policy: Allows from frontend and monitoring, egress to database
# - Database Policy: Only allows from backend
# - Monitoring Policy: Egress to backend metrics
#
# Pods with nftables rules: frontend, backend, database, monitoring (all have policies)
# Pods without nftables rules: external (no policies affecting it)

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	frontend_net1=$(get_net1_ip "test-production" "pod-frontend")
	backend_net1=$(get_net1_ip "test-production" "pod-backend")
	database_net1=$(get_net1_ip "test-production" "pod-database")
	monitoring_net1=$(get_net1_ip "test-production" "pod-monitoring")
	external_net1=$(get_net1_ip "test-external" "pod-external")
}

@test "setup production-like test environments" {
	# create test manifests
	kubectl create -f production-like-scenarios.yml

	# verify all pods are available
	run kubectl -n test-production wait --for=condition=ready -l app=test-production pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]

	sleep 5
}

@test "check generated nftables rules" {
	# wait for sync
	sleep 5

	run has_nftables_table "test-production" "pod-frontend"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-production" "pod-backend"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-production" "pod-database"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-production" "pod-monitoring"
	[ "$status" -eq  "0" ]

	run has_nftables_table "test-production" "pod-external"
	[ "$status" -eq  "1" ]
}

@test "production check frontend -> backend HTTP" {
	# Should succeed - frontend can access backend on HTTP
	run kubectl -n test-production exec pod-frontend -- sh -c "echo x | nc -w 1 ${backend_net1} 80"
	[ "$status" -eq  "0" ]
}

@test "production check frontend -> backend HTTPS" {
	# Should succeed - frontend can access backend on HTTPS
	run kubectl -n test-production exec pod-frontend -- sh -c "echo x | nc -w 1 ${backend_net1} 443"
	[ "$status" -eq  "0" ]
}

@test "production check frontend -> backend SSH" {
	# Should fail - frontend cannot access backend on SSH
	run kubectl -n test-production exec pod-frontend -- sh -c "echo x | nc -w 1 ${backend_net1} 22"
	[ "$status" -eq  "1" ]
}

@test "production check backend -> database" {
	# Should succeed - backend can access database
	run kubectl -n test-production exec pod-backend -- sh -c "echo x | nc -w 1 ${database_net1} 3306"
	[ "$status" -eq  "0" ]
}

@test "production check frontend -> database" {
	# Should fail - frontend cannot access database directly
	run kubectl -n test-production exec pod-frontend -- sh -c "echo x | nc -w 1 ${database_net1} 3306"
	[ "$status" -eq  "1" ]
}

@test "production check monitoring -> backend" {
	# Should succeed - monitoring can access backend
	run kubectl -n test-production exec pod-monitoring -- sh -c "echo x | nc -w 1 ${backend_net1} 8080"
	[ "$status" -eq  "0" ]
}

@test "production check monitoring -> database" {
	# Should fail - monitoring cannot access database
	run kubectl -n test-production exec pod-monitoring -- sh -c "echo x | nc -w 1 ${database_net1} 3306"
	[ "$status" -eq  "1" ]
}

@test "production check external -> frontend" {
	# Should fail - external cannot access frontend
	run kubectl -n test-production exec pod-external -- sh -c "echo x | nc -w 1 ${frontend_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "production check backend -> external" {
	# Should fail - backend cannot access external
	run kubectl -n test-production exec pod-backend -- sh -c "echo x | nc -w 1 ${external_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "production check monitoring -> frontend" {
	# Should fail - monitoring cannot access frontend (no policy allows this)
	run kubectl -n test-production exec pod-monitoring -- sh -c "echo x | nc -w 1 ${frontend_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "production check frontend -> monitoring" {
	# Should fail - frontend cannot access monitoring (no policy allows this)
	run kubectl -n test-production exec pod-frontend -- sh -c "echo x | nc -w 1 ${monitoring_net1} 8080"
	[ "$status" -eq  "1" ]
}

@test "production check database -> backend" {
	# Should fail - database cannot access backend (no egress policy for database)
	run kubectl -n test-production exec pod-database -- sh -c "echo x | nc -w 1 ${backend_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "production check external -> backend" {
	# Should fail - external cannot access backend
	run kubectl -n test-production exec pod-external -- sh -c "echo x | nc -w 1 ${backend_net1} 80"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
	# remove test manifests
	kubectl delete -f production-like-scenarios.yml
	run kubectl -n test-production wait --for=delete -l app=test-production pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
