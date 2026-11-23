# tofu test (from infra/modules/rke2-node): the rendered cloud-init carries the CIS config for servers, joins through
# the API host, labels the node, and agents get no control-plane settings.
variables {
  rke2_version = "v1.33.5+rke2r1"
  api_host     = "api.difme.internal"
  join_token   = "test-token"
  node_labels  = { "difme/region" = "region-b" }
}

run "joining_server" {
  command = plan
  variables {
    role = "server"
  }
  assert {
    condition     = strcontains(output.user_data, "profile: cis") && strcontains(output.user_data, "tls-san") && strcontains(output.user_data, "https://api.difme.internal:9345")
    error_message = "server must carry the CIS profile, tls-san and the join address"
  }
  assert {
    condition     = strcontains(output.user_data, "difme/region=region-b") && strcontains(output.user_data, "INSTALL_RKE2_TYPE=server")
    error_message = "node label or install type missing"
  }
}

run "first_server_does_not_join" {
  command = plan
  variables {
    role         = "server"
    first_server = true
  }
  assert {
    condition     = !strcontains(output.user_data, ":9345")
    error_message = "the first server initialises the cluster and must not join one"
  }
}

run "agent" {
  command = plan
  variables {
    role = "agent"
  }
  assert {
    condition     = !strcontains(output.user_data, "profile: cis") && !strcontains(output.user_data, "tls-san") && strcontains(output.user_data, "INSTALL_RKE2_TYPE=agent")
    error_message = "agents only join"
  }
}

run "bad_role" {
  command = plan
  variables {
    role = "worker"
  }
  expect_failures = [var.role]
}
