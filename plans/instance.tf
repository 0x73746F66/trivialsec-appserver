resource "random_string" "linode_password" {
    length  = 32
    special = true
}
resource "linode_instance" "appserver" {
  label             = local.instance_hostname
  group             = "SaaS"
  tags              = ["API"]
  region            = local.linode_default_region
  type              = local.linode_default_type
  image             = local.linode_default_image
  authorized_keys   = length(var.public_key) == 0 ? [] : [
    var.public_key
  ]
  authorized_users  = length(var.allowed_linode_username) == 0 ? [] : [
    var.allowed_linode_username
  ]
  root_pass         = random_string.linode_password.result
  stackscript_id    = linode_stackscript.appserver.id
  stackscript_data  = {
    "FQDN"                  = local.instance_hostname
    "FLASK_RUN_PORT"        = 8888
    "AWS_REGION"            = local.aws_default_region
    "AWS_ACCESS_KEY_ID"     = var.aws_access_key_id
    "AWS_SECRET_ACCESS_KEY" = var.aws_secret_access_key
    "TRIVIALSEC_PY_LIB_VER" = var.trivialsec_py_lib_ver
    "GITLAB_USER"           = var.gitlab_user
    "GITLAB_PASSWORD"       = var.gitlab_password
    "BRANCH"                = local.branch
  }
  alerts {
      cpu            = 90
      io             = 10000
      network_in     = 10
      network_out    = 10
      transfer_quota = 80
  }
}
output "appserver_id" {
  value = linode_instance.appserver.id
}
output "appserver_ipv4" {
  value = [for ip in linode_instance.appserver.ipv4 : join("/", [ip, "32"])]
}
output "appserver_ipv6" {
  value = linode_instance.appserver.ipv6
}
output "appserver_linode_password" {
  sensitive = true
  value = random_string.linode_password.result
}
