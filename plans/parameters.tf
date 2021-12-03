resource "aws_ssm_parameter" "ssm_linode_appserver_password" {
  name        = "/linode/${linode_instance.appserver.id}/linode_appserver_password"
  description = join(", ", linode_instance.appserver.ipv4)
  type        = "SecureString"
  value       = random_string.linode_password.result
  tags = {
    cost-center = "saas"
  }
}
