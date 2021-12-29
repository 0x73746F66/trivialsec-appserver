resource "aws_ssm_parameter" "ssm_linode_appserver_password" {
  name        = "/linode/${linode_instance.appserver.id}/linode_appserver_password"
  description = join(", ", linode_instance.appserver.ipv4)
  type        = "SecureString"
  value       = random_string.linode_password.result
  tags = {
    cost-center = "saas"
  }
}
resource "aws_ssm_parameter" "recaptcha_site_key" {
  name        = "/${var.app_env}/Deploy/${var.app_name}/recaptcha_site_key"
  type        = "String"
  value       = var.recaptcha_site_key
  tags = {
    cost-center = "saas"
  }
  overwrite   = true
}
resource "aws_ssm_parameter" "recaptcha_secret_key" {
  name        = "/${var.app_env}/Deploy/${var.app_name}/recaptcha_secret_key"
  type        = "SecureString"
  value       = var.recaptcha_secret_key
  tags = {
    cost-center = "saas"
  }
  overwrite   = true
}