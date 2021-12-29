variable "linode_token" {
  description = "The linode api token"
  type        = string
  sensitive   = true
}
variable "sendgrid_api_key" {
  description = "The sendgrid api key"
  type        = string
  sensitive   = true
}
variable "aws_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY"
  type        = string
  sensitive   = true
}
variable "allowed_linode_username" { # space delimited
  description = "ALLOWED_LINODE_USERNAME"
  type        = string
  default     = ""
}
variable "gitlab_password" {
  description = "GITLAB_PAT"
  type        = string
}
variable "recaptcha_secret_key" {
  description = ""
  type        = string
  sensitive   = true
}