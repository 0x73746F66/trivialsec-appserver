variable "aws_access_key_id" {
  description = "AWS_ACCESS_KEY_ID"
  type        = string
}
variable "app_env" {
  description = "default Dev"
  type        = string
  default     = "Dev"
}
variable "app_name" {
  description = "default trivialsec"
  type        = string
  default     = "trivialsec"
}
variable "recaptcha_site_key" {
  description = ""
  type        = string
}
variable "trivialsec_py_lib_ver" {
  description = "TRIVIALSEC_PY_LIB_VER"
  type        = string
}
variable "gitlab_user" {
  description = "GITLAB_USER"
  type        = string
}
variable "public_key" {
  description = "The linode authorized_key"
  type        = string
  default     = ""
}