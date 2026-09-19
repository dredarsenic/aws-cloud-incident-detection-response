variable "aws_region" {
  description = "AWS region used by the security lab."
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "security-lab"
}

variable "alert_email" {
  description = "Email address that receives security alerts."
  type        = string
}

variable "response_mode" {
  description = "Security response mode."
  type        = string
  default     = "alert"

  validation {
    condition     = contains(["alert", "contain"], var.response_mode)
    error_message = "response_mode must be alert or contain."
  }
}
