terraform {
  required_version = ">= 1.6.0"

  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.33"
    }
  }
}

# Auth: export VULTR_API_KEY=... (Account -> API). Never commit it.
provider "vultr" {
  rate_limit  = 100
  retry_limit = 3
}
