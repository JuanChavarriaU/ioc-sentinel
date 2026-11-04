output "public_ip" {
  value = vultr_instance.control_plane.main_ip
}

output "vpc_ip" {
  description = "Control-plane address inside the VPC."
  value       = vultr_instance.control_plane.internal_ip
}

output "vpc_id" {
  value = vultr_vpc.main.id
}

output "vpc_cidr" {
  value = "${vultr_vpc.main.v4_subnet}/${vultr_vpc.main.v4_subnet_mask}"
}

output "ssh" {
  value = "ssh ${var.admin_user}@${vultr_instance.control_plane.main_ip}"
}

output "repo_dir" {
  value = local.repo_dir
}

output "admin_user" {
  value = var.admin_user
}

output "inference_id" {
  value = var.create_inference ? vultr_inference.agent[0].id : null
}

output "inference_api_key" {
  value     = var.create_inference ? vultr_inference.agent[0].api_key : null
  sensitive = true
}
