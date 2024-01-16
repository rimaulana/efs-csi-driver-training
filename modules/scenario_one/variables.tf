variable "cluster_name" {
    type        = string
    description = "The name of EKS cluster"
}

variable "cluster_version" {
    type        = string
    description = "The Kubernetes version of EKS cluster"
}

variable "region" {
    type        = string
    description = "The region of the cluster"
}

variable "tags" {
  description = "Tags to be attached to the cluster"
  type        = map(any)
}

variable "vpc_id" {
  description = "vpc_id for EKS cluster"
  type        = string
}

variable "node_subnet_ids" {
  description = "subnet ids for worker nodes"
  type        = list(string)
}

variable "vpce_sg_id" {
  description = "security group for node"
  type        = string
}

variable "efs_sg_id" {
  description = "security group of efs"
  type        = string
}

variable "control_plane_subnet_ids" {
  description = "subnet ids for EKS control plane"
  type        = list(string)
}

variable "file_system_id" {
  description = "EFS ID"
  type        = string
}