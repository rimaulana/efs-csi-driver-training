provider "aws" {
  region = local.region
}

data "aws_availability_zones" "available" {}

locals {
  name     = basename(path.cwd)
  region   = "us-east-1"

  primary_cidr   = "172.20.0.0/23"
  secondary_cidr = "100.64.0.0/20"
  
  azs      = slice(data.aws_availability_zones.available.names, 0, 2)

  tags = {
    blueprint  = local.name
    "auto-delete" = "no"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = local.primary_cidr
  secondary_cidr_blocks = [local.secondary_cidr]
  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.primary_cidr, 2, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.primary_cidr, 4, k + 10)]
  database_subnets= [for k, v in local.azs : cidrsubnet(local.primary_cidr, 4, k + 12)]
  intra_subnets   = concat ([for k, v in local.azs : cidrsubnet(local.primary_cidr, 4, k + 14)], [for k, v in local.azs : cidrsubnet(local.secondary_cidr, 2, k)])
 
  enable_nat_gateway = true
  single_nat_gateway = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
    "type" = "public"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
    "type" = "private"
  }

  tags = local.tags
}

resource "aws_security_group" "vpce_security_group_1" {
  name        = "vpce_security_group_1"
  description = "VPC Endpoint Security Group"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [local.primary_cidr,local.secondary_cidr]
  }

  tags = local.tags
}

resource "aws_security_group" "vpce_security_group_2" {
  name        = "vpce_security_group_2"
  description = "VPC Endpoint Security Group"
  vpc_id      = module.vpc.vpc_id

  tags = local.tags
}

resource "aws_security_group" "efs_security_group" {
  name        = "efs_security_group"
  description = "EFS Mount Target Security Group"
  vpc_id      = module.vpc.vpc_id

  tags = local.tags
}

resource "aws_route" "intra_net_gateway" {
  route_table_id              = module.vpc.intra_route_table_ids[0]
  destination_cidr_block      = "0.0.0.0/0"
  nat_gateway_id              = module.vpc.natgw_ids[0]
}
################################################################################
# VPC Endpoints Module
################################################################################

module "vpc_endpoints" {
  source = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  vpc_id = module.vpc.vpc_id
  
  endpoints = {
    s3 = {
      service         = "s3"
      service_type    = "Gateway"
      route_table_ids = flatten([module.vpc.intra_route_table_ids])
      tags            = { Name = "s3-vpc-endpoint" }
    },
    ecr_api = {
      service             = "ecr.api"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_1.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    ecr_dkr = {
      service             = "ecr.dkr"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_1.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    ec2 = {
      service             = "ec2"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_1.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    sts = {
      service             = "sts"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_2.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    efs = {
      service             = "elasticfilesystem"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_2.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
  }

  tags = merge(local.tags, {
    Endpoint = "true"
  })
}

################################################################################
# EFS
################################################################################
resource "aws_efs_file_system" "efs" {
  tags = local.tags
}

resource "aws_efs_mount_target" "mountarget" {
  for_each        = {for k, v in local.azs : k => module.vpc.private_subnets[k]}
  file_system_id  = aws_efs_file_system.efs.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs_security_group.id]
}

module scenario_one {
  source                    = "./modules/scenario_one"
  cluster_name              = "scenario_one"
  cluster_version           = "1.27"
  region                    = local.region
  tags                      = local.tags
  vpc_id                    = module.vpc.vpc_id
  node_subnet_ids           = module.vpc.intra_subnets
  vpce_sg_id                = aws_security_group.vpce_security_group_2.id
  efs_sg_id                 = aws_security_group.efs_security_group.id
  control_plane_subnet_ids  = module.vpc.private_subnets
  file_system_id            = aws_efs_file_system.efs.id
}

module scenario_two {
  source                    = "./modules/scenario_two"
  cluster_name              = "scenario_two"
  cluster_version           = "1.27"
  region                    = local.region
  tags                      = local.tags
  vpc_id                    = module.vpc.vpc_id
  node_subnet_ids           = module.vpc.intra_subnets
  vpce_sg_id                = aws_security_group.vpce_security_group_2.id
  efs_sg_id                 = aws_security_group.efs_security_group.id
  control_plane_subnet_ids  = module.vpc.private_subnets
  file_system_id            = aws_efs_file_system.efs.id
}

module scenario_three {
  source                    = "./modules/scenario_three"
  cluster_name              = "scenario_three"
  cluster_version           = "1.27"
  region                    = local.region
  tags                      = local.tags
  vpc_id                    = module.vpc.vpc_id
  node_subnet_ids           = module.vpc.intra_subnets
  vpce_sg_id                = aws_security_group.vpce_security_group_2.id
  efs_sg_id                 = aws_security_group.efs_security_group.id
  control_plane_subnet_ids  = module.vpc.private_subnets
  file_system_id            = aws_efs_file_system.efs.id
}