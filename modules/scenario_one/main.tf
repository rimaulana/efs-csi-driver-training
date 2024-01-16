data "aws_availability_zones" "available" {}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      # This requires the awscli to be installed locally where Terraform is executed
      args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

locals {
  name      = basename(path.cwd)
  region    = var.region
  azs       = slice(data.aws_availability_zones.available.names, 0, 2)
  tags      = var.tags
}

data "aws_ami" "eks_default" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.cluster_version}-v*"]
  }
}
################################################################################
# Cluster
################################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.16"

  cluster_name                   = var.cluster_name
  cluster_version                = var.cluster_version
  cluster_endpoint_public_access = true

  vpc_id     = var.vpc_id
  control_plane_subnet_ids = var.control_plane_subnet_ids
  subnet_ids = var.node_subnet_ids
  
  create_aws_auth_configmap = true
  manage_aws_auth_configmap = true
  
  self_managed_node_groups = {
    # Complete
    complete = {
      name            = "${var.cluster_name}-node"
      use_name_prefix = false

      subnet_ids = var.node_subnet_ids
      min_size     = 1
      max_size     = 2
      desired_size = 2

      ami_id = data.aws_ami.eks_default.id

      instance_type = "m5.large"

      launch_template_name            = "${var.cluster_name}-ex"
      launch_template_use_name_prefix = true
      launch_template_description     = "Self managed node group example launch template"

      ebs_optimized     = true
      enable_monitoring = true

      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 100
            volume_type           = "gp3"
            iops                  = 3000
            throughput            = 150
            delete_on_termination = true
          }
        }
      }
      
      instance_attributes = {
        bootstrap_extra_args = "--use-max-pods false --kubelet-extra-args '--max-pods=29'"
      }
      
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 2
        instance_metadata_tags      = "disabled"
      }

      create_iam_role          = true
      iam_role_name            = "${var.cluster_name}-node-role"
      iam_role_use_name_prefix = true
      iam_role_description     = "Self managed node group complete example role"
      iam_role_additional_policies = {
        AmazonEC2ContainerRegistryReadOnly = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }

      timeouts = {
        create = "80m"
        update = "80m"
        delete = "80m"
      }

      tags = {
        ExtraTag = "Self managed node group complete example"
      }
    }
  }

  tags = local.tags
}

resource "aws_security_group_rule" "vpce_rule" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = var.vpce_sg_id
  source_security_group_id  = module.eks.node_security_group_id
}

resource "aws_security_group_rule" "vpce_rule_custom" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = var.vpce_sg_id
  source_security_group_id  = aws_security_group.eni_security_group.id
}

resource "aws_security_group_rule" "efs_rule" {
  type              = "ingress"
  from_port         = 2049
  to_port           = 2049
  protocol          = "tcp"
  security_group_id = var.efs_sg_id
  source_security_group_id  = module.eks.node_security_group_id
}
################################################################################
# IRSA for EKS Managed Addons
################################################################################
data "aws_iam_policy_document" "vpc_cni_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider_arn, "/^(.*provider/)/", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [module.eks.oidc_provider_arn]
      type        = "Federated"
    }
  }
}

data "aws_iam_policy_document" "efs_csi_driver_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider_arn, "/^(.*provider/)/", "")}:sub"
      values   = ["system:serviceaccount:kube-system:efs-csi-controller-sa"]
    }

    principals {
      identifiers = [module.eks.oidc_provider_arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "vpc_cni_role" {
  assume_role_policy = data.aws_iam_policy_document.vpc_cni_assume_role_policy.json
}

resource "aws_iam_role" "efs_csi_role" {
  assume_role_policy = data.aws_iam_policy_document.efs_csi_driver_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "vpc_cni_role_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.vpc_cni_role.name
}

resource "aws_iam_policy" "efs_policy" {
  description = "Policy for EFS CSI Driver"
  policy      = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
            Effect =  "Allow"
            Action =  [
                "elasticfilesystem:DescribeAccessPoints",
                "elasticfilesystem:DescribeFileSystems",
                "elasticfilesystem:DescribeMountTargets",
                "ec2:DescribeAvailabilityZones"
            ]
            Resource =  "*"
        },
        {
            Effect = "Allow"
            Action = [
                "elasticfilesystem:CreateAccessPoint"
            ]
            Resource =  "*"
            Condition = {
                StringLike = {
                    "aws:RequestTag/efs.csi.aws.com/cluster" =  "true"
                }
            }  
        },
        {
            Effect = "Allow"
            Action = [
                "elasticfilesystem:TagResource"
            ],
            Resource = "*"
            Condition = {
                StringLike = {
                    "aws:ResourceTag/efs.csi.aws.com/cluster" = "true"
                }
            }
        },
        {
            Effect = "Allow"
            Action = "elasticfilesystem:DeleteAccessPoint"
            Resource = "*"
            Condition = {
                StringEquals = {
                    "aws:ResourceTag/efs.csi.aws.com/cluster" = "true"
                }
            }
        }
      ]
  })
}

resource "aws_iam_role_policy_attachment" "efs_csi_role_attachment" {
  policy_arn = aws_iam_policy.efs_policy.arn
  role       = aws_iam_role.efs_csi_role.name
}

################################################################################
# EKS Blueprints Addons
################################################################################

module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.0"

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn
  
  # create_delay_dependencies = [for prof in module.eks.self_managed_node_groups : prof.autoscaling_group_arn]

  # EKS Add-ons
  eks_addons = {
    coredns = {
      most_recent    = true
    }
    vpc-cni    = {
      most_recent    = true # To ensure access to the latest settings provided
      service_account_role_arn = aws_iam_role.vpc_cni_role.arn
      configuration_values = jsonencode({
        env = {
          WARM_IP_TARGET        = "1"
          MINIMUM_IP_TARGET     = "5"
          ENI_CONFIG_LABEL_DEF  = "failure-domain.beta.kubernetes.io/zone"
          AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG    = "true"
        }
      })
    }
    kube-proxy = {
      most_recent    = true
    }
    aws-efs-csi-driver = {
      most_recent = true
      service_account_role_arn = aws_iam_role.efs_csi_role.arn
    }
  }
  tags = local.tags
}

################################################################################
# EFS CSI Driver
################################################################################
resource "kubectl_manifest" "efs_csi_storage_class" {
  apply_only = true
  yaml_body = <<-YAML
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: efs-csi
    provisioner: efs.csi.aws.com
    volumeBindingMode: WaitForFirstConsumer
  YAML

  depends_on = [
    module.eks
  ]
}

resource "aws_security_group" "eni_security_group" {
  description = "ENI Security Group"
  vpc_id      = var.vpc_id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  
  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    security_groups  = [module.eks.node_security_group_id,module.eks.cluster_security_group_id]
  }

  tags = local.tags
}

resource "aws_security_group_rule" "allow_self_sg" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.eni_security_group.id
  source_security_group_id  = aws_security_group.eni_security_group.id
}

resource "aws_security_group_rule" "allow_cross_sg" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = module.eks.node_security_group_id
  source_security_group_id  = aws_security_group.eni_security_group.id
}

resource "aws_security_group_rule" "allow_cross_sg_1" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = module.eks.cluster_security_group_id
  source_security_group_id  = aws_security_group.eni_security_group.id
}

resource "kubectl_manifest" "eni_config_definitions" {
  for_each = { for k, v in local.azs : v => var.node_subnet_ids[k+2] }
  apply_only = true
  yaml_body = <<-YAML
    apiVersion: crd.k8s.amazonaws.com/v1alpha1
    kind: ENIConfig
    metadata: 
      name: ${each.key}
    spec: 
      securityGroups: 
      - ${aws_security_group.eni_security_group.id}
      subnet: ${each.value}
  YAML

  depends_on = [
    module.eks
  ]
}

################################################################################
# EFS WORKLOAD
################################################################################
resource "kubectl_manifest" "efs_pv" {
  apply_only = true
  yaml_body = <<-YAML
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: efs-pv
    spec:
      capacity:
        storage: 5Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteOnce
      storageClassName: efs-sc
      persistentVolumeReclaimPolicy: Retain
      csi:
        driver: efs.csi.aws.com
        volumeHandle: fs-09880f9ce5e763795
  YAML

  depends_on = [
    module.eks
  ]
}

resource "kubectl_manifest" "efs_claim" {
  apply_only = true
  yaml_body = <<-YAML
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: efs-claim
    spec:
      accessModes:
        - ReadWriteOnce
      storageClassName: efs-sc
      resources:
        requests:
          storage: 5Gi
  YAML

  depends_on = [
    module.eks
  ]
}

resource "kubectl_manifest" "efs_pod" {
  apply_only = true
  wait_for_rollout = false
  yaml_body = <<-YAML
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: efs-app
      labels:
        app: efs-sample
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: efs-sample
      template:
        metadata:
          labels:
            app: efs-sample
        spec:
          containers:
          - name: app
            image: centos
            command: ["/bin/sh"]
            args: ["-c", "while true; do echo $(date -u) >> /data/out.txt; sleep 5; done"]
            volumeMounts:
            - name: persistent-storage
              mountPath: /data
          volumes:
          - name: persistent-storage
            persistentVolumeClaim:
              claimName: efs-claim
  YAML

  depends_on = [
    module.eks
  ]
}