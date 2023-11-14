# terraform {
#   required_version = ">= 1.5.7"

#   required_providers {
#     aws = {
#       source  = "hashicorp/aws"
#       version = ">= 3.72"
#     }
#     kubernetes = {
#       source  = "hashicorp/kubernetes"
#       version = ">= 2.10"
#     }
#     helm = {
#       source  = "hashicorp/helm"
#       version = ">= 2.4.1"
#     }
#     kubectl = {
#       source  = "gavinbunney/kubectl"
#       version = ">= 1.14"
#     }
#     docker = {
#       source  = "kreuzwerker/docker"
#       version = "~> 3.0.1"
#     }
#   }
# }

# provider "aws" {
#   region = var.region
# }

# provider "kubernetes" {
#   host                   = module.eks.cluster_endpoint
#   cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
#   token                  = data.aws_eks_cluster_auth.this.token
# }

# provider "helm" {
#   kubernetes {
#     host                   = module.eks.cluster_endpoint
#     cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
#     token                  = data.aws_eks_cluster_auth.this.token
#   }
# }

# provider "kubectl" {
#   apply_retry_count      = 10
#   host                   = module.eks.cluster_endpoint
#   cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
#   load_config_file       = false
#   token                  = data.aws_eks_cluster_auth.this.token
# }

# variable "region" {
#   description = "Region to deploy the resources"
#   type        = string
#   default     = "me-south-1"
# }

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

data "aws_availability_zones" "available" {}

locals {
  name   = "rancher-eks"
  region = var.region

  cluster_version = "1.27"

  node_group_name_one = "rancher-eks-ng-1"
  node_group_name_two = "rancher-eks-ng-2"

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    blueprint = local.name
  }
}

################################################################################
# Cluster
################################################################################
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.16.0"

  cluster_name                   = local.name
  cluster_version                = local.cluster_version
  cluster_endpoint_public_access = true

  cluster_addons = {
    # aws-ebs-csi-driver = { most_recent = true }
    kube-proxy = { most_recent = true }
    coredns    = { most_recent = true }

    vpc-cni = {
      most_recent    = true
      before_compute = true
      configuration_values = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  create_cluster_security_group = false
  create_node_security_group    = false

  manage_aws_auth_configmap = true
  # aws_auth_roles = [
  #   {
  #     rolearn  = module.eks_blueprints_addons.karpenter.node_iam_role_arn
  #     username = "system:node:{{EC2PrivateDNSName}}"
  #     groups = [
  #       "system:bootstrappers",
  #       "system:nodes",
  #     ]
  #   }
  # ]

  eks_managed_node_groups = {
    chaos_eks_node_one = {
      node_group_name = local.node_group_name_one
      instance_types  = ["t3.small"]
      capacity_type  = "SPOT"

      create_security_group = false

      subnet_ids   = module.vpc.private_subnets
      min_size     = 2
      max_size     = 2
      desired_size = 2

      # Launch template configuration
      create_launch_template = true              # false will use the default launch template
      launch_template_os     = "amazonlinux2eks" # amazonlinux2eks or bottlerocket
      kubelet_extra_args     = "--node-labels=intent=control-apps"

      labels = {
        role = local.node_group_name_one
      }
      
      # Tags
      tags = {
        "k8s.io/cluster-autoscaler/enabled"                  = "true"
        "k8s.io/cluster-autoscaler/${local.name}"            = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/role" = "${local.node_group_name_one}"
        "k8s.io/cluster-autoscaler/ssm/ssmmanaged" = "true"
        "k8s.io/cluster-autoscaler/ssm/ssmactivation" = "true"
      }
    }
    
    # chaos_eks_node_two = {
    #   node_group_name = local.node_group_name_two
    #   instance_types  = ["t3.small"]
    #   capacity_type  = "SPOT"

    #   create_security_group = false

    #   subnet_ids   = module.vpc.private_subnets
    #   min_size     = 1
    #   max_size     = 1
    #   desired_size = 1

    #   # Launch template configuration
    #   create_launch_template = true              # false will use the default launch template
    #   launch_template_os     = "amazonlinux2eks" # amazonlinux2eks or bottlerocket
    #   kubelet_extra_args     = "--node-labels=intent=control-apps"
      
    #   labels = {
    #     role = local.node_group_name_two
    #   }
      
    #   # Tags
    #   tags = {
    #     "k8s.io/cluster-autoscaler/enabled"                  = "true"
    #     "k8s.io/cluster-autoscaler/${local.name}"            = "owned"
    #     "k8s.io/cluster-autoscaler/node-template/label/role" = "${local.node_group_name_two}"
    #     "k8s.io/cluster-autoscaler/ssm/ssmmanaged" = "true"
    #     "k8s.io/cluster-autoscaler/ssm/ssmactivation" = "true"
    #   }
    # }
  }
  # tags = merge(local.tags, {
  #   "karpenter.sh/discovery" = local.name
  # })
}

################################################################################
#AutoScaling Tags
################################################################################

locals {

  eks_asg_tag_list_node_group_name_one = {
    "k8s.io/cluster-autoscaler/enabled" : true
    "k8s.io/cluster-autoscaler/${local.name}" : "owned"
	"k8s.io/cluster-autoscaler/node-template/label/role" : local.node_group_name_one
  }

  # eks_asg_tag_list_node_group_name_two = {
  #   "k8s.io/cluster-autoscaler/enabled" : true
  #   "k8s.io/cluster-autoscaler/${local.name}" : "owned"
  #   "k8s.io/cluster-autoscaler/node-template/label/role" : local.node_group_name_two
  # }
}

resource "aws_autoscaling_group_tag" "node_group_name_one" {
  for_each               = local.eks_asg_tag_list_node_group_name_one
  autoscaling_group_name = element(module.eks.eks_managed_node_groups_autoscaling_group_names, 0)

  tag {
    key                 = each.key
    value               = each.value
    propagate_at_launch = true
  }
}

# resource "aws_autoscaling_group_tag" "node_group_name_two" {
#   for_each               = local.eks_asg_tag_list_node_group_name_two
#   autoscaling_group_name = element(module.eks.eks_managed_node_groups_autoscaling_group_names, 1)

#   tag {
#     key                 = each.key
#     value               = each.value
#     propagate_at_launch = true
#   }
# }

# resource "aws_iam_policy_attachment" "attach_ssm_policy_node_groups" {
#   for_each = module.eks.eks_managed_node_groups.chaos_eks_node_one
#   role_name = element(module.eks.eks_managed_node_groups.chaos_eks_node_one, 3)

#   name  = "attach-ssm-policy-node-${each.key}"
#   roles = element(module.eks.eks_managed_node_groups.chaos_eks_node_one_role_name, 3)

#   policy_arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
# }


locals {
  node_groups = concat(
    tolist([module.eks.eks_managed_node_groups.chaos_eks_node_one])
    #tolist([module.eks.eks_managed_node_groups.chaos_eks_node_two])
  )
}

resource "aws_iam_policy_attachment" "attach_ssm_policy_node_groups" {
  for_each = { for idx, node_group in local.node_groups : idx => node_group }

  name       = "attach-ssm-policy-node-${each.key}"
  roles      = [each.value.iam_role_name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
}

resource "aws_iam_policy_attachment" "attach_ec2_policy_node_groups" {
  for_each = { for idx, node_group in local.node_groups : idx => node_group }

  name       = "attach-ec2-policy-node-${each.key}"
  roles      = [each.value.iam_role_name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}


# resource "aws_iam_policy_attachment" "attach_ssm_policy_node_groups" {
#   for_each = module.eks.eks_managed_node_groups

#   name       = "attach-ssm-policy-node-${each.key}"
#   roles      = [each.value.instance_roles[0].name]
#   policy_arn = "arn:aws:iam::aws:policy/AmazonSSMFullAccess"
# }


# resource "aws_iam_policy_attachment" "attach_ssm_policy" {
#   name       = "attach-ssm-policy"
#   roles      = [local.node_group_name_one["chaos_eks_node_one"], local.node_group_name_one["chaos_eks_node_two"]]
#   policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
# }

################################################################################
#cluster_autoscaler
################################################################################

# locals {
#   k8s_service_account_namespace = "kube-system"
#   k8s_service_account_name      = "cluster-autoscaler"
# }

# resource "helm_release" "cluster-autoscaler" {
#   name             = "cluster-autoscaler"
#   namespace        = local.k8s_service_account_namespace
#   repository       = "https://kubernetes.github.io/autoscaler"
#   chart            = "cluster-autoscaler"
#   version          = "9.10.7"
#   create_namespace = false

#   set {
#     name  = "awsRegion"
#     value = local.region
#   }
#   set {
#     name  = "autoDiscovery.clusterName"
#     value = local.name
#   }
#   set {
#     name  = "autoDiscovery.enabled"
#     value = "true"
#   }

################################################################################
#EKS Addons
################################################################################

module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "1.8.0"

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn

  create_delay_dependencies = [for prof in module.eks.eks_managed_node_groups : prof.node_group_arn]

  enable_metrics_server = true

#   enable_karpenter = true
#   karpenter = {
#     repository_username = data.aws_ecrpublic_authorization_token.token.user_name
#     repository_password = data.aws_ecrpublic_authorization_token.token.password
#   }
#   karpenter_enable_spot_termination = true

  tags = local.tags

}

#---------------------------------------------------------------
# Base Infra Resources - VPC & its component
#---------------------------------------------------------------

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.1"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  # Manage so we can name
  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name}-default" }

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/elb"              = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/internal-elb"     = 1
    #"karpenter.sh/discovery"              = local.name
  }

  tags = local.tags
}

output "configure_kubectl" {
  description = "Configure kubectl: make sure you're logged in with the correct AWS profile and run the following command to update your kubeconfig"
  value       = "aws eks --region ${local.region} update-kubeconfig --name ${module.eks.cluster_name}"
}

output "cluster_name" {
  description = "Cluster name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_version" {
  description = "K8s Cluster version of the EKS cluster"
  value       = module.eks.cluster_version
}

output "vpc_id" {
  description = "VPC ID that the EKS cluster is using"
  value       = module.vpc.vpc_id
}

output "oidc_provider" {
  description = "EKS OIDC Provider"
  value       = module.eks.oidc_provider
}

output "eks_managed_node_groups" {
  description = "EKS managed node groups"
  value       = module.eks.eks_managed_node_groups
}

output "oidc_provider_arn" {
  description = "EKS OIDC Provider Arn"
  value       = module.eks.oidc_provider_arn
}

output "cluster_status" {
  description = "EKS Cluster Status"
  value       = module.eks.cluster_status
}