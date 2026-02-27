terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.34.0, < 6.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.33"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
  }
}

# --- Providers ---

provider "aws" {
  region = var.aws_region
}

# Read outputs from the infra stage (local state backend)
data "terraform_remote_state" "infra" {
  backend = "local"

  config = {
    path = "../infra/terraform.tfstate"
  }
}

# Use infra outputs to connect to EKS cluster
data "aws_eks_cluster" "main" {
  name = data.terraform_remote_state.infra.outputs.eks_cluster_name
}

data "aws_eks_cluster_auth" "main" {
  name = data.terraform_remote_state.infra.outputs.eks_cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.main.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.main.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.main.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.main.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.main.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.main.token
  }
}

# --- aws-auth ConfigMap ---

resource "kubernetes_config_map" "aws_auth" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapRoles = yamlencode([
      {
        rolearn  = data.terraform_remote_state.infra.outputs.eks_node_role_arn
        username = "system:node:{{EC2PrivateDNSName}}"
        groups   = ["system:bootstrappers", "system:nodes"]
      },
      {
        rolearn  = data.terraform_remote_state.infra.outputs.eks_control_node_role_arn
        username = "admin"
        groups   = ["system:masters"]
      }
    ])
  }
}

# --- InfraHash Deployment ---

resource "kubernetes_deployment" "infrahash" {
  metadata {
    name   = "infrahash"
    labels = { app = "infrahash" }
  }

  spec {
    replicas = 2

    selector {
      match_labels = { app = "infrahash" }
    }

    template {
      metadata {
        labels = { app = "infrahash" }
      }

      spec {
        container {
          name  = "infrahash"
          image = "${data.terraform_remote_state.infra.outputs.infrahash_repository_url}:latest"

          port {
            container_port = 5000
          }

          resources {
            limits = {
              cpu    = "250m"
              memory = "256Mi"
            }
            requests = {
              cpu    = "125m"
              memory = "128Mi"
            }
          }

          env_from {
            secret_ref {
              name = kubernetes_secret.infrahash_db_secret.metadata[0].name
            }
          }
        }
      }
    }
  }
}

# --- InfraHash Service ---

resource "kubernetes_service" "infrahash_service" {
  metadata {
    name   = "infrahash-service"
    labels = { app = "infrahash" }
  }

  spec {
    selector = { app = "infrahash" }

    port {
      port        = 5000
      target_port = 5000
      protocol    = "TCP"
    }

    type = "NodePort"
  }
}

# --- DB credentials as Kubernetes Secret ---

resource "kubernetes_secret" "infrahash_db_secret" {
  metadata {
    name      = "infrahash-db-secret"
    namespace = "default"
  }

  data = {
    DATABASE_HOST     = data.terraform_remote_state.infra.outputs.infrahash_db_endpoint
    DATABASE_PORT     = "5432"
    DATABASE_NAME     = data.terraform_remote_state.infra.outputs.infrahash_db_name
    DATABASE_USER     = data.terraform_remote_state.infra.outputs.infrahash_db_username
    DATABASE_PASSWORD = data.terraform_remote_state.infra.outputs.infrahash_db_password
  }

  type = "Opaque"
}

# --- AWS SA account creation ---

resource "kubernetes_service_account" "aws_lbc_sa" {
  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"
    annotations = {
      # "eks.amazonaws.com/role-arn" = data.terraform_remote_state.infra.outputs.alb_controller_role_arn
    }
  }
}

# --- AWS Load Balancer Controller via Helm ---

resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = "1.7.2"

  set {
    name  = "clusterName"
    value = data.terraform_remote_state.infra.outputs.eks_cluster_name
  }

  set {
    name  = "region"
    value = var.aws_region
  }

  set {
    name  = "serviceAccount.create"
    value = "false"
  }

  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }

  set {
    name  = "vpcId"
    value = data.terraform_remote_state.infra.outputs.vpc_id
  }

  timeout           = 900
  atomic            = false
  wait              = true
  recreate_pods     = true
  dependency_update = true

  depends_on = [
    kubernetes_config_map.aws_auth,
    kubernetes_service_account.aws_lbc_sa
  ]
}

# --- Ingress for InfraHash (ALB ingress) ---

resource "kubernetes_manifest" "infrahash_ingress" {
  manifest = {
    apiVersion = "networking.k8s.io/v1"
    kind       = "Ingress"
    metadata = {
      name      = "infrahash-ingress"
      namespace = "default"
      annotations = {
        "kubernetes.io/ingress.class"            = "alb"
        "alb.ingress.kubernetes.io/scheme"       = "internet-facing"
        "alb.ingress.kubernetes.io/target-type"  = "ip"
        "alb.ingress.kubernetes.io/listen-ports" = "[{\"HTTP\":80}]"
      }
    }
    spec = {
      rules = [
        {
          http = {
            paths = [
              {
                path     = "/"
                pathType = "Prefix"
                backend = {
                  service = {
                    name = kubernetes_service.infrahash_service.metadata[0].name
                    port = {
                      number = 5000
                    }
                  }
                }
              }
            ]
          }
        }
      ]
    }
  }

  depends_on = [
    helm_release.aws_load_balancer_controller,
    kubernetes_service.infrahash_service
  ]
}
