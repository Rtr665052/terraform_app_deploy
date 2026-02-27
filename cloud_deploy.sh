#!/bin/bash
set -e

terraform init

# Step 1: Build the cluster
terraform apply -target=aws_eks_cluster.main -auto-approve
terraform apply -target=null_resource.wait_for_eks_api -auto-approve

# Step 2: Wait until EKS is ready
echo "Waiting for EKS control plane to be ready..."
aws eks wait cluster-active --name my-eks-cluster --region us-east-2
aws eks update-kubeconfig --name my-eks-cluster --region us-east-2

# Step 3: Deploy workloads
terraform apply -auto-approve

# http://k8s-default-infrahas-405c5343f9-1146316303.us-east-2.elb.amazonaws.com

# curl -I http://k8s-default-infrahas-405c5343f9-1146316303.us-east-2.elb.amazonaws.com

# account ID - 215848077383
