#!/bin/sh

aws secretsmanager get-secret-value \
  --secret-id bastion-ssh-private-key \
  --query SecretString \
  --output text > bastion.pem

chmod 600 bastion.pem

ssh -i bastion.pem ec2-user@3.145.184.231

## key conflicts resolution
#restore the key after deletion
aws secretsmanager restore-secret --secret-id bastion-ssh-private-key
aws secretsmanager restore-secret --secret-id bastion-ssh-public-key
aws secretsmanager restore-secret --secret-id management-ssh-private-key
aws secretsmanager restore-secret --secret-id management-ssh-public-key

#then import to terraform so terraform can plan/apply
terraform import aws_secretsmanager_secret.bastion_private_key bastion-ssh-private-key
terraform import aws_secretsmanager_secret.bastion_public_key bastion-ssh-public-key
terraform import aws_secretsmanager_secret.management_private_key management-ssh-private-key
terraform import aws_secretsmanager_secret.management_public_key management-ssh-public-key

## making the management node part of the cluster
# reset token for aws-auth
aws eks --region us-east-2 update-kubeconfig --name my-eks-cluster --alias admin

#aws-auth possible fix
terraform import kubernetes_config_map.aws_auth kube-system/aws-auth

# may have to run this when fixing the load balancer
terraform import helm_release.aws_load_balancer_controller kube-system/aws-load-balancer-controller

#clean up
aws ec2 delete-network-interface --network-interface-id eni-08adc8bb827f47cbd--region us-east-2

