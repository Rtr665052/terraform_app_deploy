terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.34.0, < 6.0.0"
    }
  }
}

########################
# Variables & Providers
########################

provider "aws" {
  region = var.aws_region
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

########################
# AMI
########################

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

########################
# Networking (VPC, Subnets, Routes, NAT)
########################

resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "cloud_vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "main-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public_route_table"
  }
}

# Public subnets
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.128.0/20"
  availability_zone       = "us-east-2a"
  map_public_ip_on_launch = true

  tags = {
    Name                     = "public-subnet-1"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.144.0/20"
  availability_zone       = "us-east-2b"
  map_public_ip_on_launch = true

  tags = {
    Name                     = "public-subnet-2"
    "kubernetes.io/role/elb" = "1"
  }
}

# Private subnets
resource "aws_subnet" "private_1" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.0.0/19"
  availability_zone = "us-east-2a"

  tags = {
    Name                              = "private-subnet-1"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "private_2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.32.0/19"
  availability_zone = "us-east-2b"

  tags = {
    Name                              = "private-subnet-2"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# Public subnet route associations
resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public.id
}

# NAT Gateways
resource "aws_eip" "nat_1" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat_1" {
  allocation_id = aws_eip.nat_1.id
  subnet_id     = aws_subnet.public_1.id

  tags = {
    Name = "nat_gateway_a"
  }

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_eip" "nat_2" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat_2" {
  allocation_id = aws_eip.nat_2.id
  subnet_id     = aws_subnet.public_2.id

  tags = {
    Name = "nat_gateway_b"
  }

  depends_on = [aws_internet_gateway.igw]
}

# Private route tables
resource "aws_route_table" "private_1" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_1.id
  }

  tags = {
    Name = "private_rt_1"
  }
}

resource "aws_route_table" "private_2" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_2.id
  }

  tags = {
    Name = "private_rt_2"
  }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_1.id
  route_table_id = aws_route_table.private_1.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_2.id
  route_table_id = aws_route_table.private_2.id
}

########################
# Bastion Hosts (EC2, SG, Keys, NLB, ASG)
########################

resource "aws_security_group" "bastion_sg" {
  name        = "bastion_sg"
  description = "Allow SSH access to bastion host"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description = "SSH from admin IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["67.173.221.178/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "bastion_sg"
  }
}

resource "tls_private_key" "bastion_ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "bastion_keypair" {
  key_name   = "bastion-keypair"
  public_key = tls_private_key.bastion_ssh_key.public_key_openssh
}

# Store bastion keys in Secrets Manager
resource "aws_secretsmanager_secret" "bastion_private_key" {
  name        = "bastion-ssh-private-key"
  description = "Private key for Bastion Host SSH access"
}

resource "aws_secretsmanager_secret_version" "bastion_private_key_version" {
  secret_id     = aws_secretsmanager_secret.bastion_private_key.id
  secret_string = tls_private_key.bastion_ssh_key.private_key_pem
}

resource "aws_secretsmanager_secret" "bastion_public_key" {
  name        = "bastion-ssh-public-key"
  description = "Public key for Bastion Host authorized_keys"
}

resource "aws_secretsmanager_secret_version" "bastion_public_key_version" {
  secret_id     = aws_secretsmanager_secret.bastion_public_key.id
  secret_string = tls_private_key.bastion_ssh_key.public_key_openssh
}

resource "aws_instance" "bastion_1" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_1.id
  key_name               = aws_key_pair.bastion_keypair.key_name
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  associate_public_ip_address = true

  tags = {
    Name = "bastion_host_1"
  }

  depends_on = [aws_key_pair.bastion_keypair]
}

resource "aws_instance" "bastion_2" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_2.id
  key_name               = aws_key_pair.bastion_keypair.key_name
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  associate_public_ip_address = true

  tags = {
    Name = "bastion_host_2"
  }

  depends_on = [aws_key_pair.bastion_keypair]
}

# NLB in front of bastions
resource "aws_lb" "bastion_nlb" {
  name               = "bastion-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  tags = {
    Name = "bastion_nlb"
  }
}

resource "aws_lb_target_group" "bastion_tg" {
  name        = "bastion-tg"
  port        = 22
  protocol    = "TCP"
  vpc_id      = aws_vpc.main_vpc.id
  target_type = "instance"

  health_check {
    protocol            = "TCP"
    port                = "22"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
  }

  tags = {
    Name = "bastion_tg"
  }
}

resource "aws_lb_target_group_attachment" "bastion_1" {
  target_group_arn = aws_lb_target_group.bastion_tg.arn
  target_id        = aws_instance.bastion_1.id
  port             = 22
}

resource "aws_lb_target_group_attachment" "bastion_2" {
  target_group_arn = aws_lb_target_group.bastion_tg.arn
  target_id        = aws_instance.bastion_2.id
  port             = 22
}

resource "aws_lb_listener" "bastion_listener" {
  load_balancer_arn = aws_lb.bastion_nlb.arn
  port              = 22
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.bastion_tg.arn
  }
}

# Launch template & ASG for bastions (self-healing)
resource "aws_launch_template" "bastion_lt" {
  name_prefix   = "bastion-lt-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
  key_name      = aws_key_pair.bastion_keypair.key_name

  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum update -y
    yum install -y awscli jq

    SECRET_NAME="bastion-ssh-public-key"
    REGION="${var.aws_region}"

    PUBLIC_KEY=$(aws secretsmanager get-secret-value --secret-id $SECRET_NAME --query SecretString --output text --region $REGION)

    mkdir -p /home/ec2-user/.ssh
    echo "$PUBLIC_KEY" >> /home/ec2-user/.ssh/authorized_keys
    chown -R ec2-user:ec2-user /home/ec2-user/.ssh
    chmod 700 /home/ec2-user/.ssh
    chmod 600 /home/ec2-user/.ssh/authorized_keys

    echo "Bastion SSH key configured from Secrets Manager" >> /var/log/user-data.log
  EOF
  )

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "bastion-asg-instance"
    }
  }

  depends_on = [aws_key_pair.bastion_keypair]
}

resource "aws_autoscaling_group" "bastion_asg" {
  name                = "bastion-asg"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 2
  vpc_zone_identifier = [aws_subnet.public_1.id, aws_subnet.public_2.id]
  health_check_type   = "EC2"

  launch_template {
    id      = aws_launch_template.bastion_lt.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.bastion_tg.arn]

  tag {
    key                 = "Name"
    value               = "bastion-asg-instance"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_lb_listener.bastion_listener]
}

# IAM for bastion EC2 to read Secrets
resource "aws_iam_role" "bastion_role" {
  name = "bastion-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "bastion_secrets_policy" {
  name        = "bastion-secrets-access"
  description = "Allow bastion EC2 to read SSH keys from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          aws_secretsmanager_secret.bastion_private_key.arn,
          aws_secretsmanager_secret.bastion_public_key.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bastion_attach_policy" {
  role       = aws_iam_role.bastion_role.name
  policy_arn = aws_iam_policy.bastion_secrets_policy.arn
}

resource "aws_iam_instance_profile" "bastion_instance_profile" {
  name = "bastion-instance-profile"
  role = aws_iam_role.bastion_role.name
}

########################
# Lambda for Bastion Key Rotation
########################

resource "aws_iam_role" "bastion_key_rotation_role" {
  name = "bastion-key-rotation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "bastion_key_rotation_policy" {
  name = "bastion-key-rotation-policy"
  role = aws_iam_role.bastion_key_rotation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = [
          aws_secretsmanager_secret.bastion_private_key.arn,
          aws_secretsmanager_secret.bastion_public_key.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "bastion_key_rotation_lambda" {
  filename      = "rotate_bastion_key.zip"
  function_name = "rotate-bastion-ssh-key"
  role          = aws_iam_role.bastion_key_rotation_role.arn
  handler       = "rotate_bastion_key.lambda_handler"
  runtime       = "python3.10"
  timeout       = 30

  environment {
    variables = {
      PRIVATE_SECRET_ARN = aws_secretsmanager_secret.bastion_private_key.arn
      PUBLIC_SECRET_ARN  = aws_secretsmanager_secret.bastion_public_key.arn
    }
  }
}

resource "aws_lambda_permission" "allow_secretsmanager_invoke" {
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.bastion_key_rotation_lambda.function_name
  principal     = "secretsmanager.amazonaws.com"
}

resource "aws_secretsmanager_secret_rotation" "bastion_key_rotation" {
  secret_id           = aws_secretsmanager_secret.bastion_private_key.id
  rotation_lambda_arn = aws_lambda_function.bastion_key_rotation_lambda.arn

  rotation_rules {
    automatically_after_days = 30
  }

  depends_on = [aws_lambda_function.bastion_key_rotation_lambda]
}

########################
# Security Groups for ALB / App
########################

resource "aws_security_group" "alb_sg" {
  name        = "alb-sg"
  description = "Allow web traffic"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "alb-sg" }
}

resource "aws_security_group" "app_sg" {
  name   = "app-sg"
  vpc_id = aws_vpc.main_vpc.id

  ingress {
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "app-sg" }
}

########################
# EKS Cluster & Node Group
########################

resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_vpc_controller" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

resource "aws_eks_cluster" "main" {
  name     = "my-eks-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.private_1.id,
      aws_subnet.private_2.id,
      aws_subnet.public_1.id,
      aws_subnet.public_2.id
    ]
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_controller,
    aws_iam_role.eks_cluster_role
  ]
}

# OIDC provider for IRSA (ALB controller etc.)
resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da0afd10df6"]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_role" "aws_load_balancer_controller_role" {
  name = "aws-load-balancer-controller-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks.id
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "alb_controller_attach_policy" {
  role       = aws_iam_role.aws_load_balancer_controller_role.name
  policy_arn = "arn:aws:iam::215848077383:policy/AWSLoadBalancerControllerIAMPolicy"
}

# Worker node IAM
resource "aws_iam_role" "eks_node_role" {
  name = "eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker_node_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "worker_cni_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "worker_registry_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_eks_node_group" "main_nodes" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "eks-node-group"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [aws_subnet.private_1.id, aws_subnet.private_2.id]

  scaling_config {
    desired_size = 2
    min_size     = 1
    max_size     = 3
  }

  instance_types = ["t3.medium"]

  depends_on = [
    aws_eks_cluster.main,
    aws_iam_role_policy_attachment.worker_node_policy,
    aws_iam_role_policy_attachment.worker_cni_policy,
    aws_iam_role_policy_attachment.worker_registry_policy
  ]
}

########################
# EKS Management Node
########################

resource "aws_iam_role" "eks_control_node_role" {
  name = "eks-control-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_admin_policy" {
  role       = aws_iam_role.eks_control_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "control_node_policy" {
  role       = aws_iam_role.eks_control_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "control_registry_policy" {
  role       = aws_iam_role.eks_control_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "control_cni_policy" {
  role       = aws_iam_role.eks_control_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_instance_profile" "eks_control_node_profile" {
  name = "eks-control-node-profile"
  role = aws_iam_role.eks_control_node_role.name
}

resource "tls_private_key" "management_ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "management_keypair" {
  key_name   = "management-keypair"
  public_key = tls_private_key.management_ssh_key.public_key_openssh
}

resource "aws_secretsmanager_secret" "management_private_key" {
  name        = "management-ssh-private-key"
  description = "Private key for Management Node SSH access"
}

resource "aws_secretsmanager_secret_version" "management_private_key_version" {
  secret_id     = aws_secretsmanager_secret.management_private_key.id
  secret_string = tls_private_key.management_ssh_key.private_key_pem
}

resource "aws_secretsmanager_secret" "management_public_key" {
  name        = "management-ssh-public-key"
  description = "Public key for Bastion Host"
}

resource "aws_secretsmanager_secret_version" "management_public_key_version" {
  secret_id     = aws_secretsmanager_secret.management_public_key.id
  secret_string = tls_private_key.management_ssh_key.public_key_openssh
}

resource "aws_security_group" "management_sg" {
  name        = "eks-management-sg"
  description = "Security group for EKS management node"
  vpc_id      = aws_vpc.main_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-management-sg"
  }
}

resource "aws_security_group_rule" "management_allow_ssh_from_bastion" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion_sg.id
  security_group_id        = aws_security_group.management_sg.id
  description              = "Allow SSH from bastion hosts only"
}

resource "aws_security_group_rule" "allow_mgmt_to_eks_private" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
  source_security_group_id = aws_security_group.management_sg.id
  description              = "Allow management node to reach EKS private endpoint"
}

resource "aws_instance" "eks_control_node" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_1.id
  key_name               = aws_key_pair.management_keypair.key_name
  iam_instance_profile   = aws_iam_instance_profile.eks_control_node_profile.name
  vpc_security_group_ids = [aws_security_group.management_sg.id]

  associate_public_ip_address = false

  user_data = base64encode(<<-EOF
  #!/bin/bash
  set -euxo pipefail

  yum update -y
  yum install -y unzip curl jq git docker

  if command -v aws &>/dev/null; then
    yum remove -y awscli || true
  fi

  cd /tmp
  curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -q awscliv2.zip
  ./aws/install -i /usr/local/aws-cli -b /usr/local/bin
  aws --version

  systemctl enable docker
  systemctl start docker

  KUBECTL_VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt)
  curl -s -LO "https://dl.k8s.io/release/$${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
  install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

  curl -sSL https://get.helm.sh/helm-v3.14.0-linux-amd64.tar.gz -o /tmp/helm.tar.gz
  tar -xzf /tmp/helm.tar.gz -C /tmp
  mv /tmp/linux-amd64/helm /usr/local/bin/helm

  REGION="${var.aws_region}"
  CLUSTER_NAME="${aws_eks_cluster.main.name}"

  /usr/local/bin/aws eks --region "$REGION" update-kubeconfig --name "$CLUSTER_NAME"

  curl -o /etc/eks/bootstrap.sh https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/bootstrap.sh
  bash /etc/eks/bootstrap.sh "$CLUSTER_NAME" \
    --apiserver-endpoint $(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" --query "cluster.endpoint" --output text) \
    --b64-cluster-ca $(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" --query "cluster.certificateAuthority.data" --output text) \
    --kubelet-extra-args '--node-labels=role=management'

  echo "EKS management node setup complete." >> /var/log/eks-setup.log
  EOF
  )

  tags = {
    Name = "eks-control-node"
  }

  depends_on = [
    aws_key_pair.management_keypair,
    aws_eks_cluster.main
  ]
}

########################
# ECR for InfraHash
########################

resource "aws_ecr_repository" "infrahash_repo" {
  name                 = "infrahash"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "infrahash-repo"
  }
}

resource "null_resource" "build_and_push_infrahash" {
  provisioner "local-exec" {
    command = <<EOT
      set -e
      REGION=${var.aws_region}
      ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
      REPO_URL="$${ACCOUNT_ID}.dkr.ecr.${var.aws_region}.amazonaws.com/${aws_ecr_repository.infrahash_repo.name}"

      echo "Logging into ECR..."
      aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $${REPO_URL}

      echo "Building and pushing image..."
      docker build -t $${REPO_URL}:latest .
      docker push $${REPO_URL}:latest
    EOT
  }

  triggers = {
    always_run = timestamp()
  }

  depends_on = [aws_ecr_repository.infrahash_repo]
}

########################
# RDS for InfraHash
########################

resource "random_password" "infrahash_db_password" {
  length           = 20
  special          = true
  override_special = "!#$%^&*()-_=+[]{}<>:?"
}

resource "aws_db_subnet_group" "infrahash_db_subnet_group" {
  name       = "infrahash-db-subnet-group"
  subnet_ids = [aws_subnet.private_1.id, aws_subnet.private_2.id]

  tags = {
    Name = "infrahash-db-subnet-group"
  }
}

resource "aws_security_group" "rds_sg" {
  name        = "infrahash-rds-sg"
  description = "Allow PostgreSQL access from EKS app and management node"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description     = "PostgreSQL from app SG"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  ingress {
    description     = "PostgreSQL from management SG"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.management_sg.id]
  }

  ingress {
    description     = "PostgreSQL from EKS worker node SG"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = ["sg-01d8aa9d36db6d8a5"]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "infrahash-rds-sg" }
}

resource "aws_db_instance" "infrahash_db" {
  identifier              = "infrahash-db"
  engine                  = "postgres"
  engine_version          = "15.14"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  db_subnet_group_name    = aws_db_subnet_group.infrahash_db_subnet_group.name
  vpc_security_group_ids  = [aws_security_group.rds_sg.id]
  username                = "infrahash_admin"
  password                = random_password.infrahash_db_password.result
  publicly_accessible     = false
  multi_az                = true
  skip_final_snapshot     = true
  backup_retention_period = 7
  deletion_protection     = false

  tags = {
    Name    = "infrahash-db"
    Project = "InfraHash"
  }

  depends_on = [aws_subnet.private_1, aws_subnet.private_2]
}

resource "aws_secretsmanager_secret" "infrahash_db_secret" {
  name        = "infrahash-db-credentials"
  description = "Database credentials for InfraHash app and EKS workloads"
}

resource "aws_secretsmanager_secret_version" "infrahash_db_secret_value" {
  secret_id = aws_secretsmanager_secret.infrahash_db_secret.id
  secret_string = jsonencode({
    username = aws_db_instance.infrahash_db.username
    password = random_password.infrahash_db_password.result
    host     = aws_db_instance.infrahash_db.address
    port     = aws_db_instance.infrahash_db.port
    dbname   = aws_db_instance.infrahash_db.db_name
    engine   = aws_db_instance.infrahash_db.engine
  })
}

########################
# Outputs (for both usage & k8s stage)
########################

output "aws_region" {
  value = var.aws_region
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = aws_eks_cluster.main.name
}

output "eks_cluster_endpoint" {
  description = "EKS endpoint URL"
  value       = aws_eks_cluster.main.endpoint
}

output "eks_node_role_arn" {
  description = "Worker node IAM role ARN"
  value       = aws_iam_role.eks_node_role.arn
}

output "eks_control_node_role_arn" {
  description = "Control/management node IAM role ARN"
  value       = aws_iam_role.eks_control_node_role.arn
}

output "infrahash_db_endpoint" {
  description = "RDS endpoint for InfraHash"
  value       = aws_db_instance.infrahash_db.address
}

output "infrahash_db_name" {
  description = "InfraHash DB name"
  value       = aws_db_instance.infrahash_db.db_name
}

output "infrahash_db_username" {
  description = "InfraHash DB username"
  value       = aws_db_instance.infrahash_db.username
}

output "infrahash_db_password" {
  description = "InfraHash DB password (for k8s stage)"
  value       = random_password.infrahash_db_password.result
  sensitive   = true
}

output "infrahash_db_secret_arn" {
  description = "ARN of the RDS credentials secret"
  value       = aws_secretsmanager_secret.infrahash_db_secret.arn
}

output "infrahash_rds_sg_id" {
  description = "Security Group ID for InfraHash RDS instance"
  value       = aws_security_group.rds_sg.id
}

output "infrahash_repository_url" {
  description = "ECR URL for InfraHash image"
  value       = aws_ecr_repository.infrahash_repo.repository_url
}

output "bastion_keypair_name" {
  value = aws_key_pair.bastion_keypair.key_name
}

output "bastion_private_key_secret_arn" {
  value = aws_secretsmanager_secret.bastion_private_key.arn
}

output "bastion_public_key_secret_arn" {
  value = aws_secretsmanager_secret.bastion_public_key.arn
}

output "eks_control_node_private_ip" {
  value = aws_instance.eks_control_node.private_ip
}

output "management_keypair_name" {
  value = aws_key_pair.management_keypair.key_name
}

output "management_private_key_secret_arn" {
  value = aws_secretsmanager_secret.management_private_key.arn
}

output "management_public_key_secret_arn" {
  value = aws_secretsmanager_secret.management_public_key.arn
}

output "bastion_1_public_ip" {
  value = aws_instance.bastion_1.public_ip
}

output "bastion_2_public_ip" {
  value = aws_instance.bastion_2.public_ip
}

output "vpc_id" {
  description = "Main VPC ID for EKS cluster"
  value       = aws_vpc.main_vpc.id
}

output "alb_controller_role_arn" {
  value = aws_iam_role.aws_load_balancer_controller_role.arn
}
