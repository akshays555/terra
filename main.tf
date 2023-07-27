terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.9.0"
    }
  }
}
provider "aws" {
  region = "us-east-1"
}

# Step 1: Create a custom IAM policy with full admin access
resource "aws_iam_policy" "full_admin_policy" {
  name        = "FullAdminPolicy"
  description = "Custom policy with full admin access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# Step 2: Create IAM role and attach the custom policy
resource "aws_iam_role" "full_admin_access_role" {
  name = "full_admin_access_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "instance_policy_attachment" {
  policy_arn = aws_iam_policy.full_admin_policy.arn
  role       = aws_iam_role.full_admin_access_role.name
}

# Step 3: Create IAM instance profile and associate the IAM role
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "full_admin_access_instance_profile"
  role = aws_iam_role.full_admin_access_role.name
}

# Step 4: Launch EC2 instance with IAM instance profile
resource "aws_instance" "ec2" {
  ami           = "ami-05548f9cecf47b442"
  instance_type = "t2.micro"
  key_name      = "akshaykey"
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name
  vpc_security_group_ids = [aws_security_group.allow_tls.id]

 user_data = <<EOF
#!/bin/bash
BUCKET=artifactory-fdecb1
sudo yum update 
sudo yum install java-1.8.0-amazon-corretto-devel.x86_64  -y 
wget https://dlcdn.apache.org/tomcat/tomcat-8/v8.5.91/bin/apache-tomcat-8.5.91.zip
sudo yum install zip  -y 
sudo unzip apache-tomcat-8.5.91.zip
sudo mv apache-tomcat-8.5.91 /mnt/tomcat
KEY=`aws s3 ls $BUCKET --recursive | sort | tail -n 1 | awk '{print $4}'`
aws s3 cp s3://$BUCKET/$KEY /mnt/tomcat/webapps/
sudo mv /mnt/tomcat/webapps/$KEY /mnt/tomcat/webapps/student
sudo chown -R ec2-user: /mnt/tomcat
cd /mnt/tomcat/bin
sudo chmod 755 *
sudo ./catalina.sh start 

  EOF
  tags = {
    Name = "allow_tls"
  }
}

resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
}
 ingress {
    description = "TLS from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
}

 ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 ingress {
    description = "TLS from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
