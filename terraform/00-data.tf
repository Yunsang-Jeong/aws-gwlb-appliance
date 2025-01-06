locals {
  amazon_linux_2023_x86_id        = data.aws_ami.amazon_linux_2023_x86.id
  assume_role_policy_for_ec2_json = data.aws_iam_policy_document.assume_role_policy_for_ec2.json
}

data "aws_caller_identity" "current" {}


data "aws_ami" "amazon_linux_2023_x86" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "name"
    values = ["al2023-ami-2023*"]
  }
}

data "aws_iam_policy_document" "assume_role_policy_for_ec2" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}
