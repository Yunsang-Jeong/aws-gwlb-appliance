resource "aws_instance" "web" {
  count = 2

  ami                  = local.amazon_linux_2023_x86_id
  instance_type        = "m5.large"
  iam_instance_profile = aws_iam_instance_profile.web.name
  subnet_id = count.index % 2 == 0 ? (
    lookup(module.network.subnet_ids, "app-a")
    ) : (
    lookup(module.network.subnet_ids, "app-c")
  )
  vpc_security_group_ids = [
    lookup(module.security_groups.security_group_ids, "web"),
  ]
  user_data = <<-EOD
  #!/bin/bash
  dnf update
  dnf install -y nginx 
  systemctl start nginx.service 
  systemctl enable nginx.service 
  EOD

  root_block_device {
    volume_type           = "gp3"
    volume_size           = "30"
    iops                  = 3000
    throughput            = 125
    delete_on_termination = true
  }

  metadata_options {
    instance_metadata_tags = "enabled"
  }

  tags = {
    Name = "${local.name_prefix}-web"
  }
}

resource "aws_iam_role" "web" {
  name_prefix        = "${local.name_prefix}-web"
  assume_role_policy = local.assume_role_policy_for_ec2_json
}

resource "aws_iam_instance_profile" "web" {
  name = "${local.name_prefix}-web"
  role = aws_iam_role.web.name
}

resource "aws_iam_role_policy_attachment" "web" {
  role       = aws_iam_role.web.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

