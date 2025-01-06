resource "aws_instance" "gwlb" {
  count = 1

  ami                  = local.amazon_linux_2023_x86_id
  instance_type        = "m5.large"
  iam_instance_profile = aws_iam_instance_profile.gwlb.name
  subnet_id = count.index % 2 == 0 ? (
    lookup(module.network.subnet_ids, "dmz-a")
    ) : (
    lookup(module.network.subnet_ids, "dmz-c")
  )
  vpc_security_group_ids = [
    lookup(module.security_groups.security_group_ids, "gwlb_appliance"),
  ]
  user_data = <<-EOD
    #!/bin/bash
    mkdir -p /opt/gwlb
    aws s3 cp s3://${aws_s3_bucket.this.id}/appliance.py /opt/gwlb/appliance.py
    chmod +x /opt/gwlb/appliance.py
    cat <<EOF > /etc/systemd/system/gwlb.service
    [Unit]
    Description=GWLB Appliacne for test
    After=network.target

    [Service]
    ExecStart=/usr/bin/python3 /opt/gwlb/appliance.py
    Restart=always
    User=root

    [Install]
    WantedBy=multi-user.target
    EOF

    systemctl daemon-reload
    systemctl enable gwlb.service
    systemctl start gwlb.service
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
    Name = "${local.name_prefix}-gwlb"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "gwlb" {
  name_prefix        = "${local.name_prefix}-service-gwlb"
  assume_role_policy = local.assume_role_policy_for_ec2_json
}

resource "aws_iam_instance_profile" "gwlb" {
  name = "${local.name_prefix}-service-gwlb"
  role = aws_iam_role.gwlb.name
}

resource "aws_iam_role_policy_attachment" "gwlb" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
  ])
  
  role       = aws_iam_role.gwlb.name
  policy_arn = each.key
}

resource "aws_s3_bucket" "this" {
  bucket = "${local.name_prefix}-bucket"
}

resource "aws_s3_object" "object" {
  bucket = aws_s3_bucket.this.id
  key    = "appliance.py"
  source = "../appliance.py"
}