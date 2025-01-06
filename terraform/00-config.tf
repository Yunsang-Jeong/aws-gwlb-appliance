resource "random_id" "this" {
  byte_length = 4
}

locals {
  name_prefix    = "gwlb-${random_id.this.hex}"
  vpc_cidr_block = "10.0.0.0/16"
  subnets = [
    {
      identifier            = "public-a"
      availability_zone     = "ap-northeast-2a"
      cidr_block            = "10.0.1.0/24"
      enable_route_with_igw = true
      create_nat            = true
    },
    {
      identifier            = "public-c"
      availability_zone     = "ap-northeast-2c"
      cidr_block            = "10.0.2.0/24"
      enable_route_with_igw = true
    },
    {
      identifier            = "dmz-a"
      availability_zone     = "ap-northeast-2a"
      cidr_block            = "10.0.11.0/24"
      enable_route_with_nat = true
    },
    {
      identifier            = "dmz-c"
      availability_zone     = "ap-northeast-2c"
      cidr_block            = "10.0.12.0/24"
      enable_route_with_nat = true
    },
    {
      identifier            = "app-a"
      availability_zone     = "ap-northeast-2a"
      cidr_block            = "10.0.21.0/24"
      enable_route_with_nat = true
    },
    {
      identifier            = "app-c"
      availability_zone     = "ap-northeast-2c"
      cidr_block            = "10.0.22.0/24"
      enable_route_with_nat = true
    },
  ]
  security_groups = [
    {
      identifier  = "public_alb"
      description = "public_alb"
      ingresses = [
        {
          identifier  = "public",
          description = "public",
          from_port   = "8080", to_port = "8080", protocol = "tcp", cidr_blocks = ["0.0.0.0/0"],
        },
      ]
    },
    {
      identifier  = "gwlb_appliance"
      description = "gwlb_appliance"
      ingresses = [
        {
          identifier  = "geneve",
          description = "geneve",
          from_port   = "6081", to_port = "6081", protocol = "udp", cidr_blocks = ["0.0.0.0/0"],
        },
        {
          identifier  = "health",
          description = "health",
          from_port   = "80", to_port = "80", protocol = "tcp", cidr_blocks = ["0.0.0.0/0"],
        },
      ]
    },
    {
      identifier  = "web"
      description = "web"
      ingresses = [
        {
          identifier  = "public_alb",
          description = "public_alb",
          from_port   = "80", to_port = "80", protocol = "tcp", cidr_blocks = ["0.0.0.0/0"],
        },
      ]
    },
  ]
}
