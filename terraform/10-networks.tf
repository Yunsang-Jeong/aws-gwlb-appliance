module "network" {
  source = "github.com/Yunsang-Jeong/terraform-aws-network"

  name_prefix    = local.name_prefix
  vpc_cidr_block = local.vpc_cidr_block
  subnets        = local.subnets
  create_igw     = true
}

resource "aws_vpc_endpoint" "s3_gw" {
  vpc_id          = module.network.vpc_id
  service_name    = "com.amazonaws.ap-northeast-2.s3"
  route_table_ids = values(module.network.route_table_ids)
}

module "security_groups" {
  source = "github.com/Yunsang-Jeong/terraform-aws-securitygroup"

  vpc_id          = module.network.vpc_id
  security_groups = local.security_groups
}

resource "aws_route" "public_a" {
  for_each = toset([
    module.network.subnet_cidr_blocks["app-a"],
    module.network.subnet_cidr_blocks["app-c"],
  ])

  route_table_id         = module.network.route_table_ids["public-a"]
  destination_cidr_block = each.key
  vpc_endpoint_id        = aws_vpc_endpoint.gwlb["dmz-a"].id
}

resource "aws_route" "public_c" {
  for_each = toset([
    module.network.subnet_cidr_blocks["app-a"],
    module.network.subnet_cidr_blocks["app-c"],
  ])

  route_table_id         = module.network.route_table_ids["public-c"]
  destination_cidr_block = each.key
  vpc_endpoint_id        = aws_vpc_endpoint.gwlb["dmz-c"].id
}

resource "aws_route" "app_a" {
  for_each = {
    public_a = {
      destination_cidr_block = module.network.subnet_cidr_blocks["public-a"]
      vpc_endpoint_id        = aws_vpc_endpoint.gwlb["dmz-a"].id
    }
    public_c = {
      destination_cidr_block = module.network.subnet_cidr_blocks["public-c"]
      vpc_endpoint_id        = aws_vpc_endpoint.gwlb["dmz-c"].id
    }
  }

  route_table_id         = module.network.route_table_ids["app-a"]
  destination_cidr_block = each.value.destination_cidr_block
  vpc_endpoint_id        = each.value.vpc_endpoint_id
}

resource "aws_route" "app_c" {
  for_each = {
    public_a = {
      destination_cidr_block = module.network.subnet_cidr_blocks["public-a"]
      vpc_endpoint_id        = aws_vpc_endpoint.gwlb["dmz-a"].id
    }
    public_c = {
      destination_cidr_block = module.network.subnet_cidr_blocks["public-c"]
      vpc_endpoint_id        = aws_vpc_endpoint.gwlb["dmz-c"].id
    }
  }

  route_table_id         = module.network.route_table_ids["app-c"]
  destination_cidr_block = each.value.destination_cidr_block
  vpc_endpoint_id        = each.value.vpc_endpoint_id
}
