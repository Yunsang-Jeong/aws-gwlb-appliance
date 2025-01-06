resource "aws_lb" "gwlb" {
  name                             = "${local.name_prefix}-gwlb"
  load_balancer_type               = "gateway"
  enable_cross_zone_load_balancing = true
  subnets = [
    lookup(module.network.subnet_ids, "dmz-a"),
    lookup(module.network.subnet_ids, "dmz-c"),
  ]
}

resource "aws_vpc_endpoint_service" "gwlb" {
  gateway_load_balancer_arns = [aws_lb.gwlb.arn]
  allowed_principals         = [data.aws_caller_identity.current.arn]
  acceptance_required        = false
}

resource "aws_vpc_endpoint" "gwlb" {
  for_each = {
    dmz-a = lookup(module.network.subnet_ids, "dmz-a"),
    dmz-c = lookup(module.network.subnet_ids, "dmz-c"),
  }

  service_name      = aws_vpc_endpoint_service.gwlb.service_name
  vpc_endpoint_type = aws_vpc_endpoint_service.gwlb.service_type
  vpc_id            = module.network.vpc_id
  subnet_ids        = [each.value]
}

resource "aws_lb_listener" "gwlb" {
  load_balancer_arn = aws_lb.gwlb.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gwlb.arn
  }
}

resource "aws_lb_target_group" "gwlb" {
  name                 = "${local.name_prefix}-gwlb-tg"
  protocol             = "GENEVE"
  vpc_id               = module.network.vpc_id
  port                 = 6081
  deregistration_delay = 0
}

resource "aws_lb_target_group_attachment" "gwlb" {
  count = 1

  target_group_arn = aws_lb_target_group.gwlb.arn
  target_id        = aws_instance.gwlb[count.index].id
}

