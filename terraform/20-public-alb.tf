resource "aws_lb" "alb" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups = [
    lookup(module.security_groups.security_group_ids, "public_alb"),
  ]
  subnets = [
    lookup(module.network.subnet_ids, "public-a"),
    lookup(module.network.subnet_ids, "public-c"),
  ]
}

resource "aws_lb_listener" "instance" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "8080"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.instance.arn
  }
}

resource "aws_lb_target_group" "instance" {
  name     = "${local.name_prefix}-alb-instance-tg"
  vpc_id   = module.network.vpc_id
  port     = 80
  protocol = "HTTP"
}

resource "aws_lb_target_group_attachment" "instance" {
  count = 2

  target_group_arn = aws_lb_target_group.instance.arn
  target_id        = aws_instance.web[count.index].id
  port             = 80
}
