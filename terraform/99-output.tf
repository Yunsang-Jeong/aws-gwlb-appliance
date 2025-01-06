output "publc_alb_dns" {
  value = aws_lb.alb.dns_name
}

output "gwlb_instance_ids" {
  value = aws_instance.gwlb.*.id
}
