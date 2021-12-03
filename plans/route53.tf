resource "aws_route53_record" "appserver_a" {
    zone_id = local.route53_hosted_zone
    name    = local.instance_hostname
    type    = "A"
    ttl     = 300
    records = linode_instance.appserver.ipv4
}
resource "aws_route53_record" "appserver_aaaa" {
    zone_id = local.route53_hosted_zone
    name    = local.instance_hostname
    type    = "AAAA"
    ttl     = 300
    records = [
        element(split("/", linode_instance.appserver.ipv6), 0)
    ]
}
