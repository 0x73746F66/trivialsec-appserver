data "local_file" "appserver" {
    filename = "${path.root}/../bin/alpine-appserver"
}
resource "linode_stackscript" "appserver" {
  label = "appserver"
  description = "Installs appserver"
  script = data.local_file.appserver.content
  images = [local.linode_default_image]
  rev_note = "v1"
}
output "appserver_stackscript_id" {
  value = linode_stackscript.appserver.id
}
