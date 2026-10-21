variable "REGISTRY" {
  default = "us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases"
}

variable "TAG" {
  default = "local"
}

variable "DOCKERHUB_MIRROR" {
  default = "us-west1-docker.pkg.dev/opensteer-admin/dockerhub"
}

variable "SOURCE_REVISION" {
  default = "0000000000000000000000000000000000000000"
}

group "default" {
  targets = ["portablefs-files"]
}

target "portablefs-files" {
  context    = "."
  dockerfile = "deploy/files/Containerfile"
  platforms  = ["linux/amd64"]
  provenance = false
  args = {
    GO_IMAGE       = "${DOCKERHUB_MIRROR}/library/golang:1.26.10-bookworm@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51"
    SOURCE_REVISION = "${SOURCE_REVISION}"
    UBUNTU_IMAGE   = "${DOCKERHUB_MIRROR}/library/ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea"
  }
  tags = ["${REGISTRY}/portablefs-files:${TAG}"]
}
