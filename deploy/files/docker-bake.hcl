variable "REGISTRY" {
  default = "us-west1-docker.pkg.dev/opensteer-admin/staging"
}

variable "TAG" {
  default = "local"
}

variable "DOCKERHUB_MIRROR" {
  default = "us-west1-docker.pkg.dev/opensteer-admin/dockerhub"
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
    GO_IMAGE     = "${DOCKERHUB_MIRROR}/library/golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36"
    UBUNTU_IMAGE = "${DOCKERHUB_MIRROR}/library/ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea"
  }
  tags       = ["${REGISTRY}/portablefs-files:${TAG}"]
  cache-from = ["type=registry,ref=${REGISTRY}/cache/portablefs-files"]
  cache-to   = ["type=registry,ref=${REGISTRY}/cache/portablefs-files,mode=max,image-manifest=true,oci-mediatypes=true"]
}
