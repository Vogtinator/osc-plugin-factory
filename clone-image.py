import os
import sys
from docker_registry import DockerRegistryClient

source = sys.argv[1]
dc_source = DockerRegistryClient("https://registry-1.docker.io", "favogt", os.environ["DOCKER_PASSWORD"], source.split(":")[0], False)

dest = sys.argv[2]
dc_dest = DockerRegistryClient("https://registry-1.docker.io", "favogt", os.environ["DOCKER_PASSWORD"], dest.split(":")[0])

with open(source.split("/")[1], "wb") as manifestlist_file:
    manifestlist_file.write(dc_source.getManifestRaw(source.split(":")[-1]))

manifestlist = dc_source.getManifest(source.split(":")[-1])

if "manifests" not in manifestlist:
    print("Can't copy v1 manifest, use skopeo")
    sys.exit(1)

for manifestentry in manifestlist["manifests"]:
    print(manifestentry)
    with open(manifestentry["digest"], "wb") as manifest_file:
        manifest_file.write(dc_source.getManifestRaw(manifestentry["digest"]))

    manifest = dc_source.getManifest(manifestentry["digest"])
    with open(manifest["config"]["digest"], "wb") as config_file:
        config_file.write(dc_source.getBlobRaw(manifest["config"]["digest"]))

    dc_dest.uploadBlob(manifest["config"]["digest"], manifest["config"]["digest"])

    for layer in manifest["layers"]:
        print(layer)
        with open(layer["digest"], "wb") as layer_file:
            layer_file.write(dc_source.getBlobRaw(layer["digest"]))

        dc_dest.uploadBlob(layer["digest"], layer["digest"])

    dc_dest.uploadManifestFile(manifestentry["digest"], manifestentry["digest"])

dc_dest.uploadManifestFile(source.split("/")[1], dest.split(":")[1])
