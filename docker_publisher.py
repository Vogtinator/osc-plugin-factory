#!/usr/bin/python3
#
# Copyright (c) 2018 SUSE LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This script's job is to listen for new releases of products with docker images
# and publish those.
# For Tumbleweed, the images are published within RPMs as part of the OSS repo,
# so after openQA testing they need to be downloaded and extracted.
# For Leap, the .tar.xz can be downloaded directly.
# Both of those get pushed to the docker hub.
# It's also possible to push to a git repo for the official library.

import argparse
import copy
import glob
import json
import os
import re
import requests
import shutil
import subprocess
import sys
import tempfile
import zlib
from lxml import etree as xml

import docker_registry

REPOMD_NAMESPACES = {'md': "http://linux.duke.edu/metadata/common",
                     'repo': "http://linux.duke.edu/metadata/repo",
                     'rpm': "http://linux.duke.edu/metadata/rpm"}


def recompress(source, dest):
    """This function takes an archive as source and puts it to dest,
    recompressing it into a different format"""
    map_output = {'.xz':  "xz -c -",
                  '.gz':  "gzip -c -",
                  '.bz2': "bzip2 -c -"}

    command_output = None
    command_input = None

    for suffix, command in map_output.items():
        if dest.endswith(suffix):
            command_output = command

    map_input = {'application/x-xz':    "xz -cd",
                 'application/x-gzip':  "gzip -cd",
                 'application/x-bzip2': "bzip2 -cd"}

    mime = subprocess.check_output(["file", "--mime-type", "-b", source]).decode("utf-8").strip()
    if mime in map_input:
        command_input = map_input[mime]

    if command_output is None or command_input is None:
        return False

    # Same input and output format -> just copy
    if command_output.split(' ')[0] == command_input.split(' ')[0]:
        shutil.copyfile(source, dest)
        return True

    ret = subprocess.call("%s '%s' | %s > '%s'" % (command_input, source, command_output, dest), shell=True)
    return ret == 0


class DockerImagePublisher:
    """Base class for handling the publishing of docker images.
    This handles multiple architectures, which have different layers
    and therefore versions."""

    def releasedDockerImageVersion(self, arch):
        """This function returns an identifier for the released docker
        image's version."""
        raise Exception("pure virtual")

    def prepareReleasing(self):
        """Prepare the environment to allow calls to releaseDockerImage."""
        raise Exception("pure virtual")

    def addImage(self, version, arch, image_path):
        """This function adds the docker image with the image manifest, config layers
        in image_path."""
        raise Exception("pure virtual")

    def finishReleasing(self):
        """This function publishes the released layers."""
        raise Exception("pure virtual")


class DockerPublishException(Exception):
    pass


class DockerImageFetcher:
    """Base class for handling the acquiring of docker images."""

    def currentVersion(self):
        """This function returns the version of the latest available version
        of the image for the product."""
        raise Exception("pure virtual")

    def getDockerImage(self, callback):
        """This function downloads the root fs layer and calls callback
        with its path as argument."""
        raise Exception("pure virtual")


class DockerFetchException(Exception):
    pass


class DockerImagePublisherGit(DockerImagePublisher):
    def __init__(self, git_path, git_branch, path="."):
        """Initialize a DockerImagePublisherGit with:
        @git_path: Path to the local git repo clone
        @git_branch: Branch of the image
        @path: Path to the directory within the branch which will contain a
        directory for each architecture, containing:
        - Dockerfile (including version in a comment)
        - *.tar.xz: Images"""
        self.git_path = git_path
        self.git_branch = git_branch
        self.path = path
        self.updated_images = {}

        self.git_call = ["git", "-C", self.git_path]

        ret = subprocess.call(self.git_call + ["fetch", "origin"])
        if ret != 0:
            raise DockerFetchException("Could not fetch from origin")

    def releasedDockerImageVersion(self, arch):
        # Read from git using cat-file to avoid expensive checkout.
        args = self.git_call + ["cat-file", "--textconv", "origin/%s:%s/%s/Dockerfile" % (self.git_branch, self.path, arch)]
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            version_regex = re.compile(r"^# Version: (.+)$")
            for line in p.stdout:
                match = version_regex.match(line.decode('utf-8').strip())
                if match:
                    return match.group(1)

        return "0"

    def generateDockerFile(self, version, filename):
        """Return the contents of a docker file for the image"""
        return """FROM scratch
MAINTAINER Fabian Vogt <fvogt@suse.com>
# Version: %s
ADD %s /
""" % (version, filename)

    def prepareReleasing(self):
        # Try to delete the old branch
        try:
            subprocess.call(self.git_call + ["checkout", "-q", "origin/%s" % (self.git_branch)])
            subprocess.check_output(self.git_call + ["branch", "-q", "-D", self.git_branch],
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            pass

        # We do an orphan checkout to not carry the history around
        ret = subprocess.call(self.git_call + ["checkout", "-q", "--orphan", self.git_branch])
        if ret != 0:
            raise DockerPublishException("Could not checkout git branch")

        return True

    def addImage(self, version, arch, image_path):
        target_dir = "%s/%s/%s" % (self.git_path, self.path, arch)

        # Remove all old files
        for file in glob.glob(target_dir + "/*"):
            os.remove(file)

        # Re-compress it into the correct location and format
        targetfilename = "openSUSE-Tumbleweed-%s-%s.tar.xz" % (arch, version)

        # Parse the manifest to get the name of the root tar.xz
        manifest = json.loads(open(image_path + "/manifest.json").read())
        layers = manifest[0]['Layers']
        if len(layers) != 1:
            raise DockerPublishException("Unexpected count of layers in the image")

        image_layer_file = image_path + "/" + layers[0]

        if not recompress(image_layer_file, target_dir + "/" + targetfilename):
            raise DockerPublishException("Could not repackage the root fs layer")

        # Update the version number
        try:
            with open(target_dir + "/Dockerfile", "w") as dockerfile:
                dockerfile.write(self.generateDockerFile(version, targetfilename))
        except (IOError, OSError) as e:
            raise DockerPublishException("Could not update the version file: %s" % e)

        self.updated_images[arch] = version

        return True

    def finishReleasing(self):
        ret = subprocess.call(self.git_call + ["add", "--all"])
        if ret == 0:
            message = "Update image to current version\n"
            for arch, version in self.updated_images.items():
                message += "\n- Update %s image to %s" % (arch, version)

            ret = subprocess.call(self.git_call + ["commit", "-am", message])

        if ret != 0:
            raise DockerPublishException("Could not create commit")

        self.updated_images = {}

        ret = subprocess.call(self.git_call + ["push", "--force", "origin", self.git_branch])
        if ret != 0:
            raise DockerPublishException("Could not push")

        return True


class DockerImagePublisherRegistry(DockerImagePublisher):
    """The DockerImagePublisherRegistry class works by using a manifest list to
    describe a tag. The list contains a manifest for each architecture.
    The manifest will be edited instead of replaced, which means if you don't
    call addImage for an architecture, the existing released image stays in place."""
    MAP_ARCH_RPM_DOCKER = {'x86_64': "amd64",
                           'armv7l': "arm",
                           'aarch64': "arm64",
                           'ppc64le': "ppc64le",
                           's390x': "s390x"}

    def __init__(self, dhc, tag, aliases=[]):
        """Construct a DIPR by passing a DockerRegistryClient instance as dhc
        and a name for a tag as tag.
        Optionally, add tag aliases as aliases. Those will only be written to,
        never read."""
        self.dhc = dhc
        self.tag = tag
        self.aliases = aliases
        # Construct a new manifestlist for the tag.
        self.new_manifestlist = None
        # Compare it with the released manifestlist after publishing
        # to delete the superseded manifests
        self.released_manifestlist = None

    def getDockerArch(self, arch):
        if arch not in self.MAP_ARCH_RPM_DOCKER:
            raise DockerPublishException("Unknown arch %s" % arch)

        return self.MAP_ARCH_RPM_DOCKER[arch]

    def releasedDockerImageVersion(self, arch):
        docker_arch = self.getDockerArch(arch)

        manifestlist = self.dhc.getManifest(self.tag)

        if manifestlist is None:
            # No manifest -> force outdated version
            return "0"

        for manifest in manifestlist['manifests']:
            if manifest['platform']['architecture'] == docker_arch:
                if 'vnd-opensuse-version' in manifest:
                    return manifest['vnd-opensuse-version']

        # Arch not in the manifest -> force outdated version
        return "0"

    def prepareReleasing(self):
        if self.released_manifestlist is not None:
            raise DockerPublishException("Did not finish publishing")

        self.released_manifestlist = self.dhc.getManifest(self.tag)
        self.new_manifestlist = copy.deepcopy(self.released_manifestlist)

        # Generate an empty manifestlist
        if not self.new_manifestlist:
            self.new_manifestlist = {'schemaVersion': 2,
                                     'tag': self.tag,
                                     'mediaType': "application/vnd.docker.distribution.manifest.list.v2+json",
                                     'manifests': []}

        return True

    def getV2ManifestEntry(self, filename, mediaType):
        """For V1 -> V2 schema conversion. filename's basename has to equal the digest"""
        digest = os.path.basename(filename)
        if not digest.startswith("sha256"):
            raise DockerPublishException("Invalid manifest contents")

        return {'mediaType': mediaType,
                'size': os.path.getsize(filename),
                'digest': digest}

    def convertV1ToV2Manifest(self, path, manifest_v1):
        """Converts the v1 manifest in manifest_v1 to a V2 manifest and returns it"""

        layers = []
        for layer_filename in manifest_v1['Layers']:
            layers += [self.getV2ManifestEntry(path + "/" + layer_filename,
                                               "application/vnd.docker.image.rootfs.diff.tar.gzip")]

        return {'schemaVersion': 2,
                'mediaType': "application/vnd.docker.distribution.manifest.v2+json",
                'config': self.getV2ManifestEntry(path + "/" + manifest_v1['Config'],
                                                  "application/vnd.docker.container.image.v1+json"),
                'layers': layers}

    def addImage(self, version, arch, image_path):
        docker_arch = self.getDockerArch(arch)

        manifest = None

        with open(image_path + "/manifest.json") as manifest_file:
            manifest = json.load(manifest_file)

        manifest_v2 = self.convertV1ToV2Manifest(image_path, manifest[0])

        # Upload blobs
        if not self.dhc.uploadBlob(image_path + "/" + manifest_v2['config']['digest']):
            raise DockerPublishException("Could not upload the image config")

        for layer in manifest_v2['layers']:
            if not self.dhc.uploadBlob(image_path + "/" + layer['digest']):
                raise DockerPublishException("Could not upload an image layer")

        # Upload the manifest
        manifest_content = json.dumps(manifest_v2).encode("utf-8")
        manifest_digest = self.dhc.uploadManifest(manifest_content)

        if manifest_digest is False:
            raise DockerPublishException("Could not upload the manifest")

        # Register the manifest in the list
        replaced = False
        for manifest in self.new_manifestlist['manifests']:
            if manifest['platform']['architecture'] == docker_arch:
                manifest['mediaType'] = manifest_v2['mediaType']
                manifest['size'] = len(manifest_content)
                manifest['digest'] = manifest_digest
                manifest['vnd-opensuse-version'] = version
                replaced = True

        if not replaced:
            # Add it instead
            manifest = {'mediaType': manifest_v2['mediaType'],
                        'size': len(manifest_content),
                        'digest': manifest_digest,
                        'vnd-opensuse-version': version,
                        'platform': {
                            'architecture': docker_arch,
                            'os': "linux"
                            }
                        }
            self.new_manifestlist['manifests'] += [manifest]

        return True

    def finishReleasing(self):
        released_manifestlist_digest = self.dhc.getManifestDigest(self.tag)

        # Generate the manifest content
        manifestlist_content = json.dumps(self.new_manifestlist).encode('utf-8')

        # Push the new manifest list
        if not self.dhc.uploadManifest(manifestlist_content, self.tag):
            raise DockerPublishException("Could not upload the new manifest list")

        # Push the aliases
        for alias in self.aliases:
            if not self.dhc.uploadManifest(manifestlist_content, alias):
                raise DockerPublishException("Could not push an manifest list alias")

        # Delete the old manifest list
        if released_manifestlist_digest is not False:
            self.dhc.deleteManifest(released_manifestlist_digest)

        # Delete superseded manifests
        new_manifests = [manifest['digest'] for manifest in self.new_manifestlist['manifests']]
        released_manifests = []
        if self.released_manifestlist is not None:
            released_manifests = [manifest['digest'] for manifest in self.released_manifestlist['manifests']]

        for manifest in released_manifests:
            if manifest not in new_manifests:
                self.dhc.deleteManifest(manifest)

        self.new_manifestlist = None
        self.released_manifestlist = None

        return True


class DockerImageFetcherURL(DockerImageFetcher):
    """A trivial implementation. It downloads a (compressed) tar archive and passes
    the decompressed contents to the callback.
    The version number can't be determined automatically (it would need to extract
    the image and look at /etc/os-release each time - too expensive.) so it
    has to be passed manually."""
    def __init__(self, version, url):
        self.version = version
        self.url = url

    def currentVersion(self):
        return self.version

    def getDockerImage(self, callback):
        """Download the tar and extract it"""
        with tempfile.NamedTemporaryFile() as tar_file:
            tar_file.write(requests.get(self.url).content)
            with tempfile.TemporaryDirectory() as tar_dir:
                # Extract the .tar.xz into the dir
                subprocess.call("tar -xaf '%s' -C '%s'" % (tar_file.name, tar_dir), shell=True)
                return callback(tar_dir)


class DockerImageFetcherOBS(DockerImageFetcher):
    """Uses the OBS API to access the build artifacts.
    Url has to be https://build.opensuse.org/public/build/<project>/<repo>/<arch>/<pkgname>"""
    def __init__(self, url):
        self.url = url

    def _getFilename(self):
        """Return the name of the binary at the URL with the filename ending in
        .docker.tar."""
        binarylist_req = requests.get(self.url)
        binarylist = xml.fromstring(binarylist_req.content)
        for binary in binarylist.xpath("binary/@filename"):
            if binary.endswith(".docker.tar"):
                return binary

        raise DockerFetchException("No docker image built in the repository")

    def currentVersion(self):
        """Return {version}-Build{build} of the docker file."""
        filename = self._getFilename()
        return re.match(".*((-[^-]+){2})\.docker\.tar", filename).group(1)[1:]

    def getDockerImage(self, callback):
        """Download the tar and extract it"""
        filename = self._getFilename()
        with tempfile.NamedTemporaryFile() as tar_file:
            tar_file.write(requests.get(self.url + "/" + filename).content)
            with tempfile.TemporaryDirectory() as tar_dir:
                # Extract the .tar into the dir
                subprocess.call("tar -xaf '%s' -C '%s'" % (tar_file.name, tar_dir), shell=True)
                return callback(tar_dir)


class DockerImageFetcherRepo(DockerImageFetcher):
    """This can be used when the image is wrapped into an RPM and released as
    part of the main repository, as it is the case for Tumbleweed.
    The version equals the version of the product in the repository, determined
    by the versioned_redir URL redirection target."""
    def __init__(self, versioned_redir, repourl, packagename, arch):
        self.versioned_redir = versioned_redir
        self.repourl = repourl
        self.packagename = packagename
        self.arch = arch

    def currentVersion(self):
        # For TW we ask the mirrorbrain server about the -Current redirection target
        meta4_xml = requests.get(self.versioned_redir + ".meta4")
        meta4 = xml.fromstring(meta4_xml.content)
        filename = meta4.xpath("//m:metalink//m:file//@name", namespaces={'m': "urn:ietf:params:xml:ns:metalink"})[0]
        return re.search(r"Snapshot(\d+)-", filename).group(1)

    def fetchPrimaryXml(self):
        repoindex_req = requests.get(self.repourl + "/repodata/repomd.xml")
        repoindex = xml.fromstring(repoindex_req.content)
        path_primary = repoindex.xpath("string(./repo:data[@type='primary']/repo:location/@href)",
                                       namespaces=REPOMD_NAMESPACES)
        primary_req = requests.get(self.repourl + "/" + path_primary)
        return zlib.decompress(primary_req.content, zlib.MAX_WBITS | 32)

    def getRPMUrl(self, pkgname, arch):
        primary_tree = xml.fromstring(self.fetchPrimaryXml())
        pkgs = primary_tree.xpath("md:package[./md:name/text() = '%s']" % (pkgname),
                                  namespaces=REPOMD_NAMESPACES)

        for pkg in pkgs:
            if arch in pkg.xpath("./md:arch/text()", namespaces=REPOMD_NAMESPACES):
                return self.repourl + "/" + pkg.xpath("./md:location/@href",
                                                      namespaces=REPOMD_NAMESPACES)[0]

    def getDockerImage(self, callback):
        # Download and extract the RPM from the repo.
        image_layer_file = tempfile.NamedTemporaryFile(delete=False)

        rpm_url = self.getRPMUrl(self.packagename, self.arch)
        if rpm_url is None:
            raise DockerFetchException("Could not get the URL for the RPM package")

        with tempfile.NamedTemporaryFile() as rpm_file:
            rpm_file.write(requests.get(rpm_url).content)
            with tempfile.TemporaryDirectory() as tar_dir:
                # Extract the .tar.xz inside the RPM into the dir
                subprocess.call("rpm2cpio '%s' | cpio -i --quiet --to-stdout \*.tar.xz | tar -xJf - -C '%s'" % (rpm_file.name, tar_dir), shell=True)
                return callback(tar_dir)


def run():
    drc_tw = docker_registry.DockerRegistryClient(os.environ['REGISTRY'], os.environ['REGISTRY_USER'], os.environ['REGISTRY_PASSWORD'], os.environ['REGISTRY_REPO_TW'])
    drc_leap = docker_registry.DockerRegistryClient(os.environ['REGISTRY'], os.environ['REGISTRY_USER'], os.environ['REGISTRY_PASSWORD'], os.environ['REGISTRY_REPO_LEAP'])

    config = {
        'tumbleweed': {
            'fetchers': {
                'x86_64': DockerImageFetcherRepo(versioned_redir="http://download.opensuse.org/tumbleweed/iso/openSUSE-Tumbleweed-DVD-x86_64-Current.iso",
                                                 repourl="http://download.opensuse.org/tumbleweed/repo/oss",
                                                 packagename="opensuse-tumbleweed-image",
                                                 arch="x86_64"),
                # No release yet, so we'll have to take them from the OBS project directly
#                'aarch64': DockerImageFetcherOBS(url="https://build.opensuse.org/public/build/openSUSE:Factory:Containers/container_ARM/aarch64/opensuse-tumbleweed-image"),
#                'ppc64le': DockerImageFetcherOBS(url="https://build.opensuse.org/public/build/openSUSE:Factory:Containers/container_PowerPC/ppc64le/opensuse-tumbleweed-image"),
#                's390x': DockerImageFetcherOBS(url="https://build.opensuse.org/public/build/openSUSE:Factory:Containers/container_zSystems/s390x/opensuse-tumbleweed-image"),
            },
            'publisher': DockerImagePublisherRegistry(drc_tw, "latest"),
        },
        'leap-42.3': {
            'fetchers': {
                # No officially built images available - use the devel prj
                'x86_64': DockerImageFetcherOBS(url="https://build.opensuse.org/public/build/Virtualization:containers:images:openSUSE-Leap-42.3/containers/x86_64/openSUSE-Leap-42.3-container-image"),
                'aarch64': DockerImageFetcherOBS(url="https://build.opensuse.org/public/build/Virtualization:containers:images:openSUSE-Leap-42.3/containers/aarch64/openSUSE-Leap-42.3-container-image"),
                'ppc64le': DockerImageFetcherOBS(url="https://build.opensuse.org/public/build/Virtualization:containers:images:openSUSE-Leap-42.3/containers/ppc64le/openSUSE-Leap-42.3-container-image"),
            },
            'publisher': DockerImagePublisherRegistry(drc_leap, "42.3", ["42"]),
        },
        'leap-15.0': {
            'fetchers': {
                # No official release available yet - use OBS directly
                'x86_64': DockerImageFetcherOBS(url="https://build.opensuse.org/public/build/openSUSE:Leap:15.0:Images/images/x86_64/opensuse-leap-image"),
            },
            'publisher': DockerImagePublisherRegistry(drc_leap, "15.0", ["15"]),
        },
    }

    # Parse args after defining the config - the available distros are included
    # in the help output
    parser = argparse.ArgumentParser(description="Docker image publish script",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("distros", metavar="distro", type=str, nargs="*",
                        default=[key for key in config],
                        help="Which distros to check for images to publish.")

    args = parser.parse_args()

    success = True

    for distro in args.distros:
        print("Handling %s" % distro)

        archs_to_update = {}
        fetchers = config[distro]['fetchers']
        publisher = config[distro]['publisher']

        for arch in fetchers:
            print("\tArchitecture %s" % arch)
            try:
                current = fetchers[arch].currentVersion()
                print("\t\tAvailable version: %s" % current)

                released = publisher.releasedDockerImageVersion(arch)
                print("\t\tReleased version: %s" % released)

                if current != released:
                    archs_to_update[arch] = current
            except Exception as e:
                print("\t\tException during version fetching: %s" % e)

        if not archs_to_update:
            print("\tNothing to do.")
            continue

        if not publisher.prepareReleasing():
            print("\tCould not prepare the publishing")
            success = False
            continue

        for arch, version in archs_to_update.items():
            print("\tUpdating %s image to version %s" % (arch, version))
            try:
                fetchers[arch].getDockerImage(lambda image_path: publisher.addImage(version=version,
                                                                                    arch=arch,
                                                                                    image_path=image_path))
            except DockerFetchException as dfe:
                print("\t\tCould not fetch the image: %s" % dfe)
                success = False
                continue
            except DockerPublishException as dpe:
                print("\t\tCould not publish the image: %s" % dpe)
                success = False
                continue

        if not publisher.finishReleasing():
            print("\tCould not publish the image")
            continue

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(run())
