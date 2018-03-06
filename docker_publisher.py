#!/usr/bin/env python3
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
# For Tumbleweed, the images are published within RPMs as part of the OSS repo.
# They need to be extracted and pushed into gitHub/openSUSE/docker-containers-build.
# For anything else, still WIP.
# This script is written with easy extensibility in mind, as in the future it may:
# - pull docker images from different locations in different formats
# - push to oS registries

import sys
import requests
import re
import subprocess
import os
import zlib
import tempfile
import json
import shutil
import glob
from lxml import etree as xml

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
    """Base class for handling the publishing of docker images."""

    def releasedDockerImageVersion(self):
        """This function returns an identifier for the released docker
        image's version."""
        raise "pure virtual"

    def releaseDockerImage(self, version, rootfile):
        """This function publishes the docker image with root fs layer @rootfile.
        After this was called, releasedDockerImageVersion must return @version."""
        raise "pure virtual"


class DockerPublishException(Exception):
    pass


class DockerImageFetcher:
    """Base class for handling the acquiring of docker images."""

    def currentVersion(self):
        """This function returns the version of the latest available version
        of the image for the product."""
        raise "pure virtual"

    def getDockerImage(self, callback):
        """This function downloads the root fs layer and calls callback
        with its path as argument."""
        raise "pure virtual"


class DockerFetchException(Exception):
    pass


class DockerImagePublisherGit(DockerImagePublisher):
    def __init__(self, git_path, git_branch, path, arch):
        """Initialize a DockerImagePublisherGit with:
        @git_path: Path to the local git repo clone
        @git_branch: Branch of the image
        @path: Path to the directory within the branch which will contain:
        - Dockerfile (including version in a comment)
        - *.tar.xz: Images"""
        self.git_path = git_path
        self.git_branch = git_branch
        self.path = path
        self.arch = arch

        self.git_call = ["git", "-C", self.git_path]

        ret = subprocess.call(self.git_call + ["fetch", "origin"])
        if ret != 0:
            raise DockerFetchException("Could not fetch from origin")

    def releasedDockerImageVersion(self):
        # Read from git using cat-file to avoid expensive checkout.
        args = self.git_call + ["cat-file", "--textconv", "origin/%s:%s/Dockerfile" % (self.git_branch, self.path)]
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            version_regex = re.compile("^# Version: (.+)$")
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

    def releaseDockerImage(self, version, rootfile):
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

        # Remove all old files
        for file in glob.glob("%s/%s/*" % (self.git_path, self.path)):
            os.remove(file)

        # Re-compress it into the correct location and format
        targetfilename = "openSUSE-Tumbleweed-%s-%s.tar.xz" % (self.arch, version)

        if not recompress(rootfile, "%s/%s/%s" % (self.git_path, self.path, targetfilename)):
            raise DockerPublishException("Could not repackage the root fs layer")

        # Update the version number
        try:
            with open("%s/%s/Dockerfile" % (self.git_path, self.path), "w") as dockerfile:
                dockerfile.write(self.generateDockerFile(version, targetfilename))
        except (IOError, OSError) as e:
            raise DockerPublishException("Could not update the version file: %s" % e)

        # And create a commit
        ret = subprocess.call(self.git_call + ["add", "--all"])
        if ret == 0:
            ret = subprocess.call(self.git_call + ["commit", "-am", "Update %s image to %s" % (self.path, version)])

        if ret != 0:
            raise DockerPublishException("Could not create commit")

        ret = subprocess.call(self.git_call + ["push", "--force", "origin", self.git_branch])
        if ret != 0:
            raise DockerPublishException("Could not push")

        return True


class DockerImageFetcherTW(DockerImageFetcher):
    def __init__(self, versioned_redir, repourl, arch):
        self.versioned_redir = versioned_redir
        self.repourl = repourl
        self.arch = arch

    def currentVersion(self):
        # For TW we ask the mirrorbrain server about the -Current redirection target
        meta4_xml = requests.get(self.versioned_redir + ".meta4")
        meta4 = xml.fromstring(meta4_xml.content)
        filename = meta4.xpath("//m:metalink//m:file//@name", namespaces={'m': 'urn:ietf:params:xml:ns:metalink'})[0]
        return re.search('Snapshot(\d+)-', filename).group(1)

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
        """Download and extract the RPM from the OSS repo."""
        image_layer_file = tempfile.NamedTemporaryFile(delete=False)

        rpm_url = self.getRPMUrl("opensuse-tumbleweed-image", self.arch)
        if rpm_url is None:
            raise DockerFetchException("Could not get the URL for the RPM package")

        with tempfile.NamedTemporaryFile() as rpm_file:
            rpm_file.write(requests.get(rpm_url).content)
            with tempfile.TemporaryDirectory() as tar_dir:
                # Extract the .tar.xz inside the RPM into the dir
                subprocess.call("rpm2cpio '%s' | cpio -i --quiet --to-stdout \*.tar.xz | tar -xJf - -C '%s'" % (rpm_file.name, tar_dir), shell=True)
                # Parse the manifest to get the name of the root tar.xz
                manifest = json.loads(open(tar_dir + '/manifest.json').read())
                layers = manifest[0]['Layers']
                if len(layers) != 1:
                    raise DockerFetchException("Unexpected count of layers in the image")

                image_layer_file = tar_dir + '/' + layers[0]
                return callback(image_layer_file)


def run():
    tw_fetcher = DockerImageFetcherTW(versioned_redir="http://download.opensuse.org/tumbleweed/iso/openSUSE-Tumbleweed-DVD-x86_64-Current.iso",
                                      repourl="http://download.opensuse.org/tumbleweed/repo/oss/suse",
                                      arch="x86_64")
    tw_publisher = DockerImagePublisherGit(git_path=os.path.expanduser("~/docker-containers-build"),
                                           git_branch="openSUSE-Tumbleweed",
                                           path="x86_64", arch="x86_64")

    try:
        current = tw_fetcher.currentVersion()
        released = tw_publisher.releasedDockerImageVersion()
    except Exception as e:
        print("Exception during version fetching - aborting:")
        raise e

    print("Available version: %s" % (current))
    print("Released version: %s" % (released))

    release = current != released

    if "--release" in sys.argv[1:]:
        print("Forcing release.")
        release = True

    if not release:
        print("Nothing to do.")
        return 0

    try:
        tw_fetcher.getDockerImage(lambda rootfs: tw_publisher.releaseDockerImage(current, rootfs))
    except DockerFetchException as dfe:
        print("Could not fetch the image: %s" % dfe)
        return 1
    except DockerPublishException as dpe:
        print("Could not publish the image: %s" % dpe)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(run())
