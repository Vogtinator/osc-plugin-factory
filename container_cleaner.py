#!/usr/bin/python3
# (c) 2019 fvogt@suse.de
# GPLv3-only

import osc.conf
import osc.core
import logging
import ToolBase
import subprocess
import sys
import re
import urllib.error
from lxml import etree as xml


class ContainerCleaner(ToolBase.ToolBase):
    def __init__(self):
        ToolBase.ToolBase.__init__(self)
        self.logger = logging.getLogger(__name__)

    def getDirEntries(self, path):
        url = self.makeurl(path)
        directory = xml.parse(self.retried_GET(url))
        return directory.xpath("entry/@name")

    def getDirBinaries(self, path):
        url = self.makeurl(path)
        directory = xml.parse(self.retried_GET(url))
        return directory.xpath("binary/@filename")

    def findSourcepkgsToDelete(self, project):
        # Get a list of all images
        srccontainers = self.getDirEntries(["source", project])

        # Sort them into buckets for each package:
        # {"opensuse-tumbleweed-image": ["opensuse-tumbleweed-image.20190402134201", ...]}
        buckets = {}
        regex_maintenance_release = re.compile(R"^(.+)\.[0-9]+$")
        for srccontainer in srccontainers:
            # Get the right bucket
            match = regex_maintenance_release.match(srccontainer)
            if match:
                # Maintenance release
                package = match.group(1)
            else:
                # Not renamed
                package = srccontainer

            if package not in buckets:
                buckets[package] = []

            buckets[package] += [srccontainer]

        for package in buckets:
            # Sort each bucket: Newest provider first
            buckets[package].sort(reverse=True)
            logging.debug("Found %d providers of %s", len(buckets[package]), package)

        # Get a hash for sourcecontainer -> arch with binaries
        # {"opensuse-tumbleweed-image.20190309164844": ["aarch64", "armv7l", "armv6l"],
        # "kubic-pause-image.20190306124139": ["x86_64", "i586"], ... }
        srccontainerarchs = {}

        archs = self.getDirEntries(["build", project, "containers"])
        regex_srccontainer = re.compile(R"^([^:/]+)(:[^:/]+)?/$")
        for arch in archs:
            rsync_proc = subprocess.run(["rsync", "--timeout=3600", "--info=name", "--recursive", "--dry-run", f"obspublish::openqa/openSUSE:Containers:Tumbleweed/containers/{arch}/*" , "does/not/exist"],
                                        capture_output=True, check=True)
            for binary in rsync_proc.stdout.decode("ascii").split("\n"):
                # Filter for source container directories
                if not binary or binary[0] == ':' or binary[-1] != '/':
                    continue

                match = regex_srccontainer.match(binary)
                if not match:
                    raise Exception("Could not map %s to source container" % binary)

                srccontainer = match.group(1)
                if srccontainer not in srccontainers:
                    raise Exception("Mapped %s to wrong source container (%s)" % (binary, srccontainer))

                if srccontainer not in srccontainerarchs:
                    srccontainerarchs[srccontainer] = []

                logging.debug("%s provides binaries for %s", srccontainer, arch)
                srccontainerarchs[srccontainer] += [arch]

        # Now go through each bucket and find out what doesn't contribute to the newest five
        can_delete = []
        for package in buckets:
            # {"x86_64": 1, "aarch64": 2, ...}
            archs_found = {}
            for arch in archs:
                archs_found[arch] = 0

            for srccontainer in buckets[package]:
                contributes = False
                if srccontainer in srccontainerarchs:
                    for arch in srccontainerarchs[srccontainer]:
                        if archs_found[arch] < 5:
                            archs_found[arch] += 1
                            contributes = True
                else:
                    logging.info("%s doesn't provide binaries for any arch?", srccontainer)

                if contributes:
                    logging.debug("%s contributes to %s", srccontainer, package)
                else:
                    logging.info("%s does not contribute", srccontainer)
                    if len([count for count in archs_found.values() if count > 0]) == 0:
                        # If there are A, B, C and D, with only C and D providing binaries,
                        # A and B aren't deleted because they have newer sources. This is
                        # to avoid deleting something due to unforeseen circumstances, e.g.
                        # OBS didn't copy the binaries yet.
                        logging.info("No newer provider found either, ignoring")
                    else:
                        can_delete += [srccontainer]

            # This should be done in a more planned way:
            # * Perform deletion if the newest release is >14d old
            # * but only if there have been new container releases for that arch,
            #   to not delete if there was no snapshot released
            try:
                osc.core.http_GET(self.makeurl(["source", "openSUSE:Factory", package]))
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    logging.info("%s no longer exists?", package)
                    all_older = True
                    for srccontainer in buckets[package]:
                        if ".2024" in srccontainer:
                            all_older = False
                            break

                    if all_older:
                        for srccontainer in buckets[package]:
                            can_delete += [srccontainer]

        return can_delete

    def run(self, project):
        packages = self.findSourcepkgsToDelete(project)

        for package in packages:
            url = self.makeurl(["source", project, package])
            if self.dryrun:
                logging.info("DELETE %s", url)
            else:
                osc.core.http_DELETE(url)


class CommandLineInterface(ToolBase.CommandLineInterface):
    def __init__(self, *args, **kwargs):
        ToolBase.CommandLineInterface.__init__(self, args, kwargs)

    def setup_tool(self):
        tool = ContainerCleaner()
        if self.options.debug:
            logging.basicConfig(level=logging.DEBUG)
        elif self.options.verbose:
            logging.basicConfig(level=logging.INFO)

        return tool

    def do_run(self, subcmd, opts, project):
        """${cmd_name}: run the Container cleaner for the specified project

        ${cmd_usage}
        ${cmd_option_list}
        """

        self.tool.run(project)


if __name__ == "__main__":
    cli = CommandLineInterface()
    sys.exit(cli.main())
