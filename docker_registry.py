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

# This is a very basic client for the Docker Registry V2 API.
# It exists for a single reason: All clients either:
# - Don't work
# - Don't support uploading
# - Don't support multi-arch images (manifest lists)
# and some even all three.

import requests
import json
import os
import urllib.parse
import hashlib


class DockerHubClient():
    def __init__(self, url, username, password, repository):
        self.url = url
        self.username = username
        self.password = password
        self.repository = repository
        self.scopes = ["repository:%s:pull,push" % repository]
        self.token = None

    def _updateToken(self):
        scope_param = "&scope=".join([""] + [urllib.parse.quote(scope) for scope in self.scopes])
        response = requests.get("https://auth.docker.io/token?service=registry.docker.io" + scope_param,
                                auth=(self.username, self.password))
        self.token = response.json()["token"]

    def doHttpCall(self, method, url, **kwargs):
        try_update_token = True

        # Relative to the host
        if url.startswith("/"):
            url = self.url + url

        if "headers" not in kwargs:
            kwargs["headers"] = {}

        while True:
            resp = None
            if self.token is not None:
                kwargs["headers"]["Authorization"] = "Bearer " + self.token

                methods = {'POST': requests.post,
                           'GET': requests.get,
                           'HEAD': requests.head,
                           'PUT': requests.put,
                           'DELETE': requests.delete}

                if method not in methods:
                    return False

                resp = methods[method](url, **kwargs)

            if self.token is None or resp.status_code == 401 or resp.status_code == 403:
                if try_update_token:
                    try_update_token = False
                    self._updateToken()
                    continue

            return resp

    def uploadManifest(self, filename, reference=None):
        """Upload a manifest. If the filename doesn't equal the digest, it's computed.
        If reference is None, the digest is used. You can use the manifest's tag
        for example."""
        with open(filename, "rb") as manifest:
            content = manifest.read()

            if reference is None:
                reference = os.path.basename(filename)
                if not reference.startswith("sha256:"):
                    alg = hashlib.sha256()
                    alg.update(content)
                    reference = "sha256:" + alg.hexdigest()

            if reference is None:
                raise Exception("No reference determined")

            content_json = json.loads(content)
            if "mediaType" not in content_json:
                raise Exception("Invalid manifest")

            resp = self.doHttpCall("PUT", "/v2/%s/manifests/%s" % (self.repository, reference),
                                   headers={'Content-Type': content_json["mediaType"]},
                                   data=content)

            return resp.status_code == 200

    def getManifest(self, reference):
        """Get a (json-parsed) manifest with the given reference (digest or tag)"""
        resp = self.doHttpCall("GET", "/v2/%s/manifests/%s" % (self.repository, reference),
                               headers={'Accept': "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json"})

        if resp.status_code != 200:
            return False

        return json.loads(resp.content)

    def uploadBlob(self, filename):
        digest = os.path.basename(filename)
        if not digest.startswith("sha256:"):
            raise Exception("Invalid filename")

        # For now we can do a single upload call with everything inlined
        # (which also means completely in ram, but currently it's never > 50 MiB)
        content = None
        with open(filename, "rb") as blob:
            content = blob.read()

        # First request an upload "slot", we get an URL we can PUT to back
        upload_request = self.doHttpCall("POST", "/v2/%s/blobs/uploads/" % self.repository)
        if upload_request.status_code == 202:
            location = upload_request.headers["Location"]
            upload = self.doHttpCall("PUT", location + "&digest=" + digest,
                                     headers={'Content-Length': str(len(content))},
                                     data=content)
            return upload.status_code == 201

        return False


dhc = DockerHubClient("https://registry-1.docker.io", "favogt", os.environ["DHCPASS"], "favogt/tumbleweed")
print(dhc.getManifest("experimental"))
