# -*- coding: utf-8 -*-
#
# (C) 2014 mhrusecky@suse.cz, openSUSE.org
# (C) 2014 tchvatal@suse.cz, openSUSE.org
# (C) 2014 aplanas@suse.de, openSUSE.org
# (C) 2014 coolo@suse.de, openSUSE.org
# (C) 2017 okurz@suse.de, openSUSE.org
# (C) 2018 dheidler@suse.de, openSUSE.org
# Distribute under GPLv2 or GPLv3

import yaml
from osclib.core import attribute_value_load

class ImageProduct(object):
    def __init__(self, package, archs):
        self.package = package
        self.archs = archs

class ToTest(object):

    """Base class to store the basic interface"""

    def __init__(self, project, apiurl):
        self.name = project

        # set the defaults
        self.do_not_release = False
        self.need_same_build_number = False
        self.set_snapshot_number = False
        self.snapshot_number_prefix = "Snapshot"
        self.take_source_from_product = False
        self.arch = 'x86_64'
        self.openqa_server = None

        self.product_repo = 'images'
        self.product_arch = 'local'
        self.livecd_repo = 'images'
        self.totest_container_repo = 'containers'
        # Repo for image_products. If not set, uses product_repo.
        self.totest_images_repo = None

        self.main_products = []
        self.ftp_products = []
        self.container_products = []
        self.docker_products = []
        self.livecd_products = []
        self.image_products = []

        self.test_subproject = 'ToTest'
        self.base = project.split(':')[0]

        self.jobs_num = 42
        self.load_config(apiurl)
        self.test_project = '%s:%s' % (project, self.test_subproject)

    def load_config(self, apiurl):
        config = yaml.safe_load(attribute_value_load(apiurl, self.name, 'ToTestManagerConfig'))
        for key, value in config.items():
            if key == 'products':
                self.set_products(value)
            else:
                setattr(self, key, value)

        # Set default for totest_images_repo
        if self.totest_images_repo is None:
            self.totest_images_repo = self.product_repo

    def parse_images(self, products):
        parsed = []
        for package in products:
            # there is only one
            for key, value in package.items():
                parsed.append(ImageProduct(key, value))

        return parsed

    def set_products(self, products):
        # plain arrays
        setattr(self, 'main_products', products.get('main', []))
        setattr(self, 'ftp_products', products.get('ftp', []))

        # image products
        setattr(self, 'livecd_products', self.parse_images(products.get('livecds', [])))
        setattr(self, 'image_products', self.parse_images(products.get('images', [])))
        setattr(self, 'container_products', self.parse_images(products.get('container', [])))
        setattr(self, 'docker_products', self.parse_images(products.get('docker', [])))
