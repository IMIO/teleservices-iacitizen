#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os

from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install


class inst(install):
    def run(self):
        install.run(self)
        path = (
            os.getcwd().replace(" ", r"\ ").replace("(", r"\(").replace(")", r"\)")
            + "/bin/"
        )
        os.system("sh " + path + "install_teleservices_iacitizen.sh")


version = "0.0.1"

setup(
    name="teleservices-iacitizen",
    version=version,
    author="Daniel Muyshond, Nicolas Selva, Nicolas Hislaire",
    author_email="support-ts@imio.be",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[],
    url="https://github.com/IMIO//teleservices-iacitizen",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ],
    zip_safe=False,
    cmdclass={
        "inst": inst,
    },
)
