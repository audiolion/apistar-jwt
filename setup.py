#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

with open('HISTORY.md') as history_file:
    history = history_file.read()

requirements = [
    'apistar>=0.4',
    'PyJWT',
]

setup_requirements = [
    'pytest-runner',
]

test_requirements = [
    'pytest',
    'pytest-cov',
    'coverage',
]

setup(
    name='apistar_jwt',
    version='0.5.0',
    description="A JSON Web Token Component for API Star",
    long_description=readme + '\n\n' + history,
    long_description_content_type='text/markdown',
    author="Ryan Castner",
    author_email='castner.rr@gmail.com',
    url='https://github.com/audiolion/apistar-jwt',
    packages=find_packages(include=['apistar_jwt']),
    include_package_data=True,
    install_requires=requirements,
    license="MIT license",
    zip_safe=False,
    keywords='apistar_jwt',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    setup_requires=setup_requirements,
)
