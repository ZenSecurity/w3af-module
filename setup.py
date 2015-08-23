#!/usr/bin/env python

from distutils.core import setup as distutils_setup
from mod_utils.get_version import get_version
from mod_utils.pip import get_pip_git_requirements, get_pip_requirements
from os import listdir
from os.path import normpath, join
from pip import main as pip_main
from setuptools import find_packages


def setup():
    try:
        # need to install custom library (SSLyze) for wg_ssl audit plugin support
        pip_main(['install', 'git+https://github.com/ZenSecurity/sslyze.git'])

        profiles_dir = 'w3af-repo/profiles'

        distutils_setup(
            name='w3af',

            version=get_version(),
            license='GNU General Public License v2 (GPLv2)',
            platforms='Linux',

            description='w3af is an open source web application security scanner.',
            long_description=file('README.rst').read(),

            author='em',
            author_email='mailto@zensecurity.su',
            url='https://github.com/ZenSecurity/w3af-module',

            packages=find_packages(exclude=['tests*', 'mod_utils*']),
            # include everything in source control which lives inside one of the packages identified by find_packages
            include_package_data=True,

            # include the data files, which don't live inside the directory
            data_files=[('profiles', [normpath(join(profiles_dir, profile_file)) for profile_file in listdir(profiles_dir)])],

            # This allows w3af plugins to read the data files which we deploy with data_files.
            zip_safe=False,

            # Run the module tests using nose
            test_suite='nose.collector',

            # Require at least the easiest PIP requirements from w3af
            install_requires=get_pip_requirements(),
            dependency_links=get_pip_git_requirements(),

            # Install these scripts
            scripts=['w3af-repo/w3af_console',
                     'w3af-repo/w3af_gui',
                     'w3af-repo/w3af_api'],

            # https://pypi.python.org/pypi?%3Aaction=list_classifiers
            classifiers=[
                'Development Status :: 5 - Production/Stable',
                'Intended Audience :: Developers',
                'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
                'Natural Language :: English',
                'Operating System :: POSIX :: Linux',
                'Programming Language :: Python',
                'Programming Language :: Python :: 2.7',
                'Topic :: Security'
            ],
        )
    except Exception as exception:
        print('{} - {}'.format(exception.__class__.__name__, exception))

setup()
