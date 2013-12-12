import os
import sys
import shlex
import subprocess


class BaseInstallMixin(object):

    # To be defined in child classes
    UNINSTALL_CMD = None
    INSTALL_CMD = None
    NULL = open(os.devnull, 'w')

    @classmethod
    def setUpClass(cls):
        subprocess.check_call(shlex.split(cls.INSTALL_CMD),
                              stdout=cls.NULL, stderr=subprocess.STDOUT)

    @classmethod
    def tearDownClass(cls):
        subprocess.check_call(shlex.split(cls.UNINSTALL_CMD),
                              stdout=cls.NULL, stderr=subprocess.STDOUT)

    def test_version_txt(self):
        # Get the location for the w3af module
        FILE_CMD = "%s -c 'import w3af; print w3af.__file__'" % sys.executable
        module_file = subprocess.check_output(shlex.split(FILE_CMD), cwd='tests')
        module_file = module_file.strip()

        # Append it with the location for the version.txt file
        module_dir = module_file.replace('__init__.pyc', '')
        version_txt = os.path.join(module_dir, 'core/data/constants/version.txt')

        # Check that the file was installed
        msg = '"%s" does NOT exist' % version_txt
        self.assertTrue(os.path.exists(version_txt), msg)

    def test_get_version_call(self):
        VERSION_CMD = "%s -c 'from w3af.core.controllers.misc.get_w3af_version"\
                      " import get_w3af_version; print get_w3af_version()'"
        subprocess.check_call(shlex.split(VERSION_CMD % sys.executable),
                              stdout=self.NULL, stderr=subprocess.STDOUT,
                              cwd='tests')

    def test_import(self):
        IMPORT_CMD = "%s -c 'import w3af'" % sys.executable
        subprocess.check_call(shlex.split(IMPORT_CMD),
                              stdout=self.NULL, stderr=subprocess.STDOUT,
                              cwd='tests')