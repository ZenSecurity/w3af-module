"""
wg_dir_file_bruter.py

Copyright 2009 Jon Rose

This file is part of w3af, http://w3af.org/ .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
from os import path
from itertools import repeat, izip

import w3af.core.controllers.output_manager as om

from w3af import ROOT_PATH

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.controllers.core_helpers.fingerprint_404 import is_404
from w3af.core.controllers.misc.fuzzy_string_cmp import fuzzy_not_equal

from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_types import INPUT_FILE, BOOL
from w3af.core.data.options.option_list import OptionList
from w3af.core.data.fuzzer.utils import rand_alnum
from w3af.core.data.kb.info import Info



# TODO: needs to fix problem with Invision Power Board (request *.php files)
class wg_dir_file_bruter(AuditPlugin):
    """
    Finds Web server directories and files by bruteforcing.

    Five configurable parameters exist:
        - dirs_wordlist: The wordlist to be used in the directory bruteforce process.
        - files_wordlist: The wordlist to be used in the file bruteforce process.
        - mix_wordlist: The wordlist to be used in the files + directories bruteforce process.
        - bf_directories: If set to True, this plugin will bruteforce directories.
        - bf_files: If set to True, this plugin will bruteforce files.
        - bf_mix: If set to True, this plugin will bruteforce files + directories.

    :author: Jon Rose ( jrose@owasp.org )
    :author: Andres Riancho ( andres@bonsai-sec.com )
    :author: Tomas Velazquez
    :author: EM (mailto@zensecurity.su)
    """
    def __init__(self):
        AuditPlugin.__init__(self)

        self._base_path = path.join(ROOT_PATH, 'plugins', self.get_type(), self.__class__.__name__)
        self._dirs_list_file = path.join(self._base_path, 'common_dirs_small.db')
        self._files_list_file = path.join(self._base_path, 'common_files_small.db')
        self._mix_list_file = path.join(self._base_path, 'bo0om.db')

        # User configured parameters
        self._bf_directories = False
        self._bf_files = False
        self._bf_mix = True

    def audit(self, freq, orig_response):
        """
        :param freq: A FuzzableRequest
        :param orig_resp: The HTTP response we get from sending the freq
        :return: None, all results are saved in the kb.
        """
        self._target_url = freq.get_url()
        self._bruteforce_directories(self._target_url)

    def _dir_name_generator(self, base_url):
        """
        Simple generator that returns the names of the directories and files to test.
        It extracts the information from the user configured wordlist parameter.

        @yields: (A string with the directory or file name, a URL object with the dir or file name)
        """
        if self._bf_directories:
            for directory_name in file(self._dirs_list_file):
                directory_name = directory_name.strip()
                # ignore comments and empty lines
                if directory_name and not directory_name.startswith('#'):
                    try:
                        dir_url = base_url.url_join(directory_name + '/')
                    except ValueError, ve:
                        msg = 'The "%s" line at "%s" generated an invalid URL: %s'
                        om.out.error(msg % (directory_name, self._dirs_list_file, ve))
                    else:
                        yield directory_name, dir_url

        elif self._bf_files:
            for file_name in file(self._files_list_file):
                file_name = file_name.strip()
                # ignore comments and empty lines
                if file_name and not file_name.startswith('#'):
                    try:
                        file_url = base_url.url_join(file_name)
                    except ValueError, ve:
                        msg = 'The "%s" line at "%s" generated an invalid URL: %s'
                        om.out.error(msg % (file_name, self._files_list_file, ve))
                    else:
                        yield file_name, file_url

        elif self._bf_mix:
            for path in file(self._mix_list_file):
                path = path.strip()
                # ignore comments and empty lines
                if path and not path.startswith('#'):
                    try:
                        url = base_url.url_join(path)
                    except ValueError, ve:
                        msg = 'The "%s" line at "%s" generated an invalid URL: %s'
                        om.out.error(msg % (path, self._mix_list_file, ve))
                    else:
                        yield path, url

    def _send_and_check(self, base_url, (path, url)):
        """
        Performs a GET and verifies that the response is not a 404.

        :return: None
        """
        if base_url == url:
            return

        http_response = self._uri_opener.GET(url, cache=False)
        http_response_code = http_response.get_code()
        if is_404(http_response) and http_response_code in (204, 301, 302, 404, 503):
            return

        # Looking good, but lets see if this is a false positive or not...
        url = base_url.url_join(path + rand_alnum(5) + '/')
        invalid_http_response = self._uri_opener.GET(url, cache=False)

        if is_404(invalid_http_response) or fuzzy_not_equal(http_response.get_body(), invalid_http_response.get_body(), 0.35):
            # Good, the path + rand_alnum(5) return a 404, the original path is not a false positive.
            desc = 'Path: "{}" found with HTTP "response code: {}" and "Content-Length: {}". ' \
                   'It might exposes private information and requires a manual review'.format(http_response.get_url(),
                                                                                              http_response_code,
                                                                                              len(http_response.get_body()))
            i = Info('.listing file found', desc, http_response.id, self.get_name())
            i.set_url(self._target_url)
            self.kb_append(self, 'wg_dir_file_bruter', i)

    def _bruteforce_directories(self, base_url):
        """
        :param base_url: The base path to use in the bruteforcing process,
                          can be something like http://host.tld/ or
                          http://host.tld/images/ .
        :return: None
        """
        dir_name_generator = self._dir_name_generator(base_url)
        base_url_repeater = repeat(base_url)
        arg_iter = izip(base_url_repeater, dir_name_generator)
        self.worker_pool.map_multi_args(self._send_and_check, arg_iter, chunksize=20)

    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        ol = OptionList()

        d = 'Wordlist to use in directory bruteforcing process.'
        o = opt_factory('dirs_wordlist', self._dirs_list_file, d, INPUT_FILE)
        ol.add(o)

        d = 'Wordlist to use in file bruteforcing process.'
        o = opt_factory('files_wordlist', self._files_list_file, d, INPUT_FILE)
        ol.add(o)

        d = 'Wordlist to use in files + directories bruteforcing process.'
        o = opt_factory('mix_wordlist', self._mix_list_file, d, INPUT_FILE)
        ol.add(o)

        d = 'If set to True, this plugin will bruteforce directories.'
        o = opt_factory('bf_directories', self._bf_directories, d, BOOL)
        ol.add(o)

        d = 'If set to True, this plugin will bruteforce files.'
        o = opt_factory('bf_files', self._bf_files, d, BOOL)
        ol.add(o)

        d = 'If set to True, this plugin will bruteforce files and directories.'
        o = opt_factory('bf_mix', self._bf_mix, d, BOOL)
        ol.add(o)

        return ol

    def set_options(self, option_list):
        """
        This method sets all the options that are configured using the user interface
        generated by the framework using the result of get_options().

        :param OptionList: A dictionary with the options for the plugin.
        :return: No value is returned.
        """
        self._dirs_list_file = option_list['dirs_wordlist'].get_value()
        self._files_list_file = option_list['files_wordlist'].get_value()
        self._mix_list_file = option_list['mix_wordlist'].get_value()
        self._bf_directories = option_list['bf_directories'].get_value()
        self._bf_files = option_list['bf_files'].get_value()
        self._bf_mix = option_list['bf_mix'].get_value()

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return 'This plugin finds directories and files on a web server by brute-forcing their names using a wordlist.'

    def get_name(self):
        """
        :return: Common name for the current plugin
        """
        return 'directory/files'
