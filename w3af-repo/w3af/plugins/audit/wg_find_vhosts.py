"""
wg_find_vhosts.py

Copyright 2006 Andres Riancho

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
from itertools import izip, repeat
from os import path

from w3af import ROOT_PATH

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.controllers.misc.fuzzy_string_cmp import fuzzy_not_equal
from w3af.core.controllers.threads.threadpool import return_args, one_to_many

from w3af.core.data.fuzzer.utils import rand_alnum
from w3af.core.data.dc.headers import Headers
from w3af.core.data.kb.info import Info


class wg_find_vhosts(AuditPlugin):
    """
    Plugin tries to find additional virtual hosts for domain (modifies the HTTP Host header for searching).

    :author: Andres Riancho (andres.riancho@gmail.com)
    :author: EM (mailto@zensecurity.su)
    """

    def __init__(self):
        AuditPlugin.__init__(self)

        self._base_path = path.join(ROOT_PATH, 'plugins', self.get_type(), self.__class__.__name__)
        self._common_virtual_hosts_file = path.join(self._base_path, 'common_wg_virtual_hosts.db')

    def audit(self, freq, orig_response):
        """
        :param freq: A FuzzableRequest
        :param orig_resp: The HTTP response we get from sending the freq
        :return: None, all results are saved in the kb.
        """
        self._target_url = freq.get_url()
        self._domain = self._target_url.get_domain()
        self._root_domain = self._target_url.get_root_domain()

        analysis_result = self._analyze_generic_vhosts(orig_response)
        self._report_results(analysis_result)

    def _report_results(self, analysis_result):
        """
        Report our findings
        """
        for vhost, request_id in analysis_result:
            desc = 'Found a new virtual host at the target web server, the virtual host name is: "{}". ' \
                   'To access this site you might need to change your DNS resolution settings ' \
                   'in order to point "{}" to the IP address of "{}". ' \
                   'Move that host to another web server, and you will fix that issue.'.format(vhost, vhost, self._target_url)
            i = Info('Virtual host identified', desc, request_id, self.get_name())
            i.set_url(self._target_url)
            self.kb_append(self, 'wg_find_vhosts', i)

    def _analyze_generic_vhosts(self, original_response):
        """
        Test some generic virtual hosts.
        """
        orig_resp_body = original_response.get_body()

        non_existent_response = self._get_non_exist()
        nonexist_resp_body = non_existent_response.get_body()

        res = []
        vhosts = self._get_common_virtualhosts()

        for vhost, vhost_response in self._send_in_threads(vhosts):
            vhost_resp_body = vhost_response.get_body()

            # If they are *really* different (not just different by some chars)
            if fuzzy_not_equal(vhost_resp_body, orig_resp_body, 0.35) and \
            fuzzy_not_equal(vhost_resp_body, nonexist_resp_body, 0.35):
                res.append((vhost, vhost_response.id))

        return res

    def _send_in_threads(self, vhosts):
        base_url_repeater = repeat(self._target_url)
        args_iterator = izip(base_url_repeater, vhosts)
        http_get = return_args(one_to_many(self._http_get_vhost))
        pool_results = self.worker_pool.imap_unordered(http_get, args_iterator)

        for ((base_url, vhost),), vhost_response in pool_results:
            yield vhost, vhost_response

    def _http_get_vhost(self, base_url, vhost):
        """
        Performs an HTTP GET to a URL using a specific vhost.
        :return: HTTPResponse object.
        """
        headers = Headers([('Host', vhost)])
        return self._uri_opener.GET(base_url, cache=False, headers=headers)

    def _get_non_exist(self):
        non_existent_domain = 'iDoNotExistPleaseGoAwayNowOrDie' + rand_alnum(4)
        return self._http_get_vhost(self._target_url, non_existent_domain)

    def _get_common_virtualhosts(self):
        """
        :return: A list of possible domain names that could be hosted in the same web server that "domain".
        """
        for subdomain in file(self._common_virtual_hosts_file):
            subdomain = subdomain.strip()
            # intranet
            yield subdomain
            # intranet.www.targetsite.com
            # need to remove collisions with the next yield
            if self._domain != self._root_domain:
                yield subdomain + '.' + self._domain
            # intranet.targetsite.com
            yield subdomain + '.' + self._root_domain
            # intranet.targetsite
            yield subdomain + '.' + self._root_domain.split('.')[0]

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return 'This plugin uses the HTTP Host header to find new virtual hosts ' \
               '(check modified HTTP Host header and try to find virtual hosts from our hosts db). ' \
               'For example, if the intranet page is hosted in the same server that the public page, ' \
               'and the web server is misconfigured, this plugin will discover that virtual host. ' \
               'Please note that this plugin does not use any DNS technique to find these virtual hosts.'

    def get_name(self):
        """
        :return: Common name for the current plugin
        """
        return 'virtual hosts'