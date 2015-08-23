"""
wg_robots_txt.py

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
from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.controllers.core_helpers.fingerprint_404 import is_404
from w3af.core.data.kb.info import Info


class wg_robots_txt(AuditPlugin):
    """
    Analyze the robots.txt file and find new URLs

    :author: Andres Riancho (andres.riancho@gmail.com)
    :author: EM (mailto@zensecurity.su)
    """
    def audit(self, freq, orig_response):
        """
        :param freq: A FuzzableRequest
        :param orig_resp: The HTTP response we get from sending the freq
        :return: None, all results are saved in the kb.
        """
        allowed_paths = []
        disallowed_paths = []

        self._target_url = freq.get_url()
        robots_url = self._target_url.url_join('robots.txt')
        http_response = self._uri_opener.GET(robots_url, cache=False)

        if is_404(http_response):
            return

        for line in http_response.get_body().split('\n'):
            line = line.strip()

            if len(line) and not line.startswith('#') and \
                    (line.upper().startswith('ALLOW') or line.upper().startswith('DISALLOW')):

                path = line[line.find(':')+1:]
                path = path.strip()

                if line.upper().startswith("DISALLOW") and path not in disallowed_paths:
                    desc = 'Found DISALLOW path: "{}" in robots.txt, it might exposes private information and requires a manual review'.format(path)
                    disallowed_paths.append(path)
                elif path not in allowed_paths:
                    desc = 'Found ALLOW path: "{}" in robots.txt, it might exposes private information and requires a manual review'.format(path)
                    allowed_paths.append(path)
                i = Info('robots.txt file', desc, http_response.id, self.get_name())
                i.set_url(self._target_url)
                self.kb_append(self, 'wg_robots_txt', i)

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return "This plugin searches for the robots.txt file, and parses it (show allow/dissalow info). " \
               "Robots.txt is used to as an ACL that defines what URL's a search engine can access. " \
               "By parsing this file, you can get more information about the target web application."

    def get_name(self):
        """
        :return: Common name for the current plugin
        """
        return 'robots.txt'
