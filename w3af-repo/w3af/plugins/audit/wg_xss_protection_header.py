"""
wg_xss_protection_header.py

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
import w3af.core.data.constants.severity as severity
from w3af.core.data.kb.vuln import Vuln


class wg_xss_protection_header(AuditPlugin):
    """
    Check for enabled X-XSS-Protection header.

    :author: Andres Riancho (andres.riancho@gmail.com)
    :author: EM (mailto@zensecurity.su)
    """
    def audit(self, freq, orig_response):
        """
        :param freq: A FuzzableRequest
        :param orig_resp: The HTTP response we get from sending the freq
        :return: None, all results are saved in the kb.
        """
        headers = orig_response.get_lower_case_headers()
        x_xss_protection_value = headers.get('x-xss-protection', None)

        if x_xss_protection_value is None or x_xss_protection_value.lower() != '1; mode=block':
            desc = 'Host has no HTTP "X-XSS-Protection" header. Add "X-XSS-Protection" header ' \
                   'with value: "1; mode=block" and you will fix that issue.'
            v = Vuln('Omitted server header', desc, severity.MEDIUM, orig_response.id, self.get_name())
            v.set_url(orig_response.get_url())
            self.kb_append(self, 'wg_xss_protection_header', v)

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return 'This plugin detects insecure usage of the HTTP "X-XSS-Protection" header.\n' \
               '# Additional information:\n' \
               '* http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx'

    def get_name(self):
        """
        :return: Common name for the current plugin
        """
        return 'xss protection header'