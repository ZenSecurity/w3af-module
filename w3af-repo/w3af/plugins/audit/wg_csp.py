"""
wg_csp.py

Copyright 2013 Andres Riancho

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
from w3af.core.controllers.csp.utils import find_vulns
import w3af.core.data.constants.severity as severity
from w3af.core.data.kb.vuln import Vuln


class wg_csp(AuditPlugin):
    """
    Identifies incorrect or too permissive Content Security Policy headers.

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
        csp_value = headers.get('content-security-policy', None)

        if csp_value is None:
            desc = 'Host has no HTTP "Content-Security-Policy" header. Add it correctly and you will fix that issue.'
            v = Vuln('Omitted server header', desc, severity.MEDIUM, orig_response.id, self.get_name())
            v.set_url(orig_response.get_url())
            self.kb_append(self, 'wg_csp', v)
        else:
            # Search issues using dedicated module
            csp_vulns = find_vulns(orig_response)
            for csp_directive_name in csp_vulns:
                csp_vuln = csp_vulns[csp_directive_name][0]
                v = Vuln('Server header', csp_vuln.desc, csp_vuln.severity, orig_response.id, self.get_name())
                v.set_url(orig_response.get_url())
                self.kb_append(self, 'wg_csp', v)

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return 'This plugin identifies incorrect or too permissive CSP (Content Security Policy) ' \
               'headers returned by the web application under analysis ' \
               '(check for: Content-Security-Policy, X-Content-Security-Policy, X-WebKit-CSP / Content-Security-Policy-Report-Only).\n' \
               '# Additional information:\n' \
               '* https://developer.mozilla.org/en-US/docs/Web/Security/CSP\n' \
               '* https://www.owasp.org/index.php/Content_Security_Policy\n' \
               '* http://www.w3.org/TR/CSP'

    def get_name(self):
        """
        :return: Common name for the current plugin
        """
        return "csp"