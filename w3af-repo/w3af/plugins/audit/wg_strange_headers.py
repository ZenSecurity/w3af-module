"""
wg_strange_headers.py

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
from w3af.core.data.kb.info import Info


class wg_strange_headers(AuditPlugin):
    """
    Check for uncommon headers sent in HTTP response.

    :author: Andres Riancho (andres.riancho@gmail.com)
    :author: EM (mailto@zensecurity.su)
    """
    # Remember that this headers are only the ones SENT BY THE SERVER TO THE
    # CLIENT. Headers must be uppercase in order to compare them
    COMMON_HEADERS = {'ACCEPT-RANGES', 'AGE', 'ALLOW', 'CONNECTION',
                      'CONTENT-DISPOSITION', 'CONTENT-ENCODING',
                      'CONTENT-LENGTH', 'CONTENT-TYPE', 'CONTENT-SCRIPT-TYPE',
                      'CONTENT-STYLE-TYPE', 'CONTENT-SECURITY-POLICY',
                      'CONTENT-SECURITY-POLICY-REPORT-ONLY', 'CONTENT-LANGUAGE',
                      'CONTENT-LOCATION', 'CACHE-CONTROL', 'DATE', 'EXPIRES',
                      'ETAG', 'FRAME-OPTIONS', 'KEEP-ALIVE', 'LAST-MODIFIED',
                      'LOCATION', 'P3P', 'PUBLIC', 'PUBLIC-KEY-PINS',
                      'PUBLIC-KEY-PINS-REPORT-ONLY', 'PRAGMA',
                      'PROXY-CONNECTION', 'SET-COOKIE', 'SERVER',
                      'STRICT-TRANSPORT-SECURITY', 'TRANSFER-ENCODING', 'VIA',
                      'VARY', 'WWW-AUTHENTICATE', 'X-FRAME-OPTIONS',
                      'X-CONTENT-TYPE-OPTIONS', 'X-POWERED-BY',
                      'X-ASPNET-VERSION', 'X-CACHE', 'X-UA-COMPATIBLE', 'X-PAD',
                      'X-XSS-PROTECTION', 'MIME-VERSION', 'ALTERNATE-PROTOCOL', 'X-XRDS-LOCATION',
                      'ACCESS-CONTROL-ALLOW-ORIGIN'}

    def audit(self, freq, orig_response):
        """
        :param freq: A FuzzableRequest
        :param orig_resp: The HTTP response we get from sending the freq
        :return: None, all results are saved in the kb.
        """
        # Should we remove that check for protocol anomalies ? # by em
        self._content_location_not_300(freq, orig_response)

        # Check header names
        for header_name in orig_response.get_headers().keys():
            if header_name.upper() in self.COMMON_HEADERS:
                continue
            # Create a new info object and save it to the KB
            header_value = orig_response.get_headers()[header_name]

            desc = 'Host sent strange HTTP header: "{}" with value: "{}", ' \
                   'which is quite uncommon and requires manual analysis.'.format(header_name, header_value)
            i = Info('Strange header', desc, orig_response.id, self.get_name())
            i.set_url(orig_response.get_url())
            self.kb_append(self, 'wg_strange_headers', i)

    def _content_location_not_300(self, freq, orig_response):
        """
        Check if the response has a content-location header and the response
        code is not in the 300 range.

        :return: None, all results are saved in the kb.
        """
        response_url = orig_response.get_url()

        headers = orig_response.get_headers()
        header_value = headers.get('content-location', None)

        if header_value is not None and 300 < orig_response.get_code() < 310:
            desc = 'The URL: "{}" sent the HTTP header: "content-location" ' \
                   'with value: "{}" in an HTTP response with code {} ' \
                   'which is a violation to the RFC.'.format(response_url, header_value, orig_response.get_code())
            i = Info('Content-Location HTTP header anomaly', desc, orig_response.id, self.get_name())
            i.set_url(response_url)
            self.kb_append(self, 'wg_anomaly', i)

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return 'This plugin checks for non-common headers sent in HTTP responses. ' \
               'It is could be useful to identify special modules and features added to the server.'

    def get_name(self):
        """
        :return: Common name for the current plugin
        """
        return 'strange headers'