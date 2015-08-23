"""
wg_ssl.py

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
import w3af.core.controllers.output_manager as om
from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
import w3af.core.data.constants.severity as severity
from w3af.core.data.kb.vuln import Vuln

from sys import argv
from plugins import PluginsFinder
from utils.CommandLineParser import CommandLineParser, CommandLineParsingError
from utils.ServersConnectivityTester import ServersConnectivityTester
from ast import literal_eval


class wg_ssl(AuditPlugin):
    """
    Check for SSL certificate validity (if https is being used).

    :author: EM ( mailto@zensecurity.su )
    """

    def __init__(self):
        AuditPlugin.__init__(self)

        # Internal variables
        self._result = {}
        self._min_expire_days = 30
        self._plugin_name = self.get_name()
        self._response_id = None

    def audit(self, freq, orig_response):
        """
        :param freq: A FuzzableRequest
        :param orig_resp: The HTTP response we get from sending the freq
        :return: None, all results are saved in the kb.
        """
        self._response_id = orig_response.id
        self._target_url = freq.get_url()

        if self._target_url.scheme == "https":
            self._analyze_ssl_cert()

    def _analyze_ssl_cert(self):
        """
        Analyze the SSL cert and store the information in the KB.
        """
        SSLYZE_VERSION = '0.11.0'
        sslyze_plugins = PluginsFinder()
        available_plugins = sslyze_plugins.get_plugins()
        available_commands = sslyze_plugins.get_commands()
        sslyze_parser = CommandLineParser(available_plugins, SSLYZE_VERSION)

        def get_dict_command_result(command_name, xml):
            command_dict_result = {}

            if command_name == "certinfo":
                certificate_validation = xml.find("certificateValidation")
                for path_validation in certificate_validation.findall("pathValidation"):
                    command_dict_result["ca_trust"] = {"is_affected": False if (path_validation.attrib["validationResult"] == "ok") else True}
                command_dict_result["certificate_matches_server_hostname"] = {"is_affected": not literal_eval(certificate_validation.find("hostnameValidation").attrib["certificateMatchesServerHostname"])}
                command_dict_result["ocsp_stapling"] = {"is_affected": not literal_eval(xml.find("ocspStapling").attrib["isSupported"])}
                expiration_date = xml.find("expirationDate")
                # failed here without patch below for certinfo plugin.
                """
                from time import gmtime
                from datetime import date
                from ssl import cert_time_to_seconds

                ...
                xml_output.append(cert_chain_xml)
                ...

                # XML output - expiration date

                # em begin
                cert_dict = x509_cert.as_dict()
                expiration_date = gmtime(cert_time_to_seconds(cert_dict['validity']['notAfter']))
                expire_days = (date(expiration_date.tm_year, expiration_date.tm_mon, expiration_date.tm_mday) - date.today()).days
                expiration_date_xml = Element("expirationDate", notAfter=cert_dict['validity']['notAfter'],
                                              expiresDays=expire_days)
                xml_output.append(expiration_date_xml)
                # em end
                """
                command_dict_result["expiration_date"] = {"not_after": expiration_date.attrib["notAfter"],
                                            "expires_days": expiration_date.attrib["expiresDays"]}
            elif command_name == "hsts":
                command_dict_result["is_affected"] = not literal_eval(xml.find("httpStrictTransportSecurity").attrib["isSupported"])
            elif command_name == "heartbleed":
                command_dict_result["is_affected"] = literal_eval(xml.find("openSslHeartbleed").attrib["isVulnerable"])
            elif command_name == "chrome_sha1":
                command_dict_result["is_affected"] = literal_eval(xml.find("chromeSha1Deprecation").attrib["isServerAffected"])
            elif command_name in ("sslv2", "sslv3"):
                command_dict_result["is_affected"] = True if len(xml.find("acceptedCipherSuites")) else False
            else:
                om.out.error("Unexpected command: {}".format(command_name))
            return command_dict_result

        command_line_arguments = ["--hsts", "--chrome_sha1", "--heartbleed", "--sslv2", "--sslv3",
                                  "--certinfo=basic", self._target_url.get_domain()]

        original_argv = argv[:]
        argv[1:] = command_line_arguments
        (command_list, target_list, shared_settings) = sslyze_parser.parse_command_line()
        argv[:] = original_argv

        target_results = ServersConnectivityTester.test_server_list(target_list, shared_settings)
        for target in target_results:
            if target is None:
                break  # None is a sentinel here

            for plugin_class in available_commands.itervalues():
                plugin_class._shared_settings = shared_settings

            for command in available_commands:
                if getattr(command_list, command):
                    args = command_list.__dict__[command]
                    # Instantiate the proper plugin
                    plugin_instance = available_commands[command]()
                    try:
                        # Process the task
                        """
                        #!/usr/bin/env python
                        # certificate file corrector

                        cert_prefix = "-----BEGIN CERTIFICATE-----\n"
                        cert_postfix = "-----END CERTIFICATE-----\n"
                        cert_lines = False

                        temp_file = open("temp.pem", "wa")

                        for line in open("mozilla.pem", "r"):
                            if line.startswith("#"):
                                continue
                            elif line.startswith(cert_prefix):
                                temp_file.write(cert_prefix)
                                cert_lines = True
                            elif line.startswith(cert_postfix):
                                temp_file.write(cert_postfix)
                                cert_lines = False
                            elif cert_lines:
                                temp_file.write(line)
                        """
                        result = plugin_instance.process_task(target, command, args)
                        xml = result.get_xml_result()
                        self._result[command] = get_dict_command_result(command, xml)
                    except Exception as e:
                        om.out.error('Unhandled exception when processing --{}: {}.{} - {}'.format(command,
                                                                                               e.__class__.__module__,
                                                                                               e.__class__.__name__,
                                                                                               e))
            self._is_trusted_cert()
            self._is_certificate_matches_server_hostname()
            self._is_cert_expired()
            self._is_ocsp_stapling_supported()
            self._is_sha1_signature()
            self._is_vulnerable_to_heartbleed()
            self._is_hsts_supported()
            self._is_sslv2_supported()
            self._is_sslv3_supported()

    def _is_trusted_cert(self):
        if self._result["certinfo"]["ca_trust"]["is_affected"]:
            desc = 'Host uses an invalid certificate.'
            v = Vuln("Invalid SSL certificate", desc, severity.HIGH, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_invalid_ssl', v)

    def _is_certificate_matches_server_hostname(self):
        if self._result["certinfo"]["certificate_matches_server_hostname"]["is_affected"]:
            desc = 'Host certificate mismatch with server virtual host.'
            v = Vuln("Invalid SSL certificate", desc, severity.HIGH, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_hostname_mismatch_ssl', v)

    def _is_cert_expired(self):
        if self._result["certinfo"]["expiration_date"]["expires_days"] < self._min_expire_days:
            desc = 'Host certificate expiration date: {}.'.format(self._result["certinfo"]["expiration_date"]["not_after"])
            v = Vuln("Soon to expire SSL certificate", desc, severity.HIGH, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_expired_ssl', v)

    def _is_ocsp_stapling_supported(self):
        if self._result["certinfo"]["ocsp_stapling"]["is_affected"]:
            desc = 'Host does not support OCSP stapling.'
            v = Vuln("Invalid SSL connection", desc, severity.MEDIUM, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_ocsp_stapling_ssl', v)

    def _is_sha1_signature(self):
        if self._result["chrome_sha1"]["is_affected"]:
            desc = 'Host certificate signed by sha1 signature.'
            v = Vuln("Invalid SSL certificate", desc, severity.MEDIUM, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_sha1_signature_ssl', v)

    def _is_vulnerable_to_heartbleed(self):
        if self._result["heartbleed"]["is_affected"]:
            desc = 'Host is vulnerable to heartbleed attack.'
            v = Vuln("Insecure SSL version", desc, severity.HIGH, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_heartbleed_ssl', v)

    def _is_hsts_supported(self):
        if self._result["hsts"]["is_affected"]:
            desc = 'Host has no HTTP "Strict-Transport-Security" header.'
            v = Vuln("Server header", desc, severity.MEDIUM, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_hsts_ssl', v)

    def _is_sslv2_supported(self):
        if self._result["sslv2"]["is_affected"]:
            desc = 'Host supports vulnerable ssl v2.'
            v = Vuln("Insecure SSL version", desc, severity.MEDIUM, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_sslv2_ssl', v)

    def _is_sslv3_supported(self):
        if self._result["sslv3"]["is_affected"]:
            desc = 'Host supports vulnerable ssl v3.'
            v = Vuln("Insecure SSL version", desc, severity.MEDIUM, self._response_id, self._plugin_name)
            v.set_url(self._target_url)
            self.kb_append(self, 'wg_sslv3_ssl', v)

    def get_long_desc(self):
        """
        :return: A DETAILED description of the plugin functions and features.
        """
        return 'This plugin detects insecure usage of SSL ' \
               '(check the SSL certificate validity for: weak cipher suites, insecure renegotiation, CRIME, Heartbleed, HSTS).\n' \
               '# Additional information:\n' \
               '* https://www.ssllabs.com/downloads/SSL_TLS_Deployment_Best_Practices.pdf'

    def get_name(self):
        """
        :return: Common name for the current plugin
        """
        return 'ssl'