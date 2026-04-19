#!/usr/bin/env python3
"""
Unit Tests for BlogSecurityTester class
Socrates Blade v3.2
"""

import os
import sys
import json
import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
from datetime import datetime
import importlib.util

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(TEST_DIR)))
sys.path.insert(0, PROJECT_ROOT)

spec = importlib.util.spec_from_file_location("socrates_blade", os.path.join(PROJECT_ROOT, "socrates-blade.py"))
socrates_blade_module = importlib.util.module_from_spec(spec)
sys.modules['socrates_blade'] = socrates_blade_module
spec.loader.exec_module(socrates_blade_module)

BlogSecurityTester = socrates_blade_module.BlogSecurityTester
Colors = socrates_blade_module.Colors

from config import Config, Severity, OWASP, CWE_MAPPINGS


class MockArgs:
    """Mock arguments for testing BlogSecurityTester"""
    def __init__(self, **kwargs):
        self.target = kwargs.get('target', 'http://localhost')
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        self.routes_file = kwargs.get('routes_file', 'routes.json')
        self.threads = kwargs.get('threads', None)
        self.timeout = kwargs.get('timeout', None)
        self.aggressive = kwargs.get('aggressive', False)
        self.brute_force = kwargs.get('brute_force', False)
        self.wordlist = kwargs.get('wordlist', None)
        self.max_attempts = kwargs.get('max_attempts', 10)
        self.proxy = kwargs.get('proxy', None)
        self.csrf_field = kwargs.get('csrf_field', 'login_form')
        self.output = kwargs.get('output', None)
        self.html_report = kwargs.get('html_report', None)
        self.verify_ssl = kwargs.get('verify_ssl', False)


class TestColors(unittest.TestCase):
    """Test Colors class"""

    def test_colors_defined(self):
        """Test all color constants are defined"""
        self.assertIsNotNone(Colors.RED)
        self.assertIsNotNone(Colors.GREEN)
        self.assertIsNotNone(Colors.YELLOW)
        self.assertIsNotNone(Colors.BLUE)
        self.assertIsNotNone(Colors.CYAN)
        self.assertIsNotNone(Colors.MAGENTA)
        self.assertIsNotNone(Colors.WHITE)
        self.assertIsNotNone(Colors.RESET)
        self.assertIsNotNone(Colors.BRIGHT)


class TestBlogSecurityTesterInit(unittest.TestCase):
    """Test BlogSecurityTester initialization"""

    @patch('socrates_blade.requests.Session')
    def test_init_basic(self, mock_session):
        """Test basic initialization"""
        args = MockArgs(target='http://localhost')
        tester = BlogSecurityTester(args)
        self.assertEqual(tester.base_url, 'http://localhost/')
        self.assertEqual(tester.timeout, Config.REQUEST_TIMEOUT)
        self.assertEqual(tester.threads, Config.CONCURRENCY_LEVEL)
        self.assertFalse(tester.authenticated)

    @patch('socrates_blade.requests.Session')
    def test_init_aggressive_mode(self, mock_session):
        """Test initialization with aggressive mode"""
        args = MockArgs(target='http://localhost', aggressive=True)
        tester = BlogSecurityTester(args)
        self.assertEqual(tester.timeout, Config.AGGRESSIVE_TIMEOUT)
        self.assertEqual(tester.threads, Config.AGGRESSIVE_CONCURRENCY)

    @patch('socrates_blade.requests.Session')
    def test_init_with_proxy(self, mock_session):
        """Test initialization with proxy"""
        args = MockArgs(target='http://localhost', proxy='http://127.0.0.1:8080')
        tester = BlogSecurityTester(args)
        self.assertEqual(tester.session.proxies['http'], 'http://127.0.0.1:8080')
        self.assertEqual(tester.session.proxies['https'], 'http://127.0.0.1:8080')


class TestFormatBaseUrl(unittest.TestCase):
    """Test format_base_url method"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_with_http_prefix(self):
        """Test URL with http prefix"""
        result = self.tester.format_base_url('http://example.com')
        self.assertEqual(result, 'http://example.com/')

    def test_without_http_prefix(self):
        """Test URL without http prefix"""
        result = self.tester.format_base_url('example.com')
        self.assertEqual(result, 'http://example.com/')

    def test_with_https_prefix(self):
        """Test URL with https prefix"""
        result = self.tester.format_base_url('https://example.com')
        self.assertEqual(result, 'https://example.com/')

    def test_with_trailing_slash(self):
        """Test URL with trailing slash"""
        result = self.tester.format_base_url('http://example.com/')
        self.assertEqual(result, 'http://example.com/')

    def test_strips_whitespace(self):
        """Test URL with whitespace"""
        result = self.tester.format_base_url('  example.com  ')
        self.assertEqual(result, 'http://example.com/')


class TestLoadRoutes(unittest.TestCase):
    """Test load_routes method"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='{"routes": {"frontend": {"home": {"path": "/"}}}}')
    def test_load_routes_new_format(self, mock_file, mock_exists):
        """Test loading routes with new format"""
        mock_exists.return_value = True
        routes = self.tester.load_routes()
        self.assertIn('frontend.home', routes)

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='{"home": {"path": "/"}}')
    def test_load_routes_old_format(self, mock_file, mock_exists):
        """Test loading routes with old format"""
        mock_exists.return_value = True
        routes = self.tester.load_routes()
        self.assertIn('home', routes)


class TestResolveUrl(unittest.TestCase):
    """Test resolve_url method"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_resolve_url_with_params(self):
        """Test URL resolution with params"""
        result = self.tester.resolve_url('/post/(?<id>\\d+)/(?<slug>[\\w\\-]+)', {'id': '1', 'slug': 'test'})
        self.assertIn('1', result)
        self.assertIn('test', result)

    def test_resolve_url_without_params(self):
        """Test URL resolution without params"""
        result = self.tester.resolve_url('/post/(?<id>\\d+)/(?<slug>[\\w\\-]+)', {})
        self.assertIn('/post/', result)

    def test_resolve_url_default_params(self):
        """Test URL resolution with default params"""
        result = self.tester.resolve_url('/page/(?<page>[^/]+)', {})
        self.assertIn('/page/', result)


class TestCWEAndOWASP(unittest.TestCase):
    """Test CWE and OWASP mapping methods"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_get_cwe_for_type_xss(self):
        """Test CWE mapping for XSS"""
        cwe = self.tester.get_cwe_for_type("Reflected XSS")
        self.assertEqual(cwe, "CWE-79")

    def test_get_cwe_for_type_sqli(self):
        """Test CWE mapping for SQLi"""
        cwe = self.tester.get_cwe_for_type("sqli test")
        self.assertEqual(cwe, "CWE-89")

    def test_get_cwe_for_type_unknown(self):
        """Test CWE mapping for unknown type"""
        cwe = self.tester.get_cwe_for_type("Unknown Vulnerability")
        self.assertEqual(cwe, "CWE-UNKNOWN")

    def test_get_owasp_for_type_xss(self):
        """Test OWASP mapping for XSS"""
        owasp = self.tester.get_owasp_for_type("XSS")
        self.assertEqual(owasp, "A03 - Injection")

    def test_get_owasp_for_type_sqli(self):
        """Test OWASP mapping for SQLi"""
        owasp = self.tester.get_owasp_for_type("sqli test")
        self.assertEqual(owasp, "A03 - Injection")

    def test_get_owasp_for_type_idor(self):
        """Test OWASP mapping for IDOR"""
        owasp = self.tester.get_owasp_for_type("IDOR")
        self.assertEqual(owasp, "A01 - Broken Access Control")

    def test_get_owasp_for_type_csrf(self):
        """Test OWASP mapping for CSRF"""
        owasp = self.tester.get_owasp_for_type("CSRF")
        self.assertEqual(owasp, "A08 - Data Integrity Failures")

    def test_get_owasp_for_type_ssrf(self):
        """Test OWASP mapping for SSRF"""
        owasp = self.tester.get_owasp_for_type("SSRF")
        self.assertEqual(owasp, "A10 - SSRF")

    def test_get_owasp_for_type_auth(self):
        """Test OWASP mapping for auth"""
        owasp = self.tester.get_owasp_for_type("Authentication Bypass")
        self.assertEqual(owasp, "A07 - Auth Failures")

    def test_get_owasp_for_type_headers(self):
        """Test OWASP mapping for headers"""
        owasp = self.tester.get_owasp_for_type("Missing Headers")
        self.assertEqual(owasp, "A05 - Security Misconfiguration")


class TestEvidenceAndRemediation(unittest.TestCase):
    """Test evidence generation and remediation methods"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_generate_evidence_with_param(self):
        """Test evidence generation with param"""
        evidence = self.tester.generate_evidence("XSS", "http://test.com", "param", "GET")
        self.assertIn("GET", evidence)
        self.assertIn("param", evidence)

    def test_generate_evidence_without_param(self):
        """Test evidence generation without param"""
        evidence = self.tester.generate_evidence("XSS", "http://test.com", None, "GET")
        self.assertIn("GET", evidence)

    def test_get_remediation_xss(self):
        """Test remediation for XSS"""
        remediation = self.tester.get_remediation("Reflected XSS")
        self.assertIn("htmlspecialchars", remediation)

    def test_get_remediation_sqli(self):
        """Test remediation for SQLi"""
        remediation = self.tester.get_remediation("SQL Injection")
        self.assertIn("parameterized", remediation)

    def test_get_remediation_unknown(self):
        """Test remediation for unknown type"""
        remediation = self.tester.get_remediation("Unknown")
        self.assertIn("Review", remediation)


class TestAddFinding(unittest.TestCase):
    """Test add_finding method"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_add_finding_basic(self):
        """Test adding a basic finding"""
        self.tester.add_finding("XSS", "http://test.com", Severity.HIGH, "Test details", "param")
        self.assertEqual(len(self.tester.findings), 1)
        self.assertEqual(self.tester.findings[0]['type'], "XSS")
        self.assertEqual(self.tester.findings[0]['severity'], Severity.HIGH)

    def test_add_finding_no_duplicates(self):
        """Test adding duplicate finding"""
        self.tester.add_finding("XSS", "http://test.com", Severity.HIGH, None, "param")
        self.tester.add_finding("XSS", "http://test.com", Severity.HIGH, None, "param")
        self.assertEqual(len(self.tester.findings), 1)


class TestDiscoverParams(unittest.TestCase):
    """Test discover_params method"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_discover_params_with_query(self):
        """Test discovering params from URL with query string"""
        params = self.tester.discover_params("http://test.com?foo=bar&baz=qux")
        self.assertEqual(params['foo'], 'bar')
        self.assertEqual(params['baz'], 'qux')

    def test_discover_params_without_query(self):
        """Test discovering params from URL without query string"""
        params = self.tester.discover_params("http://test.com")
        self.assertEqual(params, {})


class TestTestHeaders(unittest.TestCase):
    """Test test_headers method"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_test_headers_missing(self):
        """Test detecting missing security headers"""
        headers = {'Server': 'Apache'}
        self.tester.test_headers("http://test.com", headers)
        self.assertEqual(len(self.tester.findings), 1)
        self.assertEqual(self.tester.findings[0]['type'], "Missing Security Headers")

    def test_test_headers_present(self):
        """Test when security headers are present"""
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Strict-Transport-Security': 'max-age=31536000',
            'Permissions-Policy': 'geolocation=()',
            'X-XSS-Protection': '1; mode=block',
        }
        self.tester.test_headers("http://test.com", headers)
        self.assertEqual(len(self.tester.findings), 0)


class TestPrintStatus(unittest.TestCase):
    """Test print_status method"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_print_status_info(self):
        """Test print_status with info"""
        self.tester.print_status("Test message", "info")

    def test_print_status_success(self):
        """Test print_status with success"""
        self.tester.print_status("Test message", "success")

    def test_print_status_warning(self):
        """Test print_status with warning"""
        self.tester.print_status("Test message", "warning")

    def test_print_status_error(self):
        """Test print_status with error"""
        self.tester.print_status("Test message", "error")

    def test_print_status_with_severity(self):
        """Test print_status with severity"""
        self.tester.print_status("Test message", "info", Severity.CRITICAL)


class TestConfigHelperMethods(unittest.TestCase):
    """Test Config helper classmethods"""

    def test_get_sql_time_payload_default(self):
        """Test get_sql_time_payload with default sleep time"""
        payloads = Config.get_sql_time_payload()
        self.assertIsInstance(payloads, list)
        self.assertTrue(len(payloads) > 0)

    def test_get_sql_time_payload_custom(self):
        """Test get_sql_time_payload with custom sleep time"""
        payloads = Config.get_sql_time_payload(sleep_time=10)
        self.assertIsInstance(payloads, list)
        self.assertTrue(len(payloads) > 0)
        self.assertIn("10", payloads[0])

    def test_get_all_xss_payloads(self):
        """Test get_all_xss_payloads returns list"""
        payloads = Config.get_all_xss_payloads()
        self.assertIsInstance(payloads, list)
        self.assertTrue(len(payloads) > 0)
        self.assertIn("<script>alert('XSS')</script>", payloads)

    def test_get_all_sqli_payloads(self):
        """Test get_all_sqli_payloads returns list"""
        payloads = Config.get_all_sqli_payloads()
        self.assertIsInstance(payloads, list)
        self.assertTrue(len(payloads) > 0)
        self.assertIn("' OR 1=1 --", payloads)

    def test_get_all_traversal_payloads(self):
        """Test get_all_traversal_payloads returns list"""
        payloads = Config.get_all_traversal_payloads()
        self.assertIsInstance(payloads, list)
        self.assertTrue(len(payloads) > 0)
        self.assertIn("../../../../etc/passwd", payloads)

    def test_get_all_ssrf_payloads(self):
        """Test get_all_ssrf_payloads returns dict"""
        payloads = Config.get_all_ssrf_payloads()
        self.assertIsInstance(payloads, dict)
        self.assertTrue(len(payloads) > 0)
        self.assertIn("http://169.254.169.254/latest/meta-data/", payloads)

    def test_get_brute_force_passwords_default(self):
        """Test get_brute_force_passwords returns list"""
        passwords = Config.get_brute_force_passwords()
        self.assertIsInstance(passwords, list)
        self.assertTrue(len(passwords) > 0)
        self.assertIn("password", passwords)

    def test_get_brute_force_usernames_default(self):
        """Test get_brute_force_usernames returns list"""
        usernames = Config.get_brute_force_usernames()
        self.assertIsInstance(usernames, list)
        self.assertTrue(len(usernames) > 0)
        self.assertIn("admin", usernames)


class TestDiscoverForms(unittest.TestCase):
    """Test discover_forms method"""

    @patch('socrates_blade.requests.Session')
    def setUp(self, mock_session):
        self.tester = BlogSecurityTester(MockArgs(target='http://localhost'))

    def test_discover_forms_with_form(self):
        """Test discovering forms on a page"""
        html = '''
        <html>
        <form action="/submit" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>
        </html>
        '''
        mock_response = Mock()
        mock_response.text = html
        self.tester.session.get = Mock(return_value=mock_response)

        forms = self.tester.discover_forms("http://test.com")
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]['method'], 'post')
        self.assertEqual(len(forms[0]['inputs']), 2)

    def test_discover_forms_no_form(self):
        """Test discovering forms when none exist"""
        mock_response = Mock()
        mock_response.text = '<html><body>No forms here</body></html>'
        self.tester.session.get = Mock(return_value=mock_response)

        forms = self.tester.discover_forms("http://test.com")
        self.assertEqual(len(forms), 0)

    def test_discover_forms_get_method(self):
        """Test form with GET method"""
        html = '''
        <html>
        <form action="/search" method="get">
            <input type="text" name="q" />
        </form>
        </html>
        '''
        mock_response = Mock()
        mock_response.text = html
        self.tester.session.get = Mock(return_value=mock_response)

        forms = self.tester.discover_forms("http://test.com")
        self.assertEqual(forms[0]['method'], 'get')


class TestSeverityAndOWASP(unittest.TestCase):
    """Test Severity and OWASP constants"""

    def test_severity_levels(self):
        """Test Severity levels exist"""
        self.assertIsNotNone(Severity.CRITICAL)
        self.assertIsNotNone(Severity.HIGH)
        self.assertIsNotNone(Severity.MEDIUM)
        self.assertIsNotNone(Severity.LOW)
        self.assertIsNotNone(Severity.INFO)
        self.assertEqual(len(Severity.LEVELS), 5)

    def test_owasp_categories(self):
        """Test OWASP categories"""
        self.assertEqual(OWASP.A01, "A01 - Broken Access Control")
        self.assertEqual(OWASP.A03, "A03 - Injection")
        self.assertEqual(OWASP.A10, "A10 - SSRF")

    def test_cwe_mappings(self):
        """Test CWE mappings"""
        self.assertIn("xss", CWE_MAPPINGS)
        self.assertIn("sqli", CWE_MAPPINGS)
        self.assertEqual(CWE_MAPPINGS["xss"][0], "CWE-79")
        self.assertEqual(CWE_MAPPINGS["sqli"][0], "CWE-89")


if __name__ == '__main__':
    unittest.main(verbosity=2)