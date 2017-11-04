"""
This tests the FTP server related functionality necessary for the modular input to run.
"""

import unittest
import sys
import os
import errno

import HTMLTestRunner

sys.path.append(os.path.join("..", "src", "bin") )

from ftp import *

class TestSplunkAuthorizer(unittest.TestCase):

    def test_combine_capabilities(self):
        authorizer = SplunkAuthorizer('etc/splunk/data')
        self.assertEquals(authorizer.combine_capabilities(['abc', 'abcdef', 'ghia']), 'abcdefghi')

class TestFTPPathField(unittest.TestCase):

    def setUp(self):
        self.path_field = FTPPathField("test", "title", "this is a test")

    def test_restricted_path(self):
        self.assertRaises(FieldValidationException, lambda: self.path_field.to_python("etc") )

    def test_restricted_intermediate_path(self):
        self.assertRaises(FieldValidationException, lambda: self.path_field.to_python("var/lib/splunk/kvstore") )
        
    def test_restricted_relative_path(self):
        self.assertRaises(FieldValidationException, lambda: self.path_field.to_python("var/../var/lib/splunk/kvstore") )

    def test_non_restricted_paths(self):
        self.assertTrue(self.path_field.to_python("etc/apps").endswith("etc/apps"))

if __name__ == '__main__':
    report_path = os.path.join('..', os.environ.get('TEST_OUTPUT', 'tmp/test_report.html'))

    # Make the test directory
    try:
        os.makedirs(os.path.dirname(report_path))
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

    with open(report_path, 'w') as report_file:
        test_runner = HTMLTestRunner.HTMLTestRunner(
            stream=report_file
        )
        unittest.main(testRunner=test_runner)
