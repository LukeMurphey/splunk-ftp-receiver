import unittest
import sys
import os
import re
import time

sys.path.append( os.path.join("..", "src", "bin") )

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
        self.assertTrue(self.path_field.to_python("var/lib/splunk/modinputs").endswith("var/lib/splunk/modinputs"))

if __name__ == '__main__':
    unittest.main()
