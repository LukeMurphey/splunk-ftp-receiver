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

        
if __name__ == '__main__':
    unittest.main()