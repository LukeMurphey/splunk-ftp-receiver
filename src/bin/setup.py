# This script will install and upgrade the libraries necessary for the FTP receiver app to support for SSL.
# Run this with the Python interpreter that is installed on your Splunk server. Below is an example:
#     /opt/splunk/bin/splunk cmd python /opt/splunk/etc/apps/ftp_receiver/bin/setup.py

import sys
import subprocess
import os

# This is the path to the requirements file
requirements_file = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', 'ftp_receiver', 'requirements.txt')
python_install_dir = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', 'ftp_receiver', 'bin', 'ftp_receiver_app')

# Run pip to install the libraries
subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', requirements_file, '-t', python_install_dir, '--upgrade'])
