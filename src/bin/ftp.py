from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from ftp_receiver_app.modular_input import ModularInput, Field, IntegerField, DurationField

from ftp_receiver_app.pyftpdlib.authorizers import DummyAuthorizer
from ftp_receiver_app.pyftpdlib.handlers import FTPHandler
from ftp_receiver_app.pyftpdlib.servers import FTPServer

import logging
from logging import handlers
import sys
import time
import os
import splunk

class FTPInput(ModularInput):
    """
    The FTP input modular input runs a FTP server so that files can be accepted and indexed.
    """
    
    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "FTP",
                       'description': "Retrieve information over FTP",
                       'use_single_instance': "false"}
        
        args = [
                IntegerField("port", "Port", 'The port to run the FTP server on', none_allowed=False, empty_allowed=False),
                Field("path", "Path", 'The path to place the received files; relative paths are based on $SPLUNK_HOME', none_allowed=False, empty_allowed=False),
                #DurationField("interval", "Interval", "The interval defining how often to make sure the server is running", empty_allowed=True, none_allowed=True)
                ]
        
        ModularInput.__init__( self, scheme_args, args, logger_name="ftp_modular_input" )
        
        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30
            
        self.ftp_daemons = []

    def start_server(self, port, path):
        
        # Instantiate a dummy authorizer for managing 'virtual' users
        authorizer = DummyAuthorizer()
    
        # Define a new user having full r/w permissions and a read-only
        # anonymous user
        authorizer.add_user('user', '12345', path, perm='elradfmwM')
        authorizer.add_anonymous(path)
    
        # Instantiate FTP handler class
        handler = FTPHandler
        handler.authorizer = authorizer
    
        # Define a customized banner (string returned when client connects)
        handler.banner = "Splunk FTP server ready."
    
        # Instantiate FTP server class
        address = ('', port)
        server = FTPServer(address, handler)
    
        # Set a limit for connections
        server.max_cons = 256
        server.max_cons_per_ip = 5
    
        # Start ftp server
        server.serve_forever()

        # Add the FTP server to the list
        self.ftpd_daemons.append(server)
        
        return server

    def do_shutdown(self):
        
        to_delete_list = self.ftp_daemons[:]
        
        self.logger.info("Shutting down the server")
        
        for ftpd in to_delete_list:
            del self.ftp_daemons[ftpd]
            

    def run(self, stanza, cleaned_params, input_config):
        
        # Make the parameters
        port       = cleaned_params.get("port", 2121)
        sourcetype = cleaned_params.get("sourcetype", "ftp")
        host       = cleaned_params.get("host", None)
        index      = cleaned_params.get("index", "default")
        path       = cleaned_params.get("path", None)
        source     = stanza

        # Resolve the path
        resolved_path = os.path.join(os.environ['SPLUNK_HOME'], path)

        # Start the server
        self.logger.info("Starting server on port=%r, path=%r", port, resolved_path)  
        self.start_server(port, resolved_path)
            
if __name__ == '__main__':
    ftp_input = None
    
    try:
        ftp_input = FTPInput()
        ftp_input.execute()
        sys.exit(0)
    except Exception:
        if ftp_input is not None and ftp_input.logger is not None:
            ftp_input.logger.exception("Unhandled exception was caught, this may be due to a defect in the script") # This logs general exceptions that would have been unhandled otherwise (such as coding errors)
        raise