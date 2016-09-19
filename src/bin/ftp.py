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
from collections import OrderedDict

import splunk
import splunk.entity as entity

class SplunkAuthorizer(DummyAuthorizer):
    
    CAPABILITY_MAP = {
                      'ftp_read' : 'elr',
                      'ftp_write' : 'adfmwM',
                      'ftp_full_control' : 'elradfmwM'
    }
    
    def __init__(self, path, logger=None):
        self.user_table = {}
        self.ftp_path = path
        self.logger = logger
    
    def getCapabilities4User(self, user=None, sessionKey=None):
        """
        Obtains a list of capabilities in an list for the given user.
        
        Arguments:
        user -- The user to get capabilities for (as a string)
        sessionKey -- The session key to be used if it is not none
        """
        
        roles = []
        capabilities = []
        
        # Get user info
        if user is not None:
            #self.logger.debug("Retrieving role(s) for current user: %s", user)
            userEntities = entity.getEntities('authentication/users/%s' % user, count=-1, sessionKey=sessionKey)

            for stanza, settings in userEntities.items():
                if stanza == user:
                    for key, val in settings.items():
                        if key == 'roles':
                            #self.logger.debug("Successfully retrieved role(s) for user: %s", user)
                            roles = val
        
        # Get capabilities
        for role in roles:
            #self.logger.debug("Retrieving capabilities for current user: %s", user)
            roleEntities = entity.getEntities('authorization/roles/%s' % role, count=-1, sessionKey=sessionKey)
          
            for stanza, settings in roleEntities.items():
                if stanza == role:
                    for key, val in settings.items():
                        if key == 'capabilities' or key == "imported_capabilities":
                            #logger.debug('Successfully retrieved %s for user: %s' % (key, user))
                            capabilities.extend(val)

        return capabilities
    
    def combine_capabilities(self, perm_strings):
        
        perms_resolved = []
        
        for p in perm_strings:
            for q in p:
                if q not in perms_resolved:
                    perms_resolved.append(q)
                    
        return ''.join(perms_resolved)
    
    def validate_authentication(self, username, password, handler):
        
        self.logger.info("Asking to authenticate, username=%s", username)
        
        # See if the user account is valid
        try:
            session_key = splunk.auth.getSessionKey(username=username, password=password)
        except splunk.AuthenticationFailed:
            self.logger.info("Failed to authenticate, username=%s", username)
            raise AuthenticationFailed("Authentication failed")
        
        # See that capabilities the user has
        capabilities = self.getCapabilities4User(username, session_key)
        
        # Make a list of the perms
        perms = []
        
        for capability in self.CAPABILITY_MAP:
            if capability in capabilities:
                perms.append(self.CAPABILITY_MAP[capability])
        
        perm_string = self.combine_capabilities(perms)
        
        # Stop if the user doesn't have permission
        if len(perms) == 0:
            self.logger.info("User lacks capabilities (needs ftp_read, ftp_write or ftp_full_control), username=%s", username)
            raise AuthenticationFailed("User does not have the proper capabilities (needs ftp_read, ftp_write or ftp_full_control)")
        
        # Add the user
        self.logger.info("User authenticated, username=%s, perm=%s", username, perm_string)
        self.add_user(username, '', self.ftp_path, perm=perm_string)
        
    def has_user(self, username):
        return True
    
    def add_user(self, username, password, homedir, perm='elr',
                 msg_login="Login successful.", msg_quit="Goodbye."):
        
        if not isinstance(homedir, unicode):
            homedir = homedir.decode('utf8')
        if not os.path.isdir(homedir):
            raise ValueError('no such directory: %r' % homedir)
        homedir = os.path.realpath(homedir)
        self._check_permissions(username, perm)
        dic = {'pwd': str(password),
               'home': homedir,
               'perm': perm,
               'operms': {},
               'msg_login': str(msg_login),
               'msg_quit': str(msg_quit)
               }
        self.user_table[username] = dic

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

    def start_server(self, port, path, callback):
        
        # Instantiate an authorizer for authorizing Splunk users
        authorizer = SplunkAuthorizer(path, logger=self.logger)
            
        class SplunkFTPHandler(FTPHandler):
            
            output_event = callback
            
            def on_file_sent(self, file):
                self.output_event({
                                   'message': 'File sent',
                                   'event' : 'file_sent',
                                   'file' : file
                                  })
        
            def on_file_received(self, file):
                self.output_event({
                                    'message': 'File received',
                                    'event' : 'file_received',
                                    'file' : file
                                  })
        
            def on_incomplete_file_sent(self, file):
                self.output_event({
                                    'message': 'File sent (but was not complete)',
                                    'event' : 'file_sent_received',
                                    'file' : file
                                  })
        
            def on_incomplete_file_received(self, file):
                self.output_event({
                                    'message': 'File received (but was not complete)',
                                    'event' : 'file_received_incomplete',
                                    'file' : file
                                  })
            
        # Instantiate FTP handler class
        handler = SplunkFTPHandler
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

        # Make the callback
        def callback(c, result):
            self.logger.info("Logging result: %r", result)
            self.output_event(result, source, index=index, source=source, sourcetype=sourcetype, host=host, unbroken=True, close=True)

        # Start the server
        self.logger.info("Starting server on port=%r, path=%r", port, resolved_path)  
        self.start_server(port, resolved_path, callback)
            
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