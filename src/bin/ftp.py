"""
This module defines a modular input that wires up Splunk to an FTP server (provided by pyftpdlib).
"""

import sys
import time
import os

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

from ftp_receiver_app.modular_input import ModularInput, Field, IntegerField
from ftp_receiver_app.pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from ftp_receiver_app.pyftpdlib.handlers import FTPHandler
from ftp_receiver_app.pyftpdlib.servers import FTPServer

import splunk
import splunk.entity as entity

class SplunkAuthorizer(DummyAuthorizer):
    """
    This authorizer allows the FTP server to use Splunk's capabilities and users.
    """

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
            userEntities = entity.getEntities('authentication/users/%s' % user, count=-1,
                                              sessionKey=sessionKey)

            for stanza, settings in userEntities.items():
                if stanza == user:
                    for key, val in settings.items():
                        if key == 'roles':
                            #self.logger.debug("Successfully retrieved role(s) for user: %s", user)
                            roles = val

        # Get capabilities
        for role in roles:
            #self.logger.debug("Retrieving capabilities for current user: %s", user)
            roleEntities = entity.getEntities('authorization/roles/%s' % role, count=-1,
                                              sessionKey=sessionKey)

            for stanza, settings in roleEntities.items():
                if stanza == role:
                    for key, val in settings.items():
                        if key == 'capabilities' or key == "imported_capabilities":
                            #logger.debug('Successfully retrieved %s for user: %s' % (key, user))
                            capabilities.extend(val)

        return capabilities

    def combine_capabilities(self, perm_strings):
        """
        Combines the various letters indicating permissions so that they are unique and inclusive
        of all of the items in the provided strings.
        """

        perms_resolved = []

        for p in perm_strings:
            for q in p:
                if q not in perms_resolved:
                    perms_resolved.append(q)

        return ''.join(perms_resolved)

    def validate_authentication(self, username, password, handler):
        """
        This is called to authenticate the user.
        """

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
            self.logger.info("User lacks capabilities (needs ftp_read, ftp_write or " +
                             "ftp_full_control), username=%s", username)

            raise AuthenticationFailed("User does not have the proper capabilities " +
                                       "(needs ftp_read, ftp_write or ftp_full_control)")

        # Add the user
        self.logger.info("User authenticated, username=%s, perm=%s", username, perm_string)
        self.add_user(username, '', self.ftp_path, perm=perm_string)

    def has_user(self, username):
        """
        Called to indicate if the user exists.

        This always return true in order for the add_user function to work.
        """

        return True

    def add_user(self, username, password, homedir, perm='elr',
                 msg_login="Login successful.", msg_quit="Goodbye."):
        """
        Add the user to the list so the FTP server recognizes them.

        This is copied from the orignal authentcator class for the FTP server.
        """

        if not isinstance(homedir, unicode):
            homedir = homedir.decode('utf8')
        if not os.path.isdir(homedir):
            raise ValueError('no such directory: %r' % homedir)
        homedir = os.path.realpath(homedir)
        self._check_permissions(username, perm)
        dic = {
            'pwd': str(password),
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

    MAX_ATTEMPTS_TO_START_SERVER = 60

    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "FTP",
                       'description': "Retrieve information over FTP",
                       'use_single_instance': "false"}

        args = [
                IntegerField("port", "Port", 'The port to run the FTP server on', none_allowed=False, empty_allowed=False),
                Field("path", "Path", 'The path to place the received files; relative paths are based on $SPLUNK_HOME', none_allowed=False, empty_allowed=False),
                Field("address", "Address to Listen on", 'The address to have the FTP server listen on; leave blank to listen on all interfaces', none_allowed=True, empty_allowed=True),
                #DurationField("interval", "Interval", "The interval defining how often to make sure the server is running", empty_allowed=True, none_allowed=True)
                ]

        ModularInput.__init__( self, scheme_args, args, logger_name="ftp_modular_input" )

        self.ftp_daemons = []

    def start_server(self, address, port, path, callback):
        """
        Start the FTP server on the given port.
        """

        # Instantiate an authorizer for authorizing Splunk users
        authorizer = SplunkAuthorizer(path, logger=self.logger)

        class SplunkFTPHandler(FTPHandler):
            """
            This class will handle the logging of the various FTP server events.
            """

            output_event = callback

            def on_connect(self):
                self.output_event({
                    'message': 'Connection initiated',
                    'event' : 'connection_started',
                    'remote_ip' : self.remote_ip,
                    'remote_port' : self.remote_port
                })

            def on_disconnect(self):
                self.output_event({
                    'message': 'Connection ended',
                    'event' : 'connection_ended',
                    'remote_ip' : self.remote_ip,
                    'remote_port' : self.remote_port
                })

            def on_login(self, username):
                self.output_event({
                    'message': 'User logged in',
                    'event' : 'login',
                    'username' : username
                })

            def on_logout(self, username):
                self.output_event({
                    'message': 'User logged out',
                    'event' : 'logout',
                    'username' : username
                })

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
        socket_info = (address, port)
        server = FTPServer(socket_info, handler)

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
        port = cleaned_params.get("port", 2121)
        sourcetype = cleaned_params.get("sourcetype", "ftp")
        host = cleaned_params.get("host", None)
        index = cleaned_params.get("index", "default")
        path = cleaned_params.get("path", None)
        address = cleaned_params.get("address", "")
        source = stanza

        # Resolve the path
        resolved_path = os.path.normpath(os.path.join(os.environ['SPLUNK_HOME'], path))

        # Make the path if necessary
        try:
            os.mkdir(resolved_path)
        except OSError:
            pass # Directory likely already exists

        # Ensure that the path exists
        if not os.path.exists(resolved_path):
            self.logger.critical('FTP root directory does not exist, path="%r"', resolved_path)
            return

        # Ensure that the path is a directory
        if not os.path.isdir(resolved_path):
            self.logger.critical('Path of FTP root directory is a file, not a directory,' +
                                 ' path="%r"', resolved_path)
            return

        # Make the callback
        def callback(c, result):
            self.logger.info("Logging result: %r", result)
            self.output_event(result, source, index=index, source=source, sourcetype=sourcetype,
                              host=host, unbroken=True, close=True)

        # Start the server
        self.logger.info('Starting server on address="%s", port=%r, path="%r"', address, port,
                         resolved_path)

        started = False
        attempts = 0

        while not started and attempts < FTPInput.MAX_ATTEMPTS_TO_START_SERVER:
            try:
                self.start_server(address, port, resolved_path, callback)
                started = True
            except IOError:

                # Log a message noting that port is taken
                self.logger.info("The FTP server could not yet be started, attempt %i of %i",
                                 attempts, FTPInput.MAX_ATTEMPTS_TO_START_SERVER)

                started = False
                time.sleep(2)
                attempts = attempts + 1


if __name__ == '__main__':
    ftp_input = None

    try:
        ftp_input = FTPInput()
        ftp_input.execute()
        sys.exit(0)
    except Exception:
        if ftp_input is not None and ftp_input.logger is not None:
            # This logs general exceptions that would have been unhandled otherwise
            # (such as coding errors)
            ftp_input.logger.exception("Unhandled exception was caught, " +
            "this may be due to a defect in the script")
        raise
