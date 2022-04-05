"""
This module defines a modular input that wires up Splunk to an FTP server (provided by pyftpdlib).
"""

import sys
import time
import os

path_to_mod_input_lib = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modular_input.zip')
sys.path.insert(0, path_to_mod_input_lib)

path_to_py_libs = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ftp_receiver_app')
sys.path.append(path_to_py_libs)

from splunk.clilib.bundle_paths import make_splunkhome_path

from modular_input import ModularInput, Field, IntegerField, FieldValidationException, FilePathField
from ftp_receiver_app.pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from ftp_receiver_app.pyftpdlib.handlers import FTPHandler
from ftp_receiver_app.pyftpdlib.servers import FTPServer
from ftp_receiver_app.pyftpdlib.handlers import TLS_FTPHandler

from splunk.auth import getSessionKey
from splunk import AuthenticationFailed as SplunkAuthenticationFailed
import splunk.entity as entity

if sys.version_info.major >= 3:
    unicode = str

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
            session_key = getSessionKey(username=username, password=password)
        except SplunkAuthenticationFailed:
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

class FTPPathField(Field):
    """
    Represents the path from where the files will be served by the FTP server.
    """

    def resolve_intermediate_paths(self, path):
        """
        Create a list of paths that includes all of the parents of the given path.

        For example, the path "/opt/splunk" would return resolved paths for "opt" and "opt/splunk".
        """

        # Split the path into its parts
        path_split = path.split("/") # TODO: support Windows

        # Create each part
        paths = []
        path_so_far = ''

        for path_part in path_split:

            path_so_far = os.path.join(path_so_far, path_part)

            paths.append(os.path.normpath(os.path.join(os.environ['SPLUNK_HOME'],path_so_far)))

        return paths

    def to_python(self, value, session_key=None):
        Field.to_python(self, value, session_key)

        # Resolve the path
        resolved_path = os.path.normpath(os.path.join(os.environ['SPLUNK_HOME'], value))

        # This is a list of the paths that we will not allow serving.
        restricted_paths = []

        # The mongo key lives here
        restricted_paths.extend(self.resolve_intermediate_paths('var/lib/splunk/kvstore/mongo'))

        # The Splunk secret and certificates live here and the passwd file lives in etc
        restricted_paths.extend(self.resolve_intermediate_paths('etc/auth'))

        # Make sure that user isn't serving one of the paths that is restricted
        if resolved_path in restricted_paths:
            raise FieldValidationException('The path to serve is not allowed for security' +
                                           'reasons; Splunk paths containing password files, ' +
                                           'certificates, etc. are not allowed to be served')

        # Make the path if necessary
        try:
            os.mkdir(resolved_path)
        except OSError:
            pass # Directory likely already exists

        # Ensure that the path exists
        if not os.path.exists(resolved_path):
            raise FieldValidationException('The path to serve does not exist and could not be' +
                                           'created')

        # Ensure that the path is a directory
        if not os.path.isdir(resolved_path):
            raise FieldValidationException('The path to serve is a file, not a directory')

        # Return the path that is normalized and resolved
        return resolved_path

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
                FTPPathField("path", "Path", 'The path to place the received files; relative paths are based on $SPLUNK_HOME', none_allowed=False, empty_allowed=False),
                Field("address", "Address to Listen on", 'The address to have the FTP server listen on; leave blank to listen on all interfaces', none_allowed=True, empty_allowed=True),
                FilePathField("certfile", "Certificate File", 'The path to the certificate; relative paths are based on $SPLUNK_HOME', none_allowed=True, empty_allowed=True),
                FilePathField("keyfile", "Key File", 'The path to the key file; relative paths are based on $SPLUNK_HOME', none_allowed=True, empty_allowed=True),
                ]

        ModularInput.__init__(self, scheme_args, args, logger_name="ftp_modular_input")

        self.ftp_daemons = []

    def start_server(self, address, port, path, callback, certfile=None, keyfile=None):
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


        class SplunkFTPSHandler(SplunkFTPHandler, TLS_FTPHandler):
            pass

        # Instantiate FTP handler class
        if certfile is not None:
            handler = SplunkFTPSHandler
            handler.certfile = certfile
            handler.keyfile = keyfile
        else:
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

        certfile = cleaned_params.get("certfile", None)
        keyfile = cleaned_params.get("keyfile", None)

        # Make the path if necessary
        try:
            os.mkdir(path)
        except OSError:
            pass # Directory likely already exists

        # Ensure that the path exists
        if not os.path.exists(path):
            self.logger.critical('FTP root directory does not exist, path="%r"', path)
            return

        # Ensure that the path is a directory
        if not os.path.isdir(path):
            self.logger.critical('Path of FTP root directory is a file, not a directory,' +
                                 ' path="%r"', path)
            return

        # Make the callback
        def callback(c, result):
            """
            Handles the callbacks indicating that the FTP server has done something.
            """
            #self.logger.info("Logging result: %r", result)
            self.output_event(result, source, index=index, source=source, sourcetype=sourcetype,
                              host=host, unbroken=True, close=True)

        # Start the server
        self.logger.info('Starting server on address="%s", port=%r, path="%r"', address, port,
                         path)

        started = False
        attempts = 0

        while not started and attempts < FTPInput.MAX_ATTEMPTS_TO_START_SERVER:
            try:
                self.start_server(address, port, path, callback, certfile, keyfile)
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
