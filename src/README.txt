================================================
Overview
================================================

This app provides a mechanism for indexing data provided via FTP.



================================================
Configuring Splunk
================================================


Step one: install the app into Splunk
----------------------------------------------------------------

Install this app into Splunk by doing the following:

  1. Log in to Splunk Web and navigate to "Apps » Manage Apps" via the app dropdown at the top left of Splunk's user interface
  2. Click the "install app from file" button
  3. Upload the file by clicking "Choose file" and selecting the app
  4. Click upload
  5. Restart Splunk if a dialog asks you to


[Optional step]: install libraries in order to support SSL
----------------------------------------------------------------
The FTP receiver app supports SSL but only if the SSL libraries are installed. To do this, run the setup.py script using Splunk's Python interpreter. Below is an example (assuming Splunk is installed in /opt/splunk):

    /opt/splunk/bin/splunk cmd python /opt/splunk/etc/apps/ftp_receiver/bin/setup.py

You may need to restart Splunk once this is done in order for the app to recognize that the SSL libraries have been installed. However, Splunk recognizes them without a restart in my experience.


Step two: create an input
----------------------------------------------------------------
Once the app is installed, you can use the app by configuring a new input:
  1. Navigate to "Settings » Data Inputs" at the menu at the top of Splunk's user interface.
  2. Click "FTP"
  3. Click "New" to make a new instance of an input

Make sure that the path that you are serving the files from exists.


Step three: adjust permissions
----------------------------------------------------------------
The FTP receiver app supports several capabilities to controls which user accounts can access the FTP server. To do set this up, create a user in Splunk and then assign one or more of the following capabilities:

 * ftp_read: can download data from the FTP server
 * ftp_write: can upload files to the FTP server
 * ftp_full_control: ability to do all things on the FTP server (read, write, delete, etc)

Only accounts with one of these capabilities will be able to authenticate to the FTP server. Note that the username and password of the Splunk user account will be the username and password used for authenticating with the FTP server. 


================================================
Known Limitations
================================================

1) Windows will not run the FTP server properly if the address to listen on is blank or "0.0.0.0". Instead, enter the IP address of the interface to get the input to work. 

2) Uploaded files will not be synchronized between hosts in a Search Head Clustering environment.

3) This app uses Python and thus won't work on a Universal Forwarder. Make sure to use a light or a heavy forwarder.

4) SSL is only supported if the SSL libraries are installed. See the install directions above to see how to get them installed.



================================================
Getting Support
================================================

Go to the following website if you need support:

     http://splunk-base.splunk.com/apps/3318/answers/

You can access the source-code and get technical details about the app at:

     https://github.com/LukeMurphey/splunk-ftp-receiver



================================================
FAQ
================================================

Q: Can I allow non-admin users to make and edit inputs?

A: Yes, just assign users the "edit_modinput_ftp" capability. You will likely want to give them the "list_inputs" capability too.


Q: The app isn't working; how do I best debug it?

A: Look at the logs from the application. You can see them by running a search for:

    index=_internal sourcetype=ftp_modular_input


Q: The FTP server didn't seem to shutdown properly; how do I clean this up?

A: You can force the daemon to shutdown. First, identify the PID by looking for the process that is listening on port 21:

    netstat -tulpn

   Next, kill the process with the ID that is listening on port 21 (assuming it is on port 13512):

    kill 13512



================================================
Change History
================================================

+---------+------------------------------------------------------------------------------------------------------------------+
| Version |  Changes                                                                                                         |
+---------+------------------------------------------------------------------------------------------------------------------+
| 0.5     | Initial release                                                                                                  |
|---------|------------------------------------------------------------------------------------------------------------------|
| 0.6     | Updated README                                                                                                   |
|         | Added loop that attempts to keep opening the socket if the port is taken already                                 |
|         | Directory to store files is now created if it does not already exist                                             |
|         | Input now checks to make sure that the path is a valid directory before attempting to start the FTP server       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0     | Updated README                                                                                                   |
|         | Added path restrictions so that people cannot use an FTP input to serve sensitive Splunk files                   |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.1   | Adding support for Python 3                                                                                      |
|         | Updating the pyftplib to version 1.5.5                                                                           |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.2   | Updating the mod input library to 2.1.13                                                                         |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.3   | Updating the modular input library to version 2.1.14                                                             |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.1.0   | Adding support for SSL/TLS; see the instructions above on how to enable it                                       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.1.1   | Updated the pyftplib to version 1.5.6; this ought to provide improved performance                                |
+---------+------------------------------------------------------------------------------------------------------------------+
