================================================
Overview
================================================

This app provides a mechanism for indexing data provided via FTP.



================================================
Configuring Splunk
================================================

This app exposes a new input type that can be configured in the Splunk Manager. To configure it, create a new input in the Manager under Data inputs > FTP.

The FTP receiver app supports several capabilities to controls which user accounts can access the FTP server. To do set this up, create a user in Splunk and then assign one or more of the following capabilities:

 * ftp_read: can download data from the FTP server
 * ftp_write: can upload files to the FTP server
 * ftp_full_control: ability to do all things on the FTP server (read, write, delete, etc)

Only accounts with one of these capabilities will be able to authenticate to the FTP server. Note that the username and password of the Splunk user account will be the username and password used for authenticating with the FTP server. 



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
+---------+------------------------------------------------------------------------------------------------------------------+
