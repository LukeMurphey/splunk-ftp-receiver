================================================
Overview
================================================

This app provides a mechanism for indexing data provided via FTP.



================================================
Configuring Splunk
================================================

This app exposes a new input type that can be configured in the Splunk Manager. To configure it, create a new input in the Manager under Data inputs > FTP.



================================================
Getting Support
================================================

Go to the following website if you need support:

     http://splunk-base.splunk.com/apps/CHANGEME/answers/

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
+---------+------------------------------------------------------------------------------------------------------------------+
