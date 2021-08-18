# OTP Radius server
This app will listen to Radius Access-Request messages, and send back Access-Challenge responses after generating One Time Passwords to the Radius client.
One Time Passwords will be sent to the user using SMS providers (HTTP requests) or e-mail.
Phone numbers and e-mail addresses will be taken from Active Directory.
The server does not validate users' Active Directory passwords. 


# Features:
- Send SMS text messages using a web service.
- Auto fallback to email in case no phone number is found.
- Active-Active cluster configuration using lightweight pouchdb replication.
- Logging for all radius requests and challenges.


# Configuration:
smtpconfig.json - Configure smtp server settings for email support.
adconfig.js - Configure Active Directory settings to pull phone numbers.
app.js - Main server settings.


# Installation:
1. Configure all the necessary parameters in the configuration files.
2. Modify line 158 in app.js (http request to SMS provider) according to your providers URI scheme.
3. run "npm install"
4. run "node app.js" to run the server
5. If using Windows, there's an option to automatically install as a service: "npm run-script install-windows-service"


***This code is not maintained anymore.***