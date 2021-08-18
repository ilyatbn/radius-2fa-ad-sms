//Imports
var radius = require('radius');
var dgram = require("dgram");
var request = require('request');
var activeDirectory = require('activeDirectory');
var smtpClient = require('mail');
var randomize = require('randomatic');
var express = require('express');
var PouchDB = require('pouchdb');
var fs = require('fs');
const logger = require('simple-node-logger');

//Load config files
var adConfig = require('./adConfig');
var smtpConfig = require('./smtpConfig');
var logConfig = require('./loggerconfig');

//Central Configuration
//OTP section
var OTPDigitCount = 7;
var OTPCharacterMatrix = '0'; //0-numbers,a-lowercase,A-upercase,!-special chars,*-any char,?-custom chars
//SMS Provider section
var SMSProviderURL = 'https://mysmsprovider.com/sms?params=';
//SMTP Server configuration
var SMTPFrom = 'OneTimePassword@MyDomain.io';
var SMTPSubject = 'MyDomain.io One Time Password'
var autoFailbackToEmail = true;
//Active-Active Radius server section
var enableActiveActiveMode = false;
var DBSyncListenPort = 3001;
var DBSyncRemoteHost = '0.0.0.0'; //Set the remote IP address of each server before running it.
var DBSyncRemotePort = 3001
//RadiusConfiguration
var sharedSecret = 'MyRadiusSecret';
var radiusLocalPort = 1812;

//Startup
var ad = new activeDirectory(adConfig);
var mail = new smtpClient.Mail(smtpConfig);
if (!fs.existsSync(logConfig.logDirectory)){fs.mkdirSync(logConfig.logDirectory);}
var log = new logger.createRollingFileLogger(logConfig);
var server = dgram.createSocket("udp4");
var app = express();
var db = new PouchDB('userdb');
app.use('/', require('express-pouchdb')(PouchDB));
app.listen(DBSyncListenPort);
db.changes({live: true}).on('change', console.log);
if(enableActiveActiveMode){db.sync('http://'+DBSyncRemoteHost+': '+DBSyncRemotePort+'/userdb', {live: true, retry: true});}
var UserUPN = function (name) {return name + '@' + adConfig.domain};

//Server message receive start here
server.on("message", function (msg, rinfo) {
	var code, username, password, nasIP, nasIdentifier, reqId, packet;
	let response;
	var sendResponse = function (code) {
		if (code === 'Access-Challenge') {
			response = radius.encode_response({
				packet: packet,
				code: code,
				identifier: reqId,
				secret: sharedSecret,
				attributes:[['Reply-Message', 'Enter One-Time Password:']]
			});
		} else {		
			response = radius.encode_response({
				packet: packet,
				code: code,
				identifier: reqId,
				secret: sharedSecret
			});
		}
        log.info(username+': Sending ' + code + ' for user');
        server.send(response, 0, response.length, rinfo.port, rinfo.address, function (err, bytes) {
            if (err) {
                log.error('Error sending response to ', rinfo);
            }
        });
    };


    packet = radius.decode({ packet: msg, secret: sharedSecret });
	if (packet.code !== 'Access-Request') {
        log.info('unknown packet type: ', packet.code);
		return;
	}

    username = String.prototype.toLowerCase.apply(packet.attributes['User-Name']);
    password = packet.attributes['User-Password'];
	nasIP = packet.attributes['NAS-IP-Address'];
	nasIdentifier = packet.attributes['NAS-Identifier'];
	reqId = packet.identifier;
	log.info('packet received:'+JSON.stringify(packet));

	var findUserInAd = function (name, cb) {
        ad.findUser(UserUPN(name), function (err, user) {
            if (err) {
                log.error('Error getting data: '+JSON.stringify(err));
                cb(undefined);
                return;
            }
            if (!user) {
                log.warn(UserUPN(username)+': User was not found in Active Directory');
                cb(undefined);
            } else {
                cb(user);
            }
        });
    };

	var checkDBChallenges = function (cb){
		db.get(String.prototype.toLowerCase.apply(username)).then(function (doc) {
			if (String.prototype.toLowerCase.apply(doc.sAMAccountName) === String.prototype.toLowerCase.apply(username)) {
				log.info(username+': User matches database data.');
				if (doc.code === password) {
					log.info(username+': Correct code found: ' + password);
					db.remove(doc).then(function (doc) {
					}).catch(function (err) {
						log.error(username+': Error removing item from database: '+err);
					});
					sendResponse('Access-Accept');
				} else {
					log.info(username+': User entered the wrong code: '+password);
					db.remove(doc).then(function (doc) {
					}).catch(function (err) {
						log.error(username+': Error removing item from database.');
					});
					log.info(username+': Removed from db and sending rad reject')
					sendResponse('Access-Reject');
				}
			}
			else {
				log.info(username+': User not found in database. it shouldn\'t ever get here.');
				cb();
			}
		}).catch(function (err){
		console.log (err.status);
			if (err.status === 404) {
				log.info(username+': Database output: '+err);
			} else {
				log.error(username+'Database error: '+err);
			}
			cb();
		});
	};

    findUserInAd(username, function (user) {
        if (!user) {
            sendResponse('Access-Reject');
        } else {           
			user['_id'] = String.prototype.toLowerCase.apply(user.sAMAccountName);
			user['sAMAccountName'] = String.prototype.toLowerCase.apply(user.sAMAccountName);
            checkDBChallenges(function () {
                let randomotp = randomize(OTPCharacterMatrix, OTPDigitCount);
				if (user.MobileNumber) {
					let mobile = user.MobileNumber.trim();
					log.info(user.sAMAccountName+': sending otp ' + randomotp + ' to this number ' + mobile);
                    //You will need to modify this according to your http request scheme
					smsHttpRequest = SMSProviderURL + mobile + "&CONTENT=Your One Time Password is: "
					request.get(smsHttpRequest + randomotp, function (error, response, body) {
						if (!error && response.statusCode === 200) {
							log.info(user.sAMAccountName+': http response for user:'+response.body);
                            user.code = randomotp;
							db.put(user).then(function (doc) {
							}).catch(function (err) {
								log.error(user.sAMAccountName+': error putting data into database');
								sendResponse('Access-Reject');
							});
							sendResponse('Access-Challenge');
                        } else {
							log.error(user.sAMAccountName+': could not send OTP to '+mobile+' - '+error);
							sendResponse('Access-Reject');
						}
                    });
                } else {
                    log.info(user.sAMAccountName+': No phone number found. Cannot send text unless autoFallbackToEmail is enabled.');
                    if (autoFailbackToEmail){
						log.info(user.sAMAccountName+': AutoFallback - sending OTP ' + randomotp + ' to this email ' + user.mail);
						mail.message({
							from: SMTPFrom,
							to: [user.mail],
							subject: SMTPSubject
						})
						.body('Your OTP is: '+ randomotp).send(function(err) {
							if (!err) {
								user.code = randomotp;
								db.put(user).then(function (doc) {
								}).catch(function (err) {
									log.error(user+': error putting data into database');
									sendResponse('Access-Reject');
								});
								sendResponse('Access-Challenge');
							} else {
								log.error(user+': Could not send email to '+user.email+' - '+error);
								sendResponse('Access-Reject');
							};
						});
					}
				}
            });
        }
    });
});

//Server listener start here
server.on("listening", function () {
	var address = server.address();
	log.info("radius server listening " +
		address.address + ":" + address.port);
	console.log("server started.");
});

server.bind(radiusLocalPort);