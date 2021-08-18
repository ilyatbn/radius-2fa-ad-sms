var adconfig = {
    domain: 'mydomain.io',
    url: 'ldap://1.2.3.4',
    baseDN: 'dc=mydomain,dc=io',
    username: 'mydomain\my_user_name',
    password: 'MyPassw0rd',
    attributes: { user: ['dn', 'userPrincipalName', 'sAMAccountName', 'mail', 'MobileNumber'] }
};

module.exports = adconfig;