## PAM_OTP

This PAM module can be used to authenticate a user for which:

* the provided username corresponds to a 'uid' (see config option) that is found within the LDAP_SUBTREE under the specified 'basedn'
* the 'userPassword' attribute belonging to that ldap entry contains a OTP Shared Secret (refer to RFC6238)
* the provided password contains a 6-digit OTP code (similar like Google Authenticator) that satifies the OTP calculated value with the found shared secret.

Credit:
part of code used from pam_2fa project of CERN

Harry Kodden

# Install

Requirement for building the pam module is that the basic development tools are installed on your system. This can be achieved by installing the following:

On Debian/Ubuntu:
~~~
sudo apt-get install build-essential
sudo apt-get install autoconf
sudo apt-get install shtool
sudo apt-get install libpam-dev
sudo apt-get install libcurl4-gnutls-dev
sudo apt-get install libgcrypt20 libgcrypt20-dev
sudo apt-get install libldap2-dev
~~~

On Fedora/Redhat/CentOS you will need:
~~~
sudo yum groupinstall 'Development Tools'
sudo yum install shtool
sudo yum install pam-devel
sudo yum install libcurl curl-devel
sudo yum install libgcrypt libgcrypt-devel
~~~

After cloning the repository, do the following:

~~~
cd pam_otp
ln -s /usr/bin/shtool .
autoconf
./configure
make
sudo make install
~~~

The pam module will be install under /usr/local/lib/security. In the PAM config file, you should explicity point to this path. Alternatively you can make a symbolic link to that default PAM location.

For example:

~~~
ln -s /usr/local/lib/security/pam_otp.so /lib/security
~~~

Alternatively, you can use 'docker' to install & run this package via a container.
Using the Dockerfile, you can run it as:
~~~
docker build -t pam_otp .
docker run pam_otp
~~~

# Sample Usage

Let:
- The pam_otp.so module is installed in /usr/local/lib/security
- The pam_otp.so is used to iRODS authentication

The file /etc/pam.d/irods would then look like:

~~~
#%PAM-1.0
auth      sufficient     pam_unix.so
auth      sufficient     pam_otp.so ldap=ldap://localhost basedn=dc=example,dc=org binddn=cn=admin,dc=example,dc=org passwd=...
~~~

Configuration settings:

Config | Meaning | Example
--- | --- | ---
ldap | ldap host | ldap=ldap://localhost
basedn | distinguished name for the base tree | basedn=dc=example,dc=org
binddn | distinguished name for the bind user | binddn=cn=admin,dc=example,dc=org
passwd | password of the bind user | passwd=admin
debug | debug option | debug
ttl | Time To Live of an OTP code | ttl=3600 (default = 0)
uid | ldap attribute to lookup userid | uid=uid (default = uid)


The ***ttl*** option be used to allow re-use the OTP code for a certain period. This is useful for stateless reconnects (for example WebDAV). When a OTP code is offered for authentication that was valid before, this will still be valid as long as the TTL period is not expired.



You can verify the PAM module is working as expected using the standard iRODS command line utility ***irodsPamAuthCheck***

Example 1: Verify a system user can logon to iRODS...

~~~
irodsPamAuthCheck rods
<enter your system password now>
~~~

Example 2: Verify a COManage provisioned user can logon to iRODS...

~~~
irodsPamAuthCheck harry.kodden@yoda.uu
<enter your Service Token / One Time Password now>
~~~

There is also a 'debug' option that you can activate in the pam config file. Extra logging is then produced in /var/log/secure (syslog)

# Self Test

The self test is executing the same limits as described in the RFC6238

https://tools.ietf.org/html/rfc6238#appendix-B

Running the self test requires that you compile the selftest program as follows:

Run selftests:

~~~
$ make test
~~~

Output should look like:

~~~
TEST[1]: epoch: 59, "Thu Jan  1 01:00:59 1970", SHA1, calculated TOTP: 94287082, OK !
TEST[2]: epoch: 59, "Thu Jan  1 01:00:59 1970", SHA256, calculated TOTP: 46119246, OK !
TEST[3]: epoch: 59, "Thu Jan  1 01:00:59 1970", SHA512, calculated TOTP: 90693936, OK !
TEST[4]: epoch: 1111111109, "Fri Mar 18 02:58:29 2005", SHA1, calculated TOTP: 7081804, OK !
TEST[5]: epoch: 1111111109, "Fri Mar 18 02:58:29 2005", SHA256, calculated TOTP: 68084774, OK !
TEST[6]: epoch: 1111111109, "Fri Mar 18 02:58:29 2005", SHA512, calculated TOTP: 25091201, OK !
TEST[7]: epoch: 1111111111, "Fri Mar 18 02:58:31 2005", SHA1, calculated TOTP: 14050471, OK !
TEST[8]: epoch: 1111111111, "Fri Mar 18 02:58:31 2005", SHA256, calculated TOTP: 67062674, OK !
TEST[9]: epoch: 1111111111, "Fri Mar 18 02:58:31 2005", SHA512, calculated TOTP: 99943326, OK !
TEST[10]: epoch: 1234567890, "Sat Feb 14 00:31:30 2009", SHA1, calculated TOTP: 89005924, OK !
TEST[11]: epoch: 1234567890, "Sat Feb 14 00:31:30 2009", SHA256, calculated TOTP: 91819424, OK !
TEST[12]: epoch: 1234567890, "Sat Feb 14 00:31:30 2009", SHA512, calculated TOTP: 93441116, OK !
TEST[13]: epoch: 2000000000, "Wed May 18 05:33:20 2033", SHA1, calculated TOTP: 69279037, OK !
TEST[14]: epoch: 2000000000, "Wed May 18 05:33:20 2033", SHA256, calculated TOTP: 90698825, OK !
TEST[15]: epoch: 2000000000, "Wed May 18 05:33:20 2033", SHA512, calculated TOTP: 38618901, OK !
TEST[16]: epoch: 20000000000, "Tue Oct 11 13:33:20 2603", SHA1, calculated TOTP: 65353130, OK !
TEST[17]: epoch: 20000000000, "Tue Oct 11 13:33:20 2603", SHA256, calculated TOTP: 77737706, OK !
TEST[18]: epoch: 20000000000, "Tue Oct 11 13:33:20 2603", SHA512, calculated TOTP: 47863826, OK !
Done
~~~

The 'test' application can also be given a parameter, representing the TOTP secret key. The output of the test run will be the TOTP code given that TOTP secret and the systemtime. This should be the same TOTP code as displayed on your Google Authenticator app at the same moment.
