# krb5-hibp

A password quality interface (pwqual) module for MIT Kerberos that interacts with the 
[Have I Been Pwned](https://haveibeenpwned.com/) **Pwned Password** API using k-Anonymity.

## Dependencies

To build and install this module, you will need to:
1. Build and install the [libhibp](https://github.com/jasontestart/libhibp) library.
2. Install the MIT Kerberos development libraries. 

### Debian-based installation
```bash
sudo apt update
sudo apt install krb5-config libkrb5-dev libkrb5-3
```

### RHEL-based installation
```bash
sudo dnf install TBD 
```

## Building & Installing

To build, simply run make:
```bash
make
```

This module must be installed where the Kerberos Administration Server (kadmind) is running.

The location of pwqual modules may depend on the Linux distribution,
 and in many cases the machine architecture.
To find the location of the pwqual modules in your Linux distribution, try running the following:
```bash
find /usr -name pwqual
```

### Debian-based distributions

To install on a Debian-based OS (tested with Debian, Ubuntu, and Raspberry Pi OS):
```bash
sudo PWQUAL_DIR=/usr/lib/`uname -m`-linux-gnu/krb5/plugins/pwqual make install
```

### RHEL-based distributions

To install on a RHEL-based OS (tested with Rocky Linux):
```bash
sudo PWQUAL_DIR=/usr/lib64/krb5/plugins/pwqual make install
```
## Potential Obstacles

There may be several additional steps needed to get this module to work, which will ironcally
have security implications on your system. 

#### LD_LIBRARY_PATH

This module depends on the `libhibp` library, which installs by default in `/usr/local/lib`. Your system may not 
be configured to search in this directory for system libraries.  You will need to make sure that 
`LD_LIBRARY_PATH` is set appropriately for the Kerberos administration server to find `libhibp`.`

This can be accomplished by setting up the environment specifically in `systemd`,
by running the command `sudo systemctl edit krb5-admin-server` (on Debian) and adding the following lines near the beginning of the file:

```ini
[Service]
Environment="LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH"
```

#### SELinux network security policy

The default SELinux network security policy may prevent certain programs/daemons from trying to connect to
the HIBP API.  To override this, run:
```bash
sudo setsebool -P nis_enabled 1
```

## Configuration

In `kdc.conf`:
```ini
[plugins]
  pwqual = {
    module = hibp:/usr/lib/x86_64-linux-gnu/krb5/plugins/pwqual/krb5-hibp.so
  }
```

By default, the `krb5-hibp` module, through `libhibp`, will take the SHA1 hash of the provided
password and, using k-Anonymity, will lookup the hash using the [Pwned Password API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
at `https://api.pwnedpasswords.com/range/`.
If the hash is found one or more times in the database, then authentication (or password change) is rejected
 and the action is recorded to syslog. The module's behaviour may be modified by setting the following variables
in the `kdc.conf` file:

**hibp_auditonly**

When the value of `hibp_auditonly` is set to `true`, then the detection of a Pwned Password will be written to syslog.
Authentication or password change will not be affected by the module. The default value is `false`.

**hibp_proxy**

You can configure the module to use a proxy server when connecting to the Pwned Password API. Any proxy
supported by `libcurl` is supported, provided the the scheme can be defined with a url prefix. 

Example: `hibp_proxy = https://mysquidproxy.internal:3128/`.

See [https://curl.se/libcurl/c/CURLOPT_PROXY.html](https://curl.se/libcurl/c/CURLOPT_PROXY.html).

**hibp_api**

There is a mechanism to [download](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
 the entire 85GB+ Pwned Password database and host the API yourself. This module can be configured
to use a different API endpoint, provided it behaves exactly the same as 
`https://api.pwnedpasswords.com/range/`.

Example: `hibp_api = https://mypwneddb.internal/range/`.

**hibp_threshold**

You may have a risk tolerance that allows a good quality password (i.e., a sufficiently long passphrase)
that may appear in the Pwned Password database but for a small number of breaches, as you have other 
controls in place (e.g., MFA, network segmentation). You can define a threshold so that the module will only take
action and/or log when the password is in the Pwned Password database and the number of breaches found exceeds the 
defined threshold. This value must be a whole number.

When this variable assignment is absent, the default value is zero.

### Example

On a Debian system, the following lines at the end of `/etc/krb5kdc/kdc.conf` will enable the krb5-hibp password quality module 
to reject the setting of new passwords in the Pwned Password database were the number of breaches is greater than 1000. So the password
`abc123` will be rejected but the passphrase `This is a test.` will be accepted, even though both are in the Pwned Password database.

```ini
[plugins]
  pwqual = {
    module = hibp:/usr/lib/x86_64-linux-gnu/krb5/plugins/pwqual/krb5-hibp.so
    hibp_threshold = 1000
  }
```

## Note
This is a server-side check, and the `pwqual_plugin` interface does not currently support a user return code suitable for this
use-case. Detailed reasons for password rejection are recorded to syslog on the Kerberos Administration Server (aka `kadmind`)
All error messages are in English as localization is not currently supported.
