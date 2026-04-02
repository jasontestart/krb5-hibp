# hibp-checker

An external password quality program, for the Heimdal Kerberos Administration Server,
that interacts with the [Have I Been Pwned](https://haveibeenpwned.com/) 
**Pwned Password** API using k-Anonymity.

## Dependencies

To build and install this program, you will need to:
1. build and install the
[libhibp](https://github.com/jasontestart/libhibp) library.
2. Install the `libConfuse` library and associated development libraries.

On Debian:
```bash
sudo apt update
sudo apt install libconfuse-dev
```

On RHEL-based distributions, you will need to enable the _Extra Packages for Enterprise Linux (EPEL)_ repository to
get the LibConfuse development library. The steps for this may vary based on the distribution. 
On Rocky Linux, the following should work assuming you already have the _Development Tools_ installed:
```bash
sudo dnf install epel-release
sudo dnf install libconfuse-devel
```

## Building & Installing

Simply run the following:
```bash
make
sudo make install
```

## Program Usage
This program is designed to be invoked by a Heimdal `kadmind` server using the `external-check` password
quality policy. With Debian, this would normally be accomplished by the following in `/etc/heimdal-kdc/kdc.conf`:
```ini
[password_quality]
policies = external-check
external_program = /usr/local/bin/hibp-checker
```

With no configuration, the `hibp-checker` program, through `libhibp`, will take the SHA1 hash of the provided
password and, using k-Anonymity, will lookup the hash using the 
[Pwned Password API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
at `https://api.pwnedpasswords.com/range/`.
If the hash is not found in the database, then the program outputs the message `APPROVED`,
otherwise it outputs `REJECTED` with some details about the rejection.

## Configuration

The program's behaviour may be modified using the configuration file `/etc/hibp-checker.conf`.
This file must be owned by `root (uid=0)` with file permissions `0700`, otherwise it will
be silently ignored.

Lines that begin with spaces or comments `#` will be ignored. The following configration options are supported:

**proxy**

You can configure the program to use a proxy server when connecting to the Pwned Password API. Any proxy
supported by `libcurl` is supported, provided the the scheme can be defined with a url prefix. 

Example: `proxy = https://mysquidproxy.internal:3128/`.

See [https://curl.se/libcurl/c/CURLOPT_PROXY.html](https://curl.se/libcurl/c/CURLOPT_PROXY.html).

**api**

There is a mechanism to [download](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
 the entire 85GB+ Pwned Password database and host the API yourself. This program can be configured
to use a different API endpoint, provided it behaves exactly the same as 
`https://api.pwnedpasswords.com/range/`.

Example: `api = https://mypwneddb.internal/range/`.

The `api` and `proxy` arguments may be combined.

**threshold**

You may have a risk tolerance that allows a good quality password (i.e., a sufficiently long passphrase)
that may appear in the Pwned Password database but for a small number of breaches, as you have other 
controls in place (e.g., MFA, network segmentation). You can define a threshold so that the program will 
return a rejection message when the password is in the Pwned Password database and the number of breaches 
found exceeds the defined threshold. This value must be a whole number.

Example: `threshold = 1000` The program will catch the password `abc123`, but not the passphrase `This is a test.`, 
even though both are in the Pwned Password database.

When this value is absent, the default value for threashold is zero.
