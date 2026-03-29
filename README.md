# krb5-hibp

This respository contains software, for both MIT and Heimdal implementations of Kerberos, that uses the password quality interfaces of
the Key Distribution Center (KDC) to interface with the [Have I Been Pwned Pwned](https://haveibeenpwned.com/) Password API to reject attempted 
password changes to known, breached passwords.

The work of interfacing with the Pwned Password API is done using the [libhibp](https://github.com/jasontestart/libhibp) shared object, using k-Anonymity.

## MIT Kerberos

Implemented as a password quality (pwqual) module [krb5-hibp.so](https://github.com/jasontestart/krb5-hibp/tree/main/mit).

## Heimdal Kerberos

Implemented as a simple external checking program [hibp-checker](https://github.com/jasontestart/krb5-hibp/tree/main/hibp-checker).

## Note

This software implements **server-side** checks. If you are interested in **client-side** checks, take a look at the 
[pam_hibp](https://github.com/jasontestart/pam_hibp) PAM module.
