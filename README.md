# acme

ACME Go client library and a command line too.
Also, see https://letsencrypt.org.

Contents of this repo:

* `/` - ACME client Go package
* `cmd/acme/` - cli tool, similar to the official `letsencrypt`

*This package is a work in progress and makes no API stability promises.*

## Usage

Optionally, if you would not like `acme` to generate the account key for you,
you should create an unencrypted private key for use with account registration.
This can be done using OpenSSL:

    mkdir -p ~/.config/acme
    openssl -out ~/.config/acme/account.key 2048

Next, register an account using the `acme` client. The contact information,
such as email address at the end, is optional but recommended. If you would like
to have `acme` generate the account key for you instead of using OpenSSL or
similar software, specify `-gen` flag. Both examples are shown below, though
only one should be run depending on the whether you are providing the account
key or having `acme` generate one.

    # manually generated account key
    acme reg mailto:email@example.com

    # automatically generated account key
    acme reg -gen mailto:email@example.com

Next, review the terms and, if you agree, accept them like so:

    acme update -accept

Now, we are ready to request our certificate. The certificate will be placed
alongside a key file, specified with the `-k` argument. If the key file does not
exist, a new one will be created.

If you would prefer to generate the certificate key yourself, this may be done
using openssl or a similar tool, and shown in the example below.

`acme cert` command currently implements only the HTTP challenge mechanism (http-01).
This requires the command to be run in a way the challenge can be resolved
on the same machine, i.e. it's running a local HTTP server for the
duration of authorization phase. You may also do this manually with the `-manual`
flag if you have access to where the domain is served from, and `acme cert` will
print the appropriate instructions.

    # manually generated private cert key, automatic HTTP challenge
    openssl genrsa -out ~/.config/acme/example.com.key 2048
    acme cert example.com

    # automatically generated private key, automatic HTTP challenge
    acme cert example.com

    # automatically generated private key, manual HTTP challenge
    acme cert -manual example.com

## License

(c) Google, 2015. Licensed under [Apache-2](LICENSE) license.
