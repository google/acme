# acme

A simple command line tool to manage TLS certificates with ACME-compliant CAs,
which has no third party dependencies.

If you're looking for a package to import in your program, `golang.org/x/crypto/acme`
or `golang.org/x/crypto/acme/autocert` is what you'll want instead.

*This package is a work in progress and makes no API stability promises.*

## Usage

Quick install with `go get -u github.com/google/acme`
or download a pre-built binary from the
[releases page](https://github.com/google/acme/releases).

The release binaries have an additional command, `acme version`,
which reports the release version.

1. You need to have a user account, registered with the CA. This is represented
  by an RSA private key.

  The easiest is to let the `acme` tool generate it for you:

        acme reg -gen mailto:email@example.com

  If you want to generate a key manually:

        mkdir -p ~/.config/acme
        openssl genrsa -out ~/.config/acme/account.key 4096
        acme reg mailto:email@example.com

  The latter version assumes that default `acme` config dir is `~/.config/acme`.
  Yours may vary. Check with `acme help reg`.

  The "mailto:email@example.com" in the example above is a contact argument.
  While some ACME CA may let you register without providing any contact info,
  it is recommended to use one. For instance a CA might need to notify
  cert owners with an update.

2. Agree with the ACME CA Terms of Service.

  Before requesting your first certificate, you may need to accept
  the terms of the CA. You can check the status of your account with:

        acme whoami

  and look for the "Accepted: ..." line. If it says "no", check the CA's terms document
  provided as a link in "Terms: ..." field and agree by executing:

        acme update -accept

3. Request a new certificate for your domain.

  The easiest way to do this is:

        acme cert example.com

  The above command will generate a new certificate key (unless one already exists),
  and send a certificate request. The location of the output files is `~/.config/acme`,
  but depends on your environment. You can check this location with `acme help cert`.

  If you don't want to auto-generate a cert key, one can always be generated upfront:

        openssl genrsa -out cert.key 2048

  in which case the cert command will look something like this:

        acme cert -k cert.key example.com

  Note that for the certificate request command to succeed, it needs to be executed in a way
  allowing for resolving authorization challenges (domain ownership proof). This typically
  means the command should be executed on the same host the domain is served from.

  If the latter is not possible, use the `-manual` flag and follow the instructions:

        acme cert -manual example.com


## Usage

Optionally, if you would not like `goacme` to generate the account key for you, you should create an unencrypted private key for use with account registration. This can be done using OpenSSL:

    mkdir -p ~/.config/acme
    openssl -out ~/.config/acme/account.key 2048

Next, register an account using the `goacme` client. The contact information,
such as email address at the end, is optional but recommended. If you would like
to have `goacme` generate the account key for you instead of using OpenSSL or
similar software, include the `-gen` flag. Both example are shown below, though
only one should be run depending on the whether you are providing the account
key or having `goacme` generate one.

    # Manually Generated Account Key
    goacme reg mailto:your-email-address@gmail.com

    # Automatically Generated Account Key
    goacme reg -gen mailto:your-email-address@gmail.com

Next, review the terms and if you agree, you can accept them like so:

    goacme update -accept

Now, we are ready to request our certificate. The certificate will be placed
alongside key file, specified with the `-k` argument. If the keyfile does not
exist, a new one will be created.

If you would prefer to generate the key yourself, this may be done using openssl
or a similar tool, and has been  included / shown in the example below.

`goacme cert` currently implements only the HTTP challenge mechanism. This
requires the command to be run in a way the challenge can either be resolved
automatically on the same machine, i.e. it's running a local HTTP server for the
duration of authorization phase. You may also do this manually with the `-manual`
flag if you have access to where the domain is served, and `goacme cert` will
print the appropriate instructions.

    # Manually Generated Private Domain Key, Automatic HTTP Challenge
    openssl genrsa -out ~/.config/acme/example.com.key 2048
    goacme cert example.com

    # Automatically Generated Private Domain Key, Automatic HTTP Challenge
    goacme cert example.com

    # Automatically Generated Private Domain Key, Manual HTTP Challenge
    goacme cert -manual example.com

## License

(c) Google, 2015. Licensed under [Apache-2](LICENSE) license.

This is not an official Google product.
