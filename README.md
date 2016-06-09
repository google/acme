# goacme

ACME Go client library and AppEngine module.

Also, see https://letsencrypt.org.

Contents of this repo:

* `/` - ACME client Go package
* `cmd/goacme/` - cli tool, similar to the official `letsencrypt`
* `appengine/` - Google App Engine for Go package

## License

(c) Google, 2015. Licensed under [Apache-2](LICENSE) license.

## Usage

Optionally, if you would not like `goacme` to generate the account key for you, you should create an unencrypted private key for use with account registration. This can be done using OpenSSL:

```
mkdir -p ~/.config/acme
openssl -out ~/.config/acme/account.key 2048
```

Next, register an account using the `goacme` client. The contact information, such as email address at the end, is optional but recommended. If you would like to have `goacme` generate the account key for you instead of using OpenSSL or similar software, include the `-gen` flag. Both example are shown below, though only one should be run depending on the whether you are providing the account key or having `goacme` generate one.

```
# Manually Generated Account Key
goacme reg mailto:your-email-address@gmail.com

# Automatically Generated Account Key
goacme reg -gen mailto:your-email-address@gmail.com
```

Next, review the terms and if you agree, you can accept them like so:

```
goacme update -accept
```

Now, we are ready to request our certificate. To do this, we need a private key for the domain first.

```
openssl -out ~/.config/acme/www.domain.com.key 2048
goacme cert www.domain.com
```
