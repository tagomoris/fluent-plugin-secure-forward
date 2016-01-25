# fluent-plugin-secure-forward

[Fluentd](http://fluentd.org) input/output plugin to forward fluentd messages over SSL with authentication.

This plugin makes you to be able to:

 * protect your data from others in transferring with SSL
   * with certificate signed and registered correctly/publicly
   * with private CA certificates generated by users
   * with automatically generated and self-signed certificates **in vulnerable way**
 * authenticate by shared\_key check from both of client(out\_secure\_forward) and server(in\_secure\_forward)
 * authenticate with username / password pairs

## Installation
install with gem or fluent-gem command as:

```
 ### native gem
$ gem install fluent-plugin-secure-forward
 
 ### fluentd gem
$ fluent-gem install fluent-plugin-secure-forward
```

### Using SSL certificates issued from trusted CA

To communicate over SSL with valid certificate issued from public CA, configure params below for input plugin:

* `secure`: set `yes` or `true`
* `cert_path`: set path of certificate file issued from CA
* `private_key_path`: set path of private key file
* `private_key_passphrase`: set passphrase of private key

```apache
<source>
  @type secure_forward
  
  # bind 0.0.0.0 # default
  # port 24284 # default
  self_hostname server.fqdn.example.com
  shared_key    secret_string
  
  secure yes
  
  cert_path        /path/for/certificate/cert.pem
  private_key_path /path/for/certificate/key.pem
  private_key_passphrase secret_foo_bar_baz
</source>
```

For output plugin, specify just 2 options below:

* `secure`: set `yes` or `true`
* `enable_strict_verification`: specify `yes` or `true` to verify FQDN of servers (input plugin)

```apache
<match secret.data.**>
  @type secure_forward
  
  self_hostname client.fqdn.local
  shared_key    secret_string
  
  secure yes
  enable_strict_verification yes
  
  <server>
    host server.fqdn.example.com  # or IP
    # port 24284
  </server>
  <server>
    host 203.0.113.8 # ip address to connect
    hostlabel server.fqdn.example.com # specify hostlabel for FQDN verification if ipaddress is used for host
  </server>
</match>
```

### Using private CA file and key

This plugin has a simple utility command to generate private CA cert/key files just for secure-forward.

```
$ secure-forward-ca-generate /path/for/dir/of/certs "passphrase for private CA secret key"
```

This command generates `ca_cert.pem` and `ca_key.pem` on `/path/for/dir/of/certs`. For SSL communication with private CA, users must deploy both files for input plugins, and also must deploy `ca_cert.pem` for output plugins.
And then, configure Fluentd with these files and the passphrase. With this configuration, server certificates are automatically generated and issued by private CA.

```apache
<source>
  @type secure_forward
  
  # bind 0.0.0.0 # default
  # port 24284 # default
  self_hostname myserver.local
  shared_key    secret_string
  
  secure yes
  
  ca_cert_path        /path/for/certificate/ca_cert.pem
  ca_private_key_path /path/for/certificate/ca_key.pem
  ca_private_key_passphrase passphrase for private CA secret key
</source>
```

For output plugin, specify just 2 options below:

* `secure`: set `yes` or `true`
* `enable_strict_verification`: specify `yes` or `true`

```apache
<match secret.data.**>
  @type secure_forward
  
  self_hostname myclient.local
  shared_key    secret_string
  
  secure yes
  ca_cert_path /path/for/certificate/ca_cert.pem
  # enable_strict_verification yes
  
  <server>
    host server.fqdn.example.com  # or IP
    # port 24284
  </server>
  <server>
    host 203.0.113.8 # ip address to connect
    hostlabel server.fqdn.example.com # specify hostlabel for FQDN verification if ipaddress is used for host
  </server>
</match>
```

### Using insecure self-signed certificates

**This is very dangerous and vulnerable to man-in-the-middle attacks**

For just testing or data center internal communications, this plugin has a feature to communicate without any verification of certificates. Turn `secure` option to `false` to use this feature.

```apache
<source>
  @type secure_forward
  
  self_hostname myserver.local
  shared_key    secret_string
  
  secure no
</source>
```

Configure output plugin just same way:

```apache
<match data.**>
  @type secure_forward
  
  self_hostname myclient.local
  shared_key    secret_string
  
  secure no
  
  <server>
    host server.fqdn.example.com  # or IP
  </server>
</match>
```

In this mode, output plugin cannot verify peer node of connections. Man-in-the-middle attackers can spoof messages from output plugins under many various situations.

## Configuration

### SecureForwardInput

Default settings:
  * listen 0.0.0.0:24284
    * `bind 192.168.0.101`
    * `port 24284`
  * allow to accept from any sources
  * allow to connect without authentications
  * use certificate automatically generated
    * `generate_private_key_length 2048`
    * `generate_cert_country  US`
    * `generate_cert_state    CA`
    * `generate_cert_locality Mountain View`
    * `generate_cert_common_name SAME_WITH_SELF_HOSTNAME_PARAMETER`
  * use TLSv1.2
  
Minimal configurations like below:

```apache
<source>
  @type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local  # This fqdn is used as CN (Common Name) of certificates
  
  secure yes
  # and configurations for certs
</source>
```

To check username/password from clients, like this:

```apache
<source>
  @type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  
  secure yes
  # and configurations for certs
  
  authentication     yes # Deny clients without valid username/password
  <user>
    username tagomoris
    password foobar012
  </user>
  <user>
    username frsyuki
    password yakiniku
  </user>
</source>
```

To deny unknown source IP/hosts:

```apache
<source>
  @type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  
  secure yes
  # and configurations for certs
  
  allow_anonymous_source no  # Allow to accept from nodes of <client>
  <client>
    host 192.168.10.30
  </client>
  <client>
    host your.host.fqdn.local
    # wildcard (ex: *.host.fqdn.local) NOT Supported now
  </client>
  <client>
    network 192.168.16.0/24 # network address specification
  </client>
</source>
```

You can use both of username/password check and client check:

```apache
<source>
  @type secure_forward
  shared_key         secret_string
  self_hostname      server.fqdn.local
  
  secure yes
  # and configurations for certs
  
  allow_anonymous_source no  # Allow to accept from nodes of <client>
  authentication         yes # Deny clients without valid username/password
  <user>
    username tagomoris
    password foobar012
  </user>
  <user>
    username frsyuki
    password sukiyaki
  </user>
  <user>
    username repeatedly
    password sushi
  </user>
  <client>
    host 192.168.10.30      # allow all users to connect from 192.168.10.30
  </client>
  <client>
    host  192.168.10.31
    users tagomoris,frsyuki # deny repeatedly from 192.168.10.31
  </client>
  <client>
    host 192.168.10.32
    shared_key less_secret_string # limited shared_key for 192.168.10.32
    users      repeatedly         # and repatedly only
  </client>
</source>
```

### SecureForwardOutput

Minimal configurations like this:

```apache
<match secret.data.**>
  @type secure_forward
  shared_key secret_string
  self_hostname client.fqdn.local
  
  secure yes
  # and configurations for certs/verification
  
  <server>
    host server.fqdn.local  # or IP
    # port 24284
  </server>
</match>
```

Without hostname ACL (and it's not implemented yet), `self_hostname` is not checked in any state. `${hostname}` placeholder is available for such cases.

```apache
<match secret.data.**>
  @type secure_forward
  shared_key secret_string
  self_hostname ${hostname}
  
  secure yes
  # and configurations for certs/verification
  
  <server>
    host server.fqdn.local  # or IP
    # port 24284
  </server>
</match>
```

When specified 2 or more `<server>`, this plugin uses these nodes in simple round-robin order. And servers with `standby yes` will be selected until all of non-standby servers goes down.

If server requires username/password, set `username` and `password` in `<server>` section:

```apache
<match secret.data.**>
  @type secure_forward
  shared_key secret_string
  self_hostname client.fqdn.local
  
  secure yes
  # and configurations for certs/verification
  
  <server>
    host      first.fqdn.local
    hostlabel server.fqdn.local
    username  repeatedly
    password  sushi
  </server>
  <server>
    host      second.fqdn.local
    hostlabel server.fqdn.local
    username  sasatatsu
    password  karaage
  </server>
  <server>
    host      standby.fqdn.local
    hostlabel server.fqdn.local
    username  kzk
    password  hawaii
    standby   yes
  </server>
</match>
```

Specify `hostlabel` if server (`in_forward`) have different hostname (`self_host` configuration of `in_forward`) from DNS name (`first.fqdn.local`, `second.fqdn.local` or `standby.fqdn.local`). This configuration variable will be used to check common name (CN) of certifications.

To specify keepalive timeouts, use `keepalive` configuration with seconds. SSL connection will be disconnected and re-connected for each 1 hour with configuration below. In Default (and with `keepalive 0`), connections will not be disconnected without any communication troubles. (This feature is for dns name updates, and SSL common key refreshing.)

```apache
<match secret.data.**>
  @type secure_forward
  shared_key secret_string
  self_hostname client.fqdn.local
  
  secure yes
  # and configurations for certs/verification
  
  keepalive 3600
  <server>
    host server.fqdn.local  # or IP
    # port 24284
  </server>
</match>
```


If you connect via Proxy, 
set for `proxy_uri` in `<server>` section:
```apache
<match secret.data.**>
  @type secure_forward
  shared_key secret_string
  self_hostname client.fqdn.local

  secure yes
  # and configurations for certs/verification

  <server>
    host server.fqdn.local  # or IP
    # port 24284
    proxy_uri http://foo.bar.local:3128
  </server>
</match>
```

## Senario (developer document)

* server
  * in\_secure\_forward
* client
  * out\_secure\_forward

### Handshake

1. (client) connect to server
  * on SSL socket handshake, checks certificate and its significate (in client)
2. (server)
  * check network/domain acl (if enabled)
  * check client dns reverse lookup result (if enabled)
  * disconnect when failed
3. (server) send HELO
  * ['HELO', options(hash)]
  * options:
    * nonce: string as nonce: used for shared key digest (required, v0.3.2 or later)
    * auth: string or blank\_string (string: authentication required, and its salt is this value)
    * keepalive: bool (allowed or not)
4. (client) send PING
  * ['PING', selfhostname, sharedkey\_salt, sha512\_hex(sharedkey\_salt + selfhostname + nonce + sharedkey), username || '', sha512\_hex(auth\_salt + username + password) || '']
5. (server) check PING
  * check sharedkey
  * check username / password (if required)
  * send PONG FAILURE if failed
  * ['PONG', false, 'reason of authentication failure', '', '']
6. (server) send PONG
  * ['PONG', bool(authentication result), 'reason if authentication failed', selfhostname, sha512\_hex(salt + selfhostname + nonce + sharedkey)]
7. (client) check PONG
  * check sharedkey
  * disconnect when failed
8. connection established
  * send data from client (until keepalive expiration)

### Data transferring

CONSIDER RETURN ACK OR NOT

 * Current version has no ACKs
   * only supports burst transferring (same as ForwardInput/Output)
 * ack for each message ?
 * pipeline mode and one-by-one mode ?
 * data sequence number in keepalive session ?

## TODO

* ACK mode (protocol)
* support disabling keepalive (input/output)
* access control (input plugin)
  * network acl / domain acl
  * check connecting source ip and its dns reverse lookup result (for domaian acl)
  * access deny on accept (against DoS)
* pluggable authentication database (input plugin)
  * RDBMS, LDAP, or ...
  * Authentication by clients certificate
* TESTS!

## Copyright

* Copyright (c) 2013- TAGOMORI Satoshi (tagomoris)
* License
  * Apache License, Version 2.0
