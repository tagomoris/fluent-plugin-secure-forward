# fluent-plugin-secure-forward, a plugin for [Fluentd](http://fluentd.org)

Fluentd input/output plugin to forward fluentd messages over SSL with authentication.

This plugin makes you to be able to:

 * protect your data from others in transferring with SSL
   * with certificate signed and registered correctly
   * with self-signed certificate (and generate certificate in in\_secure\_forward automatically)
 * authenticate by shared\_key check from both of client(out\_secure\_forward) and server(in\_secure\_forward)
 * authenticate with username / password pairs

## Configuration

### SecureForwardInput

Default settings:
  * listen 0.0.0.0:24284
    * `bind 192.168.0.101`
    * `port 24285`
  * allow to accept from any sources
  * allow to connect without authentications
  * use certificate automatically generated
    * `generate_private_key_length 2048`
    * `generate_cert_country  US`
    * `generate_cert_state    CA`
    * `generate_cert_locality Mountain View`
    * `generate_cert_common_name SAME_WITH_SELF_HOSTNAME_PARAMETER`
  
Minimal configurations like below:

    <source>
      type secure_forward
      shared_key         secret_string
      self_hostname      server.fqdn.local  # This fqdn is used as CN (Common Name) of certificates
      cert_auto_generate yes                # This parameter MUST be specified
    </source>

To check username/password from clients, like this:

    <source>
      type secure_forward
      shared_key         secret_string
      self_hostname      server.fqdn.local
      cert_auto_generate yes
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

To deny unknown source IP/hosts:

    <source>
      type secure_forward
      shared_key         secret_string
      self_hostname      server.fqdn.local
      cert_auto_generate     yes
      allow_anonymous_source no  # Allow to accept from nodes of <client>
      <client>
        host 192.168.10.30
        # network address (ex: 192.168.10.0/24) NOT Supported now
      </client>
      <client>
        host your.host.fqdn.local
        # wildcard (ex: *.host.fqdn.local) NOT Supported now
      </client>
    </source>

You can use both of username/password check and client check:

    <source>
      type secure_forward
      shared_key         secret_string
      self_hostname      server.fqdn.local
      cert_auto_generate     yes
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
      </user
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

### SecureForwardOutput

Default settings:
  * allow to connect server using self-signed certificates

Minimal configurations like this:

    <match secret.data.**>
      type secure_forward
      shared_key secret_string
      self_hostname client.fqdn.local
      <server>
        host server.fqdn.local  # or IP
        # port 24284
      </server>
    </match>

Without hostname ACL (and it's not implemented yet), `self_hostname` is not checked in any state. `${hostname}` placeholder is available for such cases.

    <match secret.data.**>
      type secure_forward
      shared_key secret_string
      self_hostname ${hostname}
      <server>
        host server.fqdn.local  # or IP
        # port 24284
      </server>
    </match>

When specified 2 or more `<server>`, this plugin uses these nodes in simple round-robin order. And servers with `standby yes` will be selected until all of non-standby servers goes down.

If server requires username/password, set `username` and `password` in `<server>` section:

    <match secret.data.**>
      type secure_forward
      shared_key secret_string
      self_hostname client.fqdn.local
      <server>
        host first.fqdn.local
        username repeatedly
        password sushi
      </server>
      <server>
        host second.fqdn.local
        username sasatatsu
        password karaage
      </server>
      <server>
        host standby.fqdn.local
        username kzk
        password hawaii
        standby  yes
      </server>
    </match>

To specify keepalive timeouts, use `keepalive` configuration with seconds. SSL connection will be disconnected and re-connected for each 1 hour with configuration below. In Default (and with `keepalive 0`), connections will not be disconnected without any communication troubles. (This feature is for dns name updates, and SSL common key refreshing.)

    <match secret.data.**>
      type secure_forward
      shared_key secret_string
      self_hostname client.fqdn.local
      keepalive 3600
      <server>
        host server.fqdn.local  # or IP
        # port 24284
      </server>
    </match>

## Senario (developer document)

* server
  * in\_secure\_forward
* client
  * out\_secure\_forward

### Setup Phase (server)

1. SSLContext
  * with certificate file / private key file
    1. read cert file
    2. generate SSLContext object
  * without certificate file
    1. generate key pair
    2. generate cert data
    3. sign cert data with generated private key
2. shared key
  * read shared key from configuration
3. username / password pairs
  * read from configuration

### Setup Phase (client)

1. SSLContext
  1. certificate
    * with certificate file, read from file
    * without certificate file, `new SSLContext` without any options
  2. set SSLContext option which allow self signed key option or not
2. shared key
  * read shared key from configuration
3. read server list with username / password pairs from configuration

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
    * auth: string or blank\_string (string: authentication required, and its salt is this value)
    * keepalive: bool (allowed or not)
4. (client) send PING
  * ['PING', selfhostname, sharedkey\_salt, sha512\_hex(sharedkey\_salt + selfhostname + sharedkey), username || '', sha512\_hex(auth\_salt + username + password) || '']
5. (server) check PING
  * check sharedkey
  * check username / password (if required)
  * send PONG FAILURE if failed
  * ['PONG', false, 'reason of authentication failure', '', '']
6. (server) send PONG
  * ['PONG', bool(authentication result), 'reason if authentication failed', selfhostname, sha512\_hex(salt + selfhostname + sharedkey)]
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

* test for non self-signed certificates
* ACK mode (protocol)
* support disabling keepalive (input/output)
* access control (input plugin)
  * network acl / domain acl
  * check connecting source ip and its dns reverse lookup result (for domaian acl)
  * access deny on accept (against DoS)
* pluggable authentication database (input plugin)
  * RDBMS, LDAP, or ...
  * Authentication by clients certificate
* encryption algorithm option (output plugin)
* TESTS!

## Copyright

* Copyright (c) 2013- TAGOMORI Satoshi (tagomoris)
* License
  * Apache License, Version 2.0
