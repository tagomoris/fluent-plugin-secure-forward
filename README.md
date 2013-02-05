# fluent-plugin-secure-forward

Fluentd input/output plugin to forward fluentd messages over SSL, and authentication.

This plugin makes you to be able to:

 * protect your data from others in transferring with SSL
   * with certificate signed and registered correctly
   * with self-signed certificate (and generate certificate in in\_secure\_forward automatically)
 * check connecting source ip and its dns reverse lookup result
 * authenticate with username / password pairs
 * authenticate by shared_key check from both of client(out\_secure\_forward) and server(in\_secure\_forward)

## Senario (internal developer document)

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
2. (server) check client dns reverse lookup result (if enabled)
  * disconnect when failed
3. (server) send HELO
  * ['HELO', options(hash)]
  * options:
    * auth: bool (required or not)
    * keepalive: bool (allowed or not)
4. (client) send PING
  * ['PING', selfhostname, salt, sha512(salt + selfhostname + sharedkey), username || '', sha512(salt + username + password) || '']
5. (server) check PING
  * check sharedkey
  * check username / password (if required)
  * disconnect when failed
6. (server) send PONG
  * ['PONG', selfhostname, sha512(salt + selfhostname + sharedkey)]
7. (client) check PONG
  * check sharedkey
  * disconnect when failed
8. connection established
  * send data from client (until keepalive expiration)

### Data transferring

CONSIDER RETURN ACK OR NOT

 * ack for each message ?
 * pipeline mode and one-by-one mode ?
 * data sequence number in keepalive session ?
 * mmm...

## Installation

Add this line to your application's Gemfile:

    gem 'fluent-plugin-secure-forward'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install fluent-plugin-secure-forward

## Usage

TODO: Write usage instructions here

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
