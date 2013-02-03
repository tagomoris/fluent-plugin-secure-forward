# fluent-plugin-secure-forward

Fluentd input/output plugin to forward fluentd messages over SSL, and authentication.

This plugin makes you to be able to:

 * protect your data from others in transferring with SSL
   * with certificate signed and registered correctly
   * with self-signed certificate (and generate certificate in in\_secure\_forward automatically)
 * authenticate with username / password pairs
 * authenticate by shared_key check from both of client(out\_secure\_forward) and server(in\_secure\_forward)
 * check connecting source ip and its dns reverse lookup result

## Senario (in development)

### Over Internet with global IP and certificates signed and hosted correctly

You should in setup: 

 * make shared_key string (per in\_secure\_forward node) and username / password pairs (per out\_secure\_forward node)
 * configure 


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
