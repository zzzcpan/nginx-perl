package Nginx::Redis;

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

require Exporter;
our @ISA     = qw(Exporter);
our @EXPORT  = qw(ngx_redis ngx_redis_client ngx_redis_request);
our $VERSION = '1.1.9.1';

use Nginx;
use Redis::Parser::XS;

sub CRLF { "\x0d\x0a" }
sub ngx_redis_client ($$$;&);
sub ngx_redis ($$&);

our $AUTH;
our $TIMEOUT = 5;
my  %CLIENTS;


sub ngx_redis_client ($$$;&) {
    my ($ip, $port, $timeout, $error_cb) = @_;

    my ($error,  # push needs it
        $c, @output, @active, @queue);
    my $buf = '';


    my $push = sub {

        return 0                     #  don't do anything  if
              if  @active != 0  ||   #  sending something right now  or
                  @queue  == 0  ||   #  nothing to send  or
                  !defined $c;       #  not connected yet

        @active = @queue;
        @queue = ();

        &$error (),
          return 0                   #  handle error and return  if
                if  $c == 0;         #  connection marked as failed

        $buf =                                            #
            join ('',                                     #  redis packet:
                map {                                     #
                    '*' . scalar (@{$_->[0]}) . CRLF .    #   *1    CRLF
                    join ('',                             #
                        map {                             #
                            '$' . length ($_) . CRLF .    #   $3    CRLF
                                  $_          . CRLF      #   foo   CRLF
                        } @{$_->[0]}                      #   ...
                    )                                     #
                } @active
            );

                                     #  tell caller we need to start 
        return 1;                    #  writing flow (ngx_write/NGX_WRITE)
    };


    $error = sub {  

        $c = 0;     #  marking connection as failed

        for my $i (0 .. $#active) {
            my $cb = $active [$i]->[1];
            &$cb ( $output [$i] );
        }

        @output = ();
        @active = ();

        foreach (@queue) {
            my $cb = $_->[1];
            &$cb ();
        }

        @queue = ();
        
        ngx_log_error $!, "redis error";  

        &$error_cb ()
              if  $error_cb;
    };


    my $enqueue = sub {
        push @queue, \@_;

        &$push ()  &&
          ngx_write ($c);
    };


    ngx_connector $ip, $port, $timeout, sub {

        &$error (),
          return NGX_CLOSE
                if  $!;

        $c = shift;


        ngx_writer $c, $buf, $timeout, sub {

            &$error (),
              return NGX_CLOSE
                    if  $!;

            $buf = '';

            return NGX_READ;
        };


        ngx_reader $c, $buf, 0, 0, $timeout, sub {

            &$error (),
              return NGX_CLOSE
                    if  $!;

            my $len = parse_redis $buf, \@output;

            &$error (),
              return NGX_CLOSE
                    if  !defined $len;

            $buf = substr $buf, $len;

            return NGX_READ
                  if  @output != @active;

            $buf = '';

            for my $i (0 .. $#active) {
                my $cb = $active [$i]->[1];
                &$cb ($output [$i]);
            }

            @output = ();
            @active = ();

            &$push ()  &&
              return NGX_WRITE;

            return NGX_NOOP;
        };


        &$push ()  &&
          return NGX_WRITE;

        return NGX_NOOP;
    };


    return $enqueue;
}


sub ngx_redis_request {
    my $enqueue = shift;

    &$enqueue;
}


sub ngx_redis ($$&) {
    my $dest    = shift;
    my $enqueue = $CLIENTS{$dest};

    &$enqueue,                      #  enqueue request 
      return                        #  and return
            if defined $enqueue;    #  since we already connected

    my ($ip, $port, $auth, $timeout) = split (':', $dest);

    $ip      = '127.0.0.1'  unless  $ip;
    $port    = 6379         unless  $port;
    $auth    = $AUTH        unless  defined $auth;
    $timeout = $TIMEOUT     unless  $timeout;

    $enqueue = ngx_redis_client $ip, $port, $timeout, sub {
        delete $CLIENTS{$dest};     #  deleting on error to force reconnect
    };

    $CLIENTS{$dest} = $enqueue;

    if ($auth) {
        &$enqueue (['AUTH', $auth ], sub {
            my ($reply) = @_;

            ngx_log_error 0, "Cannot authorize on redis server at $ip:$port"
                    if $reply->[0] ne '+';
        });
    }

    &$enqueue;
}


1;
__END__

=head1 NAME

Nginx::Redis - asynchronous redis client for nginx-perl

=head1 SYNOPSIS

    use Nginx::Redis;
    
    ngx_redis '127.0.0.1:6379', ['GET', 'mykey'], sub {
        my ($reply) = @_;
        
        unless ($reply) {
            warn "error: no reply from redis\n";
            return;
        }
        
        # $reply = ['$', 'myvalue']
    };

=head1 DESCRIPTION

Fast asynchronous redis client for B<nginx-perl> that supports pipelining
and doesn't provide any command-bound interface. You can use it
for almost any feature of redis. Currently it doesn't support 
pub/sub-like flow though. 

L<Nginx::Redis> relies on L<Redis::Parser::XS> to parse reply messages. 
So you have to install it as well.

=head1 EXPORT

    ngx_redis
    ngx_redis_client
    ngx_redis_request

=head1 FUNCTIONS

=over 4

=item ngx_redis "$ip:$port:$auth:$timeout", ['GET', 'mykey'], sub { };

Encodes and sends request to the redis server specified by C<$ip:$port>.
If password is specified in C<$auth> then AUTH command will precede. 

Calls back with reply in C<$_[0]>. Format of the reply described in
L<Redis::Parser::XS>.

On error calls back without any arguments. Tries to reconnect on the
next request.

Every connection is cached forever.

Example:

    ngx_redis '127.0.0.1', ['PING'], sub {
        my ($reply) = @_;
                
        # $reply = ['+', 'PONG']
    };

=back

=head1 AUTHOR

Alexandr Gomoliako <zzz@zzz.org.ua>

=head1 LICENSE

Copyright 2011 Alexandr Gomoliako. All rights reserved.

This module is free software. It may be used, redistributed and/or modified 
under the same terms as B<nginx> itself.

=cut

