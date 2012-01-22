#!/usr/bin/perl

# Copyright 2011 Alexandr Gomoliako

use strict;
use warnings;
no  warnings 'uninitialized';

use Data::Dumper;
use Test::More;
use Nginx::Test;
use IO::Socket;
use Socket;


my $nginx = find_nginx_perl;
my $dir   = "objs/t02";

plan skip_all => "Can't find executable binary ($nginx) to test"
        if  !$nginx    ||  
            !-x $nginx    ;


# SSL support is required for this test

my %CONFARGS = get_nginx_conf_args_die $nginx;

plan skip_all => "$nginx built without SSL support" 
    unless  $CONFARGS{'--with-http_ssl_module'};


# making sure we can successfully 
# connect to remote hosts  

my $ip = inet_ntoa (inet_aton ("www.google.com"));

wait_for_peer "$ip:443", 1
    or  plan skip_all => "Cannot connect to $ip:443";


plan 'no_plan';


{
    my ($child, $peer) = fork_nginx_handler_die  $nginx, $dir, '',<<'    END';


        sub CRLF { "\x0d\x0a" }


        sub Nginx::reply_finalize {
            my $r   = shift;
            my $buf = shift || '';

            $r->header_out ('x-errno', int ( $! ));
            $r->header_out ('x-errstr', "$!");
            $r->header_out ('Content-Length', length ( $buf ));
            $r->send_http_header ('text/html; charset=UTF-8');

            $r->print ($buf)
                    unless  $r->header_only;

            $r->send_special (NGX_HTTP_LAST);
            $r->finalize_request (NGX_OK);
        }


        sub handler {
            my ($r) = @_;

            $r->main_count_inc;

            
            my ($ip, $port, $timeout) = split ':', $r->args, 3;


            ngx_connector $ip, $port, $timeout, sub {

                my $c = shift;

                $r->reply_finalize,
                  return NGX_CLOSE
                        if  $!;


                ngx_ssl_handshaker $c, $timeout, sub {

                    $r->reply_finalize,
                      return NGX_CLOSE
                            if  $!;

                    my $buf = "GET / HTTP/1.0"        . CRLF .
                              "Host: www.google.com"  . CRLF .
                                                        CRLF  ;

                    ngx_writer $c, $buf, $timeout, sub {

                        $r->reply_finalize,
                          return NGX_CLOSE
                                if  $!;

                        $buf = ''; # reusing this buffer for reading

                        return NGX_READ;
                    };


                    ngx_reader $c, $buf, 0, 0, $timeout, sub {
 
                        $r->reply_finalize,
                          return NGX_CLOSE
                                if  $! && $! != NGX_EOF;

                        $! = 0,
                          $r->reply_finalize ($buf),
                            return NGX_CLOSE
                                  if  $! == NGX_EOF;

                        return NGX_READ;
                    };


                    return NGX_WRITE;
                };

                return NGX_SSL_HANDSHAKE;
            };


            return NGX_DONE;
        }

    END


    wait_for_peer $peer, 2;


    for my $i (1 .. 2) {
        my ($body, $headers) = http_get $peer, "/?$ip:443:4", 6;

        ok $body =~ /Google/i, "google over SSL $i"
            or  diag ($body, Dumper ($headers), cat_nginx_logs $dir),
                  last;

        ok $body =~ />\s*$/is, "reponse ends with angle bracket $i"
            or  diag ($body, Dumper ($headers), cat_nginx_logs $dir),
                  last;

        is $headers->{'x-errno'}->[0], 0, "clean errno"
            or  diag ("errno = $headers->{'x-errno'}");
    }


    # catching timeout 
    
    my $port2 = get_unused_port;
    my $peer2 = "127.0.0.1:$port2";

    my $child2 = fork_child_die sub {
        my $sock = IO::Socket::INET->new('Listen'    => 5,
                                         'LocalAddr' => "127.0.0.1",
                                         'LocalPort' => $port2,
                                         'Proto'     => 'tcp');
        my $newsock = $sock->accept;
        sleep 10;
    };


    for my $i (1 .. 1) {
        my ($body, $headers) = http_get $peer, "/?$peer2:1", 2;

        ok defined $headers->{'x-errno'}->[0], "have errno"
            or  diag ($body, Dumper ($headers), cat_nginx_logs $dir),
                  last;

        isnt $headers->{'x-errno'}->[0], 0, "non-zero errno"
            or  diag ($body, Dumper ($headers), cat_nginx_logs $dir),
                  last;
    }

    undef $child2;
    undef $child;
}



