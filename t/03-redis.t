#!/usr/bin/perl

# Copyright 2011 Alexandr Gomoliako

use strict;
use warnings;
no  warnings 'uninitialized';

# we don't have blib here
use lib 'objs/src/http/modules/perl/blib/lib', 
        'objs/src/http/modules/perl/blib/arch';

BEGIN {
    use Test::More;

    eval { require Redis::Parser::XS };
    
    diag ("$@"),
      plan skip_all => "Cannot load Redis::Parser::XS"
             if  $@;
}

use Data::Dumper;
use Test::More;
use Nginx::Test;
use IO::Socket;

sub CRLF { "\x0d\x0a" }

my $redis = "127.0.0.1:6379";
my $nginx = find_nginx_perl;
my $dir   = "objs/tests";


plan skip_all => "Can't find executable binary ($nginx) to test"
        if  !$nginx    ||  
            !-x $nginx    ;

wait_for_peer $redis, 1
    or  plan skip_all => "Cannot connect to redis server on $redis";

{
    my $sock = IO::Socket::INET->new ('PeerAddr' => $redis);

    print $sock "PING" . CRLF;

    local $/ = CRLF;
    local $_ = <$sock>;

    diag ("redis-server: $_"),
      plan skip_all => "Redis didn't return +PONG"
              unless  /^\+PONG/ ;

    $sock->close;
}

plan 'no_plan';


{
    my ($child, $peer) = fork_nginx_handler_die  $nginx, $dir, '',<<'    END';

        use Nginx::Redis;

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


            ngx_redis '127.0.0.1', [ split ('&', $r->args) ], sub {
                my ($reply) = @_;

                my $buf = join '&', ($reply ? @$reply : ());
                $r->reply_finalize ($buf);
            };


            return NGX_DONE;
        }

    END


    wait_for_peer $peer, 2;


    for my $i (1 .. 10) {
        my ($body, $headers) = http_get  $peer, 
                                         "/?" . 'SET'           . '&' . 
                                                "ngxpltest_$i"  . '&' . 
                                                "val_$i"                , 
                                          6                                ;

        my $reply = [ split ('&', $body) ];

        is $reply->[0], "+", "SET key $i, +"
            or  diag ($body, Dumper ($headers), cat_nginx_logs $dir),
                  last;

        is $reply->[1], "OK", "SET key $i, OK"
            or  diag ($body, Dumper ($headers), cat_nginx_logs $dir),
                  last;

        is $headers->{'x-errno'}->[0], 0, "clean errno"
            or  diag ("errno = $headers->{'x-errno'}");
    }

    for my $i (1 .. 10) {
        my ($body, $headers) = http_get  $peer, 
                                         "/?" . 'GET'           . '&' . 
                                                "ngxpltest_$i"          , 
                                          6                                ;

        my $reply = [ split ('&', $body) ];

        is $reply->[0], '$', 'GET key $i, $'
            or  diag ($body, Dumper ($headers), cat_nginx_logs $dir),
                  last;

        is $reply->[1], "val_$i", "SET key $i, val_$i"
            or  diag ($body, Dumper ($headers), cat_nginx_logs $dir),
                  last;

        is $headers->{'x-errno'}->[0], 0, "clean errno"
            or  diag ("errno = $headers->{'x-errno'}");
    }


    undef $child;
}



