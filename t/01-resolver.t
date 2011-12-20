#!/usr/bin/perl

# Copyright 2011 Alexandr Gomoliako

use strict;
use warnings;
no  warnings 'uninitialized';

# we don't have blib here
use lib 'objs/src/http/modules/perl/blib/lib', 
        'objs/src/http/modules/perl/blib/arch';

use Data::Dumper;
use Test::More;
use Nginx::Test;

my $nginx   = find_nginx_perl;
my $testdir = "objs/tests";

plan skip_all => "Can't find executable binary ($nginx) to test"
        if  !$nginx    ||  
            !-x $nginx    ;


wait_for_peer '8.8.8.8:53', 1
    or  plan skip_all => "Cannot connect to 8.8.8.8:53";


plan 'no_plan';


{
    my ($pid, $peer) = fork_nginx_handler_die  
                      $nginx, $testdir, <<'    ENDCONF', <<'    ENDCODE';

        resolver 8.8.8.8;

    ENDCONF

        sub handler {
            my ($r) = @_;

            $r->main_count_inc;

            
            my $domain = $r->args;

            ngx_resolver $domain, 1, sub {

                local $, = ' ';
                my $buf = "@_";

                $r->header_out ('x-errno', int ( $! ));
                $r->header_out ('x-errstr', "$!");
                $r->header_out ('Content-Length', length ( $buf ));
                $r->send_http_header ('text/html; charset=UTF-8');

                $r->print ($buf)
                        unless  $r->header_only;

                $r->send_special (NGX_HTTP_LAST);
                $r->finalize_request (NGX_OK);

            };


            return NGX_DONE;
        }

    ENDCODE


    wait_for_peer $peer, 2;


    for my $i (1 .. 4) {
        my ($body, $headers) = http_get $peer, '/?www.google.com', 2;

        my @IP = split ' ', $body;

        ok $IP[0] =~ /\d+\.\d+\.\d+\.\d+/, "google's IP resolved $i"
            or  diag ("body = $body\n", cat_nginx_logs $testdir),
                  last;

        is $headers->{'x-errno'}->[0], 0, "clean errno"
            or  diag ("errno = $headers->{'x-errno'}");
    }

    for my $i (1 .. 4) {
        my ($body, $headers) = http_get $peer, '/?nonexistent.domain', 2;

        isnt $headers->{'x-errno'}->[0], 0 , "nonexistent errno"
            or  diag ("body = $body\n", cat_nginx_logs $testdir),
                  last;
    }


    quit_nginx $pid;
}

{
    my ($pid, $peer) = fork_nginx_handler_die  
                      $nginx, $testdir, <<'    ENDCONF', <<'    ENDCODE';

        resolver_timeout  1;
        resolver          1.2.3.4;

    ENDCONF

        sub handler {
            my ($r) = @_;

            $r->main_count_inc;

            
            my $domain = $r->args;

            ngx_resolver $domain, 1, sub {

                local $, = ' ';
                my $buf = "@_";

                $r->header_out ('x-errno', int ( $! ));
                $r->header_out ('x-errstr', "$!");
                $r->header_out ('Content-Length', length ( $buf ));
                $r->send_http_header ('text/html; charset=UTF-8');

                $r->print ($buf)
                        unless  $r->header_only;

                $r->send_special (NGX_HTTP_LAST);
                $r->finalize_request (NGX_OK);

            };


            return NGX_DONE;
        }

    ENDCODE


    wait_for_peer $peer, 2;


    for my $i (1 .. 3) {
        my ($body, $headers) = http_get $peer, '/?nonexistent.domain', 2;

        isnt $headers->{'x-errno'}->[0], 0 , "timeout"
            or  diag ("body = $body\n", cat_nginx_logs $testdir),
                  last;
    }


    quit_nginx $pid;
}




