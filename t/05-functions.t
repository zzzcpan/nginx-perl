#!/usr/bin/perl

# Copyright 2011 Alexandr Gomoliako

use strict;
use warnings;
no  warnings 'uninitialized';

use Data::Dumper;
use Test::More;
use Nginx::Test;


my $nginx = find_nginx_perl;
my $dir   = "objs/t05";
mkdir "objs" unless -e "objs";

plan skip_all => "Can't find executable binary ($nginx) to test"
        if  !$nginx    ||  
            !-x $nginx    ;

plan 'no_plan';


{
    my ($child, $peer) = fork_nginx_handler_die $nginx, $dir, '',<<'    END';

        use Nginx;

        sub Nginx::say {
            my ($r, $buf) = @_;

            $r->header_out ('Content-Length', length ($buf));
            $r->send_http_header ('text/html; charset=UTF-8');

            $r->print ($buf)
                    unless  $r->header_only;

            $r->send_special (NGX_HTTP_LAST);
            $r->finalize_request (NGX_OK);
        }


        my @ngx_escape_uri_tests = (

            [ NGX_ESCAPE_URI,  'a',           'a'    ], 
            [ NGX_ESCAPE_URI,  'aaaa',        'aaaa' ], 
            [ NGX_ESCAPE_URI,  '',            ''     ], 
            [ NGX_ESCAPE_URI,  ' ',           '%20'  ], 
            [ NGX_ESCAPE_URI,  'aa%20aa',     'aa%2520aa' ], 
            [ NGX_ESCAPE_URI,  'foo&bar',     'foo&bar' ], 
            [ NGX_ESCAPE_ARGS, 'foo&bar',     'foo%26bar' ], 

            [ NGX_ESCAPE_URI,  ' ' x 10,      '%20' x 10 ], 
            [ NGX_ESCAPE_URI,  ' ' x 100,     '%20' x 100 ], 
            [ NGX_ESCAPE_URI,  ' ' x 1000,    '%20' x 1000 ], 
            [ NGX_ESCAPE_URI,  ' ' x 10000,   '%20' x 10000 ], 

        );


        sub handler {
            my ($r) = @_;

            $r->main_count_inc;


            if ($r->uri eq '/ngx_escape_uri/') {

                $r->say(join "\n", map { $_->[1] } @ngx_escape_uri_tests);

            } elsif ($r->uri eq '/ngx_escape_uri/test' && $r->args >= 0) {

                my $test = $ngx_escape_uri_tests[$r->args];
                my $res = ngx_escape_uri $test->[1], $test->[0];

                $r->say ( $res eq $test->[2] 
                            ? "OK" 
                            : "FAILED: expected '$test->[2]', got '$res'" );
            }


            return NGX_DONE;
        }

    END

    wait_for_peer $peer, 5
        or diag "wair_for_peer \"$peer\" failed\n";

    my ($body, $headers) = http_get $peer, '/ngx_escape_uri/', 2;
    my @tests = split(/\n/, $body);

    if (@tests) {
        pass "got tests for ngx_escape_uri";
    } else {
        diag "body = $body\n", cat_nginx_logs $dir;
        fail "got tests for ngx_escape_uri";
    }

    my $i = 0;
    foreach (@tests) {
        my $body = http_get $peer, '/ngx_escape_uri/test?' . $i++ , 2;

        $_ = substr($_, 0, 40) . " ..." if length($_) > 40;
        ok $body eq 'OK', "test '$_'"
            or (diag "body = $body\n", cat_nginx_logs $dir),
               last;
    }

    undef $child;
}



