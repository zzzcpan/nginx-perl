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


my $nginx = find_nginx_perl;
my $dir   = "objs/tests";

plan skip_all => "Can't find executable binary ($nginx) to test"
        if  !$nginx    ||  
            !-x $nginx    ;

plan 'no_plan';


{
    my ($child, $peer) = fork_nginx_handler_die $nginx, $dir, '',<<'    END';

        sub handler {
            my ($r) = @_;

            $r->main_count_inc;


            my $buf = "Hello\n";

            $r->header_out ('Content-Length', length ($buf));
            $r->send_http_header ('text/html; charset=UTF-8');

            $r->print ($buf)
                    unless  $r->header_only;

            $r->send_special (NGX_HTTP_LAST);
            $r->finalize_request (NGX_OK);


            return NGX_DONE;
        }

    END

    wait_for_peer $peer, 2;

    my ($body, $headers) = http_get $peer, '/', 2;

    ok $body =~ /Hello/i, "hello"
        or diag "body = $body\n", cat_nginx_logs $dir;

}



