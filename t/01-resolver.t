#!/usr/bin/perl

# Copyright 2011 Alexandr Gomoliako

use strict;
use warnings;
no  warnings 'uninitialized';

use Data::Dumper;
use Test::More;
use Nginx::Test;
use Socket;

my $nginx = find_nginx_perl;
my $dir   = "objs/t01";
mkdir "objs" unless -e "objs";

plan skip_all => "Can't find executable binary ($nginx) to test"
        if  !$nginx    ||  
            !-x $nginx    ;


# choosing resolver

my $ns;

if (-e '/etc/resolv.conf') { 
    ($ns) = grep {  ($_) = / nameserver \s* ( \d+\.\d+\.\d+\.\d+ ) /x  } 
              do {  open my $fh, '<', '/etc/resolv.conf'; <$fh>  } ;
}

$ns = '8.8.8.8' 
        unless $ns;

wait_for_peer "$ns:53", 1
    or  plan skip_all => "Cannot connect to $ns:53";


# making sure we can successfully 
# connect to remote hosts  

my $ip = inet_ntoa (inet_aton ("www.google.com"));

wait_for_peer "$ip:80", 1
    or  plan skip_all => "Cannot connect to $ip:80";



plan 'no_plan';


{
    my ($child, $peer) = fork_nginx_handler_die  
                      $nginx, $dir, <<"    ENDCONF", <<'    ENDCODE';

        resolver $ns;

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


    wait_for_peer $peer, 5
        or diag "wair_for_peer \"$peer\" failed\n";


    for my $i (1 .. 2) {
        my ($body, $headers) = http_get $peer, '/?www.google.com', 2;

        my @IP = split ' ', $body;

        ok $IP[0] =~ /\d+\.\d+\.\d+\.\d+/, "google's IP resolved $i"
            or  diag ("body = $body\n", cat_nginx_logs $dir),
                  last;

        is $headers->{'x-errno'}->[0], 0, "clean errno"
            or  diag ("errno = $headers->{'x-errno'}");
    }


    # Some nameservers configured to respond succesfully 
    # for nonexistent domain queries:
    # 
    # www.cpantesters.org/cpan/report/8e8da360-5b3d-11e1-905e-bef26d82c184

    # for my $i (1 .. 2) {
    #     my ($body, $headers) = http_get $peer, '/?nonexistent.domain', 2;
    # 
    #     isnt $headers->{'x-errno'}->[0], 0 , "nonexistent errno"
    #         or  diag ("body = $body\n", cat_nginx_logs $dir),
    #               last;
    # }

    undef $child;
}

{
    my ($child, $peer) = fork_nginx_handler_die  
                      $nginx, $dir, <<'    ENDCONF', <<'    ENDCODE';

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


    wait_for_peer $peer, 5
        or diag "wair_for_peer \"$peer\" failed\n";


    for my $i (1 .. 2) {
        my ($body, $headers) = http_get $peer, '/?nonexistent.domain', 2;

        isnt $headers->{'x-errno'}->[0], 0 , "timeout"
            or  diag ("body = $body\n", cat_nginx_logs $dir),
                  last;
    }


    undef $child;
}




