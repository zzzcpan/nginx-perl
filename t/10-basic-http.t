#!/usr/bin/perl 

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

use Test::More;

use Nginx::Test;
use constant { CRLF => "\x0d\x0a" };

my $prefix = make_path 'objs/t10'
    or diag ("make_path failed: $!"),
        plan ('skip_all', "Cannot create test directory: $!");

my $port1 = get_unused_port or plan ('skip_all', 'get_unused_port failed');
my $peer1 = "127.0.0.1:$port1";

my $nginx = find_nginx_perl
    or diag ("find_nginx_perl failed: $!"),
        plan ('skip_all', "Cannot find nginx-perl");


plan 'no_plan';

{
    my $peer = $peer1;  # for easier copy-paste

    prepare_nginx_dir_die $prefix, <<"    ENDCONF";

        worker_processes  1;
        daemon            off;
        master_process    off;

        error_log  logs/error.log  debug;

        events {  
            worker_connections  128;  
        }

        http {
            default_type  text/plain;

            keepalive_requests  4;
            keepalive_timeout   3;

            server {
                listen  $peer;

                location = /index.html { }
                location = /error503 { error_page 404 =503 /index.html; }
            }
        }

    ENDCONF

    my $child = fork_nginx_die $nginx, $prefix;

    wait_for_peer $peer, 5
        or diag ("wait_for_peer '$peer' failed"),
            diag (cat_logs "$prefix/logs");

    my $fhka;      # filehandle for keepalive connection
    my $use_fhka;

  LOOP:
    foreach $_ (

    # HTTP protocol

        [
            "HTTP: no keepalive, GET /nonexistent",  3,

                "GET /nonexistent HTTP/1.0"                     .CRLF.
                "Host: nonexistent"                             .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 404 Not Found"                        .CRLF.
                "Server: nginx-perl/$Nginx::Test::VERSION"      .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",
        ],

        sub {
            my $name = "HTTP: new keepalive connection"; 

            $fhka = connect_peer $peer, 5
                or fail ($name), 
                    diag ("connect_peer '$peer' failed"),
                     diag (cat_logs "$prefix/logs"),
                      return undef;

            $use_fhka = 1;

            pass $name;
        },

        [
            "HTTP: keepalive, GET /nonexistent",  3,

                "GET /nonexistent HTTP/1.1"                     .CRLF.
                "Host: nonexistent"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 404 Not Found"                        .CRLF.
                ""                                              .CRLF.
                "",
        ],

        [
            "HTTP: closing keepalive, GET /nonexistent", 1,

                "GET /nonexistent HTTP/1.1"                     .CRLF.
                "Host: nonexistent"                             .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 404 Not Found"                        .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",
        ],

        sub {
            my $name = "HTTP: closing keepalive connection";

            $fhka->close;
            undef $fhka;

            $use_fhka = 0;

            pass $name;
        },

        [
            "HTTP: after keepalive, GET /nonexistent",  3,

                "GET /nonexistent HTTP/1.0"                     .CRLF.
                "Host: nonexistent"                             .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 404 Not Found"                        .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",
        ],

        [
            "HTTP: GET /index.html",  3,

                "GET /index.html HTTP/1.0"                      .CRLF.
                "Host: nonexistent"                             .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 200 OK"                               .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "ok",  # default in html/index.html
        ],

        [
            "HTTP: GET /error503",  3,

                "GET /error503 HTTP/1.0"                        .CRLF.
                "Host: nonexistent"                             .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 503 Service Temporarily Unavailable"  .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",  
        ],




    ) {
        if (ref $_ eq 'CODE') {
            &$_() or last;
        } else {
            my ($name, $run, $request, $response) = @$_;

            inject_content_length $request;
            inject_content_length $response;

            for my $z (1 .. $run) {
                my $test = $name . ($run > 1 ? " ($z)" : "");
                my $sock;

                if ($use_fhka) {
                    $sock = $fhka;
                } else {
                    $sock = connect_peer $peer, 5
                        or fail ($test), diag ("connect_peer '$peer' failed"),
                            diag (cat_logs "$prefix/logs"),
                             last LOOP;
                }

                send_data $sock, $request, 5
                    or fail ($test), diag ("send_data to '$peer' failed"),
                        diag ("Request: \n$request\n"),
                         diag ("Expected response: \n$response\n"),
                          diag (cat_logs "$prefix/logs"),
                           last LOOP;

                my ($remote_buf, $remote);
                read_http_response $sock, $remote_buf, $remote, 5
                    or fail ($test), diag ("read_http_response failed: $@"),
                        diag ("Request: \n$request\n"),
                         diag ("Expected response: \n$response\n"),
                          diag (cat_logs "$prefix/logs"),
                           last LOOP;

                my ($local, $local_hlen);
                $local_hlen = parse_http_response $response, $local,
                    or fail ($test), diag ("parse_http_response failed"),
                        diag ("Request: \n$request\n"),
                         diag ("Expected response: \n$response\n"),
                          diag (cat_logs "$prefix/logs"),
                           last LOOP;

                use Data::Dumper;
                local $Data::Dumper::Terse = 1;
    
                # comparing bodies

                my $local_buf;
                my $len = $local->{'content-length'}
                            ? $local->{'content-length'}->[0] : 0;
                if ($len) { $local_buf = substr $response, $local_hlen }

                if ($local_buf ne '') {
                    if ($local_buf ne $remote_buf) {
                        fail ($test), 
                         diag ("Request: \n$request\n"),
                          diag ("Expected response: \n$response\n"),
                           diag ("Got:\n" . Dumper([$remote, $remote_buf])),
                            diag ("Expected:\n" . Dumper([$local, $local_buf])),
                             diag (cat_logs "$prefix/logs"),
                              last LOOP;
                    }
                }

                # comparing headers

                foreach my $key (keys %$local) {
                    my $value = $local->{$key};
                    
                    unless (exists $remote->{$key}) {
                        fail ($test), 
                         diag ("Request: \n$request\n"),
                          diag ("Expected response: \n$response\n"),
                           diag ("Got:\n" . Dumper($remote)),
                            diag ("Expected:\n" . Dumper($local)),
                             diag (cat_logs "$prefix/logs"),
                              last LOOP;
                    }
                    
                    if (ref $value eq 'ARRAY') {
                        for my $i (0 .. $#{$value}) {
                            if ($remote->{$key}->[$i] ne $value->[$i]) {
                                fail ($test),
                                 diag ("Request: \n$request\n"),
                                  diag ("Expected response: \n$response\n"),
                                   diag ("Got:\n" . Dumper($remote)),
                                    diag ("Expected:\n" . Dumper($local)),
                                     diag (cat_logs "$prefix/logs"),
                                      last LOOP;
                            }
                        }
                    } else {
                        if ($remote->{$key} ne $value) {
                            fail ($test), 
                             diag ("Request: \n$request\n"),
                              diag ("Expected response: \n$response\n"),
                               diag ("Got:\n" . Dumper($remote)),
                                diag ("Expected:\n" . Dumper($local)),
                                 diag (cat_logs "$prefix/logs"),
                                  last LOOP;
                        }
                    }
                }

                pass $test;

                unless ($use_fhka) {
                    $sock->close;
                }
            }
        }
    }
}

