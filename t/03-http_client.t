#!/usr/bin/perl 

# This test was ported here from Nginx::PicCache
# 

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

use Digest::MD5 qw(md5_hex);
use IO::Socket;
use Test::More;

use Nginx::Test;
use constant { CRLF => "\x0d\x0a" };

my $prefix = make_path 'objs/t03'
    or diag ("make_path failed: $!"),
        plan ('skip_all', "Cannot create test directory: $!");

my $port1 = get_unused_port or plan ('skip_all', 'get_unused_port failed');
my $peer1 = "127.0.0.1:$port1";

my $port2 = get_unused_port or plan ('skip_all', 'get_unused_port failed');
my $peer2 = "127.0.0.1:$port2";

my $port3 = get_unused_port or plan ('skip_all', 'get_unused_port failed');
my $peer3 = "127.0.0.1:$port3";

my $nginx = find_nginx_perl
    or diag ("find_nginx_perl failed: $!"),
        plan ('skip_all', "Cannot find nginx-perl");


plan 'no_plan';

{
    my $sock;
    $sock = IO::Socket::INET->new('Listen'    => 128,
                                  'LocalAddr' => "127.0.0.1",
                                  'LocalPort' => $port3,
                                  'Proto'     => 'tcp');

    my $peer = $peer1;

    prepare_nginx_dir_die $prefix, <<"    ENDCONF", <<'    ENDPKG';

        worker_processes  1;
        daemon            off;
        master_process    off;

        error_log  logs/error.log  debug;

        events {  
            worker_connections  128;  
        }

        http {
            default_type  text/plain;

            perl_inc lib;
            perl_require NginxTst.pm;

            perl_eval ' \$NginxTst::peer2 = "$peer2"; ';
            perl_eval ' \$NginxTst::peer3 = "$peer3"; ';

            server {
                listen  $peer;

                location / { 
                    perl_handler NginxTst::handler_peer2; 
                }

                location = /timeout { 
                    perl_handler NginxTst::handler_peer3; 
                }
            }

            server {
                listen  $peer2;

                location = /index.html { }
                location = /err503   { error_page 404 =503 /index.html; }
                location   /junk     { perl_handler NginxTst::junk; }
                location   /         { perl_handler NginxTst::generator; }
                location   /breaking { perl_handler NginxTst::breaking; }
            }
        }

    ENDCONF

        package NginxTst;

        use strict;
        use warnings;
        no  warnings 'uninitialized';

        use Digest::MD5 qw(md5_hex);

        use Nginx;



# taken from Zigzag::Test
sub parse_http_response ($$) {
    my $buf = \$_[0];

    if ($$buf =~ /(\x0d\x0a\x0d\x0a)/gs || $$buf =~ /(\x0a\x0a)/gs) {
        my $header_len = pos($$buf) - length($1);
        my $sep_len = length($1);

        pos($$buf) = 0; 

        my @lines = split /^/, substr ($$buf, 0, $header_len);

        return undef
              if @lines < 1;

        my %h;
        @h{ '_version', 
            '_status', 
            '_message'  } = split ' ', shift (@lines), 3;

        $h{_message} =~ s/\s+$//;

        map {  
            my ($key, $value) = split ':', $_, 2;

                $key   =~ s/^\s+//; $key   =~ s/\s+$//;
                $value =~ s/^\s+//; $value =~ s/\s+$//;

            push @{$h{ lc($key) }}, $value;
        } @lines;

        if ($h{_version} eq 'HTTP/1.1') {
            if (!exists $h{connection}) {
                $h{_keepalive} = 1  
            } elsif ($h{connection}->[0] !~ /[Cc]lose/) {
                $h{_keepalive} = 1  
            }
        } elsif (exists $h{connection}) {
            if ($h{connection}->[0] =~ /[Kk]eep-[Aa]live/) {
                $h{_keepalive} = 1;
            }
        }

        $_[1] = \%h;
        return $header_len + $sep_len;
    } else {
        return 0;
    }
}


# taken from Nginx::PicCache
our $CONTENT_LENGTH_MAX = 10 * 1048576;
sub http ($$$$$$) {
    my ($ip, $port, undef, undef, $timeout, $cb) = @_;
    my ($request, $response);

    if (defined $_[2]) {
        if (ref $_[2] eq '') {
            $request = \$_[2];
        } elsif (ref $_[2] eq 'SCALAR') {
            $request = $_[2];
        } else {
            $! = NGX_EINVAL,
            &$cb(),
            return;
        }
    } else {
        $! = NGX_EINVAL,
        &$cb(),
        return;
    }

    if (defined $_[3]) {
        if (ref $_[3] eq '') {
            $response = \$_[3];
        } elsif (ref $_[3] eq 'SCALAR') {
            $response = $_[3];
        } else {
            $_[3] = '';
            $response = \$_[3];
        }
    } else {
        $_[3] = '';
        $response = \$_[3];
    }

    ngx_connector $ip, $port, $timeout, sub {
        if (!$!) {
            my ($c) = @_;

            ngx_writer $c, $$request, $timeout, sub {
                if (!$!) {
                    $$response = '';
                    return NGX_READ;
                } else {
                    &$cb(), 
                    return NGX_CLOSE;
                }
            };

            ngx_reader $c, $$response, 0, 0, $timeout, sub {
                if (!$!) {
                    my $h;
                    my $len = parse_http_response $$response, $h;
                    
                    if ($len) {
                        substr $$response, 0, $len, '';
                        $len = ref $h->{'content-length'} eq 'ARRAY'
                                 ? int "$h->{'content-length'}->[0]" : undef;

                        if ($len && length($$response) >= $len) {
                            $! = 0,
                            &$cb($h),
                            return NGX_CLOSE;
                        } elsif ($len && $len == 0) {
                            $! = 0,
                            &$cb($h),
                            return NGX_CLOSE;
                        } elsif ($len && $len > 0 && 
                                 $len < $CONTENT_LENGTH_MAX ) {
                            ngx_reader $c, $$response, $len, $len, $timeout, 
                            sub {
                                if (!$!) {
                                    &$cb($h),
                                    return NGX_CLOSE;
                                } elsif ($!) {
                                    &$cb($h),
                                    return NGX_CLOSE;
                                }
                            };
                            return NGX_READ;
                        } elsif (!$len) {
                            ngx_reader $c, $$response, 0, 
                                        $CONTENT_LENGTH_MAX, $timeout, sub {
                                if ($! == NGX_EOF) {
                                    $! = 0,
                                    &$cb($h),
                                    return NGX_CLOSE;
                                } elsif ($!) {
                                    &$cb($h),
                                    return NGX_CLOSE;
                                } else {
                                    return NGX_READ;
                                }
                            };
                            return NGX_READ;
                        } else {
                            $! = NGX_EBADE,
                            &$cb($h),
                            return NGX_CLOSE;
                        }
                    } elsif (defined $len) {
                        if (length($$response) < 4096) {
                            return NGX_READ;
                        } else {
                            $! = NGX_EBADE;
                            &$cb();
                            return NGX_CLOSE;
                        }
                    } else {
                        $! = NGX_EBADE,
                        &$cb(),
                        return NGX_CLOSE;
                    }
                } else {
                    &$cb(),
                    return NGX_CLOSE;
                }
            };

            return NGX_WRITE;
        } else {
            &$cb(),
            return NGX_CLOSE;
        }
    };
}



        sub generator {
            my ($r) = @_;
            $r->main_count_inc;

            my $buf = (substr md5_hex($r->uri), 5, 1) 
                        x (hex substr md5_hex($r->uri), 0, 4);

            $r->header_out("Content-Length", length($buf));
            $r->send_http_header("text/plain");
            $r->print($buf)  unless $r->header_only;
            $r->send_special(NGX_HTTP_LAST);
            $r->finalize_request(NGX_OK);

            return NGX_DONE;
        }

        sub junk {
            my ($r) = @_;
            $r->main_count_inc;

            my $buf = (substr md5_hex($r->uri), 5, 1) 
                        x (hex substr md5_hex($r->uri), 0, 4);

            my $c = $r->take_connection;

            ngx_writer $c, $buf, 1, sub {
                $r->give_connection,
                $r->finalize_request(NGX_DONE),
                return NGX_NOOP;
            };

            ngx_write $c;

            return NGX_DONE;
        }

        sub breaking {
            my ($r) = @_;
            $r->main_count_inc;

            my $uri = $r->uri;
            my $buf;

            if ($uri eq '/breaking/content-length/1') {
                $buf = "HTTP/1.0 200 OK"                 ."\x0d\x0a".
                       "Content-Length: asdfasdfsdf"     ."\x0d\x0a".
                       ""                                ."\x0d\x0a".
                       "cl1";
            } elsif ($uri eq '/breaking/content-length/2') {
                $buf = "HTTP/1.0 200 OK"                 ."\x0d\x0a".
                       "Content-Length: -5000000000000"  ."\x0d\x0a".
                       ""                                ."\x0d\x0a".
                       "";
            }

            my $c = $r->take_connection;

            ngx_writer $c, $buf, 1, sub {
                $r->give_connection,
                $r->finalize_request(NGX_DONE),
                return NGX_NOOP;
            };

            ngx_write $c;

            return NGX_DONE;
        }

        sub handler {
            my ($r) = @_;
            $r->main_count_inc;

            my $backend = $r->variable("backend");
            my ($ip, $port) = split ':', $backend;

            my $uri = $r->uri;
            my $res = '';
            my $req = "GET $uri HTTP/1.0" ."\x0d\x0a".
                      "Host: $backend"    ."\x0d\x0a".
                      ""                  ."\x0d\x0a";
            http $ip, $port, $req, $res, 1, sub {
                if (!$!) {
                    my ($h) = @_;

                    $r->header_out("X-Backend-Status", $h->{_status});

                    $r->header_out("Content-Length", length($res));
                    $r->send_http_header("text/plain");
                    $r->print($res)  unless $r->header_only;
                    $r->send_special(NGX_HTTP_LAST);
                    $r->finalize_request(NGX_OK);
                } else {
                    $r->header_out("x-errstr", $!);
                    $r->header_out("x-errno", int($!));
                    $r->finalize_request(502);
                }
            };

            return NGX_DONE;
        }

        our $peer2;
        our $peer3;

        sub handler_peer2 {
            my ($r) = @_;
            $r->variable("backend", $peer2);
            &handler;
        }

        sub handler_peer3 {
            my ($r) = @_;
            $r->variable("backend", $peer3);
            &handler;
        }

        1;
    
    ENDPKG

    my $child = fork_nginx_die $nginx, $prefix;

    wait_for_peer $peer, 5
        or diag ("wait_for_peer '$peer' failed"),
            diag (cat_logs "$prefix/logs");

    my $fhka;      # filehandle for keepalive connection
    my $use_fhka;

  LOOP:
    foreach $_ (


        [
            "/err503",  3,

                "GET /err503 HTTP/1.0"                          .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 200 OK"                               .CRLF.
                "Connection: close"                             .CRLF.
                "X-Backend-Status: 503"                         .CRLF.
                ""                                              .CRLF.
                "",
        ],

        [
            "/",  3,

                "GET / HTTP/1.0"                                .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 200 OK"                               .CRLF.
                "Connection: close"                             .CRLF.
                "X-Backend-Status: 200"                         .CRLF.
                ""                                              .CRLF.
                (substr md5_hex("/"), 5, 1) 
                    x (hex substr md5_hex("/"), 0, 4).
                "",
        ],

        [
            "/foo",  3,

                "GET /foo HTTP/1.0"                             .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 200 OK"                               .CRLF.
                "Connection: close"                             .CRLF.
                "X-Backend-Status: 200"                         .CRLF.
                ""                                              .CRLF.
                (substr md5_hex("/foo"), 5, 1) 
                    x (hex substr md5_hex("/foo"), 0, 4).
                "",
        ],

        [
            "/zxc",  3,

                "GET /zxc HTTP/1.0"                             .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 200 OK"                               .CRLF.
                "Connection: close"                             .CRLF.
                "X-Backend-Status: 200"                         .CRLF.
                ""                                              .CRLF.
                (substr md5_hex("/zxc"), 5, 1) 
                    x (hex substr md5_hex("/zxc"), 0, 4).
                "",
        ],

        [
            "/tgh",  3,

                "GET /tgh HTTP/1.0"                             .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 200 OK"                               .CRLF.
                "Connection: close"                             .CRLF.
                "X-Backend-Status: 200"                         .CRLF.
                ""                                              .CRLF.
                (substr md5_hex("/tgh"), 5, 1) 
                    x (hex substr md5_hex("/tgh"), 0, 4).
                "",
        ],

        [
            "/breaking/content-length/1",  3,

                "GET /breaking/content-length/1 HTTP/1.0"       .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 200 OK"                               .CRLF.
                "Connection: close"                             .CRLF.
                "X-Backend-Status: 200"                         .CRLF.
                ""                                              .CRLF.
                "cl1",
        ],

        [
            "/breaking/content-length/2",  3,

                "GET /breaking/content-length/2 HTTP/1.0"       .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 200 OK"                               .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",
        ],


        [
            "/junk",  3,

                "GET /junk HTTP/1.0"                            .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 502 Bad Gateway"                      .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",
        ],

        [
            "/junk2",  3,

                "GET /junk2 HTTP/1.0"                           .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 502 Bad Gateway"                      .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",
        ],


        [
            "/timeout",  2,

                "GET /timeout HTTP/1.0"                         .CRLF.
                "Host: $peer"                                   .CRLF.
                "Connection: close"                             .CRLF.
                ""                                              .CRLF.
                "",

                "HTTP/1.1 502 Bad Gateway"                      .CRLF.
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

