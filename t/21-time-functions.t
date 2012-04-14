#!/usr/bin/perl 

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

use Test::More;

use Nginx::Test;
use constant { CRLF => "\x0d\x0a" };

my $prefix = make_path 'objs/t21'
    or diag ("make_path failed: $!"),
        plan ('skip_all', "Cannot create test directory: $!");

my $port1 = get_unused_port or plan ('skip_all', 'get_unused_port failed');
my $peer1 = "127.0.0.1:$port1";

my $nginx = find_nginx_perl
    or diag ("find_nginx_perl failed: $!"),
        plan ('skip_all', "Cannot find nginx-perl");

{
    my $peer = $peer1;  # for easier copy-paste
    my $pkg =  "package NginxTst;\n".
               "# line ". (__LINE__+1) ." ". __FILE__ ."\n". <<'    ENDPKG';

    use Nginx;
    sub ok ($$);
    sub diag;

    my @tests = ( 

        34,  # plan

        sub {
            my $str;

            $str = ngx_http_time time;

                ok $str && length($str) > 15, "ngx_http_time: basic"
                    or diag "length(\$str) = ".length($str);

            my $zero;
            $zero = ngx_http_time 0;

                ok $zero && length($zero) > 15, "ngx_http_time: zero"
                    or diag "length(\$zero) = ".length($zero);

            my $un;
            $str = ngx_http_time $un;

                ok $str && length($str) > 15, "ngx_http_time: uninitialized"
                    or diag "length(\$str) = ".length($str);

                ok $str eq $zero, "ngx_http_time: same as zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_time undef;

                ok $str && length($str) > 15, "ngx_http_time: undef"
                    or diag "length(\$str) = ".length($str);

                ok $str eq $zero, "ngx_http_time: same as zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_time '';

                ok $str && length($str) > 15, "ngx_http_time: empty PV"
                    or diag "length(\$str) = ".length($str);

                ok $str eq $zero, "ngx_http_time: same as zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_time 'foo';

                ok $str && length($str) > 15, "ngx_http_time: PV"
                    or diag "length(\$str) = ".length($str);

                ok $str eq $zero, "ngx_http_time: same as zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_time '5foo';

                ok $str && length($str) > 15, "ngx_http_time: PV"
                    or diag "length(\$str) = ".length($str);

                ok $str ne $zero, "ngx_http_time: no a zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_time \$zero;

                ok $str && length($str) > 15, "ngx_http_time: RV"
                    or diag "length(\$str) = ".length($str);

                ok $str ne $zero, "ngx_http_time: not a zero"
                    or diag "\$str = '$str', \$zero = '$zero'";
        },

        sub {
            my $str;

            $str = ngx_http_cookie_time time;

                ok $str && length($str) > 15, "ngx_http_cookie_time: basic"
                    or diag "length(\$str) = ".length($str);

            my $zero;
            $zero = ngx_http_cookie_time 0;

                ok $zero && length($zero) > 15, "ngx_http_cookie_time: zero"
                    or diag "length(\$zero) = ".length($zero);

            my $un;
            $str = ngx_http_cookie_time $un;

                ok $str && length($str) > 15, 
                   "ngx_http_cookie_time: uninitialized"
                        or diag "length(\$str) = ".length($str);

                ok $str eq $zero, "ngx_http_cookie_time: same as zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_cookie_time undef;

                ok $str && length($str) > 15, "ngx_http_cookie_time: undef"
                    or diag "length(\$str) = ".length($str);

                ok $str eq $zero, "ngx_http_cookie_time: same as zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_cookie_time '';

                ok $str && length($str) > 15, "ngx_http_cookie_time: empty PV"
                    or diag "length(\$str) = ".length($str);

                ok $str eq $zero, "ngx_http_cookie_time: same as zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_cookie_time 'foo';

                ok $str && length($str) > 15, "ngx_http_cookie_time: PV"
                    or diag "length(\$str) = ".length($str);

                ok $str eq $zero, "ngx_http_cookie_time: same as zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_cookie_time '5foo';

                ok $str && length($str) > 15, "ngx_http_cookie_time: PV"
                    or diag "length(\$str) = ".length($str);

                ok $str ne $zero, "ngx_http_cookie_time: not a zero"
                    or diag "\$str = '$str', \$zero = '$zero'";

            $str = ngx_http_cookie_time \$zero;

                ok $str && length($str) > 15, "ngx_http_cookie_time: RV"
                    or diag "length(\$str) = ".length($str);

                ok $str ne $zero, "ngx_http_cookie_time: not a zero"
                    or diag "\$str = '$str', \$zero = '$zero'";
        },

        sub {
            my $t;
            my $time = time;

            $t = ngx_http_parse_time ngx_http_time($time);

                ok $t && $t == $time, 
                   "ngx_http_parse_time: basic"
                        or diag ("t = '$t', time = '$time'"), 
                            diag ('ngx_http_time($time) = '.
                                              ngx_http_time($time));

            $t = ngx_http_parse_time ngx_http_cookie_time($time);

                ok $t && $t == $time, 
                   "ngx_http_parse_time: cookie_time"
                        or diag "t = '$t', time = '$time'";

            my $un;
            $t = ngx_http_parse_time $un;

                ok !defined $t, 
                   "ngx_http_parse_time: uninitialized"
                        or diag "t = '$t', time = '$time'";

            $t = ngx_http_parse_time undef;

                ok !defined $t, 
                   "ngx_http_parse_time: undef"
                        or diag "t = '$t', time = '$time'";

            $t = ngx_http_parse_time '';

                ok !defined $t, 
                   "ngx_http_parse_time: empty PV"
                        or diag "t = '$t', time = '$time'";

            $t = ngx_http_parse_time 0;

                ok !defined $t, 
                   "ngx_http_parse_time: zero"
                        or diag "t = '$t', time = '$time'";
        },

    );

    our $OUT;

    sub diag {  $OUT .= join '', map { "# $_" } split(/^/, "$_[0]\n")  }
    sub ok ($$) { 
        my (undef, $f, $l) = caller; 
        if ($_[0]) {
            $OUT .= "1 - $_[1]\n";
            return 1;
        } else {
            $OUT .= "0 - $_[1]\n";
            $OUT .= "#     Subtest '$_[1]'\n".
                    "#     at $f line $l\n";
            return undef;
        }
    }

    sub handler {
        use bytes;
        my ($r) = @_;
        $r->main_count_inc;

        my $buf = '';

        if ($r->uri eq '/') {
            $buf = (@tests - 1)." ".$tests[0];
        } elsif ($r->uri =~ m!^/(\d+)$!) {
            my $sub = $tests[$1];
            $OUT = '';
            &$sub();
            $buf = $OUT;
        } else {
            $r->finalize_request(404);
            return NGX_DONE;
        }

        $r->header_out("Content-Length", length($buf));
        $r->send_http_header("text/plain");
        $r->print($buf)  
                unless $r->header_only;
        $r->send_special(NGX_HTTP_LAST);
        $r->finalize_request(NGX_OK);

        return NGX_DONE;
    }

    1;

    ENDPKG

    prepare_nginx_dir_die $prefix, <<"    ENDCONF", $pkg;

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

            server {
                listen  $peer;
                location / { perl_handler NginxTst::handler; }
            }
        }

    ENDCONF

    my $child = fork_nginx_die $nginx, $prefix;

    wait_for_peer $peer, 5
        or diag ("wait_for_peer '$peer' failed"),
            diag (cat_logs "$prefix/logs");

    
    my ($sock, $remote_buf, $remote);
    my $request = "GET / HTTP/1.0"   .CRLF.
                  "Host: $peer"      .CRLF.
                  ""                 .CRLF;
    REQ: {
        $sock = connect_peer $peer, 5
            or diag ("connect_peer '$peer' failed"),
                diag (cat_logs "$prefix/logs"),
                 last REQ;

        send_data $sock, $request, 5
            or diag ("send_data to '$peer' failed"),
                diag (cat_logs "$prefix/logs"),
                 last REQ;

        read_http_response $sock, $remote_buf, $remote, 5
            or diag ("read_http_response failed: $@"),
                diag (cat_logs "$prefix/logs"),
                 last REQ;
    }

    my ($requests, $tests) = split ' ', $remote_buf;

    if ($requests =~ /^\d+$/ && $tests =~ /^\d+$/) {
        plan 'tests', $tests;

        my $failed = 0;

      LOOP:
        for my $i (1 .. $requests) {
            my ($sock, $test);
            my $request = "GET /$i HTTP/1.0"  .CRLF.
                          "Host: $peer"       .CRLF.
                          ""                  .CRLF;
            $test = "$i";

            $sock = connect_peer $peer, 5
                or fail ($test), diag ("connect_peer '$peer' failed"),
                    diag (cat_logs "$prefix/logs"),
                     last LOOP;

            send_data $sock, $request, 5
                or fail ($test), diag ("send_data to '$peer' failed"),
                    diag ("Request: \n$request\n"),
                     diag (cat_logs "$prefix/logs"),
                      last LOOP;

            my ($remote_buf, $remote);
            read_http_response $sock, $remote_buf, $remote, 5
                or fail ($test), diag ("read_http_response failed: $@"),
                    diag ("Request: \n$request\n"),
                     diag (cat_logs "$prefix/logs"),
                      last LOOP;

            if ($remote->{_status} ne '200') {
                fail ($test), diag ("non-200 response status"),
                 diag (cat_logs "$prefix/logs"),
                  last LOOP;
            }

            my @out = split /^/, $remote_buf;
            foreach my $line (@out) {
                chomp $line;
                if ($line !~ /^#/) {
                    my ($rv, $name) = split ' - ', $line, 2;
                    if ($rv eq '1') {
                        pass "$i: $name";
                    } else {
                        fail "$i: $name";
                        $failed++;
                    }
                } else {
                    $line =~ s/^# //;
                    diag $line;
                }
            }

            $sock->close;
        }
        
        if ($failed) {
            diag (cat_logs "$prefix/logs")
        }
    } else {
        plan 'no_plan';
        fail "all";
        diag "no tests recv'd";
        use Data::Dumper;
        local $Data::Dumper::Terse = 1;
        diag "remote = \n". Dumper ($remote);
        diag "remote_buf = '$remote_buf'"; 
 
        diag cat_logs "$prefix/logs";
    }
}

