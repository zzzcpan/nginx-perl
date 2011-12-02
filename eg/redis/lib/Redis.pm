package Redis;

use strict;
use warnings;
no  warnings 'uninitialized';

use Data::Dumper;

use Nginx;
use Nginx::Redis;


sub init_worker {

    ngx_redis '127.0.0.1:6379', ['GET', 'mykey'], sub {
        warn Dumper \@_;
    };
}


sub handler {
    my ($r) = @_;

    $r->main_count_inc; 

    $r->send_http_header('text/html; charset=UTF-8');

    $r->print ("hello\n")
        unless  $r->header_only;

    $r->send_special (NGX_HTTP_LAST);
    $r->finalize_request (NGX_OK);


    return NGX_DONE;
}


sub handler_single {
    my ($r) = @_;

    $r->main_count_inc; 


    ngx_redis '127.0.0.1', ['GET', 'mykey'], sub {
        my @reply = @_;

        my $buf = $reply [0]->[1] . "\n";

        $r->send_http_header ('text/html; charset=UTF-8');

        $r->print ($buf)
            unless  $r->header_only;

        $r->send_special (NGX_HTTP_LAST);
        $r->finalize_request (NGX_OK);
    };


    return NGX_DONE;
}


sub handler_multi {
    my ($r) = @_;

    $r->main_count_inc; 


    my $cnt = 10;

    for (1 .. $cnt) {

        ngx_redis '127.0.0.1', ['GET', 'mykey'], sub {
            my @reply = @_;

            if (--$cnt == 0) {
                my $buf = $reply [0]->[1] . "\n";

                $r->send_http_header ('text/html; charset=UTF-8');

                $r->print ($buf)
                    unless $r->header_only;

                $r->send_special (NGX_HTTP_LAST);
                $r->finalize_request (NGX_OK);
            }
        };
    }


    return NGX_DONE;
}


1;
