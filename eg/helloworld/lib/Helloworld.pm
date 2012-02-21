package Helloworld;

use strict;
use warnings;
no  warnings 'uninitialized';

use Sys::Hostname;

use Nginx;

our $NAME = 'unnamed';


sub init_worker {

    my $hostname = hostname;

    warn << "    END";


    Helloworld is running on *:55555

        http://127.0.0.1:55555/
        http://$hostname:55555/


    END
}


sub handler {
    my ($r) = @_;

    return OK
        if $r->has_request_body ( \&handler_post );

    return &handler_post;
}


sub handler_post {
    my ($r) = @_;

    $r->main_count_inc; 


    my $buf = "Hello from $NAME\n";

    $r->header_out('Cache-Control',  'no-cache');
    $r->header_out('Pragma',         'no-cache');
    $r->header_out('Content-Length', length($buf));

    $r->send_http_header('text/html; charset=UTF-8');

    $r->print($buf)
        unless $r->header_only;

    $r->send_special(NGX_HTTP_LAST);
    $r->finalize_request(NGX_OK);


    return NGX_DONE;
}


1;

