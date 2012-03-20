package Httpclient;

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

use Nginx;
use Nginx::HTTP;


sub handler_post {
    my ($r) = @_; $r->main_count_inc; 

    my $dispatcher = $r->variable('dispatcher');
    my $request = "GET / HTTP/1.1"    ."\x0d\x0a".
                  "Host: $dispatcher" ."\x0d\x0a".
                  ""                  ."\x0d\x0a";

    ngx_http $dispatcher, $request, sub {
        my ($headers, $body) = @_;

        if ($headers && $headers->{_status} == 200 && $body) {
            my @backends = split ' ', $$body;

            my $request_body   = $r->request_body;
               $request_body   = ''  if !defined $request_body;
            my $request_method = $r->request_method;
            my $request_uri    = $r->unparsed_uri;

            my $buf = "$request_method $request_uri HTTP/1.1"  ."\x0d\x0a".
                      "Host: localhost"                        ."\x0d\x0a".
                      "Content-Length: ".length($request_body) ."\x0d\x0a".
                      ""                                       ."\x0d\x0a".
                      $request_body;

            my $output = '';
            my $cnt = 0;
            my $backend_callback = sub {
                my ($h, $body) = @_;

                if ($h && $h->{_status} == 200 && $body) {
                    $output .= $$body;
                }

                if (--$cnt == 0) {
                    $r->header_out('Cache-Control',  'no-cache');
                    $r->header_out('Pragma',         'no-cache');
                    $r->header_out('Content-Length', length($output));

                    $r->send_http_header('text/html; charset=UTF-8');
                    $r->print($output)  unless $r->header_only;

                    $r->send_special(NGX_HTTP_LAST);
                    $r->finalize_request(NGX_OK);
                }
            };

            foreach my $backend (@backends) { 
                $cnt++; 
                ngx_http $backend, $buf, $backend_callback; 
            }
        } else {
            $r->finalize_request(503);
        }
    };


    return NGX_DONE;
}


sub handler {
    my ($r) = @_;

    return OK
         if $r->has_request_body ( \&handler_post );

    return &handler_post;
}


sub demo_handler {
    my ($r) = @_;

    $r->discard_request_body;

    my $list = $r->variable('demo_backends');
    my @backends = split ' ', $list;
    my $buf = $backends[ int rand @backends ] ."\n".
              $backends[ int rand @backends ] ."\n";

    $r->header_out('Content-Length', length($buf));
    $r->send_http_header('text/html; charset=UTF-8');
    $r->print($buf)  unless $r->header_only;

    return OK;
}


sub demo_handler2 {
    my ($r) = @_;

    $r->discard_request_body;

    my $server_port = $r->variable('server_port');
    my $buf = "Hello from $server_port\n";

    $r->header_out('Content-Length', length($buf));
    $r->send_http_header('text/html; charset=UTF-8');
    $r->print($buf)  unless $r->header_only;

    return OK;
}


1;

