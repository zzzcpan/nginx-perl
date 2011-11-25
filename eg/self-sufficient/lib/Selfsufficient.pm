package Selfsufficient;

use strict;
use warnings;
no  warnings 'uninitialized';

use Nginx;

our $SOMETHING = '';


sub handler {
    my ($r) = @_;

    $r->main_count_inc; 


    my $prefix =  $r->location_name;
       $prefix =~ s/\/$//;

    my $uri =  $r->uri;
       $uri =~ s/^$prefix//;
       $uri =  '/'  unless $uri;

    my $title;
    my $menu;
    my $pad  = '&nbsp;' x 4;

    foreach ( [ 'index', '/'     ],
              [ 'foo',   '/foo/' ],
              [ 'bar',   '/bar/' ] ) {

        my ($name, $href) = @$_;

        if ($href eq $uri) {
            $title = $name;
            $menu .= "<b> $name </b>$pad";
        } else {
            $menu .= "<a href=$prefix$href> $name </a>$pad";
        }
    }


    unless ($title) {

        $r->finalize_request(404);
        return NGX_DONE;
    }


    my $root        = $r->variable('document_root');
    my $remote_addr = $r->variable('remote_addr');
    my $name        = $r->variable('name');

    my $buf = <<"    EOF";
        <html>
        <head>
            <title>$prefix 's $title</title>
        </head>
        <body>
            <blockquote>
                <p> $menu </p>

                <h3> $prefix 's $title </h3>

                <p> ... </p>

                <p> name        = $name <br>
                    SOMETHING   = $SOMETHING <br>
                    root        = $root <br>
                    remote_addr = $remote_addr </p>

                <p> <a href=/tralala> location /tralala </a> <br>
                    <a href=/> location / </a> </p>
            </blockquote>
        </body>
        </html>
    EOF


    $r->send_http_header('text/html; charset=UTF-8');

    $r->header_out('Cache-Control',  'no-cache');
    $r->header_out('Pragma',         'no-cache');
    $r->header_out('Content-Length', length($buf));

    $r->print($buf)
        unless $r->header_only;

    $r->send_special(NGX_HTTP_LAST);
    $r->finalize_request(NGX_OK);


    return NGX_DONE;
}


1;

