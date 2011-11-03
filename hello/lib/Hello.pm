package Hello;

use strict;
use warnings;
no  warnings 'uninitialized';

use Nginx;

sub selftest_get ($&);
sub send_response ($$);


sub World {
    my $r = shift;

    $r->main_count_inc; 

    ngx_connector '87.51.34.132', 21, 5, sub {

        send_response ( $r, "Connect failed: $!\n" )  &&  
            return NGX_CLOSE
                if $!;

        my $c   = shift;
        my $buf = "";

        ngx_reader $c, $buf, 0, 0, 5, sub {

            send_response ( $r, "Read failed: $!\n" )  &&  
                return NGX_CLOSE  
                    if $!;

            return NGX_READ  
                    if $buf !~ /\x0a/;

            send_response ( $r, "$buf\n" );
            return NGX_CLOSE;
        };

        return NGX_READ;
    };

    return NGX_DONE;
}


sub send_response ($$) {
    my ($r, $data) = @_;

    $r->send_http_header("text/html");
    $r->print($data); 

    $r->send_special(NGX_HTTP_LAST);
    $r->finalize_request(NGX_OK);

    return 1;
}


sub selftest {
    my $r   = shift;
    my $uri = $r->uri;

    if ( $r->uri eq '/selftest' ) {

        $r->main_count_inc; 

        selftest_get 'proxy', sub {

            my $data_ref = shift;

            $r->send_http_header ( "text/html" );
            $r->print ( sprintf "%010i\n", length($$data_ref) ); 

            $r->send_special ( NGX_HTTP_LAST );
            $r->finalize_request ( NGX_OK );
        };

        return NGX_DONE;

    } elsif ( $r->uri eq '/selftest/proxy' ) {

        $r->main_count_inc; 

        selftest_get 'generate', sub {

            my $data_ref = shift;

            $r->send_http_header ( "text/html" );
            $r->print ( $$data_ref ); 

            $r->send_special ( NGX_HTTP_LAST );
            $r->finalize_request ( NGX_OK );
        };

        return NGX_DONE;

    } elsif ( $r->uri eq '/selftest/generate' ) {

        $r->send_http_header ( "text/html" );
        $r->print ( "a" x (  int ( rand ( 1048576 ) ) + 1  ) ); 

        return OK;
    }

    return DECLINED;
}


sub selftest_get ($&) {
    my ($uri, $cb) = @_;

    ngx_connector '127.0.0.1', 5678, 15, sub {

        my $c   = shift;
        my $buf = "GET /selftest/$uri HTTP/1.0\x0d\x0a".
                  "Host: 127.0.0.1:5678\x0d\x0a".
                  "Connection: close\x0d\x0a".
                  "\x0d\x0a";
        if ($!) { 
            &$cb(); 
            return NGX_CLOSE; 
        }

        ngx_writer $c, $buf, 15, sub {

            if ($!) { 
                &$cb(); 
                return NGX_CLOSE; 
            }

            $buf = "";

            ngx_reader $c, $buf, 0, 0, 15, sub {

                if ($!) { 
                    &$cb(\$buf); 
                    return NGX_CLOSE; 
                }

                return NGX_READ; 
            };

            return NGX_READ;
        };

        return NGX_WRITE;
    };
}


1;
