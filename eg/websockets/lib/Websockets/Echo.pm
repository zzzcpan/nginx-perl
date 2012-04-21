package Websockets::Echo;

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

use Nginx;
use Digest::SHA1 qw(sha1_base64);
use Here::Template;


sub handler {
    my ($r) = @_;

    my $prefix = $r->location_name;  $prefix =~ s/\/$//;
    my $uri    = $r->uri;

    if ($uri eq "$prefix/websocket") {
        return &websocket_handler;
    } elsif ($uri eq "$prefix/") {
        return &webpage_handler;
    } else {
        return 404;
    }
}


sub websocket_handler {
    my ($r) = @_;
    $r->main_count_inc; 

    if (lc($r->header_in('upgrade')) ne 'websocket' || 
        $r->header_in('sec-websocket-version') ne '13') 
    {
        $r->finalize_request(501);
        return NGX_DONE;
    }

    if (lc($r->header_in('origin')) ne 
            "http://".lc($r->variable('http_host'))) {
        $r->finalize_request(403);
        return NGX_DONE;
    }

    my $wsaccept = (sha1_base64 $r->header_in('sec-websocket-key')
                                ."258EAFA5-E914-47DA-95CA-C5AB0DC85B11")."=";

    my $c = $r->take_connection;

    my $buf = "HTTP/1.1 101 Switching Protocols"  ."\x0d\x0a".
              "Upgrade: websocket"                ."\x0d\x0a".
              "Connection: Upgrade"               ."\x0d\x0a".
              "Sec-WebSocket-Accept: $wsaccept"   ."\x0d\x0a".
              ""                                  ."\x0d\x0a";

    ngx_writer $c, $buf, 5, sub {
        if (!$!) {
            $buf = '';
            return NGX_READ;
        } else {
            $r->give_connection;
            $r->finalize_request(NGX_DONE);
            return NGX_NOOP;
        }
    };

    ngx_reader $c, $buf, 0, 0, 5, sub {
        if (!$!) {
            # echoing everything back
            return NGX_WRITE; 
        } else {
            $r->give_connection;
            $r->finalize_request(NGX_DONE);
            return NGX_NOOP;
        }
    };

    ngx_write $c; 

    return NGX_DONE;  # always after $r->main_count_inc
}


sub webpage_handler {
    my ($r) = @_;
    my $buf;
    $r->main_count_inc; 

    my $prefix = $r->location_name;  $prefix =~ s/\/$//;

$buf = <<'TMPL';
<!doctype html>
<html>
<script language="javascript" type="text/javascript"><!--

    var ws;
    var wsUri = "ws://<?= $r->variable('http_host')."$prefix/websocket" ?>";
    
    function start () { 
        ws = new WebSocket(wsUri);

        ws.onopen = function (ev) {
            log("ONOPEN:");
            log("    sending 'hello'");
            ws.send("hello");
        };

        ws.onmessage = function (ev) { 
            log("ONMESSAGE:");
            log("    '" + ev.data + "'");
            ws.close();
        };

        ws.onclose = function (ev) { 
            log("ONCLOSE:");
        };

        ws.onerror = function (ev) { 
            log("ONERROR:");
            log("    '" + ev.data + "'");
        }; 
    }

    function log (message) { 
        var pre = document.createElement("span"); 
        pre.innerHTML = message + "\n"; 
        document.getElementById("log").appendChild(pre); 
    }

//--></script>

<body onload="start()">
    <pre id="log"></pre>
</body>

</html>
TMPL

    $r->header_out('Cache-Control',  'no-cache');
    $r->header_out('Pragma',         'no-cache');
    $r->header_out('Content-Length', length($buf));

    $r->send_http_header('text/html; charset=UTF-8');

    $r->print($buf)
        unless $r->header_only;

    $r->send_special(NGX_HTTP_LAST);
    $r->finalize_request(NGX_OK);

    return NGX_DONE;  # always after $r->main_count_inc
}


1;

