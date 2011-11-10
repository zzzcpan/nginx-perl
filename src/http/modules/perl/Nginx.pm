package Nginx;

use strict;
use warnings;

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(

    ngx_log_error
    ngx_log_notice
    ngx_log_info
    ngx_log_crit
    ngx_log_alert

    ngx_timer
    ngx_resolver
    ngx_connector
    ngx_ssl_handshaker
    ngx_reader
    ngx_writer
    ngx_read
    ngx_write
    ngx_close
    ngx_ssl_handshake
    ngx_noop

    NGX_READ
    NGX_WRITE
    NGX_CLOSE
    NGX_SSL_HANDSHAKE
    NGX_NOOP
    NGX_EOF
    NGX_EINVAL
    NGX_ENOMEM
    NGX_EBADE
    NGX_EBADF
    NGX_ENOMSG
    NGX_EAGAIN
    NGX_ETIMEDOUT

    NGX_RESOLVE_FORMERR
    NGX_RESOLVE_SERVFAIL
    NGX_RESOLVE_NXDOMAIN
    NGX_RESOLVE_NOTIMP
    NGX_RESOLVE_REFUSED
    NGX_RESOLVE_TIMEDOUT

    NGX_DONE
    NGX_OK
    NGX_HTTP_LAST


    OK
    DECLINED

    HTTP_OK
    HTTP_CREATED
    HTTP_ACCEPTED
    HTTP_NO_CONTENT
    HTTP_PARTIAL_CONTENT

    HTTP_MOVED_PERMANENTLY
    HTTP_MOVED_TEMPORARILY
    HTTP_REDIRECT
    HTTP_NOT_MODIFIED

    HTTP_BAD_REQUEST
    HTTP_UNAUTHORIZED
    HTTP_PAYMENT_REQUIRED
    HTTP_FORBIDDEN
    HTTP_NOT_FOUND
    HTTP_NOT_ALLOWED
    HTTP_NOT_ACCEPTABLE
    HTTP_REQUEST_TIME_OUT
    HTTP_CONFLICT
    HTTP_GONE
    HTTP_LENGTH_REQUIRED
    HTTP_REQUEST_ENTITY_TOO_LARGE
    HTTP_REQUEST_URI_TOO_LARGE
    HTTP_UNSUPPORTED_MEDIA_TYPE
    HTTP_RANGE_NOT_SATISFIABLE

    HTTP_INTERNAL_SERVER_ERROR
    HTTP_SERVER_ERROR
    HTTP_NOT_IMPLEMENTED
    HTTP_BAD_GATEWAY
    HTTP_SERVICE_UNAVAILABLE
    HTTP_GATEWAY_TIME_OUT
    HTTP_INSUFFICIENT_STORAGE
);

our $VERSION = '1.1.6.1';

require XSLoader;
XSLoader::load('Nginx', $VERSION);

1;
__END__

=head1 NAME

Nginx - full featured perl support for nginx

=head1 SYNOPSIS

    # nginx-perl.conf
    ... 

    http {
        server {
            location / {
                perl_handler  My::App::handler;
    ...


    # package My::App;

    use Nginx;

    sub handler {
        my $r = shift;

        $r->main_count_inc;

        ngx_timer 1, 0, sub {
            $r->send_http_header('text/html');
            $r->print("OK\n");

            $r->send_special(NGX_HTTP_LAST);
            $r->finilize_request(NGX_OK);
        };

        return NGX_DONE;
    }



=head1 DESCRIPTION

Nginx with capital I<N> is a part of B<nginx-perl>.

nginx-perl is aimed to support asynchronous functions for embedded perl
along with other little features to make it nice and usable perl web server.

Currently includes:

    - official old perl API;
    - asynchronous connection (ngx_connector, ngx_reader, ngx_writer);
    - timer (ngx_timer);
    - SSL without cached sessions (ngx_ssl_handshaker);
    - simple resolver (ngx_resolver);
    - access handlers (perl_access);
    - app handlers (perl_app);
    - configuration level eval (perl_eval);
    - init_worker handlers (perl_init_worker);


=head1 INSTALLATION

In this distribution perl module is enabled by default, 
so just F<./configure> should work.

To build with different perl and SSL support use something like:

    % ./configure \
         --with-http_ssl_module \
         --with-perl=/home/you/perl5/perlbrew/perls/perl-5.14.2/bin/perl
    % make

There is a working example in F<hello/>. Should be easy to try things
out:

    % ./objs/nginx-perl -p hello

Also nginx-perl can be installed alongside nginx, it is safe to do:

    % make isntall


=head1 CONFIGURATION DIRECTIVES

=over 4

=item perl_inc  /path/to/lib;

Works just like Perl's C<use lib '/path/to/lib'>. Supports only one
argument, but you can specify it multiple times.

    http {
        perl_inc  /path/to/lib;
        perl_inc  /path/to/myproject/lib;


=item perl_require  My/App.pm;

Same as Perl's own C<require>.

    http {
        perl_inc      /path/to/lib;
        perl_require  My/App.pm;


=item perl_handler  My::App::handler; 

Sets current location's http content handler (a.k.a. http handler).

    http {
        server {
            location / {
                perl_handler My::App::Handler;


=item perl_access  My::App::access_handler; 

Adds http access handler to the access phase of current location.

    http {
        server {
            location / {
                perl_access My::App::access_handler; 
                perl_handler My::App::Handler;


=item perl_eval  '$My::App::CONF{foo} = "bar"';

Evaluate some perl code on configuration level. Useful if you 
need to configure some perl modules directly fron F<nginx-perl.conf>.

    http {
        perl_eval  '$My::App::CONF{foo} = "bar"';


=item perl_app  /path/to/app.pl;

Sets http content handler to the C<sub { }> returned from
the app. Internally does simple C<$handler = do '/path/to/app.pl'>,
so you can put your app into @INC somewhere to get shorter path.
Additionally prereads entire request body before calling the handler.
Which means there is no need to call $r->has_request_body there.

    http {
        server {
            location / {
                perl_app  /path/to/app.pl;


=back


=head1 NAMING

    NGX_FOO_BAR  -- constants
    ngx_*r       -- asynchronous functions (creators)
    NGX_VERB     -- flow control constants 
    ngx_verb     -- flow control functions
    $r->foo_bar  -- request object's methods

Each asynchronous function has an B<r> at the end of its name. This is 
because those functions are creators of handlers with some parameters. 
E.g. ngx_writer creates write handler for some connection with some
scalar as a buffer.


=head1 HTTP REQUEST OBJECT

All the things from official embedded perl are there and almost
completely untouched. There are quite a few new methods though:

=over 4

=item $ctx = $r->ctx($ctx)

Sets and gets some context scalar. It will be useful to get some data 
from access handler for example.

=item $r->location_name

Returns the name of the location.

=item $r->root

Returns the root path.

=item $r->main_count_inc()

Increases value of the internal C<< r->main->count >> by 1 and
therefore allows to send response later from some other callback.

=item $r->send_special($rc)

Sends response. 

=item $r->finalize_request($rc)

Decreases C<< r->main->count >> and finalizes request.

=item $r->phase_handler_inc()

Allows to move to the next phase handler from access handler.

=item $r->core_run_phases()

Allows to break out of access handler and continue later from
some other callback.

=back

=head1 HTTP CONTENT HANDLER

This is where response should get generated and send to the client.
Here's how to send response completely asynchronously:

    sub handler {
        my $r = shift;

        $r->main_count_inc;

        ngx_timer 1, 0, sub {
            $r->send_http_header('text/html');
            $r->print("OK\n");

            $r->send_special(NGX_HTTP_LAST);
            $r->finilize_request(NGX_OK);
        };

        return NGX_DONE;
    }

Notice C<return NGX_DONE> instead of C<return OK>, this is important,
because it allows to avoid post processing response the old way.

=head1 HTTP ACCESS HANDLER



=head1 FLOW CONTROL

To specify what to do after each callback we can either call some 
function or return some value and let handler do it for us. 
Most of the ngx_* handlers support return value and even optimized
for that kind of behavior.

Functions take connection as an argument:

    ngx_read($c)
    ngx_write($c)
    ngx_ssl_handshake($c)
    ngx_close($c)

Return values only work on current connection:

    return NGX_READ;
    return NGX_WRITE;
    return NGX_SSL_HANDSHAKE;
    return NGX_CLOSE;

As an example, let's connect and close connection. We will do flow control 
via single C<return> for this:

    ngx_connector '1.2.3.4', 80, 15, sub {

        return NGX_CLOSE;
    };

Now, if we want to connect and then read exactly 10 bytes we need
to create reader and C<return NGX_READ> from connector's callback:

    ngx_connector '1.2.3.4', 80, 15, sub {

        my $c = shift;

        ngx_reader $c, $buf, 10, 10, 15, sub {
            ... 
        };

        return NGX_READ;
    };

This will be different, if we already have connection somehow:

    ngx_reader $c, $buf, 10, 10, 15, sub {
        ... 
    };

    ngx_read($c);


=head1 ERROR HANDLING

Each ngx_* handler will call back on any error with C<$!> set to some value
and reset to 0 otherwise. 
For simplicity EOF considered to be an error as well and C<$!> will be set
to NGX_EOF in such case. 

Example:

    ngx_reader $c, $buf, 0, 0, sub {

        return NGX_WRITE
            if $! == NGX_EOF;

        return NGX_CLOSE
            if $!;

        ...

    };





=head1 CONNECTION TAKEOVER

It is possible to takeover client connection completely and create
you own reader and writer on that connection. 
You need this for websockets and protocol upgrade in general.

There are two methods to support this:

=over 4

=item $r->take_connection()

C<< $r->take_connection >> initializes internal data structure and 
replaces connection's data with it. Returns I<connection> on success
or I<undef> on error.

=item $r->give_connection()

C<< $r->give_connection >> attaches request C<$r> back to its connection.
Doesn't return anything.

=back

So, to takeover you need to take connection from the request, 
tell nginx that you are going to finalize it later by calling 
C<< $r->main_count_inc >>, create reader and/or writer on that
connection, start reading and/or writing flow and return NGX_DONE
from your HTTP handler:

    sub handler {
        my $r = shift;

        my $c = $r->take_connection()
            or return HTTP_SERVER_ERROR;

        $r->main_count_inc;

            my $buf;

            ngx_reader $c, $buf, ... , sub {

                if ($!) {
                    $r->give_connection;
                    $r->finalize_request(NGX_DONE);

                    return NGX_NOOP;
                }

                ...

            };

            ngx_writer $c, ... , sub {

                if ($!) {
                    $r->give_connection;
                    $r->finalize_request(NGX_DONE);

                    return NGX_NOOP;
                }

                ...

            };

            ngx_read($c);

        return NGX_DONE;
    }


Once you are done with the connection or connection failed with some error
you MUST give connection back to the request and finalize it:

    $r->give_connection;
    $r->finalize_request(NGX_DONE);

    return NGX_NOOP;

Usually you will also need to return NGX_NOOP instead of NGX_CLOSE,
since your connection is going to be closed within http request's
finalizer. But it shouldn't cuase any problems either way.





=head1 SEE ALSO

L<Nginx::Util>,

L<http://nginx.net/>, 
L<http://sysoev.ru/nginx/>,
L<http://sysoev.ru/nginx/docs/http/ngx_http_perl_module.html>

=head1 AUTHOR

Igor Sysoev,
Alexandr Gomoliako <zzz@zzz.org.ua>

=head1 COPYRIGHT AND LICENSE

Copyright (C) Igor Sysoev

Copyright 2011 Alexandr Gomoliako. All rights reserved.

This module is free software. It may be used, redistributed and/or modified 
under the same terms as B<nginx> itself.

=cut


