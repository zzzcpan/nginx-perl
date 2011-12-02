package Nginx;

use strict;
use warnings;

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(

    ngx_prefix
    ngx_conf_prefix
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

our $VERSION = '1.1.9.1';

require XSLoader;
XSLoader::load('Nginx', $VERSION);

1;
__END__

=head1 NAME

Nginx - full-featured perl support for nginx

=head1 SYNOPSIS

    # ----- nginx-perl.conf ------------------------

    http {

        perl_inc      /path/to/lib;
        perl_inc      /path/to/apps;
        perl_require  My/App.pm;

        perl_init_worker  My::App::init_worker;
        perl_exit_worker  My::App::exit_worker;

        perl_eval  '$My::App::SOME_VAR = "foo"';

        ...

        server {
            location / {
                perl_handler  My::App::handler;
        ...

        server {
            location / {
                perl_app  app.pl;
        ...


    # ----- My/App.pm ------------------------------

    package My::App;

    use Nginx;

    sub handler {
        my $r = shift;

        $r->main_count_inc;

        ngx_timer 1, 0, sub {
            $r->send_http_header('text/html');
            $r->print("OK\n");

            $r->send_special(NGX_HTTP_LAST);
            $r->finalize_request(NGX_OK);
        };

        return NGX_DONE;
    }


    # ----- app.pl ---------------------------------

    use Nginx;

    sub {
        my $r = shift;

        ...
    };



=head1 DESCRIPTION

Nginx with capital I<N> is a part of B<nginx-perl> distribution.

nginx-perl is aimed to support asynchronous functions for embedded perl
along with other little features to make it nice and usable perl web server.

Currently includes:

    - official old perl API;
    - asynchronous connections (ngx_connector, ngx_reader, ngx_writer);
    - timer (ngx_timer);
    - SSL without cached sessions (ngx_ssl_handshaker);
    - simple resolver (ngx_resolver);
    - access handlers (perl_access);
    - app handlers (perl_app);
    - configuration level eval (perl_eval);
    - init_worker handlers (perl_init_worker);
    - client connection takeover for websockets, etc;


=head1 RATIONALE

Nginx is very popular and stable asynchronous web-server.
And reusing as much of its internals as possible gives this project 
same level of stability nginx has. Maybe not right from the beginning,
but it can catch up with a very little effort.

Internal HTTP parser, dispatcher (locations) and different types
of handlers free perl modules from reinventing all that, like most 
of the perl frameworks do. It's already there, native and extremely
fast. 

All of the output filters there as well and everything you do
can be gzipped, processed with xslt or through any filter module
for nginx. Again, extremely fast.

Nginx has a pretty decent master-worker model, which allows to do
process management right out of the box.

And probably some other things I can't remember at the moment.

So, why use any of those perl frameworks if we already have 
nginx with nice native implementation for almost everything
they offer. It just needed a little touch.

Additionally I wanted to implement new asynchronous API
with proper flow control and explicit parameters to avoid
complexity as much as possible. 


=head1 INSTALLATION

In this distribution perl is enabled by default, 
so just F<./configure> should work.

But to build with different perl and SSL support use something like:

    % ./configure \
         --with-http_ssl_module \
         --with-perl=/home/you/perl5/perlbrew/perls/perl-5.14.2/bin/perl
    % make

nginx-perl can be installed alongside nginx. It uses 
capital B<N> for perl modules and F<nginx-perl> for binaries.
So, it is safe to do:

    % make install


=head1 RUNNING EXAMPLES

You don't have to install nginx-perl to try it. There are couple
of ready to try examples in F<eg/>:

    % ./objs/nginx-perl -p eg/helloworld

Now open another terminal or your web browser and go to
http://127.0.0.1:55555/ or whatever IP you're on.


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


=item perl_init_worker  My::App::init_worker;

Adds a handler to call on worker's start.

    http {
        perl_inc          /path/to/lib;
        perl_require      My/App.pm;

        perl_init_worker  My::App::init_worker;
        perl_init_worker  My::AnotherApp::init_worker;


=item perl_exit_worker  My::App::exit_worker;

Adds a handler to call on worker's exit.

    http {
        perl_inc          /path/to/lib;
        perl_require      My/App.pm;

        perl_exit_worker  My::App::exit_worker;
        perl_exit_worker  My::AnotherApp::exit_worker;


=item perl_handler  My::App::handler; 

Sets current location's http content handler (a.k.a. http handler).

    http {
        server {
            location / {
                perl_handler My::App::Handler;


=item perl_access  My::App::access_handler; 

Adds an http access handler to the access phase of current location.

    http {
        server {
            location / {
                perl_access My::App::access_handler; 
                perl_handler My::App::Handler;


=item perl_eval  '$My::App::CONF{foo} = "bar"';

Evaluates some perl code on configuration level. Useful if you 
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
            $r->finalize_request(NGX_OK);
        };

        return NGX_DONE;
    }

Notice C<return NGX_DONE> instead of C<return OK>, this is important,
because it allows to avoid post processing response the old way.

=head1 HTTP ACCESS HANDLER

todo

=head1 


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

=head1 ASYNCHRONOUS API

=over 4

=item ngx_timer $after, $repeat, sub { };

Creates new timer and calls back after C<$after> seconds.
If C<$repeat> is set reschedules the timer to call back again after 
C<$repeat> seconds or destroys it otherwise.

Internally C<$repeat> is stored as a refence, so changing it will influence
rescheduling behaviour.

Simple example calls back just once after 1 second:

    ngx_timer 1, 0, sub {
        warn "tada\n";
    };


This one is a bit trickier, calls back after 5, 4, 3, 2, 1 seconds 
and destroys itself:

    my $repeat = 5;

    ngx_timer $repeat, $repeat, sub {
        $repeat--;
    };


=item ngx_connector $ip, $port, $timeout, sub { };

Creates connect handler and attempts to connect to C<$ip:$port> within 
C<$timeout> seconds. Calls back with connection in C<@_> afterwards. 
On error calls back with C<$!> set to some value.

Expects one of the following control flow constants as a result of callback: 

    NGX_CLOSE
    NGX_READ 
    NGX_WRITE
    NGX_SSL_HANDSHAKE

Example:

    ngx_connector $ip, 80, 15, sub {

        return NGX_CLOSE
            if $!;

        my $c = shift;
        ...

        return NGX_READ;
    };


=item ngx_reader $connection, $buf, $min, $max, $timeout, sub { };

Creates read handler for C<$connection> with buffer C<$buf>.
C<$min> indicates how much data should be present in C<$buf> 
before the callback and C<$max> limits total length of C<$buf>.

Internally C<$buf>, C<$min>, C<$max> and C<$timeout> are stored
as refernces, so you can change them at any time to influence
reader's behavior.

Expects one of the following control flow constants as a result of callback: 

    NGX_CLOSE
    NGX_READ 
    NGX_WRITE
    NGX_SSL_HANDSHAKE

On error calls back with C<$!> set to some value, including 
NGX_EOF in case of EOF. 

    my $buf;

    ngx_reader $c, $buf, $min, $max, $timeout, sub {
        
        return NGX_CLOSE
            if $! && $! != NGX_EOF;
        ...

        return NGX_WRITE;
    };


=item ngx_writer $connection, $buf, $timeout, sub { };

Creates write handler for C<$connection> with buffer C<$buf> and 
write timeout in <$timeout>.

Internally C<$buf> and C<$timeout> are stored as references, so 
changing them will influence writer's behavior. 

Expects one of the following control flow constants as a result of callback: 

    NGX_CLOSE
    NGX_READ 
    NGX_WRITE
    NGX_SSL_HANDSHAKE

On error calls back with C<$!> set to some value. NGX_EOF should be
treated as fatal error here. 

Example:

    my $buf = "GET /\n";

    ngx_writer $c, $buf, 15, sub {

        return NGX_CLOSE
            if $!;
        ...

        return NGX_READ;
    };

=item ngx_ssl_handshaker $connection, sub { };

Creates its own internal handler for both reading and writing and tries 
to do SSL handshake. 

Expects one of the following control flow constants as a result of callback: 

    NGX_CLOSE
    NGX_READ 
    NGX_WRITE
    NGX_SSL_HANDSHAKE

On error calls back with C<$!> set to some value. 

It's important to understand that handshaker will replace your previous 
reader and writer, so you have to create new ones.

Typically it should be called inside connector's callback:

    ngx_connector ... sub {

        return NGX_CLOSE 
            if $!;

        my $c = shift;

        ngx_ssl_handshaker $c, sub {
            
            return NGX_CLOSE
                if $!;
            ...

            ngx_writer ... sub { };

            ngx_reader ... sub { };

            return NGX_WRITE;
        };

        return NGX_SSL_HANDSHAKE;
    };


=item ngx_resolver $name, $timeout, sub { };

Creates resolver's handler and tries to resolve C<$name> in C<$timeout>
seconds using resolver specified in F<nginx-perl.conf>.

On success returns all resolved IP addresses into C<@_>.

On error calls back with C<$!> set to some value. 

This is a thin wrapper around nginx's internal resolver.
All its current problems apply. To use it in production you'll need
a local resolver, like named that does actual resolving.

    ngx_resolver $host, $timeout, sub {
        retrun
            if $!;

        warn join(', ', @_)."\n";

        ...
    };

IMPORTANT

This wrapper is a bit too thin and currently lacks additional timer 
to cancel name resolution on timeout. This is going to be fixed 
before first official release.


=back



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


=head1 TIPS AND TRICKS

=head2 SELF-SUFFICIENT HANDLERS

It's important to know how and actually fairly easy to create 
self-sufficient reusable handlers for B<nginx-perl>.

Just remember couple of things: 

1. Use C<< $r->location_name >> as a prefix:

    location /foo/ {
        perl_handler My::handler;
    }

    sub handler {
        ...

        my $prefix =  $r->location_name;
           $prefix =~ s/\/$//;

        $out = "<a href=$prefix/something > do something </a>";
        # will result in "<a href=/foo/something > do something </a>"
        ...
    }

2. Use C<< $r->variable >> to configure handlers and to access per-server 
and per-location variables:

    location /foo/ {
        set $conf_bar "baz";
        perl_handler My::handler;
    }

    sub handler {
        ...

        my $conf_bar      = $r->variable('conf_bar');
        my $document_root = $r->variable('document_root');
        ...
    }

3. Use C<< $r->ctx >> to exchange arbitrary data between handlers:

    sub handler {
        ...

        my $ctx = { foo => 'bar' };
        $r->ctx($ctx);

        my $ctx = $r->ctx;
        ...
    }

4. Use C<perl_eval> to configure your modules directly 
from F<nginx-perl.conf>:

    http {

        perl_require  MyModule.pm;

        perl_eval  ' $My::CONF{foo} = "bar" ';
    }


    package My;

    our %CONF = ();

    sub handler {
        ...

        warn $CONF{foo};
        ...
    }


Check out F<eg/self-sufficient> to see all this in action:

    % ./objs/nginx-perl -p eg/self-sufficient


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


