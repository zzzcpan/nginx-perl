package nginx;

use strict;
use warnings;

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(

    ngx_timer
    ngx_connector
    ngx_reader
    ngx_writer
    ngx_read
    ngx_write
    ngx_close
    ngx_noop

    NGX_READ
    NGX_WRITE
    NGX_CLOSE
    NGX_NOOP
    NGX_EOF
    NGX_EINVAL
    NGX_ENOMEM
    NGX_ETIMEDOUT
    NGX_EBADE
    NGX_EBADF

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

our $VERSION = '1.1.6';

require XSLoader;
XSLoader::load('nginx', $VERSION);

1;
__END__

=head1 NAME

nginx - Perl interface to the nginx HTTP server API

=head1 SYNOPSIS

  use nginx;

=head1 DESCRIPTION

This module provides a Perl interface to the nginx HTTP server API.


=head1 SEE ALSO

http://sysoev.ru/nginx/docs/http/ngx_http_perl_module.html

=head1 AUTHOR

Igor Sysoev

=head1 COPYRIGHT AND LICENSE

Copyright (C) Igor Sysoev


=cut
