package Nginx::Util;

use strict;
use warnings;
no  warnings 'uninitialized';

require Exporter;
our @ISA       = qw(Exporter);
our @EXPORT    = qw(ngx_http_req ngx_pure_http_req);
our $VERSION   = '1.1.9.1';

use Nginx;

our $RESPONSE_LIMIT   = 4 * 1048576;
our $MAX_CONN_PER_IP  = 8;
our $MAX_QUEUE_PER_IP = 64;

my  %CONN_PER_IP;

#
# %CONN_PER_IP = ( 
#
#     '1.2.3.4' => [  
#                     123,  # counter
#                     [ 
#                        # queue
#
#                        [ IP, PORT, REQ_REF, RESP_REF, TIMEOUT, CB ], 
#                        [ IP, PORT, REQ_REF, RESP_REF, TIMEOUT, CB ], 
#                        ... 
#                     ] 
#                  ],
#      ...  
# )
#


sub ngx_pure_http_req ($$\$\$$&);
sub ngx_http_req      ($$\$\$$&);


sub ngx_pure_http_req ($$\$\$$&) {
    my ($ip, $port, $req_ref, $resp_ref, $timeout, $cb) = @_;

    ngx_connector $ip, $port, $timeout, sub {

        &$cb(), 
        return NGX_CLOSE  
            if $!;

        my $c = shift;

        ngx_writer $c, $$req_ref, $timeout, sub {

            &$cb(), 
            return NGX_CLOSE  
                if $!;

            $$resp_ref = '';

            return NGX_READ;
        };

        ngx_reader $c, $$resp_ref, 0, 4000, $timeout, sub {

            &$cb(), 
            return NGX_CLOSE  
                if $!;
            
            return NGX_READ 
                if $$resp_ref !~ / \x0d?\x0a \x0d?\x0a /x;

            my %h;

            @{h}{'_version', '_status', '_message'} = 
                 $$resp_ref =~ / 
                    ^ \s*  ( HTTP\/\d\.\d )  
                      \s+  ( \d+ )  
                      \s*  ( [^\x0d\x0a]+ )  
                      \x0d?\x0a 
                   /gcx;

            push @{$h{ lc($1) }}, $2
                while 
                    $$resp_ref =~ / 
                      \G  \s*  ( [a-zA-Z][\w-]+ ) 
                          \s*   : 
                          \s*  ( [^\x0d\x0a]+ ) 
                          \x0d?\x0a 
                      /gcx;

            $$resp_ref =~ / \G \x0d?\x0a /gcx;
            $$resp_ref = substr $$resp_ref, pos($$resp_ref);

            my $len = $h{'content-length'}->[0];
               $len = $RESPONSE_LIMIT  if $len > $RESPONSE_LIMIT;

            &$cb(\%h),
            return NGX_CLOSE
                if $len && length($$resp_ref) == $len;

            ngx_reader $c, $$resp_ref, $len, $len, $timeout, sub {

                return NGX_READ
                    if !$len && !$! && length($$resp_ref) < $RESPONSE_LIMIT;

                $! = 0
                    if $! == NGX_EOF && !$len;

                &$cb(\%h),
                return NGX_CLOSE;
            };

            return NGX_READ;
        };

        return NGX_WRITE;
    };
}


sub ngx_http_req ($$\$\$$&) {
    my ($ip, $port, $req_ref, $resp_ref, $timeout, $cb) = @_;

    if ( $CONN_PER_IP{$ip}->[0] >= $MAX_CONN_PER_IP ) {

        if ( $CONN_PER_IP{$ip}->[1] && 
                 @{ $CONN_PER_IP{$ip}->[1] } >= $MAX_QUEUE_PER_IP ) {
            $! = NGX_EAGAIN;
            &$cb();
        } else {  
            push @{ $CONN_PER_IP{$ip}->[1] }, \@_;
        }

        return;
    }


    $CONN_PER_IP{$ip}->[0]++;  

    ngx_pure_http_req $ip, $port, $$req_ref, $$resp_ref, $timeout, sub {

        &$cb;

        $CONN_PER_IP{$ip}->[0]--;  


        my $next_req = shift @{ $CONN_PER_IP{$ip}->[1] };

        return 
            if !$next_req || @$next_req == 0;


        my ($ip, $port, $req_ref, $resp_ref, $timeout, $newcb) = @$next_req;

        ngx_http_req($ip, $port, $$req_ref, $$resp_ref, $timeout, \&$newcb);
    };


    return;
}


1;
__END__

=head1 NAME

Nginx::Util - utility functions 

=head1 SYNOPSIS

    use Nginx::Util;

    my $wbuf = '';
    my $rbuf = "GET /shouldnotbethere HTTP/1.0\x0d\x0a".
               "Host: www.google.com\x0d\x0a".
               "Connection: close\x0d\x0a".
               "\x0d\x0a";

    ngx_http_req '209.85.148.104', 80, $rbuf, $wbuf, 5, sub {
        my $http_headers = shift;

        if ($! && $! != NGX_EOF) {
            ...
        }

        if ($http_headers->{'_status'} ... ) {
            ...
        }

        if ($http_headers->{'content-type'}->[0] ... ) {
            ...
        }
    };


=head1 DESCRIPTION

Just a few useful functions to quickly start using
asynchronous model.

=head1 EXPORT

    ngx_http_req
    ngx_pure_http_req

=head1 FUNCTIONS

=over 4

=item ngx_http_req $ip, $port, $reqbuf, $respbuf, $timeout, sub { };

Connects to C<$ip:$port>, sends http request from C<$reqbuf>, 
parses response header and reads an entire body into C<$respbuf>. 
Calls back with parsed response in C<$_[0]> in this form:

    {  _status        => 200,
       _message       => 'OK',
       _version       => 'HTTP/1.0',
       content-type   => ['text/html'],
       content-length => [1234]          }

On errors calls back without any arguments. You may also check $!
when error occurs. 

Example:

    my $buf = "GET /shouldnotbethere HTTP/1.0\x0d\x0a".
              "Host: www.google.com\x0d\x0a".
              "Connection: close\x0d\x0a".
              "\x0d\x0a";

    ngx_http_req '209.85.148.104', 80, $buf, $buf, 15, sub {
        my $h    = shift;
        my $dump = Dumper($h);

        warn "$!\n$dump\n$buf\n\n\n";
    };


=item ngx_pure_http_req $ip, $port, $reqbuf, $respbuf, $timeout, sub { };

Same as C<ngx_http_req> but without any queueing. To use for healthcheck 
or things like that.

=back

=head1 AUTHOR

Alexandr Gomoliako <zzz@zzz.org.ua>

=head1 LICENSE

Copyright 2011 Alexandr Gomoliako. All rights reserved.

This module is free software. It may be used, redistributed and/or modified 
under the same terms as B<nginx> itself.

=cut

