package Nginx::Util;


=head1 NAME

Nginx::Util - utility functions 

=head1 SYNOPSIS

    use Data::Dumper;

    use Nginx::Util qw(http_req);
    use nginx;

    sub handler {
        my $r = shift;

        $r->discard_request_body;
        $r->main_count_inc;

        my $buf = "GET /shouldnotbethere HTTP/1.0\x0d\x0a".
                  "Host: www.google.com\x0d\x0a".
                  "Connection: close\x0d\x0a".
                  "\x0d\x0a";

        http_req '209.85.148.104', 80, $buf, 5, sub {
            my $h    = shift;
            my $dump = Dumper($h);

            $r->send_http_header("text/plain");
            $r->print("$!\n$dump\n$buf\n\n\n");

            $r->send_special(NGX_HTTP_LAST);
            $r->finalize_request(NGX_OK);
        };

        return NGX_DONE;
    }


=head1 DESCRIPTION

Just a few useful functions to quickly start using
asynchronous model.

=head1 EXPORT

This module doesn't export anything by default.

=head1 FUNCTIONS

=over 4

=cut

use strict;
use warnings;
no  warnings 'uninitialized';

require Exporter;
our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(http_req);
our $VERSION   = '1.1.6.1';

use Nginx;


=item http_req $ip, $port, $buf, $timeout, sub { my $r = shift; };

Connects to C<$ip:$port>, sends http request from C<$buf>, 
parses response header and reads an entire body into C<$buf>. 
Calls back with parsed response in C<$_[0]> in the following 
form:

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

    http_req '209.85.148.104', 80, $buf, sub {
        my $h    = shift;
        my $dump = Dumper($h);

        warn "$!\n$dump\n$buf\n\n\n";
    };

=cut

sub http_req ($$\$$&) {
    my ($ip, $port, $buf_ref, $timeout, $cb) = @_;

    ngx_connector $ip, $port, $timeout, sub {

        &$cb(), 
        return NGX_CLOSE  
            if $!;

        my $c = shift;

        ngx_writer $c, $$buf_ref, $timeout, sub {

            &$cb(), 
            return NGX_CLOSE  
                if $!;

            $$buf_ref = '';

            return NGX_READ;
        };

        ngx_reader $c, $$buf_ref, 0, 2000, $timeout, sub {

            &$cb(), 
            return NGX_CLOSE  
                if $!;
            
            return NGX_READ 
                if $$buf_ref !~ / \x0d?\x0a \x0d?\x0a /x;

            my %h;

            ($h{_version}, 
             $h{_status}, 
             $h{_message}) = 
                 $$buf_ref =~ / 
                    ^ \s*  ( HTTP\/\d\.\d )  
                      \s+  ( \d+ )  
                      \s*  ( [^\x0d\x0a]+ )  
                      \x0d?\x0a 
                   /gcx;

            push @{$h{ lc($1) }}, $2
                while 
                    $$buf_ref =~ / 
                      \G  \s*  ( [a-zA-Z][\w-]+ ) 
                          \s*   : 
                          \s*  ( [^\x0d\x0a]+ ) 
                          \x0d?\x0a 
                      /gcx;

            $$buf_ref =~ / \G \x0d?\x0a /gcx;
            $$buf_ref = substr $$buf_ref, pos($$buf_ref);

            my $len = $h{'content-length'}->[0];

            ngx_reader $c, $$buf_ref, $len, $len, $timeout, sub {

                &$cb(\%h), 
                return NGX_CLOSE  
                    if $!;

                return NGX_READ  
                    if !$len;

                &$cb(\%h), return NGX_CLOSE;
            };

            return NGX_READ;
        };

        return NGX_WRITE;
    };
}





=back

=head1 AUTHOR

Alexandr Gomoliako <zzz@zzz.org.ua>

=head1 LICENSE

Copyright 2011 Alexandr Gomoliako. All rights reserved.

This module is free software. It may be used, redistributed and/or modified 
under the same terms as B<nginx> itself.

=cut

1;
