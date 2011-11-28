package Redis::Nginx;

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

require Exporter;
our @ISA     = qw(Exporter);
our @EXPORT  = qw(redis_client redis);
our $VERSION = '1.1.6.1';

use Nginx;
use Redis::Parser::XS;


sub CRLF { "\x0d\x0a" }


sub redis_client {
    my ($ip, $port, $timeout) = @_;

    my ($error,  # push needs it
        $c, @output, @active, @queue);
    my $buf = '';


    my $push = sub {

        return 0
            if  @active != 0  ||   #  sending something right now  or
                @queue  == 0  ||   #  nothing to send  or
                !defined $c;       #  not connected yet

        @active = @queue;
        @queue = ();

        &$error(),
            return 0
                if  $c == -1;      #  connection failed long ago
                
        $buf = 
            join ('', 
                map {                                     #
                    '*' . scalar(@{$_->[0]}) . CRLF .     #   *1    CRLF
                    join ('',                             #
                        map {                             #
                            '$' . length($_) . CRLF .     #   $3    CRLF
                                  $_         . CRLF       #   foo   CRLF
                        } @{$_->[0]}                      #   ...
                    )                                     #
                } @active
            );


        return 1;
    };


    $error = sub {  

        $c = -1;    #  marking connection as failed

        for my $i (0 .. $#active) {
            my $cb = $active [$i]->[1];
            &$cb ( $output [$i] );
        }

        @output = ();
        @active = ();

        foreach (@queue) {
            my $cb = $_->[1];
            &$cb ();
        }

        @queue = ();
        
        ngx_log_error $!, "redis error";  
    };


    my $enqueue = sub {
        push @queue, \@_;

        &$push()  &&
            ngx_write ($c);
    };


    ngx_connector $ip, $port, $timeout, sub {

        &$error(),
            return NGX_CLOSE
                if  $!;

        $c = shift;


        ngx_writer $c, $buf, $timeout, sub {

            &$error(),
                return NGX_CLOSE
                    if  $!;

            $buf = '';

            return NGX_READ;
        };


        ngx_reader $c, $buf, 0, 0, $timeout, sub {

            &$error(),
                return NGX_CLOSE
                    if  $!;

            my $len = parse_redis $buf, \@output;

            &$error(),
                return NGX_CLOSE
                    if  !defined $len;

            $buf = substr $buf, $len;

            return NGX_READ
                if  @output != @active;

            $buf = '';

            for my $i (0 .. $#active) {
                my $cb = $active [$i]->[1];
                &$cb ($output [$i]);
            }

            @output = ();
            @active = ();

            &$push()  &&
                return NGX_WRITE;

            return NGX_NOOP;
        };


        &$push()  &&
            return NGX_WRITE;

        return NGX_NOOP;
    };


    return $enqueue;
}


sub redis {
    my $self = shift;

    &$self;
}


1;
