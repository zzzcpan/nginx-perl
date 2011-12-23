#!/usr/bin/perl

# Copyright 2011 Alexandr Gomoliako

use strict;
use warnings;
no  warnings 'uninitialized';

# we don't have blib here
use lib 'objs/src/http/modules/perl/blib/lib', 
        'objs/src/http/modules/perl/blib/arch';

BEGIN {
    use Test::More;

    eval { require Redis::Parser::XS };
    
    diag ("$@"),
      plan skip_all => "Cannot load Redis::Parser::XS"
             if  $@;

    plan skip_all => '$Redis::Parser::XS::VERSION < 0.02'
            if  $Redis::Parser::XS::VERSION < 0.02;
}

use Data::Dumper;
use Test::More;
use Nginx::Test;
use IO::Socket;

sub CRLF { "\x0d\x0a" }

my $redis = "127.0.0.1:6379";
my $nginx = find_nginx_perl;
my $dir   = "objs/tests";


plan skip_all => "Can't find executable binary ($nginx) to test"
        if  !$nginx    ||  
            !-x $nginx    ;

wait_for_peer $redis, 1
    or  plan skip_all => "Cannot connect to redis server on $redis";

{
    my $sock = IO::Socket::INET->new ('PeerAddr' => $redis);

    print $sock "PING" . CRLF;

    local $/ = CRLF;
    local $_ = <$sock>;

    diag ("redis-server: $_"),
      plan skip_all => "Redis didn't return +PONG"
              unless  /^\+PONG/ ;

    $sock->close;
}

plan 'no_plan';


{
    my ($child, $peer) = fork_nginx_handler_die  $nginx, $dir, '',<<'    END';

        use Nginx::Redis;
        use Data::Dumper;

        sub CRLF { "\x0d\x0a" }


        sub Nginx::reply_finalize {
            my $r   = shift;
            my $buf = shift || '';

            $r->header_out ('x-errno', int ( $! ));
            $r->header_out ('x-errstr', "$!");
            $r->header_out ('Content-Length', length ( $buf ));
            $r->send_http_header ('text/html; charset=UTF-8');

            $r->print ($buf)
                    unless  $r->header_only;

            $r->send_special (NGX_HTTP_LAST);
            $r->finalize_request (NGX_OK);
        }



        sub handler {
            my ($r) = @_;

            $r->main_count_inc;


            my $tr = $r->args;
            my $rd = '127.0.0.1:6379:::' . $tr;
                        # redis supports separate connection

            if ($tr eq 'trans1') {

                ngx_redis $rd, ['WATCH', 'ngxpltest_1'], sub {
                    warn "$tr: 'WATCH', 'ngxpltest_1': " . Dumper @_;
                };


                ngx_redis $rd, ['GET', 'ngxpltest_1'], sub {
                    warn "$tr: 'GET', 'ngxpltest_1': " . Dumper @_;
                };

                ngx_redis $rd, ['MULTI'], sub {
                    warn "$tr: 'MULTI': " . Dumper @_;
                };

                ngx_redis $rd, ['SET', 'ngxpltest_1', $tr], sub {
                    warn "$tr: 'SET', 'ngxpltest_1', $tr: " . Dumper @_;
                };

                ngx_timer 1, 0, sub {

                    ngx_redis $rd, ['EXEC'], sub {
                        warn "$tr: 'EXEC': " . Dumper @_;
                    };
                };
                    
            } elsif ($r->args eq 'trans2') {

                ngx_redis $rd, ['SET', 'ngxpltest_1', $tr], sub {
                    warn "$tr: 'SET', 'ngxpltest_1', $tr: " . Dumper @_;
                };

            } elsif ($r->args eq 'trans3') {

                my $rd = '127.0.0.1:6379:::trans1'; 
                            # same connection as trans1

                ngx_redis $rd, ['APPEND', 'ngxpltest_1', $tr], sub {
                    warn "$tr: 'APPEND', 'ngxpltest_1', $tr: " . Dumper @_;
                };
            } 
            
            
            if ($r->args eq 'res') {

                ngx_redis $rd, ['GET', 'ngxpltest_1'], sub {
                    
                    my ($reply) = @_;

                    $r->reply_finalize ($reply->[1]);

                };

            } elsif ($r->args eq 'trans1wait') {

                ngx_timer 2, 0, sub {
                    $r->reply_finalize ("OK");
                };


            } else {

                $r->reply_finalize ("OK");
            }


            return NGX_DONE;
        }

    END


    wait_for_peer $peer, 2;


    http_get  $peer, '/?trans1', 2;       #  does exec after 1 second

    http_get  $peer, '/?trans2', 2;       #  sets key to trans2
                                          #  in separate connection

    # so, trans1 should fail at this point and trans2
    # should have set the key 

    http_get  $peer, '/?trans1wait', 3;   #  waiting for trans1 to finish

    my $res = http_get  $peer, '/?res', 2;

    ok $res eq 'trans2', "transaction 1 failed"
        or diag (cat_nginx_logs $dir);


    http_get  $peer, '/?trans1', 2;       #  does exec after 1 second

    http_get  $peer, '/?trans3', 2;       #  appends trans3 to the key over 
                                          #  trans1's connection

    # this should result in successful execution of both commands
    # over the same connection

    http_get  $peer, '/?trans1wait', 3;   #  waiting for trans1 to finish

    $res = http_get  $peer, '/?res', 2;

    ok $res eq 'trans1trans3', "transactions 1 and 3 succeeded"
        or diag (cat_nginx_logs $dir);


    undef $child;
}



