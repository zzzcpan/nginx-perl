package Nginx::Test;

use strict;
use warnings;
no  warnings 'uninitialized';

require Exporter;
our @ISA       = qw(Exporter);
our $VERSION   = '1.1.9.1';
our @EXPORT    = qw( 

    find_nginx_perl
    get_unused_port 
    wait_for_peer 
    prepare_nginx_dir_die
    cat_nginx_logs
    get_nginx_conf_args_die
    fork_nginx_die
    fork_child_die
    http_get
    fork_nginx_handler_die

);

use Config;
use IO::Socket;

sub CRLF { "\x0d\x0a" }

$Nginx::Test::PARENT = 1;


sub find_nginx_perl () {

    foreach ( './objs/nginx-perl',
              "$Config{'scriptdir'}/nginx-perl",
              "$Config{'sitescript'}/nginx-perl",
              "$Config{'vendorscript'}/nginx-perl",
              "$Config{'installscript'}/nginx-perl",
              "$Config{'installsitescript'}/nginx-perl",
              "$Config{'installvendorscript'}/nginx-perl",
              '/usr/local/nginx-perl/sbin/nginx-perl'      ) {

        return $_ 
              if  -f $_ && 
                  -x $_;
    }
}


sub get_unused_port () {
    my $port = 50000 + int (rand() * 5000);

    while ($port++ < 64000) {
        my $sock = IO::Socket::INET->new ( Listen    => 5,
                                           LocalAddr => '127.0.0.1',
                                           LocalPort => $port,
                                           Proto     => 'tcp',
                                           ReuseAddr => 1            )
                or next;

        $sock->close;
        return $port;
    }

    return undef;
}


sub wait_for_peer ($$) {
    my ($peer, $timeout) = @_;
    my $rv;

    eval {
        local $SIG{'ALRM'} = sub {  die "timedout\n";  };

        alarm $timeout;

        for (1 .. $timeout * 10) {
            my $sock = IO::Socket::INET->new ( Proto    => 'tcp',
                                               PeerAddr => "$peer" );
            unless ($sock) {
                select ('','','', 0.1);
                next;
            }

            $rv = 1;

            $sock->close;

            alarm 0;
            last;
        }
    };

    alarm 0;

    return $rv;
}


sub prepare_nginx_dir_die {
    my ($dir, $conf, @pkgs) = @_;

    if (!-e $dir) {
        mkdir "$dir"
            or die "Cannot create directory '$dir': $!";
        mkdir "$dir/conf"
            or die "Cannot create directory '$dir/conf': $!";
        mkdir "$dir/lib"
            or die "Cannot create directory '$dir/lib': $!";
        mkdir "$dir/logs"
            or die "Cannot create directory '$dir/logs': $!";
    }

    foreach ( "$dir/lib", 
              "$dir/logs" ) {

        open my $fh, '>', "$_/.exists"
            or die "Cannot open file '$_/.exists' for writing: $!";
        close $fh;
    }

    {
        opendir my $d, "$dir/logs"
            or die "Cannot opendir '$dir/logs': $!";

        my @FILES = grep { $_ ne '.' && $_ ne '..' && $_ ne '.exists' && 
                            -f "$dir/logs/$_" } 
                      readdir $d;
        closedir $d;

        foreach (@FILES) {
            unlink "$dir/logs/$_";
        }
    }

    {
        open my $fh, '>', "$dir/conf/nginx-perl.conf"
            or die "Cannot open file '$dir/conf/nginx-perl.conf' " .
                   "for writing: $!";

        print $fh $conf;

        close $fh;
    }

    foreach (@pkgs) {

        my ($pkg) = /  ^  \s*  package  \s+  ( [^\s]+ )  \;  /sx;

        my @path = split '::', $pkg;
        my $name = pop @path;
        my $fullpath = "$dir/lib";

        foreach my $subdir (@path) {
            $fullpath .= "/" . $subdir;

            mkdir $fullpath  unless  -e $fullpath;
        }

        open my $fh, '>', "$fullpath/$name.pm"
            or die "Cannot open file '$fullpath/$name.pm' for writing: $!";

        print $fh $_;

        close $fh;
    }
}


sub cat_nginx_logs ($) {
    my ($dir) = @_;
    my $out;

    opendir my $d, "$dir/logs"
        or return undef;

    my @FILES = grep { $_ ne '.' && $_ ne '..' && $_ ne '.exists' && 
                        -f "$dir/logs/$_" } 
                  readdir $d;
    closedir $d;

    foreach (@FILES) {

        my $buf = do { open my $fh, '<', "$dir/logs/$_"; local $/; <$fh> };

        $out .= <<"        EOF";

$dir/logs/$_:
------------------------------------------------------------------
$buf
------------------------------------------------------------------


        EOF
    }

    return $out;
}


sub fork_nginx_die ($$) {
    my ($nginx, $path) = @_;
    my $pid = fork();

    die "failed to fork()" 
            if  !defined $pid;

    if ($pid == 0) {
        $Nginx::Test::PARENT = 0;

        open STDOUT, '>', "$path/logs/stdout.log"
            or die "Cannot open file '$path/logs/stdout.log' for writing: $!";

        open STDERR, '>', "$path/logs/stderr.log"
            or die "Cannot open file '$path/logs/stderr.log' for writing: $!";

        exec $nginx, '-p', $path
            or die "exec '$nginx -p $path' failed\n";
    } 

    return Nginx::Test::Child->new ($pid);
}


sub fork_child_die (&) {
    my ($cb) = @_;
    my $pid = fork();

    die "failed to fork()" 
            if  !defined $pid;

    if ($pid == 0) {
        $Nginx::Test::PARENT = 0;

        &$cb;
        exit;
    } 

    return Nginx::Test::Child->new ($pid);
}


sub get_nginx_conf_args_die ($) {
    my ($nginx) = @_;

    return  map {  $_ => 1  }
              grep {  /^--with/  }
                map {  split ' ', (split ':')[1]  }  
                  grep {  /arguments/i  } 
                     do {  open my $fh, '-|', "$nginx -V 2>&1"
                               or die "Can't open '$nginx -V 2>&1 |': $!";
                           <$fh>                                           } ;
}


sub http_get ($$$) {
    my ($peer, $uri, $timeout) = @_;
    my %h;
    local $_;

    eval {
        local $SIG{'ALRM'} = sub {  die "timedout\n";  };

        alarm $timeout;

        my $sock = IO::Socket::INET->new ( Proto    => 'tcp',
                                           PeerAddr => $peer  )
                or die "$!\n";

        print $sock  "GET $uri HTTP/1.0"     . CRLF .
                     "Host: $peer"           . CRLF .
                                               CRLF  ;
        local $/;
        $_ = <$sock>;

        $sock->close;


        # parsing HTTP response

        @{h}{'_version', '_status', '_message'} = 
             /  ^ \s*  ( HTTP\/\d\.\d )  
                  \s+  ( \d+ )  
                  \s*  ( [^\x0d\x0a]+ )  
                  \x0d?\x0a               /gcx;

        push @{$h{ lc($1) }}, $2
            while 
              /   \G  \s*  ( [a-zA-Z][\w-]+ ) 
                      \s*   : 
                      \s*  ( [^\x0d\x0a]+ ) 
                      \x0d?\x0a                 /gcx;

        / \G \x0d?\x0a /gcx;

        $_ = substr $_, pos($_);

    };

    alarm 0;

    return wantarray  ? $@  ? () 
                            : ($_, \%h) 
                      : $_;
}


sub fork_nginx_handler_die ($$$$) {
    my ($nginx, $path, $conf, $code) = @_;

    my $port = get_unused_port;

    prepare_nginx_dir_die $path, <<"    ENDCONF", <<"    ENDPKG";

        worker_processes  1;
        daemon            off;
        master_process    off;

        error_log  logs/error.log  debug;

        events {  
            worker_connections  128;  
        }

        http {
            default_type  text/plain;

            perl_inc  ../../objs/src/http/modules/perl/blib/lib;
            perl_inc  ../../objs/src/http/modules/perl/blib/arch;

            perl_inc  lib;
            perl_inc  ../lib;

            perl_require  NginxPerlTest.pm;

$conf

            server {
                listen  127.0.0.1:$port;

                location / {
                    perl_handler  NginxPerlTest::handler;
                }
            }
        }

    ENDCONF

        package NginxPerlTest;

        use strict;
        use warnings;
        no  warnings 'uninitialized';

        use Nginx;

$code

        1;

    ENDPKG

    my $pid = fork_nginx_die $nginx, $path;
    my $peer = "127.0.0.1:$port";

    return ($pid, $peer);
}


1;
package Nginx::Test::Child;


sub new {
    my $class = shift;
    my $pid   = shift;
    my $self  = \$pid;

    bless $self, $class;
}


sub terminate {
    my $self = shift;

    if ($$self && $Nginx::Test::PARENT) {
        kill 'TERM', $$self;
        $$self = 0;
        wait;
    }
}


sub DESTROY {
    my $self = shift;

    if ($$self && $Nginx::Test::PARENT) {
        kill 'TERM', $$self;
        $$self = 0;
        wait;
    }
}

1;
__END__

=head1 NAME

Nginx::Test - simple framework for writing tests for nginx-perl and nginx

=head1 SYNOPSIS

    use Nginx::Test;
    

    
=head1 DESCRIPTION





=head1 EXPORT

    find_nginx_perl
    get_unused_port 
    wait_for_peer 
    prepare_nginx_dir_die
    cat_nginx_logs
    get_nginx_conf_args_die
    fork_nginx_die
    quit_nginx
    fork_child_die
    quit_child
    http_get

=head1 FUNCTIONS

=over 4

=item prepare_nginx_dir_die $path, $conf, $package1, $package2, ...

Create directory tree suitable for nginx-perl, put there config
and packages specified as string scalars.

Example:

    prepare_nginx_dir_die "tmp/foo", <<'ENDCONF', <<'ENDONETWO';
    
        worker_processes  1;
        events {  
            worker_connections  1024;  
        }
        http {
            server {
                location / {
                    ...
                }
            }
        }
     
    ENDCONF
    
        package One::Two;
        
        sub handler {
            ...
        }
        
        1;
    
    ENDONETWO

=back

=head1 AUTHOR

Alexandr Gomoliako <zzz@zzz.org.ua>

=head1 LICENSE

Copyright 2011 Alexandr Gomoliako. All rights reserved.

This module is free software. It may be used, redistributed and/or modified 
under the same terms as B<nginx> itself.

=cut

