package Nginx::Test;

use strict;
use warnings;
no  warnings 'uninitialized';

our $VERSION   = '1.1.18.1';

require Exporter;
our @ISA       = qw(Exporter);
our @EXPORT    = qw( 

    find_nginx_perl
    get_nginx_conf_args_die
    get_unused_port 
    wait_for_peer 
    prepare_nginx_dir_die
    cat_nginx_logs
    fork_nginx_die
    fork_child_die
    http_get
    get_nginx_incs
    fork_nginx_handler_die

);

use Config;
use IO::Socket;

sub CRLF { "\x0d\x0a" }

$Nginx::Test::PARENT = 1;


sub find_nginx_perl () {

    foreach ( './objs/nginx-perl' ) {

        return $_ 
              if  -f $_ && 
                  -x $_;
    }


    # Assuming @INC contains .../Nginx-Perl-N.N.N.N/blib/lib
    # it might have objs/nginx-perl there somewhere

    foreach my $inc ( @INC ) {

        local $_ = $inc;

        s!/+blib/+lib/*$!!;
        s!/+blib/+arch/*$!!;

        if ( -f "$_/objs/nginx-perl" &&
             -x "$_/objs/nginx-perl"    ) {

            my $x = "$_/objs/nginx-perl";

            $x = "./$x"  unless $x =~ m!^/|^\./!; 

            return $x;
        }
    }


    foreach ( "$Config{'scriptdir'}/nginx-perl",
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

    return undef;
}


sub get_unused_port () {
    my $port = 50000 + int (rand() * 5000);

    while ($port++ < 64000) {
        my $sock = IO::Socket::INET->new ( 
            Listen    => 5,
            LocalAddr => '127.0.0.1',
            LocalPort => $port,
            Proto     => 'tcp',
            ReuseAddr => 1
        ) or next;

        $sock->close;
        return $port;
    }

    return undef;
}


sub wait_for_peer ($$) {
    my ($peer, $timeout) = @_;
    my $rv;
    my $at = time + $timeout;

    eval {
        local $SIG{'ALRM'} = sub {  die "SIGALRM\n";  };

        for (my $t = time ; $at - $t > 0; $t = time) {
            alarm $at - $t;

            my $sock = IO::Socket::INET->new ( Proto     => 'tcp',
                                               PeerAddr  => "$peer",
                                               ReuseAddr => 1        );
            alarm 0;

            unless ($sock) {
                select ('','','', 0.1);
                next;
            }

            $rv = 1;
            $sock->close;

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


sub get_nginx_incs ($$) {
    my ($nginx, $path) = @_;
    my $prefix = '';

    if ($path !~ m!^/!) {
        $path =~ s!/+$!!;
        $prefix = join '/', map { '..' } split /\/+/, $path;
    }
    
    return map {  m!^/! ? $_ : "$prefix/$_"  } 
             ('blib/lib', 'blib/arch', @INC);
}


sub fork_nginx_handler_die ($$$$) {
    my ($nginx, $path, $conf, $code) = @_;

    my $port = get_unused_port
        or die "Cannot get unused port";

    my $incs = join "\n", 
                 map { "perl_inc \"$_\";" } 
                   get_nginx_incs ($nginx, $path);

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

$incs

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

        select '','','', 0.1;
    }
}


sub DESTROY {
    my $self = shift;

    if ($$self && $Nginx::Test::PARENT) {
        kill 'TERM', $$self;
        $$self = 0;
        wait;

        select '','','', 0.1;
    }
}

1;
__END__

=head1 NAME

Nginx::Test - simple framework for writing tests for nginx-perl and nginx

=head1 SYNOPSIS

    use Nginx::Test;
     
    my $nginx = find_nginx_perl;
    my $dir   = 'tmp/test';
    
    my ($child, $peer) = 
        fork_nginx_handler_die  $nginx, $dir, '', <<'END';
        
        sub handler {
            my $r = shift;
            ...
             
            return OK;
        }
        
    END
    
    wait_for_peer $peer, 2
        or die "peer never started\n";
    
    my ($body, $headers) = http_get $peer, "/", 2;
    ...
    
=head1 DESCRIPTION

Making sure testing isn't a nightmare. 

This module provides some basic functions to find nginx-perl, prepare
configuration, generate handler, start in a child process, query it and
get something back. And it comes with Nginx::Perl. You can simply add it
as a dependency for you module and use.

=head1 EXPORT

    find_nginx_perl
    get_nginx_conf_args_die
    get_unused_port 
    wait_for_peer 
    prepare_nginx_dir_die
    cat_nginx_logs
    fork_nginx_die
    fork_child_die
    fork_nginx_handler_die
    http_get

=head1 FUNCTIONS

=head3 C<< $nginx = find_nginx_perl (); >>

Finds executable F<nginx-perl> binary to run. Returns C<undef> if
can't find any or executable path otherwise. 

    $nginx = './objs/nginx-perl'

=head3 C<< %CONFARGS = get_nginx_conf_args_dir $nginx; >>

Runs C<nginx-perl -V> and parses its output to produce set
of keys out of the list of configure arguments:

    %CONFARGS = ( '--with-http_ssl_module' => 1,
                  '--with-...'             => 1  )

=head3 C<< $port = get_unused_port (); >>

Gives you available port number to bind to. Tries to use it first.
Returns undef on error.

=head3 C<< $rv = wait_for_peer "$host:$port", $timeout; >>

Tries to connect to C<$host:$port> within C<$timeout> seconds. Returns C<1>
on success and C<undef> on error.

    wait_for_peer "127.0.0.1:1234", 2
        or ...;

=head3 C<< prepare_nginx_dir_die $dir, $conf, $package1, $package2, ...; >>

Creates directory tree suitable to run F<nginx-perl> from. Puts there 
config and packages specified as string scalars. Dies on errors.

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

=head3 C<< $text = cat_nginx_logs $dir; >>

Scans C<$dir> for logs and concatenates them into a single scalar.
Useful for diagnostics.

    prepate_nginx_dir_dir $dir, ... 
    ...
    
    ok $foo, "bar", "foo is bar"
        or diag cat_nginx_logs $dir;

=head3 C<< $child = fork_nginx_die $nginx, $dir; >>

Forks F<nginx-perl> using executable binary from C<$nginx> and 
prepared directory path from C<$dir>. Dies on errors.
Internally does something like this: C<"$nginx -p $dir">

    my $child = fork_nginx_die $nginx, $dir;
    ...
     
    undef $child;

=head3 C<< $child = fork_child_die sub { ... }; >>

Forks sub in a child process. Dies on errors.

    my $child = fork_child_die sub {
        ...
         
        sleep 5;  
    };
    ...
     
    undef $child;

=head3 C<< @incs = get_nginx_incs $nginx, $dir; >>

Generates proper C<@INC> to use in F<nginx-perl.conf> during tests.

=head3 C<< ($child, $peer) = fork_nginx_handler_dir $nginx, $dir, $conf, $code; >>

Gets unused port, prepares directory for nginx with predefined 
package name, forks nginx and gives you child object and peer back.
Allows to inject C<$conf> into config and C<$code> into the package.
Expects to have C<sub handler { ... }> in the code. Dies on errors.

    my ($child, $peer) = 
        fork_nginx_handler_die $nginx, $dir, <<'ENDCONF', <<'ENDCODE';
        
        resolver 8.8.8.8;
        
    ENDCONF

        sub handler {
            my ($r) = @_;
            ...
            
            return OK;
        }
        
    ENDCODE
    
    ...
     
    undef $child; 

Be aware that this function is not suited for every module. It expects 
C<$dir> to be relative to the current directory or any of its subdirectories,
i.e. F<foo>, F<foo/bar>. And also expects F<blib/lib> and F<blib/arch>
to contain your libraries, which is where L<ExtUtils::MakeMaker> puts them.

=head3 C<< ($body, $headers) = http_get $peer, $uri, $timeout; >>

Connects to C<$peer>, sends GET request and return C<$body> and C<$headers>.

    my ($body, $headers) = http_get '127.0.0.1:1234', '/', 2;
    
    $headers = {  _status        => 200,
                  _message       => 'OK',
                  _version       => 'HTTP/1.0',
                  content-type   => ['text/html'],
                  content-length => [1234],
                  ...                               }

=head1 AUTHOR

Alexandr Gomoliako <zzz@zzz.org.ua>

=head1 LICENSE

Copyright 2011 Alexandr Gomoliako. All rights reserved.

This module is free software. It may be used, redistributed and/or modified 
under the same terms as B<nginx> itself.

=cut

