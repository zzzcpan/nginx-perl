package Nginx::Test;

our $VERSION = '1.2.6.6';


=head1 NAME

Nginx::Test - testing framework for nginx-perl and nginx

=head1 SYNOPSIS

    use Nginx::Test;
     
    my $nginx = find_nginx_perl;
    my $dir   = make_path 'tmp/test';
    
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

=cut

use strict;
use warnings;
no  warnings 'uninitialized';
use bytes;

use Config;
use IO::Socket;
use File::Path qw(rmtree);
sub CRLF { "\x0d\x0a" }


=head1 EXPORT

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
    eval_wait_sub
    connect_peer
    send_data
    parse_http_request
    parse_http_response
    inject_content_length
    read_http_response
    make_path
    cat_logs

=cut

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
    eval_wait_sub
    connect_peer
    send_data
    parse_http_request
    parse_http_response
    inject_content_length
    read_http_response
    make_path
    cat_logs

);


=head1 FUNCTIONS

=head2 find_nginx_perl

Finds executable binary for F<nginx-perl>. Returns executable path
or C<undef> if not found.

    my $nginx = find_nginx_perl
        or die "Cannot find nginx-perl\n";
    
    # $nginx = './objs/nginx-perl'

=cut

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


=head2 get_unused_port

Returns available port number to bind to. Tries to use it first and returns
C<undef> if fails.

    $port = get_unused_port
        or die "No unused ports\n";

=cut

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


=head2 wait_for_peer C<< "$host:$port", $timeout >>

Tries to connect to C<$host:$port> within C<$timeout> seconds. Returns C<1>
on success and C<undef> on error.

    wait_for_peer "127.0.0.1:1234", 2
        or die "Failed to connect to 127.0.0.1:1234 within 2 seconds";

=cut

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


=head2 prepare_nginx_dir_die C<< $dir, $conf, @pkgs >>

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

=cut

sub prepare_nginx_dir_die {
    my ($dir, $conf, @pkgs) = @_;

    foreach ("$dir/html", "$dir/data") {
        if (-e $_) {
            rmtree $_, 0, 0;
        }
    }

    foreach ("$dir", 
             "$dir/conf", 
             "$dir/lib", 
             "$dir/logs", 
             "$dir/html", 
             "$dir/data") {
        if (!-e $_) {
            mkdir $_
                or die "Cannot create directory '$_': $!";
        }
    }

    foreach ( "$dir/lib", 
              "$dir/logs" ) {

        open my $fh, '>', "$_/.exists"
            or die "Cannot open file '$_/.exists' for writing: $!";
        close $fh;
    }

    {
        open my $fh, '>', "$dir/html/index.html"
            or die "Cannot open file '$dir/html/index.html' for writing: $!";
        binmode $fh;
        print $fh "ok";
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
        my $incs = join "\n", 
                     map { "perl_modules \"$_\";" } 
                       get_nginx_incs (undef, $dir);
          # injecting proper @INC
        $conf =~ s/(\s+http\s*{)/$1\n$incs\n/gs;

          # injecting testing defaults
        if ($conf !~ /events/) {
            $conf = "events { worker_connections 128; }\n$conf";
        }
        if ($conf !~ /error_log/) {
            $conf = "error_log logs/error.log debug;\n$conf";
        }
        if ($conf !~ /master_process/) {
            $conf = "master_process off;\n$conf";
        }
        if ($conf !~ /daemon/) {
            $conf = "daemon off;\n$conf";
        }
        if ($conf !~ /worker_processes/) {
            $conf = "worker_processes 1;\n$conf";
        }

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


=head2 cat_nginx_logs C<< $dir >>

Returns all logs from C<$dir.'/logs'> as a single scalar. Useful for 
diagnostics.

    diag cat_nginx_logs $dir;

=cut

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


=head2 fork_nginx_die C<< $nginx, $dir >>

Forks F<nginx-perl> using executable binary from C<$nginx> and 
prepared directory path from C<$dir> and returns guard object. 
Dies on errors. Internally does something like this: C<"$nginx -p $dir">

    my $child = fork_nginx_die $nginx, $dir;
    ...
     
    undef $child;

=cut

{
    package Nginx::Test::Child;

    sub new {
        my $class = shift;
        my $pid   = shift;
        my $self  = \$pid;

        bless $self, $class;
    }

    sub terminate {
        my $self = shift;

        unless ($Nginx::Test::Child::IS_CHILD) {
            if ($$self) {
                kill 'TERM', $$self;  $$self = 0; 
                wait;
                select '','','', 0.1;
            }
        }
    }

    sub DESTROY { my $self = shift; $self->terminate; }
}

sub fork_nginx_die ($$) {
    my ($nginx, $path) = @_;
    my $pid = fork();

    die "failed to fork()" 
            if  !defined $pid;

    if ($pid == 0) {
        $Nginx::Test::Child::IS_CHILD = 1;

        open STDOUT, '>', "$path/logs/stdout.log"
            or die "Cannot open file '$path/logs/stdout.log' for writing: $!";

        open STDERR, '>', "$path/logs/stderr.log"
            or die "Cannot open file '$path/logs/stderr.log' for writing: $!";

        exec $nginx, '-p', $path
            or die "exec '$nginx -p $path' failed\n";
    } 

    return Nginx::Test::Child->new ($pid);
}


=head2 fork_child_die C<< sub {} >>

Forks sub in a child process and returns its guard object. Dies on errors.

    my $child = fork_child_die sub {
        ...
        sleep 5;  
    };
     
    undef $child;

=cut

sub fork_child_die (&) {
    my ($cb) = @_;
    my $pid = fork();

    die "failed to fork()" 
            if  !defined $pid;

    if ($pid == 0) {
        $Nginx::Test::Child::IS_CHILD = 1;

        &$cb;
        exit;
    } 

    return Nginx::Test::Child->new ($pid);
}

=head2 get_nginx_conf_args_dir C<< $nginx >>

Runs C<nginx-perl -V>, parses its output and returns a set of keys 
out of the list of configure arguments. 

    my %CONFARGS = get_nginx_conf_args_dir;
    
    # %CONFARGS = ( '--with-http_ssl_module' => 1,
    #               '--with-...'             => 1  )

=cut

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


=head2 http_get C<< $peer, $uri, $timeout >>

Connects to C<$peer>, sends GET request and return its C<$body> and 
parsed C<$headers>.

    my ($body, $headers) = http_get '127.0.0.1:1234', '/', 2;
    
    $headers = {  _status          => 200,
                  _message         => 'OK',
                  _version         => 'HTTP/1.0',
                  'content-type'   => ['text/html'],
                  'content-length' => [1234],
                  ...                               }

=cut

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
             m/  ^ \s*  ( HTTP\/\d\.\d )  
                   \s+  ( \d+ )  
                   \s*  ( [^\x0d\x0a]+ )  
                   \x0d?\x0a               /gcx;

        push @{$h{ lc($1) }}, $2
            while 
              m/   \G  \s*  ( [a-zA-Z][\w-]+ ) 
                       \s*   : 
                       \s*  ( [^\x0d\x0a]+ ) 
                       \x0d?\x0a                 /gcx;

        m/ \G \x0d?\x0a /gcx;

        $_ = substr $_, pos($_);

    };

    alarm 0;

    return wantarray  ? $@  ? () 
                            : ($_, \%h) 
                      : $_;
}


=head2 get_nginx_incs C<< $nginx, $dir >>

Returns proper C<@INC> to use in F<nginx-perl.conf> during tests. 

    my @incs = get_nginx_incs $nginx, $dir;

=cut

sub get_nginx_incs ($$) {
    my ($nginx, $path) = @_;
    my $prefix = '';

    if ($path !~ m!^/!) {
        $path =~ s!/+$!!;
        $prefix = join '/', map { '..' } split /\/+/, $path;
    }
    
    return ( 'lib', map {  m!^/! ? $_ : "$prefix/$_"  } 
                     ('blib/lib', 'blib/arch', @INC)    );
}


=head2 fork_nginx_handler_dir C<< $nginx, $dir, $conf, $code >>

Gets unused port, prepares directory for nginx with predefined 
package name, forks nginx and gives you a child object and generated 
peer back. Allows to inject C<$conf> into F<nginx-perl.conf> and 
C<$code> into the package. Expects to found C<sub handler { ... }> 
in C<$code>. Dies on errors.

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

=cut

sub fork_nginx_handler_die ($$$$) {
    my ($nginx, $path, $conf, $code) = @_;

    my $port = get_unused_port
        or die "Cannot get unused port";

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


=head2 eval_wait_sub C<< $name, $timeout, $sub >>

Wraps C<eval> block around subroutine C<$sub>, sets alarm to C<$timeout> 
and waits for sub to finish. Returns undef on alarm and if C<$sub> dies.

    my $rv = eval_wait_sub "test1", 5, sub {
        ...
        pass "test1";
    };
    
    fail "test1"  unless $rv;

=cut

sub eval_wait_sub ($$) {
    my $timeout = shift;
    my $sub     = shift;
    my $rv;

    eval {
        local $SIG{ALRM} = sub { die "SIGALRM\n" };
        alarm $timeout;

        $rv = &$sub;
    };

    alarm 0;

    unless ($@) {
        return $rv;
    } else {
      # Test::More::diag "\neval_wait_sub ('$name', $timeout, ...) died: $@\n";
        return undef;
    }
}


=head2 connect_peer C<< "$host:$port", $timeout >>

Tries to connect to C<$host:$port> within C<$timeout> seconds.
Returns socket handle on success or C<undef> otherwise.

    $sock = connect_peer "127.0.0.1:55555", 5
        or ...;

=cut

sub connect_peer ($$) {
    my ($peer, $timeout) = @_;

    return eval_wait_sub $timeout, sub {
        my $sock = IO::Socket::INET->new (PeerAddr => $peer)
            or die "$!\n";

        $sock->autoflush(1);

        return $sock;
    };
}


=head2 send_data C<< $sock, $buf, $timeout >>

Sends an entire C<$buf> to the socket C<$sock> in C<$timeout> seconds. 
Returns amount of data sent on success or undef otherwise. This amount 
is guessed since C<print> is used to send data.

    send_data $sock, $buf, 5
        or ...;

=cut

sub send_data ($$$) {
    my ($sock, undef, $timeout) = @_;
    my $buf = \$_[1];

    return eval_wait_sub $timeout, sub {
        print $sock $$buf;
        return length $$buf;
    };
}


=head2 parse_http_request C<< $buf, $r >>

Parses HTTP request from C<$buf> and puts parsed data structure into C<$r>. 
Returns length of the header in bytes on success or C<undef> on error.
Returns C<0> if cannot find header separator C<"\n\n"> in C<$buf>.

Data returned in the following form:

    $r = { 'connection'    => ['close'],
           'content-type'  => ['text/html'],
           ...
           '_method'       => 'GET',
           '_request_uri'  => '/?foo=bar',
           '_version'      => 'HTTP/1.0',
           '_uri'          => '/',
           '_query_string' => 'foo=bar',
           '_keepalive'    => 0              };

Example:

    $len = parse_http_request $buf, $r;
    
    if ($len) {
        # ok
        substr $buf, 0, $len, '';
        warn Dumper $r;
    } elsif (defined $len) {
        # read more data 
        # and try again
    } else {
        # bad request
    }

=cut

sub parse_http_request ($$) {
    my $buf = \$_[0];

    if ($$buf =~ /(\x0d\x0a\x0d\x0a)/gs || $$buf =~ /(\x0a\x0a)/gs) {
        my $header_len = pos($$buf) - length($1);
        my $sep_len = length($1);

        pos($$buf) = 0; # just in case we want to reparse 

        my @lines = split /^/, substr ($$buf, 0, $header_len);

        return undef  
              if  @lines < 1;

        my %h;
        @h{ '_method', 
            '_request_uri', 
            '_version'      } = split ' ', shift @lines;

        @h{'_uri', '_query_string'} = split /\?/, $h{_request_uri}, 2;

        map {  
            my ($key, $value) = split ':', $_, 2;

                $key   =~ s/^\s+//; $key   =~ s/\s+$//;
                $value =~ s/^\s+//; $value =~ s/\s+$//;

            push @{$h{ lc($key) }}, $value;
        } @lines;

        if ($h{_version} eq 'HTTP/1.1') {
            if (!exists $h{connection}) {
                $h{_keepalive} = 1  
            } elsif ($h{connection}->[0] !~ /[Cc]lose/) {
                $h{_keepalive} = 1  
            }
        } elsif (exists $h{connection}) {
            if ($h{connection}->[0] =~ /[Kk]eep-[Aa]live/) {
                $h{_keepalive} = 1;
            }
        }

        $_[1] = \%h;
        return $header_len + $sep_len;
    } else {
        return 0;
    }
}


=head2 parse_http_response C<< $buf, $r >>

Parses HTTP response from C<$buf> and puts parsed data structure into C<$r>. 
Returns length of the header in bytes on success or C<undef> on error.
Returns C<0> if cannot find header separator C<"\n\n"> in C<$buf>.

Data returned in the following form:

    $r = { 'connection'   => ['close'],
           'content-type' => ['text/html'],
           ...
           '_status'      => '404',
           '_message'     => 'Not Found',
           '_version'     => 'HTTP/1.0',
           '_keepalive'   => 0              };

Example:

    $len = parse_http_response $buf, $r;
    
    if ($len) {
        # ok
        substr $buf, 0, $len, '';
        warn Dumper $r;
    } elsif (defined $len) {
        # read more data 
        # and try again
    } else {
        # bad response
    }

=cut

sub parse_http_response ($$) {
    my $buf = \$_[0];

    if ($$buf =~ /(\x0d\x0a\x0d\x0a)/gs || $$buf =~ /(\x0a\x0a)/gs) {
        my $header_len = pos($$buf) - length($1);
        my $sep_len = length($1);

        pos($$buf) = 0; 

        my @lines = split /^/, substr ($$buf, 0, $header_len);

        return undef
              if @lines < 1;

        my %h;
        @h{ '_version', 
            '_status', 
            '_message'  } = split ' ', shift (@lines), 3;

        $h{_message} =~ s/\s+$//;

        map {  
            my ($key, $value) = split ':', $_, 2;

                $key   =~ s/^\s+//; $key   =~ s/\s+$//;
                $value =~ s/^\s+//; $value =~ s/\s+$//;

            push @{$h{ lc($key) }}, $value;
        } @lines;

        if ($h{_version} eq 'HTTP/1.1') {
            if (!exists $h{connection}) {
                $h{_keepalive} = 1  
            } elsif ($h{connection}->[0] !~ /[Cc]lose/) {
                $h{_keepalive} = 1  
            }
        } elsif (exists $h{connection}) {
            if ($h{connection}->[0] =~ /[Kk]eep-[Aa]live/) {
                $h{_keepalive} = 1;
            }
        }

        $_[1] = \%h;
        return $header_len + $sep_len;
    } else {
        return 0;
    }
}


=head2 inject_content_length C<< $buf >>

Parses HTTP header and inserts B<Content-Length> if needed, assuming
that C<$buf> contains entire request or response.

    $buf = "PUT /"          ."\x0d\x0a".
           "Host: foo.bar"  ."\x0d\x0a".
           ""               ."\x0d\x0a".
           "hello";
           
    inject_content_length $buf;

=cut

sub inject_content_length ($) {
    my $buf = \$_[0];

    if ($$buf =~ /(\x0d\x0a\x0d\x0a)/gs) {
        my $header_len = pos($$buf) - length($1);
            pos($$buf) = 0;
        my $sep_len = length($1);
        my @lines = split /^/, substr ($$buf, 0, $header_len);
        shift @lines;

        my %h;
        map {  
            my ($key, $value) = split ':', $_, 2;

                $key   =~ s/^\s+//; $key   =~ s/\s+$//;
                $value =~ s/^\s+//; $value =~ s/\s+$//;

            push @{$h{ lc($key) }}, $value;
        } @lines;

        if (length ($$buf) - $header_len - $sep_len > 0) {
            if (!exists $h{'content-length'}) {
                my $len = (length ($$buf) - $header_len - $sep_len);
                substr $$buf, $header_len + length (CRLF), 0, 
                   "Content-Length: $len"  .CRLF;
                return $len;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else {
        return undef;
    }
}


=head2 read_http_response C<< $sock, $h, $timeout >>

Reads and parses HTTP response header from C<$sock> into C<$h>
within C<$timeout> seconds. 
Returns true on success or C<undef> on error.

    read_http_response $sock, $h, 5
        or ...;

=cut

sub read_http_response ($$$$) {
    my ($sock, undef, undef, $timeout) = @_;
    my $buf = \$_[1];
    my $h   = \$_[2];

    return eval_wait_sub $timeout, sub {
        local $/ = CRLF.CRLF; 
        $$buf = <$sock>;

        parse_http_response $$buf, $$h
            or return undef;

        $$buf = '';
        my $len = $$h->{'content-length'} ? $$h->{'content-length'}->[0] : 0;

        if ($len) {
            local $/ = \$len;
            $$buf = <$sock>;
        }

        return 1;
    };
}


=head2 make_path C<< $path >>

Creates directory tree specified by C<$path> and returns this path 
or undef on error. 

    $path = make_path 'tmp/foo'
        or die "Can't create tmp/foo: $!\n";

=cut

sub make_path ($) {
    my $path = shift;
    my @dirs = split /[\/\\]+/, $path;
    my $dir;

    pop @dirs  if @dirs && $dirs[-1] eq '';

    foreach (@dirs) {
        $dir .= "$_";

        if ($dir) {
            if (!-e $dir) {
                mkdir $dir
                    or return undef;
            }
        }

        $dir .= '/';
    }

    return $path;
}


=head2 cat_logs C<< $dir >>

Scans directory C<$dir> for logs, concatenates them and returns.

    diag cat_logs $dir;

=cut

sub cat_logs ($) {
    my ($dir) = @_;
    my $out;

    opendir my $d, $dir
        or return undef;

    my @FILES = grep { ($_ ne '.' && $_ ne '..' && $_ ne '.exists') && 
                        -f "$dir/$_" } 
                  readdir $d;
    closedir $d;

    foreach (@FILES) {

        my $buf = do { open my $fh, '<', "$dir/$_"; local $/; <$fh> };

        $out .= <<"        EOF";

$dir/$_:
------------------------------------------------------------------
$buf
------------------------------------------------------------------


        EOF
    }

    return $out;
}


=head1 AUTHOR

Alexandr Gomoliako <zzz@zzz.org.ua>

=head1 LICENSE

Copyright 2011-2012 Alexandr Gomoliako. All rights reserved.

This module is free software. It may be used, redistributed and/or modified 
under the same terms as B<nginx> itself.

=cut

1;
