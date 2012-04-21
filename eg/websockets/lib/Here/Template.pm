package Here::Template;

=head1 NAME

Here::Template - heredoc templates

=head1 SYNOPSIS

    use Here::Template;
    
    print <<'TMPL';
    
        Hello, my pid is <?= $$ ?>
        Let's count to 10: <? for (1..10) { ?>$_ <? } ?>
    
    TMPL

=head1 DESCRIPTION

Simple Filter::Util::Call based implementation of heredoc templates.

To enable templates in some heredoc use quoted heredoc mark that contains
B<TMPL>. Output is added to the buffer C<$here>. You can append data
there as well:

    print <<'TMPL';
    
        Hello, my pid is <?= $$ ?>
        Let's count to 10: <? for (1..10) { $here.= "$_" } ?>
    
    TMPL

=head1 EXPORT

This module doesn't export anything by default.

Special argument B<relaxed> can be used to disable strict and
warnings inside templates. E.g.:

    use strict;
    use warnings; 
    
    use Here::Template 'relaxed';
    
    print <<'TMPL';
    
        Let's count to 10: <? 
            for $k (1..10) { 
                $here .= "$k ";
            }
        ?>
    
    TMPL

=cut

our $VERSION = '0.2';

use strict;
use warnings;
no  warnings 'uninitialized';

use Filter::Util::Call;

sub import {
    my $ctl = $_[1] eq 'relaxed' 
                 ? 'no strict; no warnings;' : '';

    filter_add  sub {  

        my $st = filter_read();

        if ( m/  << \s* (['"]) ( [^\1]* TMPL [^\1]* ) \1 \s* /gcx ) {
            my $q       = $1;
            my $eof     = quotemeta $2;
            my $start   = quotemeta '<?'; 
            my $out     = '$here';
            my $end     = quotemeta '?>';

            my $buf     = substr($_, 0, pos($_) - length($&));
            my $buf_end = substr($_, pos($_));

            chomp($buf_end);

            return $st
                if /^\s*#/;

            $_ = '';

            # do { my $var = '
            $buf .= "do{ $ctl \n".($out eq '$_' ? 'local' : 'my')." $out =$q";

            while (1) {
                $st = filter_read();

                if (/ $start (=)? /gcx) {
                    my $echo = $1;

                    # foo bar\' baz
                    my $tmp  =  substr($_, 0, pos($_) - length($&));
                       $_    =  substr($_, pos($_)); 
                       $tmp  =~ s/$q/\\$q/g;
                       $buf .=  $tmp;

                    $st = filter_read()
                        while !/ $end /gcx;

                    # '; ... ; $out .='
                    $tmp  =  substr($_, 0, pos($_) - length($&));
                    $_    =  substr($_, pos($_)); 
                    $buf .= "$q; ".
                             ($echo ? "$out.=$tmp" : "$tmp").
                             "; $out .=$q";
                }

                if (/ $eof /gcx) {
                    my $tmp  =  substr($_, 0, pos($_) - length($&));
                       $_    =  substr($_, pos($_));
                       $tmp  =~ s/$q/\\$q/g;
                       $buf .=  $tmp;

                    # '; $var }
                    $buf .= "$q; $out }";
                    $_    = $buf.$buf_end.$_;
                    last;
                }

                last 
                    unless $st;
            }
        }

        return $st;
    };
}


=head1 AUTHOR

Alexandr Gomoliako <zzz@zzz.org.ua>

=head1 LICENSE

Copyright 2011-2012 Alexandr Gomoliako. All rights reserved.

This module is free software. It may be used, redistributed and/or modified 
under the same terms as perl itself.

=cut

1;
