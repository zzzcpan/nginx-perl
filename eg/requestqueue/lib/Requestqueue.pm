package Requestqueue;

use strict;
use warnings;
no  warnings 'uninitialized';

use Nginx;

our @QUEUE;
our $MAX_ACTIVE_REQUESTS = 4;
our $ACTIVE_REQUESTS = 0;


sub access_handler {
    my ($r) = @_;

    if ($ACTIVE_REQUESTS < $MAX_ACTIVE_REQUESTS) {
        $ACTIVE_REQUESTS++;

        return NGX_OK;
    } else {
        $r->log_error(0, "Too many concurrent requests, queueing");

        push @QUEUE, $r;

        return NGX_DONE;
    }
}


sub Nginx::DESTROY {
    if (@QUEUE == 0) {
        $ACTIVE_REQUESTS--;
    } else {
        my $r = shift @QUEUE;

        $r->log_error(0, "Dequeuing");

        $r->phase_handler_inc;
        $r->core_run_phases;
    }
}


1;
