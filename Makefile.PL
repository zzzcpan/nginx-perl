#!/usr/bin/perl

# Copyright 2011 Alexandr Gomoliako

use strict;

use Config;

my @args;

push @args, 
    '--prefix=' . $Config{siteprefix} . "/nginx-perl" 
            if  $Config{siteprefix} ;

push @args, 
    '--sbin-path=' . ( $Config{installsitebin}    || 
                       $Config{installsitescript} ||
                       $Config{sitebin}           ||
                       $Config{sitescript}           )

            if  $Config{installsitebin}    || 
                $Config{installsitescript} ||
                $Config{sitebin}           ||
                $Config{sitescript}           ;

push @args,
    '--with-perl=' . $^X;


# ignoring MakeMaker's options

shift @ARGV
    while  @ARGV && $ARGV[0] !~ /^--/; 


exec './configure', @args, @ARGV;


