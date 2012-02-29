#!/usr/bin/perl

# Copyright 2011 Alexandr Gomoliako

use strict;

use Config;

my @args;

push @args, '--prefix=' . $Config{siteprefix} . "/nginx-perl" 
        if  $Config{siteprefix} ;

push @args, '--sbin-path=' . ( $Config{installsitebin}    || 
                               $Config{installsitescript} ||
                               $Config{sitebin}           ||
                               $Config{sitescript}           )

                           if  $Config{installsitebin}    || 
                               $Config{installsitescript} ||
                               $Config{sitebin}           ||
                               $Config{sitescript}           ;


# ignoring MakeMaker's options

shift @ARGV
    while  @ARGV && $ARGV[0] !~ /^--/; 


unless (@ARGV) {
    # disabling pcre / building statically for automatic testing

    my @PCRE_INCLUDE = 
         grep { -e "$_/pcre.h" } 
           qw( /usr/include
               /usr/local/include
               /usr/pkg/include
               /use/include/pcre
               /opt/local/include );

    push @args, '--with-pcre=pcre' 
            if  -e 'pcre' && !@PCRE_INCLUDE;

    push @args, '--without-http_rewrite_module',
                '--without-pcre'
            if !-e 'pcre' && !@PCRE_INCLUDE;


    # disabling zlib / building statically for automatic testing

    my @ZLIB_INCLUDE = 
         grep { -e "$_/zlib.h" } 
           qw( /usr/include
               /usr/local/include
               /usr/pkg/include
               /use/include/pcre
               /opt/local/include );

    push @args, '--with-zlib=zlib' 
            if  -e 'pcre' && !@PCRE_INCLUDE;

    push @args, '--without-http_gzip_module'
            if !-e 'zlib' && !@ZLIB_INCLUDE;
}

# our perl interpreter

push @args, '--with-perl=' . $^X;


exec './configure', @args, @ARGV;


