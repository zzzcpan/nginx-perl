
# Copyright (C) Igor Sysoev, Alexandr Gomoliako

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Nginx',
    VERSION_FROM      => 'Nginx.pm',
    PREREQ_PM         => {},
    ABSTRACT_FROM     => 'Nginx.pm',
    AUTHOR            => 'Igor Sysoev, Alexandr Gomoliako',
    CCFLAGS           => "$ENV{NGX_PM_CFLAGS}",
    OPTIMIZE          => '-O',
    INC               => "-I ../../../../../src/core " .
                         "-I ../../../../../src/event " .
                         "-I ../../../../../src/os/unix " .
                         "-I ../../../../../src/http " .
                         "-I ../../../../../src/http/modules " .
                         "-I ../../../../../src/http/modules/perl " .
                         "-I ../../../../../$ENV{NGX_OBJS} " .
                         ($ENV{NGX_PCRE} =~ /^(YES|NO)/ ? "" :
                             ($ENV{NGX_PCRE} =~ m#^/# ? "-I $ENV{NGX_PCRE} " :
                                  "-I ../../../../../$ENV{NGX_PCRE} ")),

    depend => {
        'Nginx.c' =>
            "../../../../../src/http/modules/perl/ngx_http_perl_module.h"
    },

    PM => {
        'Nginx.pm' => '$(INST_LIBDIR)/Nginx.pm',
        'Test.pm'  => '$(INST_LIBDIR)/Nginx/Test.pm',
        'Perl.pm'  => '$(INST_LIBDIR)/Nginx/Perl.pm',
    }
);
