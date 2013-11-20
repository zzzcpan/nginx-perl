
# Copyright (C) Igor Sysoev, Alexandr Gomoliako
# Copyright (C) Nginx, Inc.

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Nginx',
    VERSION_FROM      => 'Nginx.pm',
    PREREQ_PM         => {},
    ABSTRACT_FROM     => 'Nginx.pm',
    AUTHOR            => 'Igor Sysoev, Alexandr Gomoliako',
    CCFLAGS           => "$ENV{NGX_PM_CFLAGS}",
    OPTIMIZE          => '-O',
    INC               => join(" ", map {
                             m#^/# ? "-I $_" : "-I ../../../../../$_"
                         } (split /\s+/, $ENV{NGX_INCS})),

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
