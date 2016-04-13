
1.8.1.9 Wed Apr 13 22:42:54 EEST 2016
	- bugfix: missing patches from nginx.xs;

1.8.1.8 Fri Feb 26 23:13:16 EET 2016
	- merged with nginx-1.8.1;

1.2.9.7 Wed Nov 20 02:16:37 EET 2013
	- merged with nginx-1.2.9;
	- applied CVE-2013-4547 patch;

1.2.6.6 Thu Jan 31 02:25:52 EET 2013
	- merged with nginx-1.2.6;

1.2.2.5 Sat Jul  7 15:57:38 EEST 2012
	- merged with nginx-1.2.2;

1.2.1.5 Tue Jun  5 17:48:18 EEST 2012
	- merged with nginx-1.2.1;

1.2.0.5 Fri May 11 02:27:50 EEST 2012
	- bugfix: segfault on reload on linux;
	- added perl_content as an alias for perl_handler for consistency;
	- some work on Test.pm in preparation for declarative approach;
	- fixed bugs in eg/websockets;

1.2.0.4 Mon Apr 23 17:04:10 EEST 2012
	- merged with nginx-1.2.0;
	- added websockets to examples;
	- fixed: missed timer on EAGAIN;
	- cleaned up and optimized ngx_write();

1.1.19.3 Fri Apr 13 04:44:11 EEST 2012
	- fixed broken tests;
	- disabled umask(0) in daemon mode;

1.1.19.2 Thu Apr 12 16:36:54 EEST 2012
	- merged with nginx-1.1.19;

1.1.18.2 Thu Apr 12 16:11:09 EEST 2012
	- improved Nginx::Test, more tests;
	- added ngx_http_time, ngx_http_cookie_time, ngx_http_parse_time;
	- fixed uninitialized check in ngx_escape_uri, covered in t/05;
	- bugfix: handler was called twice in a row in loop mode
	  in ngx_reader and ngx_writer;

1.1.18.1 Wed Mar 28 17:33:13 EEST 2012
	- merged with nginx-1.1.18;
	- added 2 new examples;
1.1.17.1
	- merged with nginx-1.1.17;
	- fixes for travis-ci;
	- bugfix: typo in zlib detection;
1.1.16.1
	- merged with nginx-1.1.16;
	- testing: disabling pcre and zlib for non-humans if not found;
	- bugfix: make test was failing without make, needed dependecny
	  on object;
	- bugfix: prove was failing without make;
	- bugfix: it was not possible to read POST request with
	  connection takeover;
	- new method: $r->preread, useful for connection takeover;
	- removed anon sub enforcement from prototypes;
1.1.15.1
	- merged with nginx-1.1.15;
1.1.14.1
	- merged with nginx-1.1.14;
	- fix: Makemaker's options caused ./configure to fail;
1.1.13.1
	- merged with nginx-1.1.13;
	- fixed make to use blib/;
1.1.12.1
	- merged with nginx-1.1.12;
	- added tests for internal functions;
	- added ngx_escape_uri;
	- redis client moved to cpan (Nginx::Redis);
	- http client on cpan as well (Nginx::HTTP);
	- improved documentation;

1.1.11.1 Thu Dec 22 03:48:41 EET 2011
	- merging with nginx-1.1.11;
	- four tests;
	- added META.yml for CPAN;
	- added Makefile.PL to install into perl's tree;
	- added logo;
	- added framework for writing tests;
	- fix: dedicated timer for resolver;
	- fix: uninitialized buffer for reader caused segfault,
	  thanks to chenryn for helping to spot it;
	- Nginx::Redis as a reusable redis client;
	- merging with nginx-1.1.9;
1.1.9.1
	- added eg/redis;
	- added eg/self-sufficient;
	- added eg/helloworld;
	- added Nginx/Util.pm with connection queueing;
	- added $r->unparsed_uri;
	- added ngx_prefix(), ngx_conf_prefix();
	- added perl_exit_worker directive;
	- added support for initial connection takeover with
	  $r->take_connection, $r->give_connection;
	- added $r->headers_in: { host => ['f.com'], x-foo => ['bar', 'baz'] }
	- added perl_inc as an alias to perl_modules;
	- added perl_app directive;
	- perl directive renamed to perl_handler;
	- fixed: destroyed requests don't cause segfault anymore;
	- binary renamed to nginx-perl to avoid conflicts with nginx;
	- added $r->ctx, $r->root;
	- added perl_init_worker directive;
	- added perl_eval directive;
	- added SSL support with ssl handshaker;
	- added access phase handler and related functions;
	- added resolver;
	- nginx.pm renamed to Nginx.pm;
	- added ngx_log_*;
	- fixed XS formatting;
	- added $r->location_name, useful as a prefix
	- added asynchronous reader and writer;
	- added timer;

1.1.6.1
	- initial import of nginx-1.1.6;

