

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

