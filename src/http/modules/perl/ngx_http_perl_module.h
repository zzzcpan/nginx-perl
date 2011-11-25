
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_HTTP_PERL_MODULE_H_INCLUDED_
#define _NGX_HTTP_PERL_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <EXTERN.h>
#include <perl.h>


typedef ngx_http_request_t   *nginx;

typedef struct {
    ngx_str_t                 filename;
    ngx_str_t                 redirect_uri;
    ngx_str_t                 redirect_args;

    SV                       *r;
    SV                       *ctx;

    SV                       *next;

    ngx_uint_t                done;       /* unsigned  done:1; */

    ngx_array_t              *variables;  /* array of ngx_http_perl_var_t */

#if (NGX_HTTP_SSI)
    ngx_http_ssi_ctx_t       *ssi;
#endif
    ngx_int_t                 have_body;
} ngx_http_perl_ctx_t;


typedef struct {
    ngx_uint_t    hash;
    ngx_str_t     name;
    ngx_str_t     value;
} ngx_http_perl_var_t;


extern ngx_module_t  ngx_http_perl_module;


/*
 * workaround for "unused variable `Perl___notused'" warning
 * when building with perl 5.6.1
 */
#ifndef PERL_IMPLICIT_CONTEXT
#  undef  dTHXa
#  define dTHXa(a)
#endif


extern void boot_DynaLoader(pTHX_ CV* cv);


void ngx_http_perl_handle_request(ngx_http_request_t *r);
void ngx_http_perl_sleep_handler(ngx_http_request_t *r);



typedef struct {
    ngx_int_t   after;
    SV         *repeat;
    SV         *cb;
} ngx_perl_timer_t;

ngx_connection_t *ngx_perl_timer(ngx_int_t after, SV *repeat, SV *cb);
void ngx_perl_timer_clear(ngx_connection_t *c);


#define NGX_PERL_NOOP             0
#define NGX_PERL_READ             1
#define NGX_PERL_WRITE            2
#define NGX_PERL_CONNECT          4
#define NGX_PERL_CLOSE            8
#define NGX_PERL_SSL_HANDSHAKE   16

#ifndef EBADE
#  define  EBADE  52
#endif

#ifndef ENOMSG
#  define  ENOMSG  42
#endif

#define NGX_PERL_EOF         42   /* ENOMSG */
#define NGX_PERL_EINVAL      EINVAL
#define NGX_PERL_ENOMEM      ENOMEM
#define NGX_PERL_EBADE       EBADE
#define NGX_PERL_EBADF       EBADF
#define NGX_PERL_ETIMEDOUT   ETIMEDOUT
#define NGX_PERL_ENOMSG      ENOMSG
#define NGX_PERL_EAGAIN      EAGAIN
#define NGX_PERL_ENOTSUP     ENOTSUP

typedef struct {
    SV          *connect_cb;
    SV          *read_buffer;
    SV          *read_min;
    SV          *read_max;
    SV          *read_timeout;
    SV          *read_cb;
    SV          *write_buffer;
    ssize_t      write_offset;
    SV          *write_timeout;
    SV          *write_cb;
#if (NGX_HTTP_SSL)
    ngx_flag_t   ssl;
    SV          *ssl_handshake_cb;
#endif
} ngx_perl_connection_t;

ngx_int_t ngx_perl_connection_init(ngx_connection_t *c);
ngx_connection_t *ngx_perl_connector(SV *address, SV *port, SV *timeout, 
        SV *cb);
void ngx_perl_ssl_handshaker(ngx_connection_t *c, SV *cb);
void ngx_perl_writer(ngx_connection_t *c, SV *buf, SV *timeout, SV *cb);
void ngx_perl_reader(ngx_connection_t *c, SV *buf, SV *min, SV *max, 
        SV *timeout, SV *cb);
void ngx_perl_close(ngx_connection_t *c);
void ngx_perl_read(ngx_connection_t *c);
void ngx_perl_write(ngx_connection_t *c);
void ngx_perl_noop(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
void ngx_perl_ssl_handshake(ngx_connection_t *c);
#endif


typedef struct {
    ngx_str_t   name;
    SV         *cb;
} ngx_perl_resolver_t;

void ngx_perl_resolver(SV *name, SV *timeout, SV *cb);


extern ngx_log_t  *ngx_perl_log;

#endif /* _NGX_HTTP_PERL_MODULE_H_INCLUDED_ */
