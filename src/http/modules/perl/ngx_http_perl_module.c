
/*
 * Copyright (C) Igor Sysoev, Alexandr Gomoliako
 * Copyright (C) Nginx, Inc.
 */

/* TODO
    - fix debug messages;
    - cleanup reader/writer, avoid ngx_perl_read/write for AGAIN calls;
*/


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_perl_module.h>


typedef struct {
    ngx_array_t       *modules;
    ngx_array_t       *requires;
    ngx_array_t       *init_worker;
    ngx_array_t       *exit_worker;
} ngx_http_perl_main_conf_t;


typedef struct {
    SV                *sub;
    ngx_str_t          handler;
    SV                *access_sub;
    ngx_str_t          access_handler;
#if (NGX_HTTP_SSL)
    ngx_ssl_t         *ssl;
#endif
    ngx_int_t          read_body;
} ngx_http_perl_loc_conf_t;


typedef struct {
    SV                *sub;
    ngx_str_t          handler;
} ngx_http_perl_variable_t;


#if (NGX_HTTP_SSI)
static ngx_int_t ngx_http_perl_ssi(ngx_http_request_t *r,
    ngx_http_ssi_ctx_t *ssi_ctx, ngx_str_t **params);
#endif

static char *ngx_http_perl_init_interpreter(ngx_conf_t *cf,
    ngx_http_perl_main_conf_t *pmcf);
static PerlInterpreter *ngx_http_perl_create_interpreter(ngx_conf_t *cf,
    ngx_http_perl_main_conf_t *pmcf);
static ngx_int_t ngx_http_perl_run_requires(pTHX_ ngx_array_t *requires,
    ngx_log_t *log);
static ngx_int_t ngx_http_perl_call_handler(pTHX_ ngx_http_request_t *r,
    SV *sub, SV **args, ngx_str_t *handler, ngx_str_t *rv);
static void ngx_http_perl_eval_anon_sub(pTHX_ ngx_str_t *handler, SV **sv);

static ngx_int_t ngx_http_perl_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_perl_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_perl_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_perl_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_perl_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_perl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_perl_app(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_perl_access(ngx_conf_t *cf, ngx_command_t *cmd, 
    void *conf);
static char *ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_perl_eval(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_perl_init_worker(ngx_cycle_t *cycle);
static void ngx_http_perl_exit_worker(ngx_cycle_t *cycle);
static void ngx_http_perl_exit(ngx_cycle_t *cycle);

static void ngx_perl_timer_callback(ngx_event_t *ev);
static void ngx_perl_connection_cleanup(void *data);
static void ngx_perl_connect_handler(ngx_event_t *ev);
static void ngx_perl_dummy_handler(ngx_event_t *ev);
static void ngx_perl_read_handler(ngx_event_t *ev);
static void ngx_perl_write_handler(ngx_event_t *ev);
static void ngx_perl_resolver_timeout_handler(ngx_event_t *ev);
static void ngx_perl_resolver_handler(ngx_resolver_ctx_t *ctx);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_perl_set_ssl(ngx_conf_t *cf, 
    ngx_http_perl_loc_conf_t *plcf);
static void ngx_perl_ssl_handshake_handler(ngx_connection_t *c);
#endif

static void ngx_http_perl_ctx_cleanup(void *data);


static ngx_command_t  ngx_http_perl_commands[] = {

    { ngx_string("perl_modules"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, modules),
      NULL },

    { ngx_string("perl_inc"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, modules),
      NULL },

    { ngx_string("perl_require"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, requires),
      NULL },

    { ngx_string("perl_init_worker"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, init_worker),
      NULL },

    { ngx_string("perl_exit_worker"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_perl_main_conf_t, exit_worker),
      NULL },

    { ngx_string("perl_handler"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_perl,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("perl_app"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_perl_app,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("perl_access"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_perl_access,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("perl_set"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_perl_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("perl_eval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_perl_eval,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_perl_module_ctx = {
    ngx_http_perl_preconfiguration,        /* preconfiguration */
    ngx_http_perl_postconfiguration,       /* postconfiguration */

    ngx_http_perl_create_main_conf,        /* create main configuration */
    ngx_http_perl_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_perl_create_loc_conf,         /* create location configuration */
    ngx_http_perl_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_perl_module = {
    NGX_MODULE_V1,
    &ngx_http_perl_module_ctx,             /* module context */
    ngx_http_perl_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_perl_init_worker,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_perl_exit_worker,             /* exit process */
    ngx_http_perl_exit,                    /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HTTP_SSI)

#define NGX_HTTP_PERL_SSI_SUB  0
#define NGX_HTTP_PERL_SSI_ARG  1


static ngx_http_ssi_param_t  ngx_http_perl_ssi_params[] = {
    { ngx_string("sub"), NGX_HTTP_PERL_SSI_SUB, 1, 0 },
    { ngx_string("arg"), NGX_HTTP_PERL_SSI_ARG, 0, 1 },
    { ngx_null_string, 0, 0, 0 }
};

static ngx_http_ssi_command_t  ngx_http_perl_ssi_command = {
    ngx_string("perl"), ngx_http_perl_ssi, ngx_http_perl_ssi_params, 0, 0, 1
};

#endif


static ngx_str_t         ngx_null_name = ngx_null_string;
static HV               *nginx_stash;
static PerlInterpreter  *my_perl;

       ngx_log_t        *ngx_perl_log; 


static void
ngx_http_perl_xs_init(pTHX)
{
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);

    nginx_stash = gv_stashpv("Nginx", TRUE);
}


static void
ngx_http_perl_ctx_cleanup(void *data) 
{
    ngx_http_perl_ctx_t  *ctx;

    ctx = (ngx_http_perl_ctx_t *) data;

    if (ctx->ctx != NULL) {
        SvREFCNT_dec(ctx->ctx);
        ctx->ctx = NULL;
    }

    if (ctx->r != NULL) {
        SvOK_off(SvRV(ctx->r));
        SvREFCNT_dec(ctx->r);
        ctx->r = NULL;
    }

    return;
}


static ngx_int_t
ngx_http_perl_handler(ngx_http_request_t *r)
{
    r->main->count++;

    ngx_http_perl_handle_request(r);

    return NGX_DONE;
}


static ngx_int_t
ngx_http_perl_access_handler(ngx_http_request_t *r)
{
    ngx_http_perl_loc_conf_t  *plcf;
    ngx_http_perl_ctx_t       *ctx;
    ngx_pool_cleanup_t        *ctxcln;
    ngx_int_t                  rc;
    dSP;

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ctxcln = ngx_pool_cleanup_add(r->pool, 0);
        if (ctxcln == NULL) {
            return NGX_ERROR;
        }

        ctxcln->data    = (void *) ctx;
        ctxcln->handler = ngx_http_perl_ctx_cleanup;

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);

        ctx->r = sv_bless(newRV_noinc(newSViv(PTR2IV(r))), nginx_stash);
    }

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_perl_module);

    if (!plcf->access_sub) {
        return NGX_OK;
    }

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);
    XPUSHs(ctx->r);
    PUTBACK;

    call_sv(plcf->access_sub, G_SCALAR);

    SPAGAIN;
    rc = POPi;
    PUTBACK;

    FREETMPS;
    LEAVE;

    return rc;
}


void
ngx_http_perl_handle_request(ngx_http_request_t *r)
{
    SV                         *sub;
    ngx_int_t                   rc;
    ngx_str_t                   uri, args, *handler;
    ngx_http_perl_ctx_t        *ctx;
    ngx_pool_cleanup_t         *ctxcln;
    ngx_http_perl_loc_conf_t   *plcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "perl handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        ctxcln = ngx_pool_cleanup_add(r->pool, 0);
        if (ctxcln == NULL) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        ctxcln->data    = (void *) ctx;
        ctxcln->handler = ngx_http_perl_ctx_cleanup;

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);

        ctx->r = sv_bless(newRV_noinc(newSViv(PTR2IV(r))), nginx_stash);
    }


    plcf = ngx_http_get_module_loc_conf(r, ngx_http_perl_module);

    if (plcf->read_body && !ctx->have_body && 
        r->headers_in.content_length_n > 0) 
    {
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        if (r->request_body_in_file_only) {
            r->request_body_file_log_level = 0;
        }

        ctx->have_body = 1;

        ngx_http_read_client_request_body(r, ngx_http_perl_handle_request);
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }


    if (ctx->next == NULL) {
        sub = plcf->sub;
        handler = &plcf->handler;
    } else {
        sub = ctx->next;
        handler = &ngx_null_name;
        ctx->next = NULL;
    }

    rc = ngx_http_perl_call_handler(aTHX_ r, sub, NULL, handler, NULL);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl handler done: %i", rc);

    if (rc == NGX_DONE) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (rc > 600) {
        rc = NGX_OK;
    }

    if (ctx->redirect_uri.len) {
        uri = ctx->redirect_uri;
        args = ctx->redirect_args;

    } else {
        uri.len = 0;
    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    if (ctx->done || ctx->next) {
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (uri.len) {
        ngx_http_internal_redirect(r, &uri, &args);
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (rc == NGX_OK || rc == NGX_HTTP_OK) {
        ngx_http_send_special(r, NGX_HTTP_LAST);
        ctx->done = 1;
    }

    ngx_http_finalize_request(r, rc);
}


void
ngx_http_perl_sleep_handler(ngx_http_request_t *r)
{
    ngx_event_t  *wev;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sleep handler");

    wev = r->connection->write;

    if (wev->timedout) {
        wev->timedout = 0;
        ngx_http_perl_handle_request(r);
        return;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}


static ngx_int_t
ngx_http_perl_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_perl_variable_t *pv = (ngx_http_perl_variable_t *) data;

    ngx_int_t                   rc;
    ngx_str_t                   value;
    ngx_http_perl_ctx_t        *ctx;
    ngx_pool_cleanup_t         *ctxcln;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ctxcln = ngx_pool_cleanup_add(r->pool, 0);
        if (ctxcln == NULL) {
            return NGX_ERROR;
        }

        ctxcln->data    = (void *) ctx;
        ctxcln->handler = ngx_http_perl_ctx_cleanup;

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);

        ctx->r = sv_bless(newRV_noinc(newSViv(PTR2IV(r))), nginx_stash);
    }

    value.data = NULL;

    rc = ngx_http_perl_call_handler(aTHX_ r, pv->sub, NULL,
                                    &pv->handler, &value);

    if (value.data) {
        v->len = value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = value.data;

    } else {
        v->not_found = 1;
    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable done");

    return rc;
}


#if (NGX_HTTP_SSI)

static ngx_int_t
ngx_http_perl_ssi(ngx_http_request_t *r, ngx_http_ssi_ctx_t *ssi_ctx,
    ngx_str_t **params)
{
    SV                         *sv, **asv;
    ngx_int_t                   rc;
    ngx_str_t                  *handler, **args;
    ngx_uint_t                  i;
    ngx_http_perl_ctx_t        *ctx;
    ngx_pool_cleanup_t         *ctxcln;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl ssi handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ctxcln = ngx_pool_cleanup_add(r->pool, 0);
        if (ctxcln == NULL) {
            return NGX_ERROR;
        }

        ctxcln->data    = (void *) ctx;
        ctxcln->handler = ngx_http_perl_ctx_cleanup;

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);

        ctx->r = sv_bless(newRV_noinc(newSViv(PTR2IV(r))), nginx_stash);
    }

    ctx->ssi = ssi_ctx;

    handler = params[NGX_HTTP_PERL_SSI_SUB];
    handler->data[handler->len] = '\0';

#if 0

    /* the code is disabled to force the precompiled perl code using only */

    ngx_http_perl_eval_anon_sub(aTHX_ handler, &sv);

    if (sv == &PL_sv_undef) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "eval_pv(\"%V\") failed", handler);
        return NGX_ERROR;
    }

    if (sv == NULL) {
        sv = newSVpvn((char *) handler->data, handler->len);
    }

#endif

    sv = newSVpvn((char *) handler->data, handler->len);

    args = &params[NGX_HTTP_PERL_SSI_ARG];

    if (args) {

        for (i = 0; args[i]; i++) { /* void */ }

        asv = ngx_pcalloc(r->pool, (i + 1) * sizeof(SV *));

        if (asv == NULL) {
            SvREFCNT_dec(sv);
            return NGX_ERROR;
        }

        asv[0] = (SV *) i;

        for (i = 0; args[i]; i++) {
            asv[i + 1] = newSVpvn((char *) args[i]->data, args[i]->len);
        }

    } else {
        asv = NULL;
    }

    rc = ngx_http_perl_call_handler(aTHX_ r, sv, asv, handler,
                                    NULL);

    SvREFCNT_dec(sv);

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;
    ctx->ssi = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "perl ssi done");

    return rc;
}

#endif


static char *
ngx_http_perl_init_interpreter(ngx_conf_t *cf, ngx_http_perl_main_conf_t *pmcf)
{
    ngx_str_t           *m;
    ngx_uint_t           i;

#ifdef NGX_PERL_MODULES
    if (pmcf->modules == NGX_CONF_UNSET_PTR) {

        pmcf->modules = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (pmcf->modules == NULL) {
            return NGX_CONF_ERROR;
        }

        m = ngx_array_push(pmcf->modules);
        if (m == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_str_set(m, NGX_PERL_MODULES);
    }
#endif

    if (pmcf->modules != NGX_CONF_UNSET_PTR) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            if (ngx_conf_full_name(cf->cycle, &m[i], 0) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (my_perl) {

        if (ngx_set_environment(cf->cycle, NULL) == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_http_perl_run_requires(aTHX_ pmcf->requires, cf->log)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }


    if (nginx_stash == NULL) {
        PERL_SYS_INIT(&ngx_argc, &ngx_argv);
    }

    my_perl = ngx_http_perl_create_interpreter(cf, pmcf);

    if (my_perl == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static PerlInterpreter *
ngx_http_perl_create_interpreter(ngx_conf_t *cf,
    ngx_http_perl_main_conf_t *pmcf)
{
    int                n;
    STRLEN             len;
    SV                *sv;
    char              *ver, **embedding;
    ngx_str_t         *m;
    ngx_uint_t         i;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "create perl interpreter");

    if (ngx_set_environment(cf->cycle, NULL) == NULL) {
        return NULL;
    }

    my_perl = perl_alloc();
    if (my_perl == NULL) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "perl_alloc() failed");
        return NULL;
    }

    {

    perl_construct(my_perl);

    PL_origalen = 1;

#ifdef PERL_EXIT_DESTRUCT_END
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif

    n = (pmcf->modules != NGX_CONF_UNSET_PTR) ? pmcf->modules->nelts * 2 : 0;

    embedding = ngx_palloc(cf->pool, (4 + n) * sizeof(char *));
    if (embedding == NULL) {
        goto fail;
    }

    embedding[0] = "";

    if (n++) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            embedding[2 * i + 1] = "-I";
            embedding[2 * i + 2] = (char *) m[i].data;
        }
    }

    embedding[n++] = "-MNginx";
    embedding[n++] = "-e";
    embedding[n++] = "0";

    n = perl_parse(my_perl, ngx_http_perl_xs_init, n, embedding, NULL);

    if (n != 0) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "perl_parse() failed: %d", n);
        goto fail;
    }

    sv = get_sv("Nginx::VERSION", FALSE);
    ver = SvPV(sv, len);

    if (ngx_strcmp(ver, NGINX_VERSION) != 0) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, 0,
                      "version " NGINX_VERSION " of Nginx.pm is required, "
                      "but %s was found", ver);
        goto fail;
    }

    if (ngx_http_perl_run_requires(aTHX_ pmcf->requires, cf->log) != NGX_OK) {
        goto fail;
    }

    }

    return my_perl;

fail:

    (void) perl_destruct(my_perl);

    perl_free(my_perl);

    return NULL;
}


static ngx_int_t
ngx_http_perl_run_requires(pTHX_ ngx_array_t *requires, ngx_log_t *log)
{
    u_char      *err;
    STRLEN       len;
    ngx_str_t   *script;
    ngx_uint_t   i;

    if (requires == NGX_CONF_UNSET_PTR) {
        return NGX_OK;
    }

    script = requires->elts;
    for (i = 0; i < requires->nelts; i++) {

        require_pv((char *) script[i].data);

        if (SvTRUE(ERRSV)) {

            err = (u_char *) SvPV(ERRSV, len);
            while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "require_pv(\"%s\") failed: \"%*s\"",
                          script[i].data, len + 1, err);

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_perl_call_handler(pTHX_ ngx_http_request_t *r, SV *sub,
    SV **args, ngx_str_t *handler, ngx_str_t *rv)
{
    int                   n, status;
    char                 *line;
    u_char               *err;
    STRLEN                len, n_a;
    ngx_uint_t            i;
    ngx_connection_t     *c;
    ngx_http_perl_ctx_t  *ctx;

    dSP;

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    status = 0;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);

    XPUSHs(ctx->r);

    if (args) {
        EXTEND(sp, (intptr_t) args[0]);

        for (i = 1; i <= (ngx_uint_t) args[0]; i++) {
            PUSHs(sv_2mortal(args[i]));
        }
    }

    PUTBACK;

    c = r->connection;

    n = call_sv(sub, G_EVAL);

    SPAGAIN;

    if (n) {
        if (rv == NULL) {
            status = POPi;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "call_sv: %d", status);

        } else {
            line = SvPVx(POPs, n_a);
            rv->len = n_a;

            rv->data = ngx_pnalloc(r->pool, n_a);
            if (rv->data == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(rv->data, line, n_a);
        }
    }

    PUTBACK;

    FREETMPS;
    LEAVE;

    /* check $@ */

    if (SvTRUE(ERRSV)) {

        err = (u_char *) SvPV(ERRSV, len);
        while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "call_sv(\"%V\") failed: \"%*s\"", handler, len + 1, err);

        if (rv) {
            return NGX_ERROR;
        }

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (n != 1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "call_sv(\"%V\") returned %d results", handler, n);
        status = NGX_OK;
    }

    if (rv) {
        return NGX_OK;
    }

    return (ngx_int_t) status;
}


static void
ngx_http_perl_eval_anon_sub(pTHX_ ngx_str_t *handler, SV **sv)
{
    u_char  *p;

    for (p = handler->data; *p; p++) {
        if (*p != ' ' && *p != '\t' && *p != CR && *p != LF) {
            break;
        }
    }

    if (ngx_strncmp(p, "sub ", 4) == 0
        || ngx_strncmp(p, "sub{", 4) == 0
        || ngx_strncmp(p, "use ", 4) == 0)
    {
        *sv = eval_pv((char *) p, FALSE);

        /* eval_pv() does not set ERRSV on failure */

        return;
    }

    *sv = NULL;
}


static void *
ngx_http_perl_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_perl_main_conf_t  *pmcf;

    pmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_perl_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    pmcf->modules     = NGX_CONF_UNSET_PTR;
    pmcf->requires    = NGX_CONF_UNSET_PTR;
    pmcf->init_worker = NGX_CONF_UNSET_PTR;
    pmcf->exit_worker = NGX_CONF_UNSET_PTR;

    return pmcf;
}


static char *
ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_perl_main_conf_t *pmcf = conf;

    if (my_perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}



static ngx_int_t
ngx_http_perl_preconfiguration(ngx_conf_t *cf)
{
#if (NGX_HTTP_SSI)
    ngx_int_t                  rc;
    ngx_http_ssi_main_conf_t  *smcf;

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ssi_filter_module);

    rc = ngx_hash_add_key(&smcf->commands, &ngx_http_perl_ssi_command.name,
                          &ngx_http_perl_ssi_command, NGX_HASH_READONLY_KEY);

    if (rc != NGX_OK) {
        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting SSI command \"%V\"",
                               &ngx_http_perl_ssi_command.name);
        }

        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_perl_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_perl_access_handler;

    return NGX_OK;
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_perl_set_ssl(ngx_conf_t *cf, ngx_http_perl_loc_conf_t *plcf)
{
    ngx_pool_cleanup_t  *cln;

    plcf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (plcf->ssl == NULL) {
        return NGX_ERROR;
    }

    plcf->ssl->log = cf->log;

    if (ngx_ssl_create(plcf->ssl,
                       NGX_SSL_SSLv2|NGX_SSL_SSLv3|NGX_SSL_TLSv1, NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = plcf->ssl;

    return NGX_OK;
}

#endif


static void *
ngx_http_perl_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_perl_loc_conf_t *plcf;

    plcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_perl_loc_conf_t));
    if (plcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     plcf->handler = { 0, NULL };
     */

#if (NGX_HTTP_SSL)
    if (ngx_http_perl_set_ssl(cf, plcf) != NGX_OK) {
        return NULL;
    }
#endif

    return plcf;
}


static char *
ngx_http_perl_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_perl_loc_conf_t *prev = parent;
    ngx_http_perl_loc_conf_t *conf = child;

    if (conf->sub == NULL) {
        conf->sub = prev->sub;
        conf->handler = prev->handler;
    }

    if (conf->access_sub == NULL) {
        conf->access_sub = prev->access_sub;
        conf->access_handler = prev->access_handler;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_perl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_perl_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (plcf->handler.data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate perl handler \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);

    if (my_perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    plcf->handler = value[1];

    ngx_http_perl_eval_anon_sub(aTHX_ &value[1], &plcf->sub);

    if (plcf->sub == &PL_sv_undef) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (plcf->sub == NULL) {
        plcf->sub = newSVpvn((char *) value[1].data, value[1].len);
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_perl_handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_perl_app(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_perl_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_perl_main_conf_t  *pmcf;
    SV                         *sv;

    value = cf->args->elts;

    if (plcf->handler.data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate perl_handler \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);

    if (my_perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    plcf->handler = value[1];

    sv = newSVpvf("require '%s'", (char *) value[1].data);

    plcf->sub = eval_pv(SvPVX(sv), 1);

    SvREFCNT_dec(sv);

    plcf->read_body = 1;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_perl_handler;

    return NGX_CONF_OK;
}


static char *
ngx_http_perl_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_perl_loc_conf_t *plcf = conf;

    ngx_str_t                  *value;
    ngx_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (plcf->access_handler.data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate perl_access handler \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);

    if (my_perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    plcf->access_handler = value[1];

    ngx_http_perl_eval_anon_sub(aTHX_ &value[1], &plcf->access_sub);

    if (plcf->access_sub == &PL_sv_undef) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (plcf->access_sub == NULL) {
        plcf->access_sub = newSVpvn((char *) value[1].data, value[1].len);
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                   index;
    ngx_str_t                  *value;
    ngx_http_variable_t        *v;
    ngx_http_perl_variable_t   *pv;
    ngx_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    pv = ngx_palloc(cf->pool, sizeof(ngx_http_perl_variable_t));
    if (pv == NULL) {
        return NGX_CONF_ERROR;
    }

    index = ngx_http_get_variable_index(cf, &value[1]);
    if (index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);

    if (my_perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    pv->handler = value[2];

    {

    ngx_http_perl_eval_anon_sub(aTHX_ &value[2], &pv->sub);

    if (pv->sub == &PL_sv_undef) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (pv->sub == NULL) {
        pv->sub = newSVpvn((char *) value[2].data, value[2].len);
    }

    }

    v->get_handler = ngx_http_perl_variable;
    v->data = (uintptr_t) pv;

    return NGX_CONF_OK;
}


static char *
ngx_http_perl_eval(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                  *value;
    ngx_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    pmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_perl_module);

    if (my_perl == NULL) {
        if (ngx_http_perl_init_interpreter(cf, pmcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    eval_pv((char *) value[1].data, TRUE);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_perl_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_perl_main_conf_t  *pmcf;

    pmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_perl_module);

    if (pmcf) {

        /* set worker's $$ */

        sv_setiv(GvSV(gv_fetchpv("$", TRUE, SVt_PV)), (I32) ngx_pid);
    }

    ngx_perl_log = ngx_cycle->log;


    if (pmcf) {
        ngx_str_t   *script;
        ngx_uint_t   i;
        SV          *cb;
        dSP;

        if (pmcf->init_worker == NGX_CONF_UNSET_PTR) {
            return NGX_OK;
        }

        script = pmcf->init_worker->elts;

        for (i = 0; i < pmcf->init_worker->nelts; i++) {

            cb = sv_2mortal ( 
                    newSVpvn ((char *) script[i].data, script[i].len)
                 );

            ENTER;
            SAVETMPS;
            
            PUSHMARK(SP);
            PUTBACK;

            call_sv(cb, G_VOID|G_DISCARD);

            FREETMPS;
            LEAVE;
        }
    }


    return NGX_OK;
}


static void
ngx_http_perl_exit_worker(ngx_cycle_t *cycle)
{
    ngx_http_perl_main_conf_t  *pmcf;

    pmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_perl_module);

    if (pmcf) {
        ngx_str_t   *script;
        ngx_uint_t   i;
        SV          *cb;
        dSP;

        if (pmcf->exit_worker == NGX_CONF_UNSET_PTR) {
            return;
        }

        script = pmcf->exit_worker->elts;

        for (i = 0; i < pmcf->exit_worker->nelts; i++) {

            cb = sv_2mortal ( 
                    newSVpvn ((char *) script[i].data, script[i].len)
                 );

            ENTER;
            SAVETMPS;
            
            PUSHMARK(SP);
            PUTBACK;

            call_sv(cb, G_VOID|G_DISCARD);

            FREETMPS;
            LEAVE;
        }
    }


    return;
}


static void
ngx_http_perl_exit(ngx_cycle_t *cycle)
{

    if (nginx_stash) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "perl term");

        (void) perl_destruct(my_perl);

        perl_free(my_perl);

        PERL_SYS_TERM();
    }
}


ngx_connection_t *
ngx_perl_timer(ngx_int_t after, SV *repeat, SV *cb) 
{
    ngx_connection_t  *c;
    ngx_perl_timer_t  *t;

    c = ngx_get_connection((ngx_socket_t) 0, ngx_perl_log);
    if (c == NULL) {
        return NULL;
    }
 
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->data   = NULL;

    Newz(0, t, 1, ngx_perl_timer_t);

    if (t == NULL) {
        ngx_perl_timer_clear(c);
        return NULL;
    }

    c->read->handler = ngx_perl_timer_callback;
    c->read->active  = 1;
    c->read->log     = c->log;

    c->data = (void *) t;

    t->after  = after;
    t->repeat = repeat;
    t->cb     = cb; 
    
    SvREFCNT_inc(t->repeat);
    SvREFCNT_inc(t->cb);

    ngx_add_timer(c->read, t->after * 1000);

    return c;
}


void
ngx_perl_timer_clear(ngx_connection_t *c) 
{
    ngx_perl_timer_t  *t;

    if (c->destroyed) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ngx_perl_timer_clear: connection already destroyed");
        return;
    }

    if (c->data) {
        t = (ngx_perl_timer_t *) c->data;

        if (t->repeat) {
            SvREFCNT_dec(t->repeat);
            t->repeat = NULL;
        }

        if (t->cb) {
            SvREFCNT_dec(t->cb);
            t->cb = NULL;
        }

        safefree(t);
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->destroyed = 1;
    ngx_free_connection(c);

    return;
}


static void 
ngx_perl_timer_callback(ngx_event_t *ev) 
{
    ngx_connection_t  *c;
    ngx_perl_timer_t  *t;
    SV                *cb;
    dSP;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    c = (ngx_connection_t *) ev->data;
    t = (ngx_perl_timer_t *) c->data;

    cb = t->cb;

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSViv(PTR2IV(c))));
    PUTBACK;

    call_sv(cb, G_VOID|G_DISCARD);

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);

    if (!c->destroyed && SvOK(t->repeat) && SvIV(t->repeat) > 0) {
        ngx_add_timer(ev, SvIV(t->repeat) * 1000);
    } else {
        ngx_perl_timer_clear(c);
    }

    return;
}


void
ngx_perl_resolver(SV *name, SV *timeout, SV *cb)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_perl_resolver_t       *pr;
    ngx_resolver_ctx_t        *ctx, temp;
    ngx_event_t               *ev;
    dSP;

    clcf = ngx_http_cycle_get_module_loc_conf(ngx_cycle, 
                                              ngx_http_core_module);

    errno = 0;

    Newz(0, pr, 1, ngx_perl_resolver_t);

    if (pr == NULL) {
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }


    Newz(0, pr->name.data, SvCUR(name), u_char);

    if (pr->name.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_perl_log, 0,
                      "ngx_perl_resolver: "
                      "Newz failed");
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    ngx_memcpy(pr->name.data, SvPV_nolen(name), SvCUR(name));
    pr->name.len = SvCUR(name);

    temp.name = pr->name;


    pr->cb = cb;
    SvREFCNT_inc(cb);


    ctx = ngx_resolve_start(clcf->resolver, &temp);

    if (ctx == NULL) {
        errno = NGX_PERL_EBADE;
        goto FATAL;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, ngx_perl_log, 0,
                      "ngx_perl_resolver: "
                      "no resolver defined to resolve %V", 
                      &temp.name);
        errno = NGX_PERL_EBADE;
        goto FATAL;
    }

    ctx->name    = pr->name;
    ctx->type    = NGX_RESOLVE_A;
    ctx->handler = ngx_perl_resolver_handler;
    ctx->data    = pr;
    ctx->timeout = clcf->resolver_timeout;

    if (clcf->resolver_timeout == NGX_CONF_UNSET_MSEC) {
        ctx->timeout = 30000; 
    }


    /* timer */

    Newz(0, ev, 1, ngx_event_t);

    if (ev == NULL) {
        ngx_resolve_name_done(ctx);
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    ev->data    = ctx;
    ev->handler = ngx_perl_resolver_timeout_handler;

    pr->ev = ev;

    ngx_add_timer ( ev,  SvOK (timeout) && SvIV (timeout) > 0 
                            ? SvIV (timeout) * 1000 
                            : 15000                            );


    if (ngx_resolve_name(ctx) != NGX_OK) {
        errno = NGX_PERL_EBADE;
        goto FATAL;
    }

    return;

FATAL:

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    PUTBACK;

    call_sv(cb, G_VOID|G_DISCARD); 

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);
    errno = 0;

    if (pr) {
        if (pr->name.data) {
            safefree(pr->name.data);
            pr->name.data = NULL;
        }

        if (pr->cb) {
            SvREFCNT_dec(pr->cb);
            pr->cb = NULL;
        }

        if (pr->ev) {
            if (pr->ev->timer_set) {
                ngx_del_timer(pr->ev);
            }

            safefree(pr->ev);
            pr->ev = NULL;
        }

        safefree(pr);
    }

    return;
}


static void
ngx_perl_resolver_timeout_handler(ngx_event_t *ev)
{
    ngx_resolver_ctx_t  *ctx;

    ctx = (ngx_resolver_ctx_t *) ev->data;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    ngx_perl_resolver_handler(ctx);
    return;
}


static void
ngx_perl_resolver_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_perl_resolver_t  *pr;
    in_addr_t             addr;
    ngx_uint_t            i;
    SV                   *cb;
    dSP;

    pr = (ngx_perl_resolver_t *) ctx->data;

    if (pr->ev->timer_set) {
        ngx_del_timer(pr->ev);
    }


    errno = 0;

    cb = pr->cb;

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, ngx_perl_log, 0,
                      "ngx_perl_resolver: "
                      "\"%V\" could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        if (ctx->state == NGX_RESOLVE_TIMEDOUT) {
            errno = NGX_PERL_ETIMEDOUT;
        } else if (ctx->state == NGX_RESOLVE_NXDOMAIN) {
            errno = NGX_PERL_ENOMSG;
        } else {
            errno = NGX_PERL_EAGAIN;
        }

        XPUSHs(newSViv(ctx->state));
        XPUSHs(newSVpvf("%s", ngx_resolver_strerror(ctx->state)));
    } else {
        EXTEND(SP, ctx->naddrs);

        for (i = 0; i < ctx->naddrs; i++) {
            addr = ctx->addrs[i];
            PUSHs(newSVpvf("%u.%u.%u.%u",
                           (ntohl(addr) >> 24) & 0xff,
                           (ntohl(addr) >> 16) & 0xff,
                           (ntohl(addr) >> 8) & 0xff,
                           ntohl(addr) & 0xff));
        }
    }

    ngx_resolve_name_done(ctx);

    PUTBACK;

    call_sv(cb, G_VOID|G_DISCARD); 

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);
    errno = 0;

    if (pr) {
        if (pr->name.data) {
            safefree(pr->name.data);
            pr->name.data = NULL;
        }

        if (pr->cb) {
            SvREFCNT_dec(pr->cb);
            pr->cb = NULL;
        }

        if (pr->ev) {
            if (pr->ev->timer_set) {
                ngx_del_timer(pr->ev);
            }

            safefree(pr->ev);
            pr->ev = NULL;
        }

        safefree(pr);
    }

    return;
}


ngx_int_t
ngx_perl_connection_init(ngx_connection_t *c) 
{
    ngx_pool_t             *pool;
    ngx_perl_connection_t  *plc;
    ngx_pool_cleanup_t     *plccln;

    errno = 0;

    pool = c->pool;

    plc = ngx_pcalloc(pool, sizeof(ngx_perl_connection_t));

    if (plc == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_perl_connection_init: ngx_pcalloc() failed");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_ENOMEM;
        return 0;
    }

    plccln = ngx_pool_cleanup_add(pool, 0);

    if (plccln == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
            "ngx_perl_connection_init: ngx_pool_cleanup_add() failed");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_ENOMEM;
        return 0;
    }

    plccln->data    = (void *) plc;
    plccln->handler = ngx_perl_connection_cleanup;

    c->data = (void *) plc;

    c->write->handler = ngx_perl_dummy_handler;
    c->read->handler  = ngx_perl_dummy_handler;

    return 1;
}


ngx_connection_t *
ngx_perl_connector(SV *address, SV *port, SV *timeout, SV *cb) 
{
    in_addr_t               inaddr;
    in_port_t               inport;
    ngx_pool_t             *pool;
    struct sockaddr_in     *sin;
    ngx_peer_connection_t  *peer;
    ngx_perl_connection_t  *plc;
    ngx_pool_cleanup_t     *plccln;
    ngx_connection_t       *c;
    ngx_int_t               rc;
    dSP;

    errno = 0;

    if (!SvOK(address) || !SvOK(port) || !SvOK(timeout)) {
        ngx_log_error(NGX_LOG_ERR, ngx_perl_log, 0,
                      "ngx_perl_connector: incorrect argument(s)");
        errno = NGX_PERL_EINVAL;
        goto FATAL;
    }

    inport = (in_port_t) SvIV(port);

    inaddr = ngx_inet_addr((u_char *) SvPV_nolen(address), SvCUR(address));

    if (inaddr == INADDR_NONE) {
        ngx_log_error(NGX_LOG_ERR, ngx_perl_log, 0,
                      "ngx_perl_connector: incorrect address");
        errno = NGX_PERL_EINVAL;
        goto FATAL;
    }

    pool = ngx_create_pool(1024, ngx_perl_log);

    if (pool == NULL) {
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));

    if (sin == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "ngx_perl_connector: ngx_pcalloc() failed");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    sin->sin_family      = AF_INET;
    sin->sin_addr.s_addr = inaddr;
    sin->sin_port        = htons(inport);



    plc = ngx_pcalloc(pool, sizeof(ngx_perl_connection_t));

    if (plc == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "ngx_perl_connector: ngx_pcalloc() failed");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    plccln = ngx_pool_cleanup_add(pool, 0);

    if (plccln == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "ngx_perl_connector: ngx_pool_cleanup_add() failed");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    plccln->data    = (void *) plc;
    plccln->handler = ngx_perl_connection_cleanup;



    peer = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));

    if (peer == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "ngx_perl_connector: ngx_pcalloc() failed");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    peer->sockaddr  = (struct sockaddr *) sin;
    peer->socklen   = sizeof(struct sockaddr_in);
    peer->get       = ngx_event_get_peer;
    peer->log       = pool->log;
    peer->log_error = NGX_ERROR_ERR;


    peer->name = ngx_pcalloc(pool, sizeof(ngx_str_t));

    if (peer->name == NULL) {
        ngx_log_error(NGX_LOG_ERR, peer->log, 0,
                      "ngx_perl_connector: ngx_pcalloc() failed");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    peer->name->data = ngx_pcalloc(pool, SvCUR(address));

    if (peer->name->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, peer->log, 0,
                      "ngx_perl_connector: ngx_pcalloc() failed");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_ENOMEM;
        goto FATAL;
    }

    ngx_memcpy(peer->name->data, SvPV_nolen(address), SvCUR(address));
    peer->name->len = SvCUR(address);



    rc = ngx_event_connect_peer(peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, peer->log, 0,
                      "ngx_perl_connector: ngx_event_connect_peer() failed");

        if (peer->connection) 
            ngx_close_connection(peer->connection);

        ngx_destroy_pool(pool);

        errno = NGX_PERL_EBADF;
        goto FATAL;
    }


    c = peer->connection;

    if (c == NULL) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                      "ngx_perl_connector: no peer->connection");
        ngx_destroy_pool(pool);
        errno = NGX_PERL_EBADF;
        goto FATAL;
    }

    c->pool = pool;
    c->log  = pool->log;
    c->data = (void *) plc;

    plc->connect_cb = cb;
    SvREFCNT_inc(cb);

    c->write->handler = ngx_perl_connect_handler;
    c->read->handler  = ngx_perl_connect_handler;

    ngx_add_timer(c->write, SvOK(timeout) && SvIV(timeout) 
                                ? SvIV(timeout) * 1000 : 15000);

    if (rc == NGX_OK) {
        c->write->handler(c->write);
        return c;
    } 

    return c;

FATAL:

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    PUTBACK;

    call_sv(cb, G_VOID|G_DISCARD); 

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);
    errno = 0;

    return NULL;
}


void
ngx_perl_reader(ngx_connection_t *c, SV *buf, SV *min, SV *max, 
        SV *timeout, SV *cb) 
{
    ngx_perl_connection_t  *plc;

    plc = (ngx_perl_connection_t *) c->data;

    if (plc->read_min) {
        SvREFCNT_dec(plc->read_min);
        plc->read_min = NULL;
    }

    if (plc->read_max) {
        SvREFCNT_dec(plc->read_max);
        plc->read_max = NULL;
    }

    if (plc->read_timeout) {
        SvREFCNT_dec(plc->read_timeout);
        plc->read_timeout = NULL;
    }

    if (plc->read_buffer) {
        SvREFCNT_dec(plc->read_buffer);
        plc->read_buffer = NULL;
    }

    if (plc->read_cb) {
        SvREFCNT_dec(plc->read_cb);
        plc->read_cb = NULL;
    }

    plc->read_min     = min;
    plc->read_max     = max;
    plc->read_buffer  = buf;
    plc->read_timeout = timeout;
    plc->read_cb      = cb;

    SvREFCNT_inc(min);
    SvREFCNT_inc(max);
    SvREFCNT_inc(buf);
    SvREFCNT_inc(timeout);
    SvREFCNT_inc(cb);

    return;
}


void
ngx_perl_writer(ngx_connection_t *c, SV *buf, SV *timeout, SV *cb) 
{
    ngx_perl_connection_t  *plc;

    plc = (ngx_perl_connection_t *) c->data;

    if (plc->write_timeout) {
        SvREFCNT_dec(plc->write_timeout);
        plc->write_timeout = NULL;
    }

    if (plc->write_buffer) {
        SvREFCNT_dec(plc->write_buffer);
        plc->write_buffer = NULL;
    }

    if (plc->write_cb) {
        SvREFCNT_dec(plc->write_cb);
        plc->write_cb = NULL;
    }

    plc->write_buffer  = buf;
    plc->write_timeout = timeout;
    plc->write_cb      = cb;

    SvREFCNT_inc(buf);
    SvREFCNT_inc(timeout);
    SvREFCNT_inc(cb);

    return;
}


void
ngx_perl_ssl_handshaker(ngx_connection_t *c, SV *timeout, SV *cb) 
{
#if (NGX_HTTP_SSL)
    ngx_perl_connection_t     *plc;
    ngx_http_perl_loc_conf_t  *plcf;

    plc = (ngx_perl_connection_t *) c->data;

    if (plc->ssl_handshake_timeout) {
        SvREFCNT_dec(plc->ssl_handshake_timeout);
        plc->ssl_handshake_timeout = NULL;
    }

    if (plc->ssl_handshake_cb) {
        SvREFCNT_dec(plc->ssl_handshake_cb);
        plc->ssl_handshake_cb = NULL;
    }

    plc->ssl                   = 1;
    plc->ssl_handshake_cb      = cb;
    plc->ssl_handshake_timeout = timeout;

    SvREFCNT_inc(cb);
    SvREFCNT_inc(timeout);


    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (!c->write->timer_set) {

        if (plc->ssl_handshake_timeout != NULL  && 
            SvOK  (plc->ssl_handshake_timeout)  && 
            SvIV  (plc->ssl_handshake_timeout) >= 0) 
        {
            ngx_add_timer(c->write, SvIV(plc->ssl_handshake_timeout) * 1000);

        } else {

            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "ngx_perl_ssl_handshaker: "
                "incorrent timeout, using 15 s instead");

            ngx_add_timer(c->write, 15000);
        }
    }


    plcf = ngx_http_cycle_get_module_loc_conf(ngx_cycle, ngx_http_perl_module);

    if ( ngx_ssl_create_connection
            ( plcf->ssl, 
              c,
              NGX_SSL_BUFFER|NGX_SSL_CLIENT ) != NGX_OK ) 
    {
        c->error = 1;
        ngx_perl_ssl_handshake_handler(c);
        return;
    }

    c->sendfile = 0;
    c->log->action = "SSL handshaking with peer";

    return;
#else 
    dSP;

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
        "ngx_perl_ssl_handshake: "
        "SSL support is required to use ngx_ssl_handshaker()");

    errno = NGX_PERL_ENOTSUP; 

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    PUTBACK;

    call_sv(cb, G_VOID|G_DISCARD); 

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);
    errno = 0;

    return;
#endif
}


static void
ngx_perl_connection_cleanup(void *data)
{
    ngx_perl_connection_t  *plc;

    plc = (ngx_perl_connection_t *) data;


    if (plc->connect_cb) {
        SvREFCNT_dec(plc->connect_cb);
        plc->connect_cb = NULL;
    }


    if (plc->read_min) {
        SvREFCNT_dec(plc->read_min);
        plc->read_min = NULL;
    }

    if (plc->read_max) {
        SvREFCNT_dec(plc->read_max);
        plc->read_max = NULL;
    }

    if (plc->read_timeout) {
        SvREFCNT_dec(plc->read_timeout);
        plc->read_timeout = NULL;
    }

    if (plc->read_buffer) {
        SvREFCNT_dec(plc->read_buffer);
        plc->read_buffer = NULL;
    }

    if (plc->read_cb) {
        SvREFCNT_dec(plc->read_cb);
        plc->read_cb = NULL;
    }


    if (plc->write_timeout) {
        SvREFCNT_dec(plc->write_timeout);
        plc->write_timeout = NULL;
    }

    if (plc->write_buffer) {
        SvREFCNT_dec(plc->write_buffer);
        plc->write_buffer = NULL;
    }

    if (plc->write_cb) {
        SvREFCNT_dec(plc->write_cb);
        plc->write_cb = NULL;
    }

#if (NGX_HTTP_SSL)

    if (plc->ssl_handshake_timeout) {
        SvREFCNT_dec(plc->ssl_handshake_timeout);
        plc->ssl_handshake_timeout = NULL;
    }

    if (plc->ssl_handshake_cb) {
        SvREFCNT_dec(plc->ssl_handshake_cb);
        plc->ssl_handshake_cb = NULL;
    }

#endif

    return;
}


void
ngx_perl_close(ngx_connection_t *c) 
{
    ngx_pool_t  *pool;

    if (c->destroyed) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_close: "
            "connection already destroyed");
        return;
    }

#if (NGX_HTTP_SSL)

    /* XXX taken from ngx_http_upstream.c */

    /* TODO: do not shutdown persistent connection */

    if (c->ssl) {

        /*
         * We send the "close notify" shutdown alert to the upstream only
         * and do not wait its "close notify" shutdown alert.
         * It is acceptable according to the TLS standard.
         */

        c->ssl->no_wait_shutdown = 1;

        (void) ngx_ssl_shutdown(c);
    }

#endif

    pool = c->pool; 

    ngx_close_connection(c);
    ngx_destroy_pool(pool);

    return;
}


void
ngx_perl_read(ngx_connection_t *c) 
{
    ngx_perl_connection_t  *plc;

    plc = (ngx_perl_connection_t *) c->data;
 
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
 
    c->read->handler  = ngx_perl_read_handler;
    c->write->handler = ngx_perl_dummy_handler;

    if (c->read->ready) {
        c->read->handler(c->read);
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {

        if (c->read->error == 0) 
            c->read->error = 1;

        c->read->handler(c->read);
        return;
    }

    if (!c->read->timer_set) {

        if (plc->read_timeout != NULL  && 
            SvOK  (plc->read_timeout)  && 
            SvIV  (plc->read_timeout) >= 0) 
        {
            ngx_add_timer(c->read, SvIV(plc->read_timeout) * 1000);

        } else {

            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "ngx_perl_read: "
                "incorrent read timeout, using 15 s instead");

            ngx_add_timer(c->read, 15000);
        }
    }

    return;
}


void
ngx_perl_write(ngx_connection_t *c) 
{
    ngx_perl_connection_t  *plc;

    plc = (ngx_perl_connection_t *) c->data;

    plc->write_offset = 0;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->read->handler  = ngx_perl_dummy_handler;
    c->write->handler = ngx_perl_write_handler;

    if (c->write->ready) {
        ngx_post_event(c->write, &ngx_posted_events);
        return;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {

        if (c->write->error == 0) 
            c->write->error = 1;

        c->write->handler(c->write);
        return;
    }

    if (!c->write->timer_set) {

        if (plc->write_timeout != NULL  && 
            SvOK  (plc->write_timeout)  && 
            SvIV  (plc->write_timeout) >= 0) 
        {
            ngx_add_timer(c->write, SvIV(plc->write_timeout) * 1000);

        } else {

            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "ngx_perl_write: "
                "incorrent write timeout, using 15 s instead");

            ngx_add_timer(c->write, 15000);
        }
    }

    return;
}


#if (NGX_HTTP_SSL)

void
ngx_perl_ssl_handshake(ngx_connection_t *c) 
{
    ngx_perl_connection_t  *plc;
    ngx_int_t               rc;

    plc = (ngx_perl_connection_t *) c->data;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (!c->write->timer_set) {

        if (plc->ssl_handshake_timeout != NULL  && 
            SvOK  (plc->ssl_handshake_timeout)  && 
            SvIV  (plc->ssl_handshake_timeout) >= 0) 
        {
            ngx_add_timer(c->write, SvIV(plc->ssl_handshake_timeout) * 1000);

        } else {

            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "ngx_perl_ssl_handshaker: "
                "incorrent timeout, using 15 s instead");

            ngx_add_timer(c->write, 15000);
        }
    }

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        c->ssl->handler = ngx_perl_ssl_handshake_handler;
        return;
    }

    ngx_perl_ssl_handshake_handler(c);

    return;
}

#endif


void
ngx_perl_noop(ngx_connection_t *c) 
{

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->read->handler  = ngx_perl_dummy_handler;
    c->write->handler = ngx_perl_dummy_handler;

    return;
}


static void
ngx_perl_dummy_handler(ngx_event_t *ev) 
{
    ngx_connection_t  *c;

    c = (ngx_connection_t *) ev->data;

    ngx_log_debug(NGX_LOG_DEBUG, c->log, 0,
        "ngx_perl_dummy_handler called");

    return;
}


static void
ngx_perl_connect_handler(ngx_event_t *ev) 
{
    ngx_connection_t       *c;
    ngx_perl_connection_t  *plc;
    ngx_int_t               cmd, count;
    SV                     *cb;
    dSP;

    c   = (ngx_connection_t *)      ev->data;
    plc = (ngx_perl_connection_t *) c->data;

    errno = 0;

    c->read->handler  = ngx_perl_dummy_handler;
    c->write->handler = ngx_perl_dummy_handler;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->timedout) {
        errno = NGX_PERL_ETIMEDOUT;
        goto CALLBACK;
    }

    if (ev->error || c->error) {
        errno = NGX_PERL_EBADE;
        goto CALLBACK;
    }

    errno = 0;

CALLBACK:

    cb = plc->connect_cb;

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSViv(PTR2IV(c)))); 
    PUTBACK;

    count = call_sv(cb, G_SCALAR); 

    if (count != 1) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_connect_handler: "
            "call_sv returned wrong count = %i",
            count);
    }

    SPAGAIN;
    cmd = POPi;
    PUTBACK;

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);
    errno = 0;

    if ((ev->error || c->error || ev->timedout) && cmd != NGX_PERL_CLOSE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_connect_handler: "
            "NGX_CLOSE required on error and timeout here, forcing");
        ngx_perl_close(c);
        return;
    }

    switch (cmd) {
        case NGX_PERL_CLOSE:
            ngx_perl_close(c);
            break;
        case NGX_PERL_READ:
            ngx_perl_read(c);
            break;
        case NGX_PERL_WRITE:
            ngx_perl_write(c);
            break;
        case NGX_PERL_SSL_HANDSHAKE:
#if (NGX_HTTP_SSL)
            ngx_perl_ssl_handshake(c);
#else
            ngx_perl_close(c);
#endif
            break;
        case NGX_PERL_NOOP:
            ngx_perl_noop(c);
            break;
    }

    return;
}


static void
ngx_perl_read_handler(ngx_event_t *ev)
{
    ssize_t                 n;
    ngx_connection_t       *c;
    ngx_perl_connection_t  *plc;
    SV                     *sv, *cb;
    U32                     min, max;
    ngx_int_t               cmd, count;
    dSP;

    c   = (ngx_connection_t *) ev->data;
    plc = (ngx_perl_connection_t *) c->data;

    errno = 0;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->timedout) {
        errno = NGX_PERL_ETIMEDOUT;
        goto CALLBACK;
    }

AGAIN:

    if (ev->error || c->error) {
        errno = NGX_PERL_EBADE;
        goto CALLBACK;
    }


    min = 0;
    max = 0;

    if (  SvOK ( plc->read_min ) && 
          SvIV ( plc->read_min )     ) 
        min = SvIV ( plc->read_min );

    if (  SvOK ( plc->read_max ) && 
          SvIV ( plc->read_max )     ) 
        max = SvIV ( plc->read_max );


    sv = plc->read_buffer;

    if (SvTYPE (sv) != SVt_PV) {
        SvUPGRADE (sv, SVt_PV);
        SvPOK_on (sv);
    }
    
    for ( ;; ) {

        if ( SvLEN(sv) - SvCUR(sv) < 1500) {
            if ( max ) {
                if ( SvLEN(sv) < max + 1 ) {
                    SvGROW(sv, ( SvCUR(sv) * 2 ) + 1500);
                } else {
                    if ( SvCUR(sv) >= max ) {
                        errno = NGX_PERL_ENOMEM;
                        goto CALLBACK;
                    }
                }
            } else {
                SvGROW(sv, ( SvCUR(sv) * 2 ) + 1500);
            }
        }

        ngx_socket_errno = 0;

        n = c->recv(c, (u_char *) SvPVX (sv) + SvCUR (sv), 
                       ( max && SvLEN (sv) > max 
                               ? max : SvLEN (sv) - 1 ) - SvCUR (sv));

        if (n == NGX_AGAIN) {

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                errno = NGX_PERL_EBADE;
                goto CALLBACK;
            }

            if (!c->read->timer_set) {

                if (plc->read_timeout != NULL  && 
                    SvOK  (plc->read_timeout)  && 
                    SvIV  (plc->read_timeout) >= 0) 
                {
                    ngx_add_timer(c->read, SvIV(plc->read_timeout) * 1000);

                } else {

                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "ngx_perl_read_handler: "
                        "incorrent read timeout, using 15 s instead");

                    ngx_add_timer(c->read, 15000);
                }
            }

            return;
        }

        if (n == 0) {
            errno = NGX_PERL_EOF;
            goto CALLBACK;
        }

        if (n == NGX_ERROR) {
            errno = ngx_socket_errno ? ngx_socket_errno : NGX_PERL_EBADE;
            goto CALLBACK;
        }

        SvCUR_set (sv, SvCUR (sv) + n);

        if ( SvCUR (sv) < min ) {
            continue;
        }

        break;
    }

    errno = 0;

CALLBACK:

    cb = plc->read_cb;

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSViv(PTR2IV(c)))); 
    PUTBACK;

    ngx_log_debug(NGX_LOG_DEBUG, c->log, 0,
        "ngx_perl_read_handler: "
        "ev->eof = %i, ev->error = %i, c->error = %i",
        ev->eof, ev->error, c->error);

    count = call_sv(cb, G_SCALAR); 

    if (count != 1) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_read_handler: "
            "call_sv returned wrong count = %i",
            count);
    }

    SPAGAIN;
    cmd = POPi;
    PUTBACK;

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);
    errno = 0;

    if ((ev->error || c->error) && cmd != NGX_PERL_CLOSE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_read_handler: "
            "NGX_CLOSE required on error here, forcing");
        ngx_perl_close(c);
        return;
    }

    switch (cmd) {
        case NGX_PERL_CLOSE:
            ngx_perl_close(c);
            break;
        case NGX_PERL_READ:
            if (c->read->ready) {
                goto AGAIN;
            } else {
                ngx_perl_read(c);
            }
            break;
        case NGX_PERL_WRITE:
            ngx_perl_write(c);
            break;
        case NGX_PERL_SSL_HANDSHAKE:
#if (NGX_HTTP_SSL)
            ngx_perl_ssl_handshake(c);
#else
            ngx_perl_close(c);
#endif
            break;
        case NGX_PERL_NOOP:
            ngx_perl_noop(c);
            break;
    }

    return;
}


static void
ngx_perl_write_handler(ngx_event_t *ev)
{
    ssize_t                 n;
    ngx_connection_t       *c;
    ngx_perl_connection_t  *plc;
    SV                     *sv, *cb;
    ngx_int_t               cmd, count;
    dSP;

    c   = (ngx_connection_t *) ev->data;
    plc = (ngx_perl_connection_t *) c->data;

    errno = 0;

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    if (ev->timedout) {
        errno = NGX_PERL_ETIMEDOUT;
        goto CALLBACK;
    }

AGAIN:

    if (ev->error || c->error) {
        errno = NGX_PERL_EBADE;
        goto CALLBACK;
    }

    sv = plc->write_buffer;

    if (SvTYPE (sv) != SVt_PV || SvCUR (sv) <= 0) {
        errno = 0;
        goto CALLBACK;
    }

    for ( ;; ) {

        ngx_socket_errno = 0;

        n = c->send(c, (u_char *) SvPV_nolen (sv) + plc->write_offset, 
                                  SvCUR (sv) - plc->write_offset); 

        if (n == NGX_AGAIN) {

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                errno = NGX_PERL_EBADE;
                goto CALLBACK;
            }

            if (!c->write->timer_set) {

                if (plc->write_timeout != NULL  && 
                    SvOK  (plc->write_timeout)  && 
                    SvIV  (plc->write_timeout) >= 0) 
                {
                    ngx_add_timer(c->write, SvIV(plc->write_timeout) * 1000);

                } else {

                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "ngx_perl_write_handler: "
                        "incorrent write timeout, using 15 s instead");

                    ngx_add_timer(c->write, 15000);
                }
            }

            return;
        }

        if (n == 0) {
            errno = NGX_PERL_EOF;
            goto CALLBACK;
        }

        if (n == NGX_ERROR) {
            errno = ngx_socket_errno ? ngx_socket_errno : NGX_PERL_EBADE;
            goto CALLBACK;
        }

        plc->write_offset += n;

        if (SvCUR(sv) - plc->write_offset > 0) {
            continue;
        }

        break;
    }

    errno = 0;

CALLBACK:

    plc->write_offset = 0;

    cb = plc->write_cb;

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSViv(PTR2IV(c)))); 
    PUTBACK;

    count = call_sv(cb, G_SCALAR); 

    if (count != 1) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_write_handler: "
            "call_sv returned wrong count = %i",
            count);
    }

    SPAGAIN;
    cmd = POPi;
    PUTBACK;

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);
    errno = 0;

    if ((ev->error || c->error) && cmd != NGX_PERL_CLOSE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_write_handler: "
            "NGX_CLOSE required on error here, forcing");
        ngx_perl_close(c);
        return;
    }

    switch (cmd) {
        case NGX_PERL_CLOSE:
            ngx_perl_close(c);
            break;
        case NGX_PERL_READ:
            ngx_perl_read(c);
            break;
        case NGX_PERL_WRITE:
            if (c->write->ready) {
                goto AGAIN;
            } else {
                ngx_perl_write(c);
            }
            break;
        case NGX_PERL_SSL_HANDSHAKE:
#if (NGX_HTTP_SSL)
            ngx_perl_ssl_handshake(c);
#else
            ngx_perl_close(c);
#endif
            break;
        case NGX_PERL_NOOP:
            ngx_perl_noop(c);
            break;
    }

    return;
}


#if (NGX_HTTP_SSL)

static void
ngx_perl_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_perl_connection_t  *plc;
    SV                     *cb;
    ngx_int_t               cmd, count;
    dSP;

    plc = (ngx_perl_connection_t *) c->data;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (c->write->timedout) {
        errno = NGX_PERL_ETIMEDOUT;
        goto CALLBACK;
    }

    if (c->error) {
        errno = NGX_PERL_EBADE;
        goto CALLBACK;
    }

    if (c->ssl->handshaked) {
        errno = 0;
        goto CALLBACK;
    }

    c->error = 1;
    errno = NGX_PERL_EBADE;

CALLBACK:

    cb = plc->ssl_handshake_cb;

    SvREFCNT_inc(cb);

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSViv(PTR2IV(c)))); 
    PUTBACK;

    count = call_sv(cb, G_SCALAR); 

    if (count != 1) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_ssl_handshake_handler: "
            "call_sv returned wrong count = %i",
            count);
    }

    SPAGAIN;
    cmd = POPi;
    PUTBACK;

    FREETMPS;
    LEAVE;

    SvREFCNT_dec(cb);
    errno = 0;

    if ((c->error) && cmd != NGX_PERL_CLOSE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_ssl_handshake_handler: "
            "NGX_CLOSE required on error here, forcing");
        ngx_perl_close(c);
        return;
    }

    switch (cmd) {
        case NGX_PERL_CLOSE:
            ngx_perl_close(c);
            break;
        case NGX_PERL_READ:
            ngx_perl_read(c);
            break;
        case NGX_PERL_WRITE:
            ngx_perl_write(c);
            break;
        case NGX_PERL_SSL_HANDSHAKE:
            ngx_perl_ssl_handshake(c);
            break;
        case NGX_PERL_NOOP:
            ngx_perl_noop(c);
            break;
    }

    return;
}

#endif


