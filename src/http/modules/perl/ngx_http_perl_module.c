
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_perl_module.h>


typedef struct {
    ngx_array_t       *modules;
    ngx_array_t       *requires;
} ngx_http_perl_main_conf_t;


typedef struct {
    SV                *sub;
    ngx_str_t          handler;
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
static void *ngx_http_perl_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_perl_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_perl_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_perl_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_perl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_perl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_perl_init_worker(ngx_cycle_t *cycle);
static void ngx_http_perl_exit(ngx_cycle_t *cycle);

static void ngx_perl_timer_callback(ngx_event_t *ev);
static void ngx_perl_connection_cleanup(void *data);
static void ngx_perl_connect_handler(ngx_event_t *ev);
static void ngx_perl_dummy_handler(ngx_event_t *ev);
static void ngx_perl_read_handler(ngx_event_t *ev);
static void ngx_perl_write_handler(ngx_event_t *ev);


static ngx_command_t  ngx_http_perl_commands[] = {

    { ngx_string("perl_modules"),
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

    { ngx_string("perl"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_perl,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("perl_set"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_perl_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_perl_module_ctx = {
    ngx_http_perl_preconfiguration,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

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
    NULL,                                  /* exit process */
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


static ngx_int_t
ngx_http_perl_handler(ngx_http_request_t *r)
{
    r->main->count++;

    ngx_http_perl_handle_request(r);

    return NGX_DONE;
}


void
ngx_http_perl_handle_request(ngx_http_request_t *r)
{
    SV                         *sub;
    ngx_int_t                   rc;
    ngx_str_t                   uri, args, *handler;
    ngx_http_perl_ctx_t        *ctx;
    ngx_http_perl_loc_conf_t   *plcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "perl handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);
    }


    if (ctx->next == NULL) {
        plcf = ngx_http_get_module_loc_conf(r, ngx_http_perl_module);
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);
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

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl ssi handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_perl_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_perl_module);
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
    SV                *sv;
    int                n, status;
    char              *line;
    u_char            *err;
    STRLEN             len, n_a;
    ngx_uint_t         i;
    ngx_connection_t  *c;

    dSP;

    status = 0;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);

    sv = sv_2mortal(sv_bless(newRV_noinc(newSViv(PTR2IV(r))), nginx_stash));
    XPUSHs(sv);

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

    pmcf->modules = NGX_CONF_UNSET_PTR;
    pmcf->requires = NGX_CONF_UNSET_PTR;

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

    return NGX_OK;
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

    c = ngx_get_connection((ngx_socket_t) 0, ngx_cycle->log);
    if (c == NULL) {
        return NULL;
    }
 
    Newz(0, t, 1, ngx_perl_timer_t);
    if (t == NULL) {
        return NULL;
    }

    c->read->handler = ngx_perl_timer_callback;
    c->read->active  = 1;
    c->read->log     = ngx_cycle->log;

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

    t = (ngx_perl_timer_t *) c->data;

    SvREFCNT_dec(t->repeat);
    SvREFCNT_dec(t->cb);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    safefree(t);
    ngx_free_connection(c);

    return;
}


static void 
ngx_perl_timer_callback(ngx_event_t *ev) 
{
    ngx_connection_t  *c;
    ngx_perl_timer_t  *t;
    dSP;

    c = (ngx_connection_t *) ev->data;
    t = (ngx_perl_timer_t *) c->data;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSViv(PTR2IV(c))));
    PUTBACK;

    call_sv(t->cb, G_VOID|G_DISCARD);

    FREETMPS;
    LEAVE;

    if (SvIV(t->repeat) > 0) {
        ngx_add_timer(ev, SvIV(t->repeat) * 1000);
    } else {
        ngx_perl_timer_clear(c);
    }

    return;
}


void
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

    ngx_memcpy(peer->name->data, SvPVX(address), SvCUR(address));
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
        return;
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

    return;
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

    c->read->handler  = ngx_perl_read_handler;
    c->write->handler = ngx_perl_dummy_handler;

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

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->read->handler  = ngx_perl_read_handler;
    c->write->handler = ngx_perl_write_handler;

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


void
ngx_perl_noop(ngx_connection_t *c) 
{

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

    count = call_sv(cb, G_VOID|G_SCALAR); 

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

    if ((ev->error || c->error) && cmd != NGX_PERL_CLOSE) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "ngx_perl_connect_handler: "
            "NGX_CLOSE required on error, forcing");
        ngx_perl_close(c);
        return;
    }

    switch (cmd) {
        case NGX_PERL_CLOSE:
            ngx_perl_close(c);
            break;
        case NGX_PERL_READ:
            ngx_perl_read(c);
            if (c->read->ready) {
                c->read->handler(c->read);
            }
            break;
        case NGX_PERL_WRITE:
            ngx_perl_write(c);
            if (c->write->ready) {
                c->write->handler(c->write);
            }
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

    SvPOK_on(sv);
    
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

    count = call_sv(cb, G_VOID|G_SCALAR); 

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
            "NGX_CLOSE required on error, forcing");
        ngx_perl_close(c);
        return;
    }

    switch (cmd) {
        case NGX_PERL_CLOSE:
            ngx_perl_close(c);
            break;
        case NGX_PERL_READ:
            ngx_perl_read(c);
            if (c->read->ready) {
                goto AGAIN;
            }
            break;
        case NGX_PERL_WRITE:
            ngx_perl_write(c);
            if (c->write->ready) {
                c->write->handler(c->write);
            }
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

    for ( ;; ) {

        ngx_socket_errno = 0;

        n = c->send(c, (u_char *) SvPV_nolen (sv) + plc->write_offset, 
                                  SvCUR (sv) - plc->write_offset); 

        if (n == NGX_AGAIN) {

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                errno = NGX_PERL_EBADE;
                goto CALLBACK;
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

    count = call_sv(cb, G_VOID|G_SCALAR); 

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
            "NGX_CLOSE required on error, forcing");
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
            if (c->write->ready) {
                goto AGAIN;
            }
            break;
        case NGX_PERL_NOOP:
            ngx_perl_noop(c);
            break;
    }

    return;
}


