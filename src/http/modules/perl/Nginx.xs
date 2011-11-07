
/*
 * Copyright (C) Igor Sysoev, Alexandr Gomoliako
 */


#define PERL_NO_GET_CONTEXT

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_perl_module.h>

#include "XSUB.h"


#define ngx_http_perl_set_request(r)                                          \
    if ( !SvOK( ST(0) ) || !SvROK( ST(0) )  || !SvOK(SvRV( ST(0) )) ) {       \
        ngx_log_error(NGX_LOG_ERR,                                            \
                      ngx_perl_log ? ngx_perl_log : ngx_cycle->log,           \
                      0,                                                      \
                      "perl: attempt to use destroyed request");              \
        XSRETURN_UNDEF;                                                       \
    }                                                                         \
    r = INT2PTR(ngx_http_request_t *, SvIV((SV *) SvRV(ST(0))))


#define ngx_http_perl_set_targ(p, len)                                        \
                                                                              \
    SvUPGRADE(TARG, SVt_PV);                                                  \
    SvPOK_on(TARG);                                                           \
    sv_setpvn(TARG, (char *) p, len)


static ngx_int_t
ngx_http_perl_sv2str(pTHX_ ngx_http_request_t *r, ngx_str_t *s, SV *sv)
{
    u_char  *p;
    STRLEN   len;

    if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
        sv = SvRV(sv);
    }

    p = (u_char *) SvPV(sv, len);

    s->len = len;

    if (SvREADONLY(sv) && SvPOK(sv)) {
        s->data = p;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl sv2str: %08XD \"%V\"", sv->sv_flags, s);

        return NGX_OK;
    }

    s->data = ngx_pnalloc(r->pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->data, p, len);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sv2str: %08XD \"%V\"", sv->sv_flags, s);

    return NGX_OK;
}


static ngx_int_t
ngx_http_perl_output(ngx_http_request_t *r, ngx_buf_t *b)
{
    ngx_chain_t           out;
#if (NGX_HTTP_SSI)
    ngx_chain_t          *cl;
    ngx_http_perl_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

    if (ctx->ssi) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;
        *ctx->ssi->last_out = cl;
        ctx->ssi->last_out = &cl->next;

        return NGX_OK;
    }
#endif

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

#define ci(stash, a, b)   newCONSTSUB (stash, a, newSViv(b))

MODULE = Nginx    PACKAGE = Nginx

BOOT:
    HV *stash = gv_stashpv ("Nginx", 1);
    ci (stash, "NGX_DONE",                       NGX_DONE);
    ci (stash, "NGX_HTTP_LAST",                  NGX_HTTP_LAST);
    ci (stash, "NGX_OK",                         NGX_OK);
    ci (stash, "NGX_DECLINED",                   NGX_DECLINED);
    ci (stash, "NGX_NOOP",                       NGX_PERL_NOOP);
    ci (stash, "NGX_READ",                       NGX_PERL_READ);
    ci (stash, "NGX_WRITE",                      NGX_PERL_WRITE);
    ci (stash, "NGX_CLOSE",                      NGX_PERL_CLOSE);
    ci (stash, "NGX_SSL_HANDSHAKE",              NGX_PERL_SSL_HANDSHAKE);
    ci (stash, "NGX_EOF",                        NGX_PERL_EOF);
    ci (stash, "NGX_EINVAL",                     NGX_PERL_EINVAL);
    ci (stash, "NGX_ENOMEM",                     NGX_PERL_ENOMEM);
    ci (stash, "NGX_EBADF",                      NGX_PERL_EBADF);
    ci (stash, "NGX_EBADE",                      NGX_PERL_EBADE);
    ci (stash, "NGX_EAGAIN",                     NGX_PERL_EAGAIN);
    ci (stash, "NGX_ENOMSG",                     NGX_PERL_ENOMSG);
    ci (stash, "NGX_ETIMEDOUT",                  NGX_PERL_ETIMEDOUT);
    ci (stash, "NGX_ENOTSUP",                    NGX_PERL_ENOTSUP);
    ci (stash, "NGX_RESOLVE_FORMERR",            NGX_RESOLVE_FORMERR);
    ci (stash, "NGX_RESOLVE_SERVFAIL",           NGX_RESOLVE_SERVFAIL);
    ci (stash, "NGX_RESOLVE_NXDOMAIN",           NGX_RESOLVE_NXDOMAIN);
    ci (stash, "NGX_RESOLVE_NOTIMP",             NGX_RESOLVE_NOTIMP);
    ci (stash, "NGX_RESOLVE_REFUSED",            NGX_RESOLVE_REFUSED);
    ci (stash, "NGX_RESOLVE_TIMEDOUT",           NGX_RESOLVE_TIMEDOUT);
    ci (stash, "OK",                             0);
    ci (stash, "DECLINED",                       -5);
    ci (stash, "HTTP_OK",                        200);
    ci (stash, "HTTP_CREATED",                   201);
    ci (stash, "HTTP_ACCEPTED",                  202);
    ci (stash, "HTTP_NO_CONTENT",                204);
    ci (stash, "HTTP_PARTIAL_CONTENT",           206);
    ci (stash, "HTTP_MOVED_PERMANENTLY",         301);
    ci (stash, "HTTP_MOVED_TEMPORARILY",         302);
    ci (stash, "HTTP_REDIRECT",                  302);
    ci (stash, "HTTP_NOT_MODIFIED",              304);
    ci (stash, "HTTP_BAD_REQUEST",               400);
    ci (stash, "HTTP_UNAUTHORIZED",              401);
    ci (stash, "HTTP_PAYMENT_REQUIRED",          402);
    ci (stash, "HTTP_FORBIDDEN",                 403);
    ci (stash, "HTTP_NOT_FOUND",                 404);
    ci (stash, "HTTP_NOT_ALLOWED",               405);
    ci (stash, "HTTP_NOT_ACCEPTABLE",            406);
    ci (stash, "HTTP_REQUEST_TIME_OUT",          408);
    ci (stash, "HTTP_CONFLICT",                  409);
    ci (stash, "HTTP_GONE",                      410);
    ci (stash, "HTTP_LENGTH_REQUIRED",           411);
    ci (stash, "HTTP_REQUEST_ENTITY_TOO_LARGE",  413);
    ci (stash, "HTTP_REQUEST_URI_TOO_LARGE",     414);
    ci (stash, "HTTP_UNSUPPORTED_MEDIA_TYPE",    415);
    ci (stash, "HTTP_RANGE_NOT_SATISFIABLE",     416);
    ci (stash, "HTTP_INTERNAL_SERVER_ERROR",     500);
    ci (stash, "HTTP_SERVER_ERROR",              500);
    ci (stash, "HTTP_NOT_IMPLEMENTED",           501);
    ci (stash, "HTTP_BAD_GATEWAY",               502);
    ci (stash, "HTTP_SERVICE_UNAVAILABLE",       503);
    ci (stash, "HTTP_GATEWAY_TIME_OUT",          504);
    ci (stash, "HTTP_INSUFFICIENT_STORAGE",      507);

PROTOTYPES: DISABLE


void
status(r, code)
    CODE:
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);

        r->headers_out.status = SvIV(ST(1));

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl status: %d", r->headers_out.status);

        XSRETURN_UNDEF;


void
send_http_header(r, ...)
    CODE:
        ngx_http_request_t  *r;
        SV                  *sv;

        ngx_http_perl_set_request(r);

        if (r->headers_out.status == 0) {
            r->headers_out.status = NGX_HTTP_OK;
        }

        if (items != 1) {
            sv = ST(1);

            if (ngx_http_perl_sv2str(aTHX_ r, &r->headers_out.content_type, sv)
                != NGX_OK)
            {
                XSRETURN_EMPTY;
            }

            r->headers_out.content_type_len = r->headers_out.content_type.len;

        } else {
            if (ngx_http_set_content_type(r) != NGX_OK) {
                XSRETURN_EMPTY;
            }
        }

        (void) ngx_http_send_header(r);


void
header_only(r)
    CODE:
        dXSTARG;
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);

        sv_upgrade(TARG, SVt_IV);
        sv_setiv(TARG, r->header_only);

        ST(0) = TARG;


void
uri(r)
    CODE:
        dXSTARG;
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);
        ngx_http_perl_set_targ(r->uri.data, r->uri.len);

        ST(0) = TARG;


void
args(r)
    CODE:
        dXSTARG;
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);
        ngx_http_perl_set_targ(r->args.data, r->args.len);

        ST(0) = TARG;


void
request_method(r)
    CODE:
        dXSTARG;
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);
        ngx_http_perl_set_targ(r->method_name.data, r->method_name.len);

        ST(0) = TARG;


void
remote_addr(r)
    CODE:
        dXSTARG;
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);
        ngx_http_perl_set_targ(r->connection->addr_text.data,
                               r->connection->addr_text.len);

        ST(0) = TARG;


void
header_in(r, key)
    CODE:
        dXSTARG;
        ngx_http_request_t         *r;
        SV                         *key;
        u_char                     *p, *lowcase_key, *cookie;
        STRLEN                      len;
        ssize_t                     size;
        ngx_uint_t                  i, n, hash;
        ngx_list_part_t            *part;
        ngx_table_elt_t            *h, **ph;
        ngx_http_header_t          *hh;
        ngx_http_core_main_conf_t  *cmcf;

        ngx_http_perl_set_request(r);

        key = ST(1);

        if (SvROK(key) && SvTYPE(SvRV(key)) == SVt_PV) {
            key = SvRV(key);
        }

        p = (u_char *) SvPV(key, len);

        /* look up hashed headers */

        lowcase_key = ngx_pnalloc(r->pool, len);
        if (lowcase_key == NULL) {
            XSRETURN_UNDEF;
        }

        hash = ngx_hash_strlow(lowcase_key, p, len);

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        hh = ngx_hash_find(&cmcf->headers_in_hash, hash, lowcase_key, len);

        if (hh) {
            if (hh->offset) {

                ph = (ngx_table_elt_t **) ((char *) &r->headers_in + 
                                                    hh->offset);
                if (*ph) {
                    ngx_http_perl_set_targ((*ph)->value.data, (*ph)->value.len);

                    goto done;
                }

                XSRETURN_UNDEF;
            }

            /* Cookie */

            n = r->headers_in.cookies.nelts;

            if (n == 0) {
                XSRETURN_UNDEF;
            }

            ph = r->headers_in.cookies.elts;

            if (n == 1) {
                ngx_http_perl_set_targ((*ph)->value.data, (*ph)->value.len);

                goto done;
            }

            size = - (ssize_t) (sizeof("; ") - 1);

            for (i = 0; i < n; i++) {
                size += ph[i]->value.len + sizeof("; ") - 1;
            }

            cookie = ngx_pnalloc(r->pool, size);
            if (cookie == NULL) {
                XSRETURN_UNDEF;
            }

            p = cookie;

            for (i = 0; /* void */ ; i++) {
                p = ngx_copy(p, ph[i]->value.data, ph[i]->value.len);

                if (i == n - 1) {
                    break;
                }

                *p++ = ';'; *p++ = ' ';
            }

            ngx_http_perl_set_targ(cookie, size);

            goto done;
        }

        /* iterate over all headers */

        part = &r->headers_in.headers.part;
        h = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                h = part->elts;
                i = 0;
            }

            if (len != h[i].key.len
                || ngx_strcasecmp(p, h[i].key.data) != 0)
            {
                continue;
            }

            ngx_http_perl_set_targ(h[i].value.data, h[i].value.len);

            goto done;
        }

        XSRETURN_UNDEF;

    done:
        ST(0) = TARG;


void
has_request_body(r, next)
    CODE:
        dXSTARG;
        ngx_http_request_t   *r;
        ngx_http_perl_ctx_t  *ctx;

        ngx_http_perl_set_request(r);

        if (r->headers_in.content_length_n <= 0) {
            XSRETURN_UNDEF;
        }

        ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);
        ctx->next = SvRV(ST(1));

        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        if (r->request_body_in_file_only) {
            r->request_body_file_log_level = 0;
        }

        ngx_http_read_client_request_body(r, ngx_http_perl_handle_request);

        sv_upgrade(TARG, SVt_IV);
        sv_setiv(TARG, 1);

        ST(0) = TARG;


void
request_body(r)
    CODE:
        dXSTARG;
        ngx_http_request_t  *r;
        size_t               len;

        ngx_http_perl_set_request(r);

        if (r->request_body == NULL
            || r->request_body->temp_file
            || r->request_body->bufs == NULL)
        {
            XSRETURN_UNDEF;
        }

        len = r->request_body->bufs->buf->last - 
              r->request_body->bufs->buf->pos;

        if (len == 0) {
            XSRETURN_UNDEF;
        }

        ngx_http_perl_set_targ(r->request_body->bufs->buf->pos, len);

        ST(0) = TARG;


void
request_body_file(r)
    CODE:
        dXSTARG;
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);

        if (r->request_body == NULL || r->request_body->temp_file == NULL) {
            XSRETURN_UNDEF;
        }

        ngx_http_perl_set_targ(r->request_body->temp_file->file.name.data,
                               r->request_body->temp_file->file.name.len);

        ST(0) = TARG;


void
discard_request_body(r)
    CODE:
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);

        ngx_http_discard_request_body(r);


void
header_out(r, key, value)
    CODE:
        ngx_http_request_t  *r;
        SV                  *key;
        SV                  *value;
        ngx_table_elt_t     *header;

        ngx_http_perl_set_request(r);

        key = ST(1);
        value = ST(2);

        header = ngx_list_push(&r->headers_out.headers);
        if (header == NULL) {
            XSRETURN_EMPTY;
        }

        header->hash = 1;

        if (ngx_http_perl_sv2str(aTHX_ r, &header->key, key) != NGX_OK) {
            XSRETURN_EMPTY;
        }

        if (ngx_http_perl_sv2str(aTHX_ r, &header->value, value) != NGX_OK) {
            XSRETURN_EMPTY;
        }

        if (header->key.len == sizeof("Content-Length") - 1
            && ngx_strncasecmp(header->key.data, (u_char *) "Content-Length",
                               sizeof("Content-Length") - 1) == 0)
        {
            r->headers_out.content_length_n = (off_t) SvIV(value);
            r->headers_out.content_length = header;
        }

        if (header->key.len == sizeof("Content-Encoding") - 1
            && ngx_strncasecmp(header->key.data, "Content-Encoding",
                               sizeof("Content-Encoding") - 1) == 0)
        {
            r->headers_out.content_encoding = header;
        }


void
filename(r)
    CODE:
        dXSTARG;
        size_t                root;
        ngx_http_request_t   *r;
        ngx_http_perl_ctx_t  *ctx;

        ngx_http_perl_set_request(r);

        ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);
        if (ctx->filename.data) {
            goto done;
        }

        if (ngx_http_map_uri_to_path(r, &ctx->filename, &root, 0) == NULL) {
            XSRETURN_UNDEF;
        }

        ctx->filename.len--;
        sv_setpv(PL_statname, (char *) ctx->filename.data);

    done:
        ngx_http_perl_set_targ(ctx->filename.data, ctx->filename.len);

        ST(0) = TARG;


void
print(r, ...)
    CODE:
        ngx_http_request_t  *r;
        SV                  *sv;
        int                  i;
        u_char              *p;
        size_t               size;
        STRLEN               len;
        ngx_buf_t           *b;

        ngx_http_perl_set_request(r);

        if (items == 2) {

            /*
             * do zero copy for prolate single read-only SV:
             *     $r->print("some text\n");
             */

            sv = ST(1);

            if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
                sv = SvRV(sv);
            }

            if (SvREADONLY(sv) && SvPOK(sv)) {

                p = (u_char *) SvPV(sv, len);

                if (len == 0) {
                    XSRETURN_EMPTY;
                }

                b = ngx_calloc_buf(r->pool);
                if (b == NULL) {
                    XSRETURN_EMPTY;
                }

                b->memory = 1;
                b->pos = p;
                b->last = p + len;
                b->start = p;
                b->end = b->last;

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "$r->print: read-only SV: %z", len);

                goto out;
            }
        }

        size = 0;

        for (i = 1; i < items; i++) {

            sv = ST(i);

            if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
                sv = SvRV(sv);
            }

            (void) SvPV(sv, len);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "$r->print: copy SV: %z", len);

            size += len;
        }

        if (size == 0) {
            XSRETURN_EMPTY;
        }

        b = ngx_create_temp_buf(r->pool, size);
        if (b == NULL) {
            XSRETURN_EMPTY;
        }

        for (i = 1; i < items; i++) {
            sv = ST(i);

            if (SvROK(sv) && SvTYPE(SvRV(sv)) == SVt_PV) {
                sv = SvRV(sv);
            }

            p = (u_char *) SvPV(sv, len);
            b->last = ngx_cpymem(b->last, p, len);
        }

    out:
        (void) ngx_http_perl_output(r, b);


void
sendfile(r, filename, offset = -1, bytes = 0)
    CODE:
        ngx_http_request_t        *r;
        char                      *filename;
        off_t                      offset;
        size_t                     bytes;
        ngx_str_t                  path;
        ngx_buf_t                 *b;
        ngx_open_file_info_t       of;
        ngx_http_core_loc_conf_t  *clcf;

        ngx_http_perl_set_request(r);

        filename = SvPV_nolen(ST(1));

        if (filename == NULL) {
            croak("sendfile(): NULL filename");
        }

        offset = items < 3 ? -1 : SvIV(ST(2));
        bytes = items < 4 ? 0 : SvIV(ST(3));

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            XSRETURN_EMPTY;
        }

        b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
        if (b->file == NULL) {
            XSRETURN_EMPTY;
        }

        path.len = ngx_strlen(filename);

        path.data = ngx_pnalloc(r->pool, path.len + 1);
        if (path.data == NULL) {
            XSRETURN_EMPTY;
        }

        (void) ngx_cpystrn(path.data, (u_char *) filename, path.len + 1);

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        ngx_memzero(&of, sizeof(ngx_open_file_info_t));

        of.read_ahead = clcf->read_ahead;
        of.directio = clcf->directio;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != NGX_OK)
        {
            if (of.err == 0) {
                XSRETURN_EMPTY;
            }

            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          "%s \"%s\" failed", of.failed, filename);
            XSRETURN_EMPTY;
        }

        if (offset == -1) {
            offset = 0;
        }

        if (bytes == 0) {
            bytes = of.size - offset;
        }

        b->in_file = 1;

        b->file_pos = offset;
        b->file_last = offset + bytes;

        b->file->fd = of.fd;
        b->file->log = r->connection->log;
        b->file->directio = of.is_directio;

        (void) ngx_http_perl_output(r, b);


void
flush(r)
    ALIAS:
        rflush = 1
    CODE:
        ngx_http_request_t  *r;
        ngx_buf_t           *b;

        ngx_http_perl_set_request(r);

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            XSRETURN_EMPTY;
        }

        b->flush = 1;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "$r->flush");

        (void) ngx_http_perl_output(r, b);

        XSRETURN_EMPTY;


void
internal_redirect(r, uri)
    CODE:
        ngx_http_request_t   *r;
        SV                   *uri;
        ngx_uint_t            i;
        ngx_http_perl_ctx_t  *ctx;

        ngx_http_perl_set_request(r);

        uri = ST(1);

        ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

        if (ngx_http_perl_sv2str(aTHX_ r, &ctx->redirect_uri, uri) != NGX_OK) {
            XSRETURN_EMPTY;
        }

        for (i = 0; i < ctx->redirect_uri.len; i++) {
            if (ctx->redirect_uri.data[i] == '?') {

                ctx->redirect_args.len = ctx->redirect_uri.len - (i + 1);
                ctx->redirect_args.data = &ctx->redirect_uri.data[i + 1];
                ctx->redirect_uri.len = i;

                XSRETURN_EMPTY;
            }
        }


void
allow_ranges(r)
    CODE:
        ngx_http_request_t  *r;

        ngx_http_perl_set_request(r);

        r->allow_ranges = 1;


void
unescape(r, text, type = 0)
    CODE:
        dXSTARG;
        ngx_http_request_t  *r;
        SV                  *text;
        int                  type;
        u_char              *p, *dst, *src;
        STRLEN               len;

        ngx_http_perl_set_request(r);

        text = ST(1);

        src = (u_char *) SvPV(text, len);

        p = ngx_pnalloc(r->pool, len + 1);
        if (p == NULL) {
            XSRETURN_UNDEF;
        }

        dst = p;

        type = items < 3 ? 0 : SvIV(ST(2));

        ngx_unescape_uri(&dst, &src, len, (ngx_uint_t) type);
        *dst = '\0';

        ngx_http_perl_set_targ(p, dst - p);

        ST(0) = TARG;


void
variable(r, name, value = NULL)
    CODE:
        dXSTARG;
        ngx_http_request_t         *r;
        SV                         *name, *value;
        u_char                     *p, *lowcase;
        STRLEN                      len;
        ngx_str_t                   var, val;
        ngx_uint_t                  i, hash;
        ngx_http_perl_var_t        *v;
        ngx_http_perl_ctx_t        *ctx;
        ngx_http_variable_value_t  *vv;

        ngx_http_perl_set_request(r);

        name = ST(1);

        if (SvROK(name) && SvTYPE(SvRV(name)) == SVt_PV) {
            name = SvRV(name);
        }

        if (items == 2) {
            value = NULL;

        } else {
            value = ST(2);

            if (SvROK(value) && SvTYPE(SvRV(value)) == SVt_PV) {
                value = SvRV(value);
            }

            if (ngx_http_perl_sv2str(aTHX_ r, &val, value) != NGX_OK) {
                XSRETURN_UNDEF;
            }
        }

        p = (u_char *) SvPV(name, len);

        lowcase = ngx_pnalloc(r->pool, len);
        if (lowcase == NULL) {
            XSRETURN_UNDEF;
        }

        hash = ngx_hash_strlow(lowcase, p, len);

        var.len = len;
        var.data = lowcase;

        #if (NGX_DEBUG)

        if (value) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "perl variable: \"%V\"=\"%V\"", &var, &val);
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "perl variable: \"%V\"", &var);
        }

        #endif

        vv = ngx_http_get_variable(r, &var, hash);
        if (vv == NULL) {
            XSRETURN_UNDEF;
        }

        if (vv->not_found) {

            ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

            if (ctx->variables) {

                v = ctx->variables->elts;
                for (i = 0; i < ctx->variables->nelts; i++) {

                    if (hash != v[i].hash
                        || len != v[i].name.len
                        || ngx_strncmp(lowcase, v[i].name.data, len) != 0)
                    {
                        continue;
                    }

                    if (value) {
                        v[i].value = val;
                        XSRETURN_UNDEF;
                    }

                    ngx_http_perl_set_targ(v[i].value.data, v[i].value.len);

                    goto done;
                }
            }

            if (value) {
                if (ctx->variables == NULL) {
                    ctx->variables = ngx_array_create (
                                         r->pool, 
                                         1,
                                         sizeof(ngx_http_perl_var_t)
                                     );
                    if (ctx->variables == NULL) {
                        XSRETURN_UNDEF;
                    }
                }

                v = ngx_array_push(ctx->variables);
                if (v == NULL) {
                    XSRETURN_UNDEF;
                }

                v->hash = hash;
                v->name.len = len;
                v->name.data = lowcase;
                v->value = val;

                XSRETURN_UNDEF;
            }

            XSRETURN_UNDEF;
        }

        if (value) {
            vv->len = val.len;
            vv->valid = 1;
            vv->no_cacheable = 0;
            vv->not_found = 0;
            vv->data = val.data;

            XSRETURN_UNDEF;
        }

        ngx_http_perl_set_targ(vv->data, vv->len);

    done:
        ST(0) = TARG;


void
sleep(r, sleep, next)
    CODE:
        ngx_http_request_t   *r;
        ngx_msec_t            sleep;
        ngx_http_perl_ctx_t  *ctx;

        ngx_http_perl_set_request(r);

        sleep = (ngx_msec_t) SvIV(ST(1));

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "perl sleep: %M", sleep);

        ctx = ngx_http_get_module_ctx(r, ngx_http_perl_module);

        ctx->next = SvRV(ST(2));

        ngx_add_timer(r->connection->write, sleep);

        r->write_event_handler = ngx_http_perl_sleep_handler;
        r->main->count++;


void
log_error(r, err, msg)
    CODE:
        ngx_http_request_t  *r;
        SV                  *err, *msg;
        u_char              *p;
        STRLEN               len;
        ngx_err_t            e;

        ngx_http_perl_set_request(r);

        err = ST(1);

        if (SvROK(err) && SvTYPE(SvRV(err)) == SVt_PV) {
            err = SvRV(err);
        }

        e = SvIV(err);

        msg = ST(2);

        if (SvROK(msg) && SvTYPE(SvRV(msg)) == SVt_PV) {
            msg = SvRV(msg);
        }

        p = (u_char *) SvPV(msg, len);

        ngx_log_error(NGX_LOG_ERR, r->connection->log, e, "perl: %s", p);


void
main_count_inc(r)
    CODE:
        ngx_http_request_t   *r;

        ngx_http_perl_set_request(r);

        r->main->count++;


void
finalize_request(r, rc)
    ALIAS:
        send_special = 1
    CODE:
        ngx_http_request_t   *r;

        ngx_http_perl_set_request(r);

        switch (ix) {
            case 1:
                ngx_http_send_special(r, SvIV(ST(1)));
                break;
            default:
                ngx_http_finalize_request(r, SvIV(ST(1)));
                break;
        }


void
core_run_phases(r)
    CODE:
        ngx_http_request_t   *r;

        ngx_http_perl_set_request(r);

        ngx_http_core_run_phases(r);


void
phase_handler_inc(r)
    CODE:
        ngx_http_request_t   *r;

        ngx_http_perl_set_request(r);

        r->phase_handler++;


SV *
location_name(r)
    CODE:
        ngx_http_request_t        *r;
        ngx_http_core_loc_conf_t  *clcf;

        ngx_http_perl_set_request(r);

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        RETVAL = newSVpvn((char *) clcf->name.data, clcf->name.len); 
    OUTPUT:
        RETVAL


SV *
root(r)
    CODE:
        ngx_http_request_t        *r;
        ngx_http_core_loc_conf_t  *clcf;

        ngx_http_perl_set_request(r);

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        RETVAL = newSVpvn((char *) clcf->root.data, clcf->root.len); 
    OUTPUT:
        RETVAL


SV *
ctx(r, ...)
    CODE:
        ngx_http_request_t        *r;
        ngx_http_core_loc_conf_t  *clcf;
        ngx_http_perl_ctx_t       *ctx;

        ngx_http_perl_set_request(r);

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        ctx  = ngx_http_get_module_ctx(r, ngx_http_perl_module);

        RETVAL = newSVsv(ctx->ctx);

        if (items == 2) {
            if (ctx->ctx != NULL) {
                SvREFCNT_dec(ctx->ctx);
                ctx->ctx = NULL;
            }

            ctx->ctx = newSVsv(ST(1));
        }
    OUTPUT:
        RETVAL


void
ngx_log_error(errno, message)
    PROTOTYPE: $$
    ALIAS:
        ngx_log_notice = 1
        ngx_log_info   = 2
        ngx_log_crit   = 3
        ngx_log_alert  = 4
    CODE:
        ngx_int_t  level;
 
        switch (ix) {
            case 1:
                level = NGX_LOG_NOTICE;
                break;
            case 2:
                level = NGX_LOG_INFO;
                break;
            case 3:
                level = NGX_LOG_CRIT;
                break;
            case 4:
                level = NGX_LOG_ALERT;
                break;
            default:
                level = NGX_LOG_ERR;
                break;
        }

        ngx_log_error ( level, 
                        ngx_perl_log 
                            ? ngx_perl_log
                            : ngx_cycle->log, 
                        SvOK (ST(0)) 
                            ? SvIV (ST(0)) 
                            : 0,
                        "perl: %s", 
                        (u_char *) SvPV_nolen (ST(1)) );


SV *
ngx_timer(after, repeat, cb)
    PROTOTYPE: $$&
    CODE:
        ngx_connection_t *c;

        c = ngx_perl_timer((ngx_int_t)SvIV(ST(0)), ST(1), ST(2));
        if (c == NULL) {
            croak("ngx_perl_timer returned NULL");
        }

        RETVAL = newSViv(PTR2IV(c));
    OUTPUT:
        RETVAL


void
ngx_timer_clear(timer)
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));
        ngx_perl_timer_clear(c);


void
ngx_connector(address, port, timeout, cb)
    PROTOTYPE: $$$&
    CODE:
        ngx_perl_connector(ST(0), ST(1), ST(2), ST(3));


void
ngx_reader(c, buf, min, max, timeout, cb)
    PROTOTYPE: $$$$$&
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));

        ngx_perl_reader(c, ST(1), ST(2), ST(3), ST(4), ST(5));


void
ngx_writer(c, buf, timeout, cb)
    PROTOTYPE: $$$&
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));

        ngx_perl_writer(c, ST(1), ST(2), ST(3));


void
ngx_close(c)
    PROTOTYPE: $
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));

        ngx_perl_close(c);


void
ngx_read(c)
    PROTOTYPE: $
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));

        ngx_perl_read(c);


void
ngx_write(c)
    PROTOTYPE: $
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));

        ngx_perl_write(c);
        if (c->write->ready) {
            c->write->handler(c->write);
        }


void
ngx_noop(c)
    PROTOTYPE: $
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));

        ngx_perl_noop(c);


void
ngx_resolver(name, timeout, cb)
    CODE:
        ngx_perl_resolver(ST(0), ST(1), ST(2));


void
ngx_ssl_handshaker(c, cb)
    PROTOTYPE: $&
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));

        ngx_perl_ssl_handshaker(c, ST(1));


void
ngx_ssl_handshake(c)
    PROTOTYPE: $
    CODE:
        ngx_connection_t  *c;

        c = INT2PTR(ngx_connection_t *, SvIV(ST(0)));

        ngx_perl_ssl_handshake(c);


