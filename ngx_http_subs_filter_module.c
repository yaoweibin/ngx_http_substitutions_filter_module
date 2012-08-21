
/*
 * Author: Weibin Yao(yaoweibin@gmail.com)
 *
 * Licence: This module could be distributed under the
 * same terms as Nginx itself.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>


#if (NGX_DEBUG)
#define SUBS_DEBUG 1
#else
#define SUBS_DEBUG 0
#endif


#ifndef NGX_HTTP_MAX_CAPTURES
#define NGX_HTTP_MAX_CAPTURES 9
#endif


#define ngx_buffer_init(b) b->pos = b->last = b->start;


typedef struct {
    ngx_flag_t     once;
    ngx_flag_t     regex;
    ngx_flag_t     insensitive;

    /* If it has captured variables? */
    ngx_flag_t     dup_capture;

    ngx_str_t      match;
#if (NGX_PCRE)
    ngx_regex_t   *match_regex;
    int           *captures;
    ngx_int_t      ncaptures;
#endif

    ngx_str_t      sub;
    ngx_array_t   *sub_lengths;
    ngx_array_t   *sub_values;

    unsigned       matched; 
} sub_pair_t;


typedef struct {
    ngx_hash_t     types;
    ngx_array_t   *sub_pairs;   /* array of sub_pair_t     */
    ngx_array_t   *types_keys;  /* array of ngx_hash_key_t */
    ngx_bufs_t     bufs;
} ngx_http_subs_loc_conf_t;


typedef struct {
    ngx_array_t   *sub_pairs;  /* array of sub_pair_t */

    ngx_chain_t   *in;

    /* the line input buffer before substitution */
    ngx_buf_t     *line_in;
    /* the line destination buffer after substitution */
    ngx_buf_t     *line_dst;

    /* the last output buffer */
    ngx_buf_t     *out_buf;
    /* point to the last output chain's next chain */
    ngx_chain_t   **last_out;
    ngx_chain_t   *out;

    ngx_chain_t   *busy;

    /* the freed chain buffers. */
    ngx_chain_t   *free;

    ngx_int_t      bufs;

    unsigned       last;

} ngx_http_subs_ctx_t;


static ngx_int_t ngx_http_subs_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_subs_init_context(ngx_http_request_t *r);

static ngx_int_t ngx_http_subs_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_subs_body_filter_init_context(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_subs_body_filter_process_buffer(ngx_http_request_t *r,
    ngx_buf_t *b);
static ngx_int_t  ngx_http_subs_match(ngx_http_request_t *r,
    ngx_http_subs_ctx_t *ctx);
static ngx_int_t ngx_http_subs_match_regex_substituion(ngx_http_request_t *r,
    sub_pair_t *pair, ngx_buf_t *b, ngx_buf_t *dst); 
static ngx_int_t ngx_http_subs_match_fix_substituion(ngx_http_request_t *r,
    sub_pair_t *pair, ngx_buf_t *b, ngx_buf_t *dst);
static ngx_buf_t * buffer_append_string(ngx_buf_t *b, u_char *s, size_t len,
    ngx_pool_t *pool);
static ngx_int_t  ngx_http_subs_out_chain_append(ngx_http_request_t *r,
    ngx_http_subs_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t  ngx_http_subs_get_chain_buf(ngx_http_request_t *r,
    ngx_http_subs_ctx_t *ctx);
static ngx_int_t ngx_http_subs_output(ngx_http_request_t *r,
    ngx_http_subs_ctx_t *ctx, ngx_chain_t *in);

static char * ngx_http_subs_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_subs_filter_regex_compile(sub_pair_t *pair, 
    ngx_http_script_compile_t *sc, ngx_conf_t *cf);


static void *ngx_http_subs_create_conf(ngx_conf_t *cf);
static char *ngx_http_subs_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_http_subs_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_subs_regex_capture_count(ngx_regex_t *re);


static ngx_command_t  ngx_http_subs_filter_commands[] = {

    { ngx_string("subs_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_subs_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("subs_filter_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_subs_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("subs_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_subs_loc_conf_t, bufs),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_subs_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_subs_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_subs_create_conf,             /* create location configuration */
    ngx_http_subs_merge_conf               /* merge location configuration */
};


ngx_module_t  ngx_http_subs_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_subs_filter_module_ctx,      /* module context */
    ngx_http_subs_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

extern volatile ngx_cycle_t  *ngx_cycle;


static ngx_int_t 
ngx_http_subs_header_filter(ngx_http_request_t *r)
{
    ngx_http_subs_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_subs_filter_module);

    if (slcf->sub_pairs->nelts == 0
        || r->header_only
        || r->headers_out.content_type.len == 0
        || r->headers_out.content_length_n == 0 
        || r->headers_out.status != NGX_HTTP_OK)
    {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_test_content_type(r, &slcf->types) == NULL) {
        return ngx_http_next_header_filter(r);
    }

    /* Don't do substitution with the compressed content */
    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len) {

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http subs filter header ignored, this may be a "
                      "compressed response.");

        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http subs filter header \"%V\"", &r->uri);

    if (ngx_http_subs_init_context(r) == NGX_ERROR) {
        return NGX_ERROR;
    }

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_subs_init_context(ngx_http_request_t *r)
{
    ngx_uint_t                 i;
    sub_pair_t                *src_pair, *dst_pair;
    ngx_http_subs_ctx_t       *ctx;
    ngx_http_subs_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_subs_filter_module);

    /* Everything in ctx is NULL or 0. */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_subs_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_subs_filter_module);

    ctx->sub_pairs = ngx_array_create(r->pool, slcf->sub_pairs->nelts,
                                      sizeof(sub_pair_t));
    if (slcf->sub_pairs == NULL) {
        return NGX_ERROR;
    }

    /* Deep copy sub_pairs from slcf to ctx */
    src_pair = (sub_pair_t *) slcf->sub_pairs->elts;

    for (i = 0; i < slcf->sub_pairs->nelts; i++) {

        dst_pair = ngx_array_push(ctx->sub_pairs);
        if (dst_pair == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(dst_pair, src_pair + i, sizeof(sub_pair_t));
    }

    if (ctx->line_in == NULL) {
        /* The default buffer size is about 32K */
        ctx->line_in = ngx_create_temp_buf(r->pool, 8 * ngx_pagesize);
        if (ctx->line_in == NULL) {
            return NGX_ERROR;
        }
    }

    if (ctx->line_dst == NULL) {
        ctx->line_dst = ngx_create_temp_buf(r->pool, 8 * ngx_pagesize);
        if (ctx->line_dst == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_subs_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t		           rc; 
    ngx_log_t                 *log;
    ngx_chain_t               *cl, *temp;
    ngx_http_subs_ctx_t       *ctx;
    ngx_http_subs_loc_conf_t  *slcf;

    log = r->connection->log;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_subs_filter_module);
    if (slcf == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_subs_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, 
                   "http subs filter \"%V\"", &r->uri);

    if (in == NULL && ctx->busy == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ngx_http_subs_body_filter_init_context(r, in) != NGX_OK){
        goto failed;
    }

    for (cl = ctx->in; cl; cl = cl->next) {

        if (cl->buf->last_buf || cl->buf->last_in_chain){
            ctx->last = 1;
        }

        /* TODO: check the flush tag */
        rc = ngx_http_subs_body_filter_process_buffer(r, cl->buf);

        if (rc == NGX_DECLINED) {
            continue;
        } else if (rc == NGX_ERROR) {
            goto failed;
        }

        if (cl->next != NULL) {
            continue;
        }

        if (ctx->last) {

            /* copy line_in to ctx->out. */
            if (ngx_buf_size(ctx->line_in) > 0) {

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                    "[subs_filter] Lost last linefeed, output anyway.");

                if (ngx_http_subs_out_chain_append(r, ctx, ctx->line_in)
                    != NGX_OK) {
                    goto failed;
                }
            }

            if (ctx->out_buf == NULL) {

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                               "[subs_filter] The last buffer is zero size.");

                /* 
                 * This is a zero buffer, it should not be set the temporary
                 * or memory flag
                 * */
                ctx->out_buf = ngx_calloc_buf(r->pool);
                if (ctx->out_buf == NULL) {
                    goto failed;
                }

                ctx->out_buf->sync = 1;

                temp = ngx_alloc_chain_link(r->pool);
                if (temp == NULL) {
                    goto failed;
                }

                temp->buf = ctx->out_buf;
                temp->next = NULL;

                *ctx->last_out = temp;
                ctx->last_out = &temp->next;
            }

            ctx->out_buf->last_buf = (r == r->main) ? 1 : 0;
            ctx->out_buf->last_in_chain = cl->buf->last_in_chain;

            break;
        }
    }

    /* It doesn't output anything, return */
    if ((ctx->out == NULL) && (ctx->busy == NULL)) {
        return NGX_OK;
    }

    return ngx_http_subs_output(r, ctx, in);

failed:

    ngx_log_error(NGX_LOG_ERR, log, 0, 
                  "[subs_filter] ngx_http_subs_body_filter error.");

    return NGX_ERROR;
}


static ngx_int_t 
ngx_http_subs_body_filter_init_context(ngx_http_request_t *r, ngx_chain_t *in) 
{
    ngx_http_subs_ctx_t       *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_subs_filter_module);

    r->connection->buffered |= NGX_HTTP_SUB_BUFFERED;

    ctx->in = NULL;

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

#if SUBS_DEBUG
    if (ngx_buf_size(ctx->line_in) > 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "subs line in buffer: %p, size:%uz",
                ctx->line_in, ngx_buf_size(ctx->line_in));
    }
#endif

#if SUBS_DEBUG
    ngx_chain_t               *cl;

    for (cl = ctx->in; cl; cl = cl->next) {
        if (cl->buf) {
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "subs in buffer: %p, size:%uz, "
                    "flush:%d, last_buf:%d", 
                    cl->buf, ngx_buf_size(cl->buf),
                    cl->buf->flush, cl->buf->last_buf);
        }
    }
#endif

    ctx->last_out = &ctx->out;
    ctx->out_buf  = NULL;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_subs_body_filter_process_buffer(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char                    *p, *last, *linefeed;
    ngx_int_t                  len, rc; 
    ngx_http_subs_ctx_t       *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_subs_filter_module);

    if (b == NULL) {
        return NGX_DECLINED;
    }

    p = b->pos;
    last = b->last;
    b->pos = b->last;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "subs process in buffer: %p %uz, line_in buffer: %p %uz",
                   b, last - p,
                   ctx->line_in, ngx_buf_size(ctx->line_in));

    if ((last - p) == 0 && ngx_buf_size(ctx->line_in) == 0){
        return NGX_OK;
    }

    if ((last - p) == 0 && ngx_buf_size(ctx->line_in) && ctx->last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                       "the last zero buffer, try to do substitution");

        rc = ngx_http_subs_match(r, ctx);
        if (rc < 0) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    while (p < last) {

        linefeed = memchr(p, LF, last - p); 

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "find linefeed: %p",
                       linefeed);

        if (linefeed == NULL) {

            if (ctx->last) {
                linefeed = last - 1;
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                               "the last buffer, not find linefeed");
            }
        }

        if (linefeed) {

            len = linefeed - p + 1;

            if (buffer_append_string(ctx->line_in, p, len, r->pool) == NULL) {
                return NGX_ERROR;
            }

            p += len;

            rc = ngx_http_subs_match(r, ctx);
            if (rc < 0) {
                return NGX_ERROR;
            }

        } else {

            /* Not find linefeed in this chain, save the left data to line_in */
            if (buffer_append_string(ctx->line_in, p, last - p, r->pool)
                == NULL) {
                return NGX_ERROR;
            }

            break;
        }
    }

    return NGX_OK;
}


/*
 * Do the substitutions from ctx->line_in
 * and output the chain buffers to ctx->out
 * */
static ngx_int_t
ngx_http_subs_match(ngx_http_request_t *r, ngx_http_subs_ctx_t *ctx)
{
    ngx_buf_t   *src, *dst, *temp;
    ngx_log_t   *log;
    ngx_int_t    count, match_count;
    sub_pair_t  *pairs, *pair;
    ngx_uint_t   i;

    count = 0;
    match_count = 0;

    log = r->connection->log;

    src = ctx->line_in;
    dst = ctx->line_dst;

    pairs = (sub_pair_t *) ctx->sub_pairs->elts;
    for (i = 0; i < ctx->sub_pairs->nelts; i++) {

        pair = &pairs[i];

        if (!pair->dup_capture) {
            if (pair->sub.data == NULL) {
                if (ngx_http_script_run(r, &pair->sub, pair->sub_lengths->elts,
                                        0, pair->sub_values->elts) == NULL)
                {
                    goto failed;
                }
            }

        } else {
            pair->sub.data = NULL;
            pair->sub.len = 0;
        }

        /* exchange the src and dst buffer */
        if (dst->pos != dst->last) {

            temp = src;
            src = dst;
            dst = temp;

            ngx_buffer_init(dst); 
        }

        if ((!pair->regex) 
             && ((ngx_uint_t)(src->last - src->pos) < pair->match.len)) {
            continue;
        }

        if (pair->once && pair->matched) {
            continue;
        }

        if (pair->sub.data == NULL && !pair->dup_capture) {

            if (ngx_http_script_run(r, &pair->sub, pair->sub_lengths->elts, 0,
                                    pair->sub_values->elts) == NULL)
            {
                goto failed;
            }
        }

        /* regex substitution */
        if (pair->regex || pair->insensitive) {
            count = ngx_http_subs_match_regex_substituion(r, pair, src, dst);
            if (count == NGX_ERROR) {
                goto failed;
            }
        }
        else {
            /* fixed string substituion */
            count = ngx_http_subs_match_fix_substituion(r, pair, src, dst);
            if (count == NGX_ERROR) {
                goto failed;
            }
        }

        /* no match. */
        if (count == 0){
            continue;
        }

        if (src->pos < src->last) {

            if (buffer_append_string(dst, src->pos, src->last - src->pos,
                                     r->pool) == NULL) {
                goto failed;
            }

            src->pos = src->last;
        }

        /* match */
        match_count += count;
    }

    /* no match last time */
    if (dst->pos == dst->last){
        dst = src;
    }

    if (ngx_http_subs_out_chain_append(r, ctx, dst) != NGX_OK) {
        goto failed;
    }

    ngx_buffer_init(ctx->line_in); 
    ngx_buffer_init(ctx->line_dst); 

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "match counts: %i", match_count);

    return match_count;

failed:

    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "[subs_filter] ngx_http_subs_match error.");

    return -1;
}


static ngx_int_t 
ngx_http_subs_match_regex_substituion(ngx_http_request_t *r, sub_pair_t *pair,
                                      ngx_buf_t *b, ngx_buf_t *dst) 
{
    ngx_str_t  line;
    ngx_log_t *log;
    ngx_int_t  rc, count = 0;

    log = r->connection->log;

    if (pair->captures == NULL || pair->ncaptures == 0) {
        pair->ncaptures = (NGX_HTTP_MAX_CAPTURES + 1) * 3;
        pair->captures = ngx_palloc(r->pool, pair->ncaptures * sizeof(int));
        if (pair->captures == NULL) {
            return NGX_ERROR;
        }
    }

    while (b->pos < b->last) {

        if (pair->once && pair->matched) {
            break;
        }

        line.data = b->pos;
        line.len = b->last - b->pos;

        rc = ngx_regex_exec(pair->match_regex, &line, 
                            (int *) pair->captures, pair->ncaptures);

        if (rc == NGX_REGEX_NO_MATCHED) {
            break;
        }
        else if(rc < 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          ngx_regex_exec_n " failed: %d on \"%V\" using \"%V\"",
                          rc, &line, &pair->match);

            return NGX_ERROR;
        }
        else if (rc == 0) {
            ngx_log_error(NGX_LOG_ALERT, log, 0, ngx_regex_exec_n 
                          " failed: ovector only has room for %d substrings",
                          (pair->ncaptures/3) - 1);
            return NGX_ERROR;
        }

        pair->matched++;
        count++;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0, 
                       "regex match:%d, start:%d, end:%d ", 
                       rc, pair->captures[0], pair->captures[1]);

        if (pair->dup_capture) {
            r->captures = pair->captures;
            r->ncaptures = pair->ncaptures;
            r->captures_data = line.data;

            if (ngx_http_script_run(r, &pair->sub, pair->sub_lengths->elts, 0, 
                                    pair->sub_values->elts) == NULL)
            {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "[subs_filter] ngx_http_script_run error.");
                return NGX_ERROR;
            }
        }

        if (buffer_append_string(dst, b->pos, pair->captures[0],
                                 r->pool) == NULL) {
            return NGX_ERROR;
        }

        if (buffer_append_string(dst, pair->sub.data, pair->sub.len,
                                 r->pool) == NULL) {
            return NGX_ERROR;
        }

        b->pos =  b->pos + pair->captures[1];
    }

    return count;
}


/*
 * Thanks to Laurent Ghigonis
 * Taken from FreeBSD
 * Find the first occurrence of the byte string s in byte string l.
 */
static void *
subs_memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
    register char *cur, *last;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;

    /* we need something to compare */
    if (l_len == 0 || s_len == 0) {
        return NULL;
    }

    /* "s" must be smaller or equal to "l" */
    if (l_len < s_len) {
        return NULL;
    }

    /* special case where s_len == 1 */
    if (s_len == 1) {
        return memchr(l, (int)*cs, l_len);
    }

    /* the last position where its possible to find "s" in "l" */
    last = (char *)cl + l_len - s_len;

    for (cur = (char *)cl; cur <= last; cur++) {
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0) {
            return cur;
        }
    }

    return NULL;
}
        

static ngx_int_t
ngx_http_subs_match_fix_substituion(ngx_http_request_t *r,
    sub_pair_t *pair, ngx_buf_t *b, ngx_buf_t *dst)
{
    u_char      *sub_start;
    ngx_int_t    count = 0;

    while(b->pos < b->last) {
        if (pair->once && pair->matched) {
            break;
        }

        sub_start = subs_memmem(b->pos, b->last - b->pos, 
                                pair->match.data, pair->match.len);
        if (sub_start == NULL) {
            break;
        }

        pair->matched++;
        count++;

        if (buffer_append_string(dst, b->pos, sub_start - b->pos,
                                 r->pool) == NULL) {
            return NGX_ERROR;
        }

        if (buffer_append_string(dst, pair->sub.data, pair->sub.len,
                                 r->pool) == NULL) {
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                       "fixed string match: %p", sub_start);

        b->pos = sub_start + pair->match.len;
       
        if ((ngx_uint_t)(b->last - b->pos) < pair->match.len)
            break;
    }

    return count;
}


static ngx_buf_t * 
buffer_append_string(ngx_buf_t *b, u_char *s, size_t len, ngx_pool_t *pool)
{
    u_char     *p;
    ngx_uint_t capacity, size;

    if (len > (size_t) (b->end - b->last)) {

        size = b->last - b->pos;

        capacity = b->end - b->start;
        capacity <<= 1;

        if (capacity < (size + len)) {
            capacity = size + len;
        }

        p = ngx_palloc(pool, capacity);
        if (p == NULL) {
            return NULL;
        }

        b->last = ngx_copy(p, b->pos, size);

        b->start = b->pos = p;
        b->end = p + capacity;
    }

    b->last = ngx_copy(b->last, s, len);

    return b;
}


static ngx_int_t  
ngx_http_subs_out_chain_append(ngx_http_request_t *r,
    ngx_http_subs_ctx_t *ctx, ngx_buf_t *b)
{
    size_t       len, capcity;

    if (b == NULL || ngx_buf_size(b) == 0) {
        return NGX_OK;
    }

    if (ctx->out_buf == NULL) {
       if (ngx_http_subs_get_chain_buf(r, ctx) != NGX_OK) {
           return NGX_ERROR;
       }
    }

    while (1) {

        len = ngx_buf_size(b);
        if (len == 0) {
            break;
        }

        capcity = ctx->out_buf->end - ctx->out_buf->last;

        if (len <= capcity) {
            ctx->out_buf->last = ngx_copy(ctx->out_buf->last, b->pos, len);
            b->pos += len;
            break;

        } else {
            ctx->out_buf->last = ngx_copy(ctx->out_buf->last,
                                          b->pos, capcity);
        }

        b->pos += capcity;

        /* get more buffer */
        if (ngx_http_subs_get_chain_buf(r, ctx) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_subs_get_chain_buf(ngx_http_request_t *r,
    ngx_http_subs_ctx_t *ctx)
{
    ngx_chain_t               *temp;
    ngx_http_subs_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_subs_filter_module);

    if (ctx->free) {
        temp = ctx->free;
        ctx->free = ctx->free->next;

    } else {
        temp = ngx_alloc_chain_link(r->pool);
        if (temp == NULL) {
            return NGX_ERROR;
        }

        temp->buf = ngx_create_temp_buf(r->pool, slcf->bufs.size);
        if (temp->buf == NULL) {
            return NGX_ERROR;
        }

        temp->buf->tag = (ngx_buf_tag_t) &ngx_http_subs_filter_module;
        temp->buf->recycled = 1;

        /* TODO: limit the buffer number */
        ctx->bufs++;
    }

    temp->next = NULL;

    ctx->out_buf = temp->buf;
    *ctx->last_out = temp;
    ctx->last_out = &temp->next;

    return NGX_OK;
}


static ngx_int_t
ngx_http_subs_output(ngx_http_request_t *r, ngx_http_subs_ctx_t *ctx,
                     ngx_chain_t *in)
{
    ngx_int_t     rc;

#if SUBS_DEBUG
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    for (cl = ctx->out; cl; cl = cl->next) {

        b = cl->buf;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "subs out buffer: %p, size:%uz, t: %d, l:%d",
                       b, ngx_buf_size(b), b->temporary, b->last_buf);
    }
#endif

    /* ctx->out may not output all the data */
    rc = ngx_http_next_body_filter(r, ctx->out);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

#if SUBS_DEBUG
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "subs out end: %p %uz", cl->buf, ngx_buf_size(cl->buf));
    }
#endif

#if defined(nginx_version) && (nginx_version >= 1001004)
    ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                            (ngx_buf_tag_t) &ngx_http_subs_filter_module);
#else
    ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out,
                            (ngx_buf_tag_t) &ngx_http_subs_filter_module);
#endif

    if (ctx->last) {
        r->connection->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static char * 
ngx_http_subs_filter( ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                   n;
    ngx_uint_t                  i;
    ngx_str_t                  *value;
    ngx_str_t                  *option;
    sub_pair_t                 *pair;
    ngx_http_subs_loc_conf_t   *slcf = conf;
    ngx_http_script_compile_t   sc;


    value = cf->args->elts;

    if (slcf->sub_pairs == NULL) {
        slcf->sub_pairs = ngx_array_create(cf->pool, 4, sizeof(sub_pair_t));
        if (slcf->sub_pairs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pair = ngx_array_push(slcf->sub_pairs);
    if (pair == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(pair, sizeof(sub_pair_t));

    pair->match = value[1];

    n = ngx_http_script_variables_count(&value[2]);
    if (n != 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[2];
        sc.lengths = &pair->sub_lengths;
        sc.values = &pair->sub_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* Dirty hacked, if it has capture variables */
        if (sc.captures_mask) {
            pair->dup_capture = 1;
        }

    } else {
        pair->sub = value[2];
    }

    if (cf->args->nelts > 3) {
        option = &value[3];
        for(i = 0; i < option->len; i++) {

            switch (option->data[i]){
            case 'i':
                pair->insensitive = 1;
                break;

            case 'o':
                pair->once = 1;
                break;

            case 'r':
                pair->regex = 1;
                break;

            case 'g':
            default:
                continue;
            }
        }
    }

    if (pair->regex || pair->insensitive) {
        if (ngx_http_subs_filter_regex_compile(pair, &sc, cf) == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_http_subs_filter_regex_compile(sub_pair_t *pair,
    ngx_http_script_compile_t *sc, ngx_conf_t *cf)
{
    ngx_int_t                   n, options;
    ngx_uint_t                  mask;
    ngx_str_t                  *value;

    value = cf->args->elts;

    /* Caseless match can only be implemented in regex. */
#if (NGX_PCRE)
    ngx_str_t         err;
    u_char            errstr[NGX_MAX_CONF_ERRSTR];

    err.len = NGX_MAX_CONF_ERRSTR;
    err.data = errstr;

    options = (pair->insensitive ? NGX_REGEX_CASELESS : 0);

    /* make nginx-0.8.25+ happy */
#if defined(nginx_version) && nginx_version >= 8025
    ngx_regex_compile_t   rc;

    rc.pattern = pair->match;
    rc.pool = cf->pool;
    rc.err = err; 
    rc.options = options;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_ERROR;
    }

    pair->match_regex = rc.regex;

#else
    pair->match_regex = ngx_regex_compile(&pair->match, options,
                                          cf->pool, &err);
#endif

    if (pair->match_regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &err);
        return NGX_ERROR;
    }

    n = ngx_http_subs_regex_capture_count(pair->match_regex);

    if (pair->dup_capture) {
        mask = ((1 << (n + 1)) - 1);
        if ( mask < sc->captures_mask ) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "You want to capture too many regex substrings, "
                               "more than %d in \"%V\"",
                               n, &value[2]);

            return NGX_ERROR;
        }
    }
#else
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "the using of the regex \"%V\" requires PCRE library",
            &pair->match);

    return NGX_ERROR;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_subs_regex_capture_count(ngx_regex_t *re)
{
    int rc, n;

    n = 0;

#if defined(nginx_version) && nginx_version >= 1002002
    rc = pcre_fullinfo(re->code, NULL, PCRE_INFO_CAPTURECOUNT, &n);
#elif defined(nginx_version) && nginx_version >= 1001012
    rc = pcre_fullinfo(re->pcre, NULL, PCRE_INFO_CAPTURECOUNT, &n);
#else
    rc = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &n);
#endif

    if (rc < 0) {
        return (ngx_int_t) rc;
    }

    return (ngx_int_t) n;
}


static void *
ngx_http_subs_create_conf(ngx_conf_t *cf)
{
    ngx_http_subs_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_subs_loc_conf_t));
    if (slcf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->sub_pairs = NULL;
     *     conf->types = {NULL, 0};
     *     conf->types_keys = NULL;
     *     conf->bufs.num = 0;
     */

    return slcf;
}


static char * 
ngx_http_subs_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_subs_loc_conf_t *prev = parent;
    ngx_http_subs_loc_conf_t *conf = child;

    if (conf->sub_pairs == NULL) {
        if (prev->sub_pairs == NULL) {
            conf->sub_pairs = ngx_array_create(cf->pool, 4, sizeof(sub_pair_t));
            if (conf->sub_pairs == NULL) {
                return NGX_CONF_ERROR;
            }
        } else {
            conf->sub_pairs = prev->sub_pairs;
        }
    }

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_subs_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_subs_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_subs_body_filter;

    return NGX_OK;
}
