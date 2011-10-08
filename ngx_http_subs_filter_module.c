
/*
 * Author: Weibin Yao(yaoweibin@gmail.com)
 * Licence:This module could be distributed under the same terms as Nginx itself.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <ngx_http_chain_buffer.h>

#if (NGX_DEBUG)
#define SUBS_DEBUG 1
#else
#define SUBS_DEBUG 0
#endif

#ifndef NGX_HTTP_MAX_CAPTURES
#define NGX_HTTP_MAX_CAPTURES 9
#endif

typedef struct {
    ngx_flag_t     once;
    ngx_flag_t     regex;
    ngx_flag_t     insensitive;

    /* If it has capture variables? */
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
    ngx_array_t   *sub_pairs;  /* array of sub_pair_t*/
    ngx_array_t   *types;      /* array of ngx_str_t */
} ngx_http_subs_loc_conf_t;

typedef struct {
    ngx_array_t   *sub_pairs;  /* array of sub_pair_t*/

    ngx_chain_t   *in;

    /* 
     *  I use queue to store output buffer chain. The reason is that the
     *  overhead of fetching tail chain is too high when there are 1000+ 
     *  substitutions in chain buffers. 
     *  */
    ngx_queue_buf_t *out;

    ngx_chain_t   *busy;

    /* store the freed chain buffers. */
    ngx_chain_t   *free;

    /* store the freed queue buffers. */
    ngx_queue_buf_t *free_queue;

    /* alloced by ctx->tpool */
    ngx_chain_t   *line_in;

    /* the temporary buffer to store the line buffer before substitution */
    ngx_buf_t     *line_src;
    /* the temporary buffer to store the line buffer after substitution */
    ngx_buf_t     *line_dst;

    /* alloced by r->pool */
    ngx_chain_t   *line_out;

    /* save every chain which does not find the linefeed */
    ngx_chain_t   *saved;

    /* 
     * last_pos is the last not matched postion, the chain will
     * not be splited until a successful matching. This will reduce 
     * the split frequency of the chain. 
     * */
    u_char        *last_pos;

    ngx_pool_t    *tpool;
} ngx_http_subs_ctx_t;

static ngx_int_t ngx_http_subs_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_subs_init_context(ngx_http_request_t *r);

static ngx_int_t ngx_http_subs_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_subs_body_filter_init_context(ngx_http_request_t *r,
        ngx_chain_t *in);
static ngx_int_t ngx_http_subs_body_filter_process_chain(ngx_http_request_t *r,
        ngx_chain_t *cl);
static ngx_int_t  ngx_http_subs_match(ngx_http_request_t *r, ngx_http_subs_ctx_t *ctx);
static ngx_buf_t *ngx_http_subs_match_read_chain_to_buffer(ngx_chain_t *in,
        ngx_buf_t *b, ngx_pool_t *tpool, ngx_flag_t quick);
static ngx_int_t ngx_http_subs_match_regex_substituion(ngx_http_request_t *r,
        sub_pair_t *pair, ngx_buf_t *b, ngx_buf_t *dst, ngx_pool_t *tpool); 
static ngx_int_t ngx_http_subs_match_fix_substituion(sub_pair_t *pair, 
        ngx_buf_t *b, ngx_buf_t *dst, ngx_pool_t *tpool);
static void ngx_http_subs_body_filter_greedy_split_chain(ngx_http_request_t *r,
        ngx_http_subs_ctx_t *ctx, ngx_chain_t *cl);
static void ngx_http_subs_body_filter_clean_context(ngx_http_request_t *r,
        ngx_http_subs_ctx_t *ctx);
static ngx_int_t ngx_http_subs_output(ngx_http_request_t *r,
        ngx_http_subs_ctx_t *ctx, ngx_chain_t *in);
static void ngx_http_subs_output_free_chain(ngx_http_subs_ctx_t *ctx);

static char * ngx_http_subs_filter(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static ngx_int_t ngx_http_subs_filter_regex_compile(sub_pair_t *pair, 
        ngx_http_script_compile_t *sc, ngx_conf_t *cf);

static char *ngx_http_subs_types(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

static void *ngx_http_subs_create_conf(ngx_conf_t *cf);
static char *ngx_http_subs_merge_conf(ngx_conf_t *cf, void *parent,
        void *child);

static ngx_int_t ngx_http_subs_filter_init(ngx_conf_t *cf);

extern ngx_int_t ngx_regex_capture_count(ngx_regex_t *re);

static ngx_command_t  ngx_http_subs_filter_commands[] = {

    { ngx_string("subs_filter"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
        ngx_http_subs_filter,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("subs_filter_types"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_subs_types,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
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
    ngx_str_t                 *type;
    ngx_uint_t                 i;
    ngx_http_subs_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_subs_filter_module);

    /*Don't substitute the compressed content*/
    if (slcf->sub_pairs->nelts == 0
            || r->header_only
            || r->headers_out.content_type.len == 0
            || r->headers_out.content_length_n == 0 
            || r->headers_out.status != NGX_HTTP_OK
            || (r->headers_out.content_encoding  
                && r->headers_out.content_encoding->value.len))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http subs filter header ignored, this may be special or compressed response");

        return ngx_http_next_header_filter(r);
    }

    type = slcf->types->elts;
    for (i = 0; i < slcf->types->nelts; i++) {
        if (r->headers_out.content_type.len >= type[i].len
                && ngx_strncasecmp(r->headers_out.content_type.data,
                    type[i].data, type[i].len) == 0)
        {
            goto found;
        }
    }

    return ngx_http_next_header_filter(r);

found:
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
    ngx_http_subs_ctx_t       *ctx;
    sub_pair_t                *src_pair, *dst_pair;
    ngx_http_subs_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_subs_filter_module);

    /* Everything in ctx is NULL or 0. */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_subs_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_subs_filter_module);

    ctx->sub_pairs = ngx_array_create(r->pool, 
            slcf->sub_pairs->nelts, sizeof(sub_pair_t));
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

    ctx->out = ngx_palloc(r->pool, sizeof(ngx_queue_buf_t));
    ngx_queue_init(&ctx->out->queue);

    ctx->free_queue = ngx_palloc(r->pool, sizeof(ngx_queue_buf_t));
    ngx_queue_init(&ctx->free_queue->queue);

    return NGX_OK;
}


static ngx_int_t 
ngx_http_subs_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                 *b = NULL;
    ngx_int_t		           rc; 
    ngx_log_t                 *log;
    ngx_chain_t               *cl;
    ngx_queue_t               *q;
    ngx_queue_buf_t           *qb;
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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http subs filter \"%V\"", &r->uri);

    if (in == NULL && ctx->in == NULL && ctx->busy == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ngx_http_subs_body_filter_init_context(r, in) != NGX_OK){
        goto failed;
    }

    for (cl = ctx->in; cl; cl = cl->next) {

        rc = ngx_http_subs_body_filter_process_chain(r, cl);

        if (rc == NGX_DECLINED) {
            continue;
        }
        else if (rc == NGX_ERROR) {
            goto failed;
        }

        /* NGX_OK */
        if (ngx_queue_empty(&ctx->out->queue)) {
            qb = ngx_alloc_queue_buf(r->pool, ctx->free_queue);
            b = create_buffer(NULL, 0, r->pool);
            
            if (qb == NULL || b == NULL) {
                goto failed;
            }

            qb->buf = b;
            
            ngx_queue_insert_tail(&ctx->out->queue, &qb->queue);     
        }

        /* Add the shadow buffer for freeing after output */
        if (ngx_buf_in_memory(cl->buf)) {
            q = ngx_queue_last(&ctx->out->queue);
            qb = ngx_queue_data(q, ngx_queue_buf_t, queue);
            b = qb->buf;

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                    "[subs_filter] add the shadow buffer: b=%p, b->shadow=%p, cl->buf->shadow=%p",
                    b, cl->buf, cl->buf->shadow);

            if (b) {
                insert_shadow_tail(&b->shadow, cl->buf);
                cl->buf->last_shadow = 1;
            }
            else {
                b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
                b->shadow = cl->buf;
                b->sync = 1;
                cl->buf->last_shadow = 1;
            }
        }

        /* copy line_in to saved. */
        if (ctx->line_in) {
            delete_and_free_chain(&ctx->saved, &ctx->free);
            ctx->saved = duplicate_chains(ctx->line_in, &ctx->free, r->pool);
            if (ctx->saved == NULL) {
                goto failed;
            }
        }

        if (cl->next != NULL) {
            continue;
        }

        /* Last chain */
        if (cl->buf->last_buf){
            if (ctx->saved) {
                ngx_queue_chain_add_copy(r->pool, &ctx->out->queue, 
                        ctx->saved, ctx->free_queue);
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                        "[subs_filter] Lost last linefeed, but output anyway.");
            }

            q = ngx_queue_last(&ctx->out->queue);
            qb = ngx_queue_data(q, ngx_queue_buf_t, queue);
            b = qb->buf;

            if (b == NULL) {
                b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
                b->sync = 1;
            }

            b->last_buf = 1;
        }
    }

    ngx_http_subs_body_filter_clean_context(r, ctx);

    if (ngx_queue_empty(&ctx->out->queue) && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_subs_output(r, ctx, in);

failed:

    ngx_http_subs_body_filter_clean_context(r, ctx);

    ngx_log_error(NGX_LOG_ERR, log, 0, 
            "[subs_filter] ngx_http_subs_body_filter error.");

    return NGX_ERROR;
}


static ngx_int_t 
ngx_http_subs_body_filter_init_context(ngx_http_request_t *r, ngx_chain_t *in) 
{
    size_t                     pool_size;
    ngx_log_t                 *log;
    ngx_chain_t               *cl;
    ngx_http_subs_ctx_t       *ctx;

    log = r->connection->log;

    ctx = ngx_http_get_module_ctx(r, ngx_http_subs_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) == NGX_ERROR) {
            return NGX_ERROR;
        }

        pool_size = 0;
        for (cl = ctx->in; cl; cl = cl->next) {
            if (cl->buf) {
                pool_size += ngx_buf_size(cl->buf);
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                        "subs in buffer: %p, size:%uz, sync:%d", 
                        cl->buf, ngx_buf_size(cl->buf), cl->buf->sync);
            }
        }


        pool_size = ngx_align(pool_size, ngx_pagesize) + ngx_pagesize;

        /*
         * tpool is only existed in body filter. It's used 
         * for the chain of 'ctx->line_in's temporary memory 
         * allocation
         * */
        ctx->tpool = ngx_create_pool(pool_size, log);
        if (ctx->tpool == NULL) {
            return NGX_ERROR;
        }
        
        ctx->line_src = ngx_create_temp_buf(ctx->tpool, 1024);
        if (ctx->line_src == NULL) {
            return NGX_ERROR;
        }

        ctx->line_dst = ngx_create_temp_buf(ctx->tpool, 1024);
        if (ctx->line_dst == NULL) {
            return NGX_ERROR;
        }

        if (ctx->saved) {
#if SUBS_DEBUG
            for (cl = ctx->saved; cl; cl = cl->next) {
                if (cl->buf) {
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                            "subs in saved: %p , size:%uz, sync:%d", 
                            cl->buf, ngx_buf_size(cl->buf), cl->buf->sync);
                }
            }
#endif
            ctx->line_in = duplicate_chains(ctx->saved, NULL, ctx->tpool);
            if (ctx->line_in == NULL) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_subs_body_filter_process_chain(ngx_http_request_t *r, ngx_chain_t *cl)
{
    u_char                    *p, *linefeed;
    ngx_buf_t                 *b = NULL;
    ngx_int_t                 len, rc; 
    ngx_chain_t               *temp_cl;
    ngx_chain_t               *part_line_in_cl;
    ngx_http_subs_ctx_t       *ctx;

#if (NGX_DEBUG)
    ngx_log_t                 *log;

    log = r->connection->log;
#endif

    ctx = ngx_http_get_module_ctx(r, ngx_http_subs_filter_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;
    if (b == NULL) {
        return NGX_DECLINED;
    }

    if ((b->last - b->pos) <= 0 && ctx->line_in == NULL){
        return NGX_OK;
    }

    if ((b->last - b->pos) == 0 && ctx->line_in != NULL && b->last_buf){

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, 
                "Zero buffer, but this is the last buffer, try to do substitution");

        rc = ngx_http_subs_match(r, ctx);

        ngx_free_chain(ctx->tpool, ctx->line_in);
        ctx->line_in = NULL;

        if (rc < 0) {
            return NGX_ERROR;
        }
        else if (rc > 0) {
            /* Matched at least 1 time*/
            delete_and_free_chain(&ctx->saved, &ctx->free);

            if (ctx->line_out) {
                ngx_queue_chain_add_copy(r->pool, &ctx->out->queue, 
                        ctx->line_out, ctx->free_queue);

                ngx_free_chain(r->pool, ctx->line_out);
                ctx->line_out = NULL;
            }
        }
        else {
            /* Not match, we will output the saved part of content*/
            if (ctx->saved) {
                ngx_queue_chain_add_copy(r->pool, &ctx->out->queue, 
                        ctx->saved, ctx->free_queue);
                ctx->saved = NULL;
            }
        }

        return NGX_OK;
    }

    p = b->pos;

    while (p < b->last) {
        linefeed = memchr(p, LF, b->last - p); 
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "find linefeed :%p", linefeed);

        if (linefeed == NULL && b->last_buf){
            linefeed = b->last - 1;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, 
                    "Not find linefeed, but this is the last buffer");
        }

        if (linefeed) {
            len = linefeed - p + 1;
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0, "create line :%p, len:%d ", p, len);

            part_line_in_cl = create_chain_buffer(p, len, ctx->tpool);
            if (part_line_in_cl == NULL) {
                return NGX_ERROR;
            }

            p += len;

            insert_chain_tail(&ctx->line_in, part_line_in_cl);

            /*
             * Do the substitutions with the chain buffers of ctx->line_in
             * and the output chain buffers is the ctx->line_out
             * */
            rc = ngx_http_subs_match(r, ctx);

            ngx_free_chain(ctx->tpool, ctx->line_in);
            ctx->line_in = NULL;

            if (rc < 0) {
                return NGX_ERROR;
            }
            else if (rc > 0) {
                /* Matched at least 1 time*/
                delete_and_free_chain(&ctx->saved, &ctx->free);

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "Last_pos :%p ", ctx->last_pos);
                ngx_http_subs_body_filter_greedy_split_chain(r, ctx, cl);

                if (ctx->line_out) {
                    ngx_queue_chain_add_copy(r->pool, &ctx->out->queue, 
                            ctx->line_out, ctx->free_queue);
                    b->pos += len;

                    ngx_free_chain(r->pool, ctx->line_out);
                    ctx->line_out = NULL;
                }
            }
            else {
                /* Not match, we will output the saved part of content*/
                if (ctx->saved) {
                    ngx_queue_chain_add_copy(r->pool, &ctx->out->queue, 
                            ctx->saved, ctx->free_queue);
                    ctx->saved = NULL;
                }

                ctx->last_pos = p;
            }
        } else {
            /* Not find the linefeed in this chain */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                    "Buffer last, last_pos :%p ", ctx->last_pos);

            ngx_http_subs_body_filter_greedy_split_chain(r, ctx, cl);

            temp_cl = ngx_alloc_chain_link(ctx->tpool);
            temp_cl->buf = b;
            temp_cl->next = NULL;

            insert_chain_tail(&ctx->line_in, temp_cl);

            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, 
            "At chain last, last_pos:%p", ctx->last_pos);

    ngx_http_subs_body_filter_greedy_split_chain(r, ctx, cl);

    return NGX_OK;
}


/* Do the substitutions by a line.*/
static ngx_int_t  
ngx_http_subs_match(ngx_http_request_t *r, ngx_http_subs_ctx_t *ctx)
{
    sub_pair_t  *pairs, *pair;
    ngx_buf_t   *b, *src, *dst, *temp;
    ngx_log_t   *log;
    ngx_int_t    count = 0, match_count = 0;
    ngx_flag_t   quick = 0;
    ngx_uint_t   i;

    log = r->connection->log;

    src = ctx->line_src;
    dst = ctx->line_dst;

    ngx_buffer_init(src); 
    ngx_buffer_init(dst); 

#if SUBS_DEBUG
    ngx_chain_t *cl;
    for (cl = ctx->line_in; cl; cl = cl->next) {
        if (cl->buf) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                    "line in buffer: %p, size:%uz",
                    cl->buf, ngx_buf_size(cl->buf));
        }
    }
#endif

    if (ctx->sub_pairs->nelts == 1) {
        quick = 1;
    }

    b = ngx_http_subs_match_read_chain_to_buffer(ctx->line_in, src, ctx->tpool, quick);
    if (b == NULL) {
        goto failed;
    }

    pairs = (sub_pair_t *) ctx->sub_pairs->elts;
    for (i = 0; i < ctx->sub_pairs->nelts; i++) {
        pair = &pairs[i];

        if (!pair->dup_capture) {
            if (pair->sub.data == NULL) {
                if (ngx_http_script_run(r, &pair->sub, pair->sub_lengths->elts, 0, 
                            pair->sub_values->elts) == NULL)
                {
                    goto failed;
                }
            }
        }
        else {
            pair->sub.data = NULL;
            pair->sub.len = 0;
        }

        if (dst->pos != dst->last) {
            temp = b;
            b = dst;
            dst = temp;

            ngx_buffer_init(dst); 
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                "http subs filter start: \"match:%V, sub:%V, regex:%d, dup_capture:%d\"",
                &pair->match, &pair->sub, (pair->regex||pair->insensitive), pair->dup_capture);

#if SUBS_DEBUG
        ngx_str_t    line;

        line.data = b->pos;
        line.len = b->last - b->pos;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "current line in: \"%V\"", &line);
#endif

        if ((!pair->regex) && ((ngx_uint_t)(b->last - b->pos) < pair->match.len)) {
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
            count = ngx_http_subs_match_regex_substituion(r, pair, b, dst, ctx->tpool);
            if (count == NGX_ERROR) {
                goto failed;
            }
        }
        else {
            /* fixed string substituion */
            count = ngx_http_subs_match_fix_substituion(pair, b, dst, ctx->tpool);
            if (count == NGX_ERROR) {
                goto failed;
            }
        }

        /* no match. */
        if (count == 0){
            continue;
        }

        if (b->pos < b->last) {
            buffer_append_string(dst, b->pos, b->last - b->pos, ctx->tpool);
            b->pos = b->last;
        }

        /* match */
        match_count += count;
    }

    if (match_count > 0) {

        /* no match last time */
        if (dst->pos == dst->last){
            dst = b;
        }
        
#if SUBS_DEBUG
        ngx_str_t    line;

        line.data = dst->pos;
        line.len = dst->last - dst->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "current line out: \"%V\"", &line);
#endif

        ctx->line_out = duplicate_chain_buffer(dst->pos, dst->last - dst->pos, r->pool);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "match counts: %d ", match_count);

    return match_count;

failed:
    ngx_log_error(NGX_LOG_ERR, log, 0,
            "[subs_filter]  ngx_http_subs_match error.");

    return -1;
}


static ngx_buf_t *
ngx_http_subs_match_read_chain_to_buffer(ngx_chain_t *in,
        ngx_buf_t *b, ngx_pool_t *tpool, ngx_flag_t quick)
{
    ngx_chain_t *cl;
    ngx_uint_t   bytes = 0;

    if (in) {
        if (in->next == NULL && quick) {
            return in->buf;
        }

        for(cl = in; cl; cl = cl->next) {
            if(cl->buf) {
                bytes = ngx_buf_size(cl->buf); 
                buffer_append_string(b, cl->buf->pos, bytes, tpool);
            }
        }
    }
    else {
        return NULL;
    }

    return b;
}


static ngx_int_t 
ngx_http_subs_match_regex_substituion(ngx_http_request_t *r,
        sub_pair_t *pair, ngx_buf_t *b, ngx_buf_t *dst, ngx_pool_t *tpool) 
{
    ngx_str_t  line;
    ngx_log_t *log;
    ngx_int_t  rc, count = 0;

    log = r->connection->log;

    if (pair->captures == NULL || pair->ncaptures == 0) {
        pair->ncaptures = (NGX_HTTP_MAX_CAPTURES + 1) * 3;
        pair->captures = (int *)(ngx_int_t)ngx_palloc(r->pool, 
                pair->ncaptures * sizeof(int));
    }

    while (b->pos < b->last) {
        if (pair->once && pair->matched) {
            break;
        }

        line.data = b->pos;
        line.len = b->last - b->pos;

        rc = ngx_regex_exec(pair->match_regex, &line, 
                (int *)pair->captures, pair->ncaptures);
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

        buffer_append_string(dst, b->pos, pair->captures[0], tpool);
        buffer_append_string(dst, pair->sub.data, pair->sub.len, tpool);

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
    if (l_len == 0 || s_len == 0)
        return NULL;

    /* "s" must be smaller or equal to "l" */
    if (l_len < s_len)
        return NULL;

    /* special case where s_len == 1 */
    if (s_len == 1)
        return memchr(l, (int)*cs, l_len);

    /* the last position where its possible to find "s" in "l" */
    last = (char *)cl + l_len - s_len;

    for (cur = (char *)cl; cur <= last; cur++)
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
            return cur;

    return NULL;
}
        

static ngx_int_t
ngx_http_subs_match_fix_substituion(sub_pair_t *pair, 
        ngx_buf_t *b, ngx_buf_t *dst, ngx_pool_t *tpool)
{
    ngx_int_t    count = 0;
    u_char      *sub_start;

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

        buffer_append_string(dst, b->pos, sub_start - b->pos, tpool);
        buffer_append_string(dst, pair->sub.data, pair->sub.len, tpool);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, 
                "fixed string match:%p", sub_start);

        b->pos = sub_start + pair->match.len;
       
        if ((ngx_uint_t)(b->last - b->pos) < pair->match.len)
            break;
    }

    return count;
}


static void 
ngx_http_subs_body_filter_greedy_split_chain(ngx_http_request_t *r,
        ngx_http_subs_ctx_t *ctx, ngx_chain_t *cl)
{
    ngx_buf_t                 *b, *nb;
    ngx_queue_buf_t           *qb;

    if (ctx->last_pos) {
        b = cl->buf;

        nb = create_buffer(b->pos, ctx->last_pos - b->pos, r->pool);
        if (nb == NULL) {
            return;
        }

        qb = ngx_alloc_queue_buf(r->pool, ctx->free_queue);
        if (qb == NULL) {
            return;
        }
        qb->buf = nb;

        ngx_queue_insert_tail(&ctx->out->queue, &qb->queue);

        b->pos = ctx->last_pos;
        ctx->last_pos = NULL;
    }
}


static void 
ngx_http_subs_body_filter_clean_context(ngx_http_request_t *r,
        ngx_http_subs_ctx_t *ctx)
{
    ctx->in = NULL;
    ctx->line_in = NULL;
    ctx->line_out = NULL;
    ctx->line_src = NULL;
    ctx->line_dst = NULL;
    ctx->last_pos = NULL;

    if (ctx->tpool) {
        ngx_destroy_pool(ctx->tpool);
        ctx->tpool = NULL;
    }
}


static ngx_int_t
ngx_http_subs_output( ngx_http_request_t *r,
        ngx_http_subs_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_int_t     rc, last_chain;
    ngx_buf_t    *b;
    ngx_chain_t  *cl, *out = NULL;

    if (ngx_chain_queue_add_copy(r->pool, &out, &ctx->out->queue) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!ngx_queue_empty(&ctx->out->queue)) {
        ngx_free_queue(&ctx->free_queue->queue, &ctx->out->queue);
    }

    last_chain = 0;
    b = NULL;
    for (cl = out; cl; cl = cl->next) {

        b = cl->buf;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "subs out buffer: %p , size:%uz, sync:%d, last_buf:%d", 
                b, ngx_buf_size(b), b->sync, b->last_buf);

        if (b->last_buf) {
            last_chain = 1;
            b->last_buf = 0;
        }

        if (cl->next == NULL) {
            b->flush = 1;
            b->last_buf = last_chain;
        }
    }

    /*ctx->out may not output all the data, and need output again.*/
    rc = ngx_http_next_body_filter(r, out);

#if SUBS_DEBUG
    size_t        size;

    size = 0;
    for (cl = out; cl; cl = cl->next) {
        size = ngx_buf_size(cl->buf);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "subs out end: %p %uz", cl->buf, size);
    }
#endif

    /*output chain is busy.*/
    insert_chain_tail(&ctx->busy, out);
    out = NULL;

    ngx_http_subs_output_free_chain(ctx);

    r->buffered &= ~NGX_HTTP_SUB_BUFFERED;

    return rc;
}


static void 
ngx_http_subs_output_free_chain(ngx_http_subs_ctx_t *ctx)
{
    ngx_buf_t    *b;
    ngx_buf_t    *temp_b;
    ngx_chain_t  *cl;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

#if (NGX_HAVE_WRITE_ZEROCOPY)
        if (b->zerocopy_busy) {
            break;
        }
#endif

        temp_b = b;

        while(temp_b->shadow) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                    "clear recursive shadow buffer: %p, %p", temp_b, temp_b->shadow);

            temp_b->shadow->pos = temp_b->shadow->last;

            temp_b = temp_b->shadow;

            if (temp_b->last_shadow) {
                break;
            }
        }

        b->shadow = NULL;

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data buffers to the free buffer chain */
            cl->next = ctx->free;
            ctx->free = cl;
        }
    }
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
    }
    else {
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

    /*  Caseless match can only be implemented in regex.*/
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
    pair->match_regex = ngx_regex_compile(&pair->match,
            options, cf->pool, &err);
#endif
    if (pair->match_regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &err);
        return NGX_ERROR;
    }

    n = ngx_regex_capture_count(pair->match_regex);

    if (pair->dup_capture) {
        mask = ((1 << (n + 1)) - 1);
        if ( mask < sc->captures_mask ) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "You want to capture too many regex substrings,"
                    " more than %d in \"%V\"",
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


static char *
ngx_http_subs_types( ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                *value, *type;
    ngx_uint_t                i;
    ngx_http_subs_loc_conf_t *slcf = conf;

    if (slcf->types == NULL) {
        slcf->types = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (slcf->types == NULL) {
            return NGX_CONF_ERROR;
        }

        type = ngx_array_push(slcf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->len = sizeof("text/html") - 1;
        type->data = (u_char *) "text/html";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "text/html") == 0) {
            continue;
        }

        type = ngx_array_push(slcf->types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->len = value[i].len;

        type->data = ngx_palloc(cf->pool, type->len + 1);
        if (type->data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_cpystrn(type->data, value[i].data, type->len + 1);
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_subs_create_conf(ngx_conf_t *cf)
{
    ngx_http_subs_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_subs_loc_conf_t));
    if (slcf == NULL) {
        return NGX_CONF_ERROR;
    }

    return slcf;
}


static char * 
ngx_http_subs_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_subs_loc_conf_t *prev = parent;
    ngx_http_subs_loc_conf_t *conf = child;

    ngx_str_t  *type;


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

    if (conf->types == NULL) {
        if (prev->types == NULL) {
            conf->types = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
            if (conf->types == NULL) {
                return NGX_CONF_ERROR;
            }

            type = ngx_array_push(conf->types);
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->len = sizeof("text/html") - 1;
            type->data = (u_char *) "text/html";

        } else {
            conf->types = prev->types;
        }
    }

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
