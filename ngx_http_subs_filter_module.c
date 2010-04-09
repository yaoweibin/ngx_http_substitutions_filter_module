
/*
 * Author: Weibin Yao(yaoweibin@gmail.com)
 * Licence:This module could be distributed under the same terms as Nginx itself.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#ifndef NGX_HTTP_MAX_CAPTURES
#define NGX_HTTP_MAX_CAPTURES 9
#endif

typedef struct {
    ngx_flag_t     once;
    ngx_flag_t     regex;
    ngx_flag_t     insensitive;
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

    unsigned       matched; /*unsgined:1*/
} sub_pair_t;

typedef struct {
    ngx_array_t   *sub_pairs;  /* array of sub_pair_t*/
    ngx_array_t   *types;      /* array of ngx_str_t */
} ngx_http_subs_loc_conf_t;

typedef struct {
    ngx_array_t   *sub_pairs;  /* array of sub_pair_t*/

    ngx_buf_t     *buf;
    u_char        *last_pos;

    ngx_chain_t   *in;
    ngx_chain_t   *out;
    ngx_chain_t   *busy;
    ngx_chain_t   *free;

    ngx_chain_t   *line_in;
    ngx_chain_t   *line_out;
    ngx_chain_t   *saved;

} ngx_http_subs_ctx_t;


static ngx_int_t ngx_http_subs_output(ngx_http_request_t *r,
        ngx_http_subs_ctx_t *ctx, ngx_chain_t *in);
static char * ngx_http_subs_filter(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_subs_types(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static void *ngx_http_subs_create_conf(ngx_conf_t *cf);
static char *ngx_http_subs_merge_conf(ngx_conf_t *cf, void *parent,
        void *child);
static ngx_int_t ngx_http_subs_filter_init(ngx_conf_t *cf);

ngx_int_t ngx_regex_capture_count(ngx_regex_t *re);

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


static ngx_int_t ngx_http_subs_header_filter(ngx_http_request_t *r)
{
    ngx_str_t                 *type;
    ngx_uint_t                 i;
    sub_pair_t                *src_pair, *dst_pair;
    ngx_http_subs_ctx_t       *ctx;
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

    /*Everything in ctx is NULL or 0.*/
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

    /*Deep copy sub_pairs from slcf to ctx*/
    src_pair = (sub_pair_t *) slcf->sub_pairs->elts;
    for (i = 0; i < slcf->sub_pairs->nelts; i++) {
        dst_pair = ngx_array_push(ctx->sub_pairs);
        if (dst_pair == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(dst_pair, src_pair + i, sizeof(sub_pair_t));
    }

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
    }

    return ngx_http_next_header_filter(r);
}

static ngx_buf_t *create_buffer(u_char *p, ngx_int_t len, ngx_pool_t *pool)
{
    ngx_buf_t   *b;

    if (len < 0 || pool == NULL)
        return NULL;

    b = ngx_pcalloc(pool, sizeof(ngx_buf_t));
    if (b == NULL)
        return NULL;
    b->start = b->pos = p;
    b->end = b->last = p + len;
    if (len == 0)
        b->sync = 1;
    else
        b->memory = 1;

    return b;
}

static ngx_chain_t * create_chain_buffer(u_char *p, 
        ngx_int_t len, ngx_pool_t *pool)
{
    ngx_chain_t *cl;
    ngx_buf_t   *b;

    if (pool == NULL || len < 0)
        return NULL;

    b = ngx_pcalloc(pool, sizeof(ngx_buf_t));
    if (b == NULL)
        return NULL;

    b->start = b->pos = p;
    b->end = b->last = p + len;
    if (len == 0)
        b->sync = 1;
    else 
        b->memory = 1;

    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL)
        return NULL;

    cl->buf = b;
    cl->next = NULL;

    return cl;
}

/* Fetch a chain buffer, if *p_free is NULL, then create it, 
 * If not, allocates the head chain of *p_free for it.*/
static ngx_chain_t * fetch_chain_buffer(u_char *p, ngx_int_t len, 
        ngx_chain_t **p_free, ngx_pool_t *pool)
{
    ngx_buf_t   *b;
    ngx_chain_t *cl;

    if (len < 0)
        return NULL;

    if (p_free != NULL && *p_free != NULL) {
        cl = *p_free;
        (*p_free) = (*p_free)->next;
        cl->next = NULL;

        b = cl->buf;
        if (b == NULL){
            if (pool == NULL)
                return NULL;
            b = ngx_pcalloc(pool, sizeof(ngx_buf_t));
            if (b == NULL)
                return NULL;
        }

        b->start = b->pos = p;
        b->end = b->last = p + len;
        if (len == 0)
            b->sync = 1;
        else 
            b->memory = 1;
        return cl;
    }
    else {
        return create_chain_buffer(p, len, pool);
    }
}

/* Deep copy the chain's buffer and fetch a chain and buffer*/
static ngx_chain_t *copy_chain_buffer(ngx_chain_t *chain, 
        ngx_chain_t **p_free, ngx_pool_t *pool)
{
    u_char      *p = NULL;
    ngx_buf_t   *b = NULL;
    ngx_int_t    len;
    ngx_chain_t *cl = NULL;

    if (chain == NULL || chain->buf == NULL)
        return NULL;
    b = chain->buf;

    len = b->last - b->pos;
    if (len < 0)
        return NULL;
    else if (len > 0) {
        p = ngx_palloc(pool, len);
        ngx_memcpy(p, b->pos, len);
    }

    cl = fetch_chain_buffer(p, len, p_free, pool);
    cl->next = NULL;

    return cl;
}

/* Deep copy chains, return the duplicate chains*/
static ngx_chain_t *duplicate_chains(ngx_chain_t *chain,
        ngx_chain_t **p_free, ngx_pool_t *pool)
{
    ngx_chain_t *head, *cl, *copy, *last;

    if (chain == NULL)
        return NULL;

    copy = last = head = NULL;
    for(cl = chain; cl; cl = cl->next) {
        copy = copy_chain_buffer(cl, p_free, pool);
        if (copy == NULL)
            return NULL;
        if (head == NULL)
            head = copy;

        if (last == NULL) {
            last = copy;
        }
        else {
            last->next = copy;
            last = copy;
        }
    }
    if (copy != NULL)
        copy->next = NULL;

    return head;
}


static ngx_inline ngx_chain_t *get_chain_tail(ngx_chain_t *chain)
{
    ngx_chain_t *cl;

    if (chain == NULL)
        return NULL;

    for(cl = chain; cl->next; cl = cl->next){}

    return cl;
}

static ngx_inline ngx_chain_t *get_chain_previous(
        ngx_chain_t *in, ngx_chain_t *chain)
{
    ngx_chain_t *cl;

    if (in == NULL)
        return NULL;

    if (in == chain)
        return chain;

    if (chain == NULL)
        return get_chain_tail(in);

    for(cl = in; cl->next; cl = cl->next) {
        if (cl->next == chain)
            return cl;
    }

    /*Not found*/
    if (cl->next == NULL)  
        return NULL;

    return cl;
}

static ngx_inline ngx_buf_t * insert_shadow_tail(
        ngx_buf_t **p_shadow, ngx_buf_t *tail)
{
    ngx_buf_t *b;

    if (*p_shadow == NULL){
        *p_shadow = tail;
        return *p_shadow;
    }

    for(b = (*p_shadow); b; b = b->shadow){}
    b = tail;

    return *p_shadow;
}

static ngx_inline ngx_chain_t * insert_chain_tail(
        ngx_chain_t **p_chain, ngx_chain_t *tail)
{
    ngx_chain_t *cl;

    if (p_chain == NULL)
        return NULL;
    if (tail == NULL)
        return *p_chain;

    if (*p_chain == NULL)
        *p_chain = tail;
    else {
        cl = get_chain_tail(*p_chain);
        cl->next = tail;
    }

    return *p_chain;
}


/* delete the chains link of *p_chain and  
 * add to the head of *p_free_chain */
static ngx_inline void delete_and_free_chain(
        ngx_chain_t **p_chain, ngx_chain_t **p_free_chain)
{
    ngx_chain_t *cl, *tail;

    if (p_chain == NULL || *p_chain == NULL)
        return;

    for(cl = *p_chain; cl; cl = cl->next) {
        if (cl->buf)
            ngx_memzero(cl->buf, sizeof(ngx_buf_t));
        if (cl->next == NULL) {
            tail = cl;
        }
    }

    if (p_free_chain == NULL)
        return;

    if (*p_free_chain == NULL)
        *p_free_chain = *p_chain;
    else {
        tail->next = *p_free_chain;
        *p_free_chain = *p_chain;
    }

    *p_chain = NULL;
}

static ngx_inline ngx_chain_t *insert_chain_before( ngx_chain_t **p_in, 
        ngx_chain_t *insert_chain, ngx_chain_t *chain)
{
    ngx_chain_t *cl;

    if (insert_chain == NULL || p_in == NULL || *p_in == NULL)
        return NULL;

    cl = get_chain_previous(*p_in, chain);
    if (cl == NULL)
        return NULL;

    /*This chain is the head of chains link.*/
    if (cl == chain) {
        insert_chain->next = chain;
        *p_in = insert_chain;
    }
    else {
        cl->next = insert_chain;
        insert_chain->next = chain;
    }

    return chain;
}

/* split the chain's buffer, len is the split point, 
 * *p_in is the chain's head*/
static ngx_inline ngx_chain_t * split_chain( ngx_chain_t *chain,
        ngx_int_t len, ngx_chain_t **p_in, ngx_pool_t *pool)
{
    ngx_chain_t *cl;
    ngx_buf_t   *b1, *b2;

    if (chain == NULL || p_in == NULL || *p_in == NULL ||
            pool == NULL || len <= 0)
        return NULL;

    b2 = chain->buf; 
    if (b2 == NULL || len > ngx_buf_size(chain->buf))
        return NULL;

    cl = create_chain_buffer(b2->pos, len, pool);
    if (cl == NULL)
        return NULL;
    b1 = cl->buf;
    if (b1 == NULL)
        return NULL;

    insert_chain_before(p_in, cl, chain);

    b2->pos += len;
    if (b2->pos == b2->last) {
        b2->sync = 1;
    }

    return cl;
}

/*read any chain's buffer and copy to *p_buff */
static ngx_int_t chain_buffer_read( ngx_chain_t *chain, 
        u_char **p_buff, ngx_int_t *p_len, ngx_pool_t *pool)
{
    ngx_chain_t *cl;
    u_char *head, *p;
    ngx_int_t size, len = 0;

    if (chain == NULL || p_buff == NULL || p_len == NULL || pool == NULL)
        return -1;

    /*Just one chain link*/
    if (chain->next == NULL) {
        *p_buff = chain->buf->pos;
        (*p_len) = ngx_buf_size(chain->buf);
        return 0;
    }

    for(cl = chain; cl; cl = cl->next) {
        if (cl->buf)
            len += ngx_buf_size(cl->buf);
    }

    p = head = ngx_palloc(pool, len);
    for(cl = chain; cl; cl = cl->next) {
        if(cl->buf) {
            size = ngx_buf_size(cl->buf); 
            ngx_memcpy(p, cl->buf->pos, size);
            p += size;
        }
    }

    if (head + len != p)
        return -1;

    (*p_buff) = head;
    (*p_len) = len;

    return 0;
}

/* fetch a body chain buffer first with *p and len, then fetch a 
 * replacement chain buffer with rep_str, and concatenate the 
 * chains of *p_in, boody and replacement chain.*/
static ngx_int_t  buffer_chain_concatenate( ngx_chain_t **p_in, u_char *p, 
        ngx_int_t len, ngx_str_t *rep_str, ngx_pool_t *pool)
{
    ngx_chain_t *head, *body, *rep_cl;


    if (p_in == NULL || p == NULL || len < 0 || pool == 0)
        return -1;

    head = body = rep_cl = NULL;

    /*'len' maybe equal to zero*/
    if (len > 0) {
        body = create_chain_buffer(p, len, pool);
        if (body == NULL)
            return -1;

        if (*p_in == NULL){
            *p_in = body;
            head = body;
        }
        else {
            head = get_chain_tail(*p_in);
            insert_chain_tail(&head, body);
        }
    }

    if (rep_str != NULL) {
        rep_cl = create_chain_buffer(rep_str->data, rep_str->len, pool);
        if (rep_cl == NULL)
            return -1;

        if (head != NULL) {
            insert_chain_tail(&head, rep_cl);
        }
        else {
            if (*p_in == NULL){
                *p_in = rep_cl;
            }
            else {
                head = get_chain_tail(*p_in);
                insert_chain_tail(&head, rep_cl);
            }
        }
    }

    return 0;
}

/* Do the substitutions by a line.*/
static ngx_int_t  ngx_http_subs_match(
        ngx_http_request_t *r, ngx_http_subs_ctx_t *ctx, ngx_pool_t *temp_pool)
{
    u_char      *buff, *sub_start, *sub_end, *p;
    sub_pair_t  *pairs, *pair;
    ngx_buf_t   *b = NULL;
    ngx_log_t   *log;
    ngx_int_t    num = 0;
    ngx_int_t    rc = 0;
    ngx_int_t    bytes = 0;
    ngx_uint_t   i;
    ngx_str_t    line;
    ngx_int_t    len;
    ngx_chain_t *cl;
    ngx_chain_t *temp_in;

    log = r->connection->log;

    if (ctx->line_in == NULL) {
        return -1;
    }

#if 1
    for (cl = ctx->line_in; cl; cl = cl->next) {
        if (cl->buf) {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                    "line in buffer: %p , size:%uz, sync:%d", 
                    cl->buf, ngx_buf_size(cl->buf), cl->buf->sync);
        }
    }
#endif

    temp_in = ctx->line_in;
    pairs = (sub_pair_t *) ctx->sub_pairs->elts;
    for (i = 0; i < ctx->sub_pairs->nelts; i++) {
        pair = &pairs[i];
        if (pair->sub.data == NULL && !pair->dup_capture) {
            if (ngx_http_script_run(r, &pair->sub, pair->sub_lengths->elts, 0, 
                        pair->sub_values->elts) == NULL)
            {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                        "[subs_filter] ngx_http_script_run error.");
                goto failed;
            }
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                "http subs filter start: \"match:%V, sub:%V, dup_capture:%d\"",
                &pair->match, &pair->sub, pair->dup_capture);

        if (temp_in) {
            /*After every substitution, rebuild the temp_in to a single buffer.*/
            if (chain_buffer_read(temp_in, &buff, &bytes, temp_pool) < 0) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                        "[subs_filter] chain_buffer_read error.");
                goto failed;
            }

            line.data = buff;
            line.len = bytes;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "Line: \"%V\"", &line );

            b = create_buffer(buff, bytes, temp_pool);
            if (b == NULL) {
                goto failed;
            }
            temp_in = NULL;

            if ((!pair->regex) && ((ngx_uint_t)bytes < pair->match.len)) {
                continue;
            }
        }
        else if (b){/*no match last time*/
            b->pos = b->start;
        }
        else if (b == NULL) {
            goto failed;
        }

        if (pair->once && pair->matched) {
            continue;
        }

        /*regex substitution*/
        if (pair->regex || pair->insensitive) {
#if (NGX_PCRE)
            if (pair->match_regex == NULL) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                        "[subs_filter] the using of the regex \"%V\" is NULL.",
                        &pair->match);
                goto failed;
            }
            if (pair->captures == NULL || pair->ncaptures == 0) {
                pair->ncaptures = (NGX_HTTP_MAX_CAPTURES + 1) * 3;
                pair->captures = (int *)(ngx_int_t)ngx_palloc(r->pool, 
                        pair->ncaptures * sizeof(int));
            }

            while (1) {
                if (pair->once && pair->matched) {
                    break;
                }

                line.data = b->pos;
                line.len = b->last - b->pos;
                if (line.len <= 0)
                    break;

                rc = ngx_regex_exec(pair->match_regex, &line, 
                        (int *)pair->captures, pair->ncaptures);
                if (rc == NGX_REGEX_NO_MATCHED)
                    break;
                else if(rc < 0) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                            ngx_regex_exec_n " failed: %d on \"%V\" using \"%V\"",
                            rc, &line, &pair->match);
                    goto failed;
                }
                else if (rc == 0) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0, ngx_regex_exec_n 
                            " failed: ovector only has room for %d substrings",
                            (pair->ncaptures/3) - 1);
                    goto failed;
                }

                r->captures = pair->captures;
                r->ncaptures = pair->ncaptures;
                r->captures_data = line.data;

                pair->matched = 1;
                num++;

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0, 
                        "regex match:%d start:%d, end:%d ", 
                        rc, pair->captures[0], pair->captures[1]);

                sub_start = b->pos +  pair->captures[0];
                sub_end = b->pos +  pair->captures[1];
                len = sub_start - b->pos;

                if (pair->dup_capture) {
                    if (ngx_http_script_run(r, &pair->sub, pair->sub_lengths->elts, 0, 
                                pair->sub_values->elts) == NULL)
                    {
                        ngx_log_error(NGX_LOG_ALERT, log, 0,
                                "[subs_filter] ngx_http_script_run error.");
                        goto failed;
                    }
                }

                rc = buffer_chain_concatenate(&temp_in, b->pos, len,
                        &pair->sub, temp_pool);
                if (rc != 0) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                            "[subs_filter] regex buffer_chain_concatenate error.");
                    goto failed;
                }

                b->pos = sub_end;
            }
#else
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                    "the using of the regex \"%V\" requires PCRE library",
                    &pair->match);
            goto failed;
#endif
        }
        else {
            /*fixed string substituion*/
            if (pair->once && pair->matched) {
                break;
            }

            while((sub_start = memmem(b->pos, bytes, pair->match.data, 
                            pair->match.len)) != NULL) {
                pair->matched = 1;
                num++;

                len = sub_start - b->pos;
                rc = buffer_chain_concatenate(&temp_in, b->pos, len,
                        &pair->sub, temp_pool);
                if (rc != 0) {
                    ngx_log_error(NGX_LOG_ALERT, log, 0,
                            "[subs_filter] buffer_chain_concatenate error.");
                    goto failed;
                }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "match:%d", len);

                b->pos = b->pos + len + pair->match.len;
                bytes = bytes - len - pair->match.len;
                if ((ngx_uint_t)bytes < pair->match.len)
                    break;
            }
        }

        if (temp_in == NULL)/*no match.*/
            continue;

        if (b->pos != b->last) {/*something left.*/
            len = b->last - b->pos;
            rc = buffer_chain_concatenate(&temp_in, b->pos, 
                    len, NULL, temp_pool);
            if (rc != 0) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                        "[subs_filter] buffer_chain_concatenate2 error.");
                goto failed;
            }
        }
    }

    if (num > 0) {
        if (temp_in) {
            ctx->line_out = duplicate_chains(temp_in, &ctx->free, r->pool);
            if (ctx->line_out == NULL) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                        "[subs_filter] duplicate_chains error.");
                goto failed;
            }
        }
        else {/*No match last time, and there is something left in b.*/
            if (b) {
                len = b->last - b->pos;
                if (len >= 0 ) {
                    if (len > 0) {
                        p = ngx_palloc(r->pool, len);
                        ngx_memcpy(p, b->pos, len);
                    }
                    else
                        p = NULL;

                    cl = create_chain_buffer(p, len, r->pool);
                    cl->next = NULL;

                    insert_chain_tail(&ctx->line_out, cl);
                }
            }
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "match counts: %d ", num);

    return num;

failed:

    return -1;
}

static ngx_int_t ngx_http_subs_body_filter(
        ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                    *p, *nl;
    size_t                     pool_size;
    ngx_buf_t                 *b = NULL;
    ngx_int_t		           len, rc, bytes; 
    ngx_str_t                  test;
    ngx_log_t                 *log;
    ngx_pool_t                *tpool = NULL;
    ngx_chain_t               *cl, *temp_cl;
    ngx_chain_t               *split_cl;
    ngx_chain_t               *part_line_in_cl;
    ngx_http_subs_ctx_t       *ctx;
    ngx_http_subs_loc_conf_t  *slcf;

    log = r->connection->log;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_subs_filter_module);
    if (slcf == NULL
            || slcf->sub_pairs->nelts == 0
            || r->headers_out.content_type.len == 0
            || r->headers_out.content_length_n == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_subs_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
            "http subs filter \"%V\"", &r->uri);

    if (in == NULL && ctx->in == NULL && ctx->busy == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in) {
        /* tpool is only existed in this function. It's used 
         * for the chain 'ctx->line_in's temporary memory 
         * allocation */

        if (ngx_chain_add_copy(r->pool, &ctx->in, in) == NGX_ERROR) {
            goto failed;
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

        tpool = ngx_create_pool(pool_size, r->connection->log);
        if (tpool == NULL) {
            goto failed;
        }

        if (ctx->saved) {
#if 1
            for (cl = ctx->saved; cl; cl = cl->next) {
                if (cl->buf) {
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                            "subs in saved: %p , size:%uz, sync:%d", 
                            cl->buf, ngx_buf_size(cl->buf), cl->buf->sync);
                }
            }
#endif
            if (ngx_chain_add_copy(tpool, &ctx->line_in, ctx->saved) 
                    == NGX_ERROR) {
                goto failed;
            }
        }
    }
    else  {
        ctx->in = NULL;
    }

    for (cl = ctx->in; cl; cl = cl->next) {
        b = cl->buf;
        if (b == NULL) {
            continue;
        }

        bytes = b->last - b->pos;
        if (bytes < 0){
            continue;
        }

        p = b->pos;
        while (bytes > 0) {
            nl = memchr(p, LF, bytes); 
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "find linefeed :%p", nl);

            if (nl == NULL && cl->buf->last_buf){
                nl = b->last;
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, 
                        "Not find linefeed, but this is the last buffer:%p ", nl);
            }

            if (nl) {
                len = nl - p + 1;
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                        "create line :%p, len:%d ", p, len);
                part_line_in_cl = create_chain_buffer(p, len, tpool);
                if (part_line_in_cl == NULL) {
                    goto failed;
                }

                bytes -= len;
                p += len;

                if (ctx->line_in != NULL){
                    insert_chain_tail(&ctx->line_in, part_line_in_cl);
                }
                else {
                    ctx->line_in = part_line_in_cl;
                }

                /*do the substitutions with the chain buffers of ctx->line_in*/
                /*and the output chain buffers is the ctx->line_out*/
                rc = ngx_http_subs_match(r, ctx, tpool);
                ctx->line_in = NULL;

                if (rc < 0) {
                    goto failed;
                }
                else if (rc > 0) {
                    /* Matched at least 1 count*/

                    /* ctx->last_pos is the last not matched postion, the chain will
                     * not be splited until a successful matching. This will reduce 
                     * the split frequency of the chain. */
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                            "Last_pos :%p ", ctx->last_pos);
                    if (ctx->last_pos) {
                        split_cl = split_chain(cl, ctx->last_pos - b->pos,
                                &ctx->in, r->pool);
                        temp_cl = fetch_chain_buffer(split_cl->buf->pos, 
                                split_cl->buf->last - split_cl->buf->pos, 
                                &ctx->free, r->pool);

                        insert_chain_tail(&ctx->out, temp_cl);

                        ctx->last_pos = 0;
                    }

                    if (ctx->line_out) {
#if 1 
                        for (temp_cl = ctx->line_out; temp_cl; temp_cl = temp_cl->next) {
                            if (temp_cl->buf) {
                                test.data = temp_cl->buf->pos;
                                test.len = temp_cl->buf->last - temp_cl->buf->pos;

                                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                                        "Line out buffer: %p , size:%uz", 
                                        temp_cl->buf, ngx_buf_size(temp_cl->buf));
                            }
                        }
#endif
                        insert_chain_tail(&ctx->out, ctx->line_out);
                        split_chain(cl, len, &ctx->in, r->pool);
                        ctx->line_out = NULL;
                    }
#if 0 
                    for (temp_cl = ctx->out; temp_cl; temp_cl = temp_cl->next) {
                        if (temp_cl->buf) {
                            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
                                    "Out buffer: %p , size:%uz, sync:%d", 
                                    temp_cl->buf, ngx_buf_size(temp_cl->buf), temp_cl->buf->sync);
                        }
                    }
#endif
                    ctx->saved = NULL;
                }
                else {
                    /*no match*/
                    if (ctx->saved) {
                        insert_chain_tail(&ctx->out, ctx->saved);
                        ctx->saved = NULL;
                    }
                    ctx->last_pos = p;
                }
            } else {
                /*Not find the linefeed in this chain*/
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                        "Buffer last, last_pos :%p ", ctx->last_pos);
                if (ctx->last_pos) {
                    split_cl = split_chain(cl, ctx->last_pos - b->pos,
                            &ctx->in, r->pool);
                    temp_cl = fetch_chain_buffer(split_cl->buf->pos, 
                            split_cl->buf->last - split_cl->buf->pos, 
                            &ctx->free, r->pool);
                    insert_chain_tail(&ctx->out, temp_cl);
                    ctx->last_pos = 0;
                }

                /*To the end of buffer and not found LF.*/
                temp_cl = ngx_alloc_chain_link(tpool);
                temp_cl->buf = cl->buf;
                temp_cl->next = NULL;
                if (ngx_chain_add_copy(tpool, &ctx->line_in, temp_cl) == NGX_ERROR){
                    ngx_log_error(NGX_LOG_ALERT, log, 0, 
                            "[subs_filter] ngx_chain_add_copy error.");
                    goto failed;
                }
                break;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                    "Left bytes:%d, p:%p ", bytes, p);
            /*There is nothing left in this buffer.*/
            if (cl->buf->last - p <= 0)
                break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                "At chain last, last_pos :%p ", ctx->last_pos);
        if (ctx->last_pos) {
            split_cl = split_chain(cl, 
                    ctx->last_pos - b->pos,
                    &ctx->in, r->pool);
            temp_cl = fetch_chain_buffer(split_cl->buf->pos, 
                    split_cl->buf->last - split_cl->buf->pos, 
                    &ctx->free, r->pool);
            insert_chain_tail(&ctx->out, temp_cl);
            ctx->last_pos = 0;
        }

        /*copy line_in to saved.*/
        if (ctx->line_in) {
            ctx->saved = duplicate_chains(ctx->line_in,
                    &ctx->free, r->pool);
            if (ctx->saved == NULL) {
                ngx_log_error(NGX_LOG_ALERT, log, 0, 
                        "[subs_filter] duplicate_chains error.");
                goto failed;
            }

            if (cl->next == NULL) {
                ctx->line_in = NULL;
            }
        }

        if (ctx->out == NULL) {
            ctx->out = create_chain_buffer(NULL, 0, r->pool);
            ctx->out->buf->sync = 1;
        }

        if (cl->buf->last_buf){
            insert_chain_tail(&ctx->out, ctx->saved);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
                    "[subs_filter] Lost last linefeed, but output anyway.");
        }

        if (cl->buf->last_buf || ngx_buf_in_memory(cl->buf)) {

            if (p == cl->buf->pos) {
                /*This buffer don't find the linefeed.*/
                temp_cl = create_chain_buffer(NULL, 0, r->pool);
                temp_cl->buf->sync = 1;
                insert_chain_tail(&ctx->out, temp_cl);
            }

            temp_cl = get_chain_tail(ctx->out);
            b = temp_cl->buf;
            /*Add the shadow buffer for freeing after output*/
            if (b) {
                insert_shadow_tail(&b->shadow, cl->buf);
            }
            else {
                b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
                b->shadow = cl->buf;
                b->sync = 1;
            }

            b->last_buf = cl->buf->last_buf;
        }

    }
    ctx->in = NULL;

    if (tpool) {
        ngx_destroy_pool(tpool);
        tpool = NULL;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_subs_output(r, ctx, in);

failed:
    if (tpool) {
        ngx_destroy_pool(tpool);
        tpool = NULL;
    }

    ngx_log_error(NGX_LOG_ALERT, log, 0, "[subs_filter] subs_match error.");

    return NGX_ERROR;
}

static ngx_int_t ngx_http_subs_output(
        ngx_http_request_t *r, ngx_http_subs_ctx_t *ctx,
        ngx_chain_t *in)
{
    size_t        size;
    ngx_int_t     rc, last_chain;
    ngx_buf_t    *b;
    ngx_buf_t    *temp_b;
    ngx_chain_t  *cl;

    last_chain = 0;
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {

        b = cl->buf;
        size = ngx_buf_size(b);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "subs out buffer: %p , size:%uz, sync:%d, last_buf:%d", 
                b, size, b->sync, b->last_buf);

        if (b->last_buf) {
            last_chain = 1;
            b->last_buf = 0;
        }
    }
    b->last_buf = last_chain;

    rc = ngx_http_next_body_filter(r, ctx->out);

#if 1
    size = 0;
    for (cl = ctx->out; cl; cl = cl->next) {
        size = ngx_buf_size(cl->buf);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "subs out end: %p %uz", cl->buf, size);
    }
#endif

    /*output chain is busy.*/
    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;
    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;

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
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "clear shadow buff: %p", b);

        while(temp_b->shadow) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "clear recursive shadow buff: %p, %p", 
                    temp_b, temp_b->shadow);
            temp_b->shadow->pos = temp_b->shadow->last;
            if (temp_b->shadow->last_shadow) {
                break;
            }
            temp_b = temp_b->shadow;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data buffers only to the free buffer chain */
            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}

static char * ngx_http_subs_filter( ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf)
{
    ngx_int_t                   n;
    ngx_uint_t                  i, mask;
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

        /*dirty hacked*/
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

        /*  Caseless match can only be implemented in regex.*/
        if (pair->regex || pair->insensitive) {
#if (NGX_PCRE)
            ngx_str_t         err;
            u_char            errstr[NGX_MAX_CONF_ERRSTR];

            err.len = NGX_MAX_CONF_ERRSTR;
            err.data = errstr;

    /* make nginx-0.8.25+ happy */
#if defined(nginx_version) && nginx_version >= 8025
            ngx_regex_compile_t   rc;

            rc.pattern = pair->match;
            rc.pool = cf->pool;
            rc.err = err; 
            rc.options = NGX_REGEX_CASELESS;

            if (ngx_regex_compile(&rc) != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
                return NGX_CONF_ERROR;
            }

            pair->match_regex = rc.regex;

#else
            if (pair->insensitive) {
                pair->match_regex = ngx_regex_compile(&pair->match,
                        NGX_REGEX_CASELESS, cf->pool, &err);
            }
            else {
                pair->match_regex = ngx_regex_compile(&pair->match,
                        0, cf->pool, &err);
            }

#endif
            if (pair->match_regex == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &err);
                return NGX_CONF_ERROR;
            }

            n = ngx_regex_capture_count(pair->match_regex);

            if (pair->dup_capture) {
                mask = ((1 << (n + 1)) - 1);
                if ( mask < sc.captures_mask ) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "You want to capture too many regex substrings,"
                            " more than %d in \"%V\"",
                            n, &value[2]);

                    return NGX_CONF_ERROR;
                }
            }
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "the using of the regex \"%V\" requires PCRE library",
                    &pair->match);

            return NGX_CONF_ERROR;
#endif
        }
    }

    return NGX_CONF_OK;
}


static char * ngx_http_subs_types(
        ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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


static void * ngx_http_subs_create_conf(ngx_conf_t *cf)
{
    ngx_http_subs_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_subs_loc_conf_t));
    if (slcf == NULL) {
        return NGX_CONF_ERROR;
    }

    return slcf;
}


static char * ngx_http_subs_merge_conf(
        ngx_conf_t *cf, void *parent, void *child)
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


static ngx_int_t ngx_http_subs_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_subs_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_subs_body_filter;

    return NGX_OK;
}
