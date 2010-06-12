
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_chain_buffer.h>

ngx_buf_t * buffer_append_string(ngx_buf_t *b, u_char *s, size_t len, ngx_pool_t *pool)
{
    u_char     *p;
    ngx_uint_t capacity, size;

    if (len > (size_t) (b->end - b->last)) {

        capacity = b->end - b->start;
        capacity *= 1.5;
        p = ngx_palloc(pool, capacity);
        if (p == NULL) {
            return NULL;
        }

        size = b->last - b->pos;
        ngx_memcpy(p, b->pos, size);

        b->start = b->pos = p;
        b->last = p + size;
        b->end = p + capacity;
    }

    ngx_memcpy(b->last, s, len);
    b->last += len;

    return b;
}

/*copy from chain to queue*/
ngx_int_t
ngx_queue_chain_add_copy(ngx_pool_t *pool, ngx_queue_t *qh, ngx_chain_t *in)
{
    ngx_queue_buf_t  *qb;

    while (in) {
        qb = ngx_calloc_queue_buf(pool);
        if (qb == NULL) {
            return NGX_ERROR;
        }

        qb->buf = in->buf;
        ngx_queue_insert_tail(qh, &qb->queue);

        in = in->next;
    }

    return NGX_OK;
}

/*copy from queue to chain*/
ngx_int_t
ngx_chain_queue_add_copy(ngx_pool_t *pool,  ngx_chain_t **chain, ngx_queue_t *qh)
{
    ngx_chain_t      *cl, **ll;
    ngx_queue_t      *q;
    ngx_queue_buf_t  *qb;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for (q = ngx_queue_head(qh); q != ngx_queue_sentinel(qh); q = ngx_queue_next(q)) {

        qb = ngx_queue_data(q, ngx_queue_buf_t, queue);

        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = qb->buf;

        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return NGX_OK;
}

ngx_buf_t * create_buffer(u_char *p, ngx_int_t len, ngx_pool_t *pool)
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

ngx_chain_t * create_chain_buffer(u_char *p, 
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

ngx_chain_t *duplicate_chain_buffer(u_char *src, 
        ngx_int_t len, ngx_pool_t *pool)
{
    u_char *dst;

    dst = ngx_palloc(pool, len);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src, len);

    return create_chain_buffer(dst, len, pool);
}

/* Fetch a chain buffer, if *p_free is NULL, then create it, 
 * If not, allocates the head chain of *p_free for it.*/
ngx_chain_t * fetch_chain_buffer(u_char *p, ngx_int_t len, 
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
ngx_chain_t *copy_chain_buffer(ngx_chain_t *chain, 
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
ngx_chain_t *duplicate_chains(ngx_chain_t *chain,
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

ngx_chain_t *get_chain_tail(ngx_chain_t *chain)
{
    ngx_chain_t *cl;

    if (chain == NULL)
        return NULL;

    for(cl = chain; cl->next; cl = cl->next) {}

    return cl;
}

/*ngx_chain_t *get_chain_previous( ngx_chain_t *in, ngx_chain_t *chain)*/
/*{*/
/*ngx_chain_t *cl;*/

/*if (in == NULL)*/
/*return NULL;*/

/*if (in == chain)*/
/*return chain;*/

/*if (chain == NULL)*/
/*return get_chain_tail(in);*/

/*for(cl = in; cl->next; cl = cl->next) {*/
/*if (cl->next == chain)*/
/*return cl;*/
/*}*/

/**//*Not found*/
/*if (cl->next == NULL)  */
/*return NULL;*/

/*return cl;*/
/*}*/

ngx_buf_t * insert_shadow_tail(ngx_buf_t **p_shadow, ngx_buf_t *tail)
{
    ngx_buf_t *b;

    if (*p_shadow == NULL){
        *p_shadow = tail;
        return *p_shadow;
    }

    for(b = (*p_shadow); b; b = b->shadow){
        if (b == tail) {
            return *p_shadow;
        }
    }

    b = tail;

    return *p_shadow;
}

ngx_chain_t * insert_chain_tail(ngx_chain_t **p_chain, ngx_chain_t *tail)
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
void delete_and_free_chain(
        ngx_chain_t **p_chain, ngx_chain_t **p_free_chain)
{
    ngx_chain_t *cl, *tail;

    if (p_chain == NULL || *p_chain == NULL) {
        return;
    }

    for(cl = *p_chain; cl; cl = cl->next) {
        if (cl->buf) {
            ngx_memzero(cl->buf, sizeof(ngx_buf_t));
        }

        if (cl->next == NULL) {
            tail = cl;
        }
    }

    if (p_free_chain == NULL) {
        return;
    }

    if (*p_free_chain == NULL) {
        *p_free_chain = *p_chain;
    }
    else {
        tail->next = *p_free_chain;
        *p_free_chain = *p_chain;
    }

    *p_chain = NULL;
}

/*ngx_chain_t *insert_chain_before( ngx_chain_t **p_in, */
/*ngx_chain_t *insert_chain, ngx_chain_t *chain)*/
/*{*/
/*ngx_chain_t *cl;*/

/*if (insert_chain == NULL || p_in == NULL || *p_in == NULL)*/
/*return NULL;*/

/*cl = get_chain_previous(*p_in, chain);*/
/*if (cl == NULL)*/
/*return NULL;*/

/**//*This chain is the head of chains link.*/
/*if (cl == chain) {*/
/*insert_chain->next = chain;*/
/**p_in = insert_chain;*/
/*}*/
/*else {*/
/*cl->next = insert_chain;*/
/*insert_chain->next = chain;*/
/*}*/

/*return chain;*/
/*}*/

/**//* split the chain's buffer, len is the split point, */
/* * *p_in is the chain's head*/
/*ngx_chain_t * split_chain( ngx_chain_t *chain,*/
/*ngx_int_t len, ngx_chain_t **p_in, ngx_pool_t *pool)*/
/*{*/
/*ngx_chain_t *cl;*/
/*ngx_buf_t   *b1, *b2;*/

/*if (chain == NULL || p_in == NULL || *p_in == NULL ||*/
/*pool == NULL || len <= 0)*/
/*return NULL;*/

/*b2 = chain->buf; */
/*if (b2 == NULL || len > ngx_buf_size(chain->buf))*/
/*return NULL;*/

/*cl = create_chain_buffer(b2->pos, len, pool);*/
/*if (cl == NULL)*/
/*return NULL;*/
/*b1 = cl->buf;*/
/*if (b1 == NULL)*/
/*return NULL;*/

/*insert_chain_before(p_in, cl, chain);*/

/*b2->pos += len;*/
/*if (b2->pos == b2->last) {*/
/*b2->sync = 1;*/
/*}*/

/*return cl;*/
/*}*/

/*read any chain's buffer and copy to *p_buff */
ngx_int_t chain_buffer_read( ngx_chain_t *chain, 
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
ngx_int_t  buffer_chain_concatenate( ngx_chain_t **p_in, u_char *p, 
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
