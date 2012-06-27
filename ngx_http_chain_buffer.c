
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_chain_buffer.h>


ngx_buf_t * 
buffer_append_string(ngx_buf_t *b, u_char *s, size_t len, ngx_pool_t *pool)
{
    u_char     *p;
    ngx_uint_t capacity, size;

    if (len > (size_t) (b->end - b->last)) {

        size = b->last - b->pos;

        capacity = b->end - b->start;
        capacity *= 1.5;
        if (capacity < (size + len)) {
            capacity = size + len;
        }

        p = ngx_palloc(pool, capacity);
        if (p == NULL) {
            return NULL;
        }

        ngx_memcpy(p, b->pos, size);

        b->start = b->pos = p;
        b->last = p + size;
        b->end = p + capacity;
    }

    ngx_memcpy(b->last, s, len);
    b->last += len;

    return b;
}


ngx_buf_t * 
create_buffer(u_char *p, ngx_int_t len, ngx_pool_t *pool)
{
    ngx_buf_t   *b;

    b = ngx_pcalloc(pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NULL;
    }

    b->start = b->pos = p;
    b->end = b->last = p + len;

    if (len == 0) {
        b->sync = 1;
    }
    else {
        b->memory = 1;
    }

    return b;
}


ngx_chain_t * 
create_chain_buffer(u_char *p, ngx_int_t len, ngx_pool_t *pool)
{
    ngx_chain_t *cl;
    ngx_buf_t   *b;

    b = create_buffer(p, len, pool);
    if (b == NULL) {
        return NULL;
    }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL)
        return NULL;

    cl->buf = b;
    cl->next = NULL;

    return cl;
}


ngx_chain_t *
duplicate_chain_buffer(u_char *src, ngx_int_t len, ngx_pool_t *pool)
{
    u_char *dst;

    dst = ngx_palloc(pool, len);
    if (dst == NULL) {
        return NULL;
    }

    ngx_memcpy(dst, src, len);

    return create_chain_buffer(dst, len, pool);
}


/*
 * Fetch a chain buffer, if *p_free is NULL, then create it, 
 * If not, allocates the head chain of *p_free for it.*/
ngx_chain_t *
fetch_chain_buffer(u_char *p, ngx_int_t len, ngx_chain_t **p_free,
                   ngx_pool_t *pool)
{
    ngx_buf_t   *b;
    ngx_chain_t *cl;

    if (p_free != NULL && *p_free != NULL) {
        cl = *p_free;
        (*p_free) = (*p_free)->next;
        cl->next = NULL;

        b = cl->buf;
        if (b == NULL){
            b = ngx_pcalloc(pool, sizeof(ngx_buf_t));
            if (b == NULL) {
                return NULL;
            }
        }

        b->start = b->pos = p;
        b->end = b->last = p + len;
        if (len == 0) {
            b->sync = 1;
        }
        else  {
            b->memory = 1;
        }

        return cl;
    }
    else {
        return create_chain_buffer(p, len, pool);
    }
}


/* Deep copy the chain's buffer and fetch a chain and buffer*/
ngx_chain_t *
copy_chain_buffer(ngx_chain_t *chain, ngx_chain_t **p_free, ngx_pool_t *pool)
{
    u_char      *p = NULL;
    ngx_buf_t   *b = NULL;
    ngx_int_t    len;
    ngx_chain_t *cl = NULL;

    if (chain == NULL || chain->buf == NULL) {
        return NULL;
    }

    b = chain->buf;

    len = b->last - b->pos;
    if (len < 0) {
        return NULL;
    }
    else if (len > 0) {
        p = ngx_palloc(pool, len);
        ngx_memcpy(p, b->pos, len);
    }

    cl = fetch_chain_buffer(p, len, p_free, pool);
    cl->next = NULL;

    return cl;
}


/* Deep copy chains, return the duplicate chains*/
ngx_chain_t *
duplicate_chains(ngx_chain_t *chain, ngx_chain_t **p_free, ngx_pool_t *pool)
{
    ngx_chain_t *head, *cl, *copy, *last;

    if (chain == NULL) {
        return NULL;
    }

    copy = last = head = NULL;
    for(cl = chain; cl; cl = cl->next) {
        copy = copy_chain_buffer(cl, p_free, pool);
        if (copy == NULL) {
            return NULL;
        }

        if (head == NULL) {
            head = copy;
        }

        if (last == NULL) {
            last = copy;
        }
        else {
            last->next = copy;
            last = copy;
        }
    }

    if (last != NULL) {
        last->next = NULL;
    }

    return head;
}


ngx_chain_t *
get_chain_tail(ngx_chain_t *chain)
{
    ngx_chain_t *cl;

    if (chain == NULL) {
        return NULL;
    }

    for(cl = chain; cl->next; cl = cl->next) {}

    return cl;
}


ngx_chain_t * 
insert_chain_tail(ngx_chain_t **p_chain, ngx_chain_t *tail)
{
    ngx_chain_t *cl;

    if (p_chain == NULL) {
        return NULL;
    }

    if (tail == NULL) {
        return *p_chain;
    }

    if (*p_chain == NULL) {
        *p_chain = tail;
    }
    else {
        cl = get_chain_tail(*p_chain);
        cl->next = tail;
    }

    return *p_chain;
}


/*
 * delete the chains link of *p_chain and  
 * add to the head of *p_free_chain */
void 
delete_and_free_chain( ngx_chain_t **p_chain, ngx_chain_t **p_free_chain)
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
