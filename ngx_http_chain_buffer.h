
#ifndef _NGX_HTTP_CHAIN_BUFFER_H_INCLUDED_
#define _NGX_HTTP_CHAIN_BUFFER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_buf_t  *buf;
    ngx_queue_t queue;
} ngx_queue_buf_t;

ngx_queue_buf_t *ngx_alloc_queue_buf(ngx_pool_t *pool, ngx_queue_buf_t *free);
ngx_queue_buf_t *ngx_calloc_queue_buf(ngx_pool_t *pool, ngx_queue_buf_t *free);

#define ngx_free_queue(qh_free, qh) \
    ngx_queue_add(qh_free, qh)      \
    ngx_queue_init(qh)              

ngx_int_t ngx_queue_chain_add_copy(ngx_pool_t *pool, ngx_queue_t *qh, ngx_chain_t *in, ngx_queue_buf_t *free);
ngx_int_t ngx_chain_queue_add_copy(ngx_pool_t *pool,  ngx_chain_t **chain, ngx_queue_t *qh);

#define ngx_buffer_init(b) b->pos = b->last = b->start;

ngx_buf_t * buffer_append_string(ngx_buf_t *b, u_char *s, size_t len, ngx_pool_t *pool);

ngx_chain_t * get_chain_tail(ngx_chain_t *chain);
ngx_buf_t * insert_shadow_tail(ngx_buf_t **p_shadow, ngx_buf_t *tail);
ngx_chain_t * insert_chain_tail(ngx_chain_t **p_chain, ngx_chain_t *tail);

ngx_buf_t * create_buffer(u_char *p, ngx_int_t len, ngx_pool_t *pool);

ngx_chain_t * create_chain_buffer(u_char *p, ngx_int_t len, ngx_pool_t *pool);
ngx_chain_t * duplicate_chain_buffer(u_char *p, ngx_int_t len, ngx_pool_t *pool);

/* Fetch a chain buffer, if *p_free is NULL, then create it, 
 * If not, allocates the head chain of *p_free for it.*/
ngx_chain_t * fetch_chain_buffer(u_char *p, ngx_int_t len, 
        ngx_chain_t **p_free, ngx_pool_t *pool);

/* Deep copy the chain's buffer and fetch a chain and buffer*/
ngx_chain_t * copy_chain_buffer(ngx_chain_t *chain, ngx_chain_t **p_free,
        ngx_pool_t *pool);

/* Deep copy chains, return the duplicate chains*/
ngx_chain_t * duplicate_chains(ngx_chain_t *chain, ngx_chain_t **p_free, 
        ngx_pool_t *pool);

/* delete the chains link of *p_chain and  
 * add to the head of *p_free_chain */
void delete_and_free_chain(ngx_chain_t **p_chain, ngx_chain_t **p_free_chain);

#endif /* _NGX_HTTP_CHAIN_BUFFER_H_INCLUDED_ */
