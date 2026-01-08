#ifndef __MD5_H__
#define __MD5_H__

// MD5 context structure
typedef struct {
    unsigned int state[4];
    unsigned int count[2];
    unsigned char buffer[64];
} md5_ctx_t;

// MD5 function declarations
void md5_init(md5_ctx_t *context);
void md5_update(md5_ctx_t *context, unsigned char *input, unsigned int inputlen);
void md5_final(unsigned char digest[16], md5_ctx_t *context);
void md5_transform(unsigned int state[4], unsigned char block[64]);
void md5_encode(unsigned char *output, unsigned int *input, unsigned int len);
void md5_decode(unsigned int *output, unsigned char *input, unsigned int len);


#endif
