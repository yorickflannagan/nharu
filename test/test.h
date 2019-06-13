#ifndef TEST_H_INCLUDED
#define TEST_H_INCLUDED

#include "pki-issue.h"

int save_buffer(unsigned char*, size_t, char*);
int load_file(char*, unsigned char**, int*);

int test_encoder();
int test_secret_sharing();
int test_indefinite_length_form();
int test_encrypt();
int test_rsa();
int test_certificate(char*, char*);
int test_crl(char*, char*);
int test_cms_signed_data(char*, char*);
int test_cms_signed_data_with_pubkey(char*);
int test_enveloped_data(char*);
int test_fake_enveloped_data();
int test_cadest();

int test_parse_request();
int test_parse_pubkey();
int test_sign_certificate();
int test_create_request();
int test_encode_p8();
int test_issue_crl();

EXTERN unsigned char __ca_privkey[];
#define CA_PRIVKEY_SIZE			1217
EXTERN unsigned char __ca_cert[];
#define CA_CERT_SIZE			1138

#endif
