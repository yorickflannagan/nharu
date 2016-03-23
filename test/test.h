#ifndef TEST_H_INCLUDED
#define TEST_H_INCLUDED

#include "cms.h"

int test_encoder();
int test_secret_sharing();
int test_encrypt();
int test_rsa();
int test_cert();
int test_pkibr();
int test_crl();
int parse_openssl_cms_signed_data();
int test_cms_signed_data();
int test_openssl_cms_enveloped_data();

#endif
