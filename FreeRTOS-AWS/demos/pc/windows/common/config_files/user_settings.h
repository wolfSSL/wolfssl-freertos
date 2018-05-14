/* WolfSSL settings file for AWS FreeRTOS PC Demo */

#ifndef _USER_SETTING_H_
#define _USER_SETTING_H_

/* Use the FreeRTOS Heap and TCP API's */
#define FREERTOS_TCP

/* Realloc for Heap */
#define XREALLOC pvPortRealloc

/* For Windows Simulator only */
#define FREERTOS_TCP_WINSIM

/* platform specific */
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MAX

/* side-channel resistance */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ignore the #warning for optional include files (misc.c, bio.c, etc...) */
#define WOLFSSL_IGNORE_FILE_WARN

/* math */
#define USE_FAST_MATH
#define ALT_ECC_SIZE
#define TFM_ECC256

/* enable algorithms */
#define HAVE_ECC
#define ECC_SHAMIR
#define HAVE_AESGCM
#define HAVE_CHACHA
#define HAVE_POLY1305
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define WOLFSSL_BASE64_ENCODE

/* these are required for TLS 1.3 */
#define HAVE_HKDF
#define WC_RSA_PSS
#define HAVE_FFDHE_2048

/* extra compatibility functions for X509 */
#define OPENSSL_EXTRA
#define OPENSSL_EXTRA_X509_SMALL
#define WOLFSSL_PEM_TO_DER

/* enable TLS features */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_ONE_TIME_AUTH

/* disable algorithms off by default */
#define NO_DSA
#define NO_RC4
#define NO_HC128
#define NO_RABBIT
#define NO_PSK
#define NO_MD4
#define NO_DES3

#endif /* _USER_SETTING_H_ */
