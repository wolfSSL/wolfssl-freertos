/* Example user settings file (enabled with WOLFSSL_USER_SETTINGS)
 * For FreeRTOS TCP wolfMQTT on Windows */

#ifndef _USER_SETTING_H_
#define _USER_SETTING_H_

/* optional debugging */
#if 0
#define DEBUG_WOLFSSL
#endif

/* Use the FreeRTOS TCP API's */
#define FREERTOS_TCP

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

/* enable TLS features */
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
