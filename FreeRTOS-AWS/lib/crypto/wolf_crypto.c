/*
 * Amazon FreeRTOS Crypto V1.0.1
 * Copyright (C) 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */


/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "FreeRTOSIPConfig.h"
#include "aws_crypto.h"

#ifdef WOLF_AWSTLS

/* wolfSSL library (github.com/wolfSSL/wolfssl) */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>


/* C runtime includes. */
#include <string.h>

/**
 * @brief Internal signature verification context structure
 */
typedef struct SignatureVerificationState
{
    BaseType_t xAsymmetricAlgorithm;
    BaseType_t xHashAlgorithm;
    wc_Sha     xSHA1Context;
    wc_Sha256  xSHA256Context;
} SignatureVerificationState_t, * SignatureVerificationStatePtr_t;

/*
 * Helper routines
 */

/**
 * @brief Implements libc calloc semantics using the FreeRTOS heap
 */
static void * prvCalloc( size_t xNmemb,
                         size_t xSize )
{
    void * pvNew = pvPortMalloc( xNmemb * xSize );

    if( NULL != pvNew )
    {
        memset( pvNew, 0, xNmemb * xSize );
    }

    return pvNew;
}

/**
 * @brief Verifies a cryptographic signature based on the signer
 * certificate, hash algorithm, and the data that was signed.
 */
static BaseType_t prvVerifySignature( char * pcSignerCertificate,
                                      size_t xSignerCertificateLength,
                                      BaseType_t xHashAlgorithm,
                                      uint8_t * pucHash,
                                      size_t xHashLength,
                                      BaseType_t xAsymmetricAlgorithm,
                                      uint8_t * pucSignature,
                                      size_t xSignatureLength )
{
    BaseType_t xResult = pdTRUE;
    int buf_format = WOLFSSL_FILETYPE_ASN1;
    uint8_t* pucSignerCertDer = (uint8_t*)pcSignerCertificate;
    size_t xSignerCertDerLength = xSignerCertificateLength;
    WOLFSSL_X509* xCertCtx = NULL;
    WOLFSSL_EVP_PKEY* xPublicKey = NULL;
    int hashAlg = NID_sha256;

    /*
     * Map the hash algorithm
     */
    if (xHashAlgorithm == cryptoHASH_ALGORITHM_SHA1) {
        hashAlg = NID_sha1;
    }

#ifdef WOLFSSL_PEM_TO_DER
    /* Determine certificate format */
    if( xSignerCertificateLength != 0 &&
        pcSignerCertificate[xSignerCertificateLength - 1] == '\0' &&
        strstr( (const char *) pcSignerCertificate, "-----BEGIN CERTIFICATE-----" ) != NULL )
    {
        buf_format = WOLFSSL_FILETYPE_PEM;

        pucSignerCertDer = (uint8_t*)pvPortMalloc(xSignerCertificateLength);
        if (pucSignerCertDer) {
            xResult = wolfSSL_CertPemToDer(
                (const unsigned char*)pcSignerCertificate,
                xSignerCertificateLength, pucSignerCertDer,
                xSignerCertificateLength, CERT_TYPE);
            if (xResult > 0) {
                xSignerCertDerLength = xResult;
                xResult = pdTRUE;
            }
            else {
                xResult = pdFALSE;
            }
        }
        else {
            xResult = pdFALSE;
        }
    }
#endif

    /*
     * Decode and create a certificate context
     */
    if (xResult == pdTRUE) {
        xCertCtx = wolfSSL_X509_load_certificate_buffer(
            (const unsigned char*)pucSignerCertDer, xSignerCertDerLength,
            WOLFSSL_FILETYPE_ASN1);
        if (xCertCtx == NULL) {
            xResult = pdFALSE;
        }
    }

    if (xResult == pdTRUE) {
        xPublicKey = wolfSSL_X509_get_pubkey(xCertCtx);
        if (xPublicKey == NULL) {
            xResult = pdFALSE;
        }
    }

    /*
     * Verify the signature using the public key from the decoded certificate
     */
    if (xResult == pdTRUE) {
        if (xAsymmetricAlgorithm == cryptoASYMMETRIC_ALGORITHM_RSA) {
            /* default to failure */
            xResult = pdFALSE;

            /* Perform verification of signature using provided RSA key */
            xResult = wolfSSL_RSA_verify(hashAlg, pucHash, xHashLength,
              pucSignature, xSignatureLength, xPublicKey->rsa);
            if (xResult == WOLFSSL_SUCCESS) {
                xResult = pdTRUE;
            }
        }
        else {
            /* not supported */
            xResult = pdFALSE;
        }
    }

    /*
     * Clean-up
     */
    if (xCertCtx) {
        wolfSSL_X509_free(xCertCtx);
    }
    if (xPublicKey) {
        wolfSSL_EVP_PKEY_free(xPublicKey);
    }

#ifdef WOLFSSL_PEM_TO_DER
    if (buf_format == WOLFSSL_FILETYPE_PEM) {
        vPortFree(pucSignerCertDer);
    }
#endif

    return xResult;
}

/*
 * Interface routines
 */

/**
 * @brief Overrides CRT heap callouts to use FreeRTOS instead
 */
void CRYPTO_ConfigureHeap( void )
{
    /* mapped in user_settings.h with FREERTOS define. */

}

/**
 * @brief Creates signature verification context.
 */
BaseType_t CRYPTO_SignatureVerificationStart( void ** ppvContext,
                                              BaseType_t xAsymmetricAlgorithm,
                                              BaseType_t xHashAlgorithm )
{
    BaseType_t xResult = pdTRUE;
    SignatureVerificationStatePtr_t pxCtx = NULL;

    /*
     * Allocate the context
     */
    if( NULL == ( pxCtx = ( SignatureVerificationStatePtr_t ) pvPortMalloc(
                      sizeof( *pxCtx ) ) ) ) /*lint !e9087 Allow casting void* to other types. */
    {
        xResult = pdFALSE;
    }

    if( pdTRUE == xResult )
    {
        *ppvContext = pxCtx;

        /*
         * Store the algorithm identifiers
         */
        pxCtx->xAsymmetricAlgorithm = xAsymmetricAlgorithm;
        pxCtx->xHashAlgorithm = xHashAlgorithm;

        /*
         * Initialize the requested hash type
         */
        if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
        {
            wc_InitSha(&pxCtx->xSHA1Context);
        }
        else
        {
            wc_InitSha256(&pxCtx->xSHA256Context);
        }
    }

    return xResult;
}

/**
 * @brief Adds bytes to an in-progress hash for subsequent signature
 * verification.
 */
void CRYPTO_SignatureVerificationUpdate( void * pvContext,
                                         uint8_t * pucData,
                                         size_t xDataLength )
{
    SignatureVerificationStatePtr_t pxCtx = ( SignatureVerificationStatePtr_t ) pvContext; /*lint !e9087 Allow casting void* to other types. */

    /*
     * Add the data to the hash of the requested type
     */
    if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
    {
        wc_ShaUpdate(&pxCtx->xSHA1Context, pucData, xDataLength);
    }
    else
    {
        wc_Sha256Update(&pxCtx->xSHA256Context, pucData, xDataLength);
    }
}

/**
 * @brief Performs signature verification on a cryptographic hash.
 */
BaseType_t CRYPTO_SignatureVerificationFinal( void * pvContext,
                                              char * pcSignerCertificate,
                                              size_t xSignerCertificateLength,
                                              uint8_t * pucSignature,
                                              size_t xSignatureLength )
{
    BaseType_t xResult = pdTRUE;
    SignatureVerificationStatePtr_t pxCtx =
        ( SignatureVerificationStatePtr_t ) pvContext; /*lint !e9087 Allow casting void* to other types. */
    uint8_t ucSHA1[ cryptoSHA1_DIGEST_BYTES ];
    uint8_t ucSHA256[ cryptoSHA256_DIGEST_BYTES ];
    uint8_t * pucHash = NULL;
    size_t xHashLength = 0;

    /*
     * Finish the hash
     */
    if( cryptoHASH_ALGORITHM_SHA1 == pxCtx->xHashAlgorithm )
    {
        wc_ShaFinal(&pxCtx->xSHA1Context, ucSHA1);
        pucHash = ucSHA1;
        xHashLength = cryptoSHA1_DIGEST_BYTES;
    }
    else
    {
        wc_Sha256Final(&pxCtx->xSHA256Context, ucSHA256);
        pucHash = ucSHA256;
        xHashLength = cryptoSHA256_DIGEST_BYTES;
    }

    /*
     * Verify the signature
     */
    xResult = prvVerifySignature( pcSignerCertificate,
                                  xSignerCertificateLength,
                                  pxCtx->xHashAlgorithm,
                                  pucHash,
                                  xHashLength,
                                  pxCtx->xAsymmetricAlgorithm,
                                  pucSignature,
                                  xSignatureLength );

    /*
     * Clean-up
     */
    vPortFree( pxCtx );

    return xResult;
}

#endif /* WOLF_AWSTLS */
