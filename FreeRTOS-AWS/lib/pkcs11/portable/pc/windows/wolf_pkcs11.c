/*
 * Amazon FreeRTOS PKCS#11 for Windows Simulator V1.0.1
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


/**
 * @file wolf_pkcs11.c
 * @brief Windows simulator PKCS#11 implementation for software keys. This
 * file deviates from the FreeRTOS style standard for some function names and
 * data types in order to maintain compliance with the PKCS#11 standard.
 */

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "FreeRTOSIPConfig.h"
#include "task.h"
#include "aws_crypto.h"
#include "aws_pkcs11.h"

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

#include "aws_clientcredential.h"

/* C runtime includes. */
#include <stdio.h>
#include <string.h>

/**
 * @brief File storage location definitions.
 */
#define pkcs11FILE_NAME_CLIENT_CERTIFICATE    "FreeRTOS_P11_Certificate.dat"
#define pkcs11FILE_NAME_KEY                   "FreeRTOS_P11_Key.dat"

/**
 * @brief Cryptoki module attribute definitions.
 */
#define pkcs11SLOT_ID                         1
#define pkcs11OBJECT_HANDLE_PUBLIC_KEY        1
#define pkcs11OBJECT_HANDLE_PRIVATE_KEY       2
#define pkcs11OBJECT_HANDLE_CERTIFICATE       3

#define pkcs11SUPPORTED_KEY_BITS              2048

#define DER_TMP_BUFFER_LEN 2048

typedef enum {
    WOLFSSL_PK_NONE = 0,
    WOLFSSL_PK_RSA,
    WOLFSSL_PK_RSASSA_PSS,
    WOLFSSL_PK_ECKEY,
    WOLFSSL_PK_ECKEY_DH,
    WOLFSSL_PK_ECDSA,
} wolfSSL_pk_type_t;

typedef struct wolfSSL_pk_context {
    union {
    #ifndef NO_RSA
        RsaKey rsa;
    #endif
    #ifdef HAVE_ECC
        ecc_key  ecc;
    #endif
        void* ptr;
    } key;
    int type;  /* wolfSSL_pk_type_t */
    int keyBits;
    byte* der;
    word32 derLen;
} wolfSSL_pk_context;


void wolfSSL_pk_init( wolfSSL_pk_context *pk )
{
    if (pk) {
        XMEMSET(pk, 0, sizeof(*pk));
    }
}

wolfSSL_pk_type_t wolfSSL_pk_get_type( const wolfSSL_pk_context *pk )
{
    if (pk)
        return pk->type;
    return WOLFSSL_PK_NONE;
}

size_t wolfSSL_pk_get_bitlen( const wolfSSL_pk_context *pk )
{
    if (pk)
        return pk->keyBits;
    return 0;
}

void* wolfSSL_pk_get_key( const wolfSSL_pk_context *pk )
{
    if (pk)
        return pk->key.ptr;
    return NULL;
}

int wolfSSL_pk_get_key_der( const wolfSSL_pk_context *pk, byte* der, word32* derLen )
{
    int ret = -1;
    if (pk && der && derLen) {
        if (*derLen >= pk->derLen)
            return BUFFER_E;
        memcpy(der, pk->der, pk->derLen);
        *derLen = pk->derLen;
        ret = 0;
    }
    return ret;
}

void wolfSSL_pk_key_free( wolfSSL_pk_context *pk )
{
    /* cleanup keys */
    switch (pk->type) {
        case WOLFSSL_PK_RSA:
        case WOLFSSL_PK_RSASSA_PSS:
    #ifndef NO_RSA
            wc_FreeRsaKey(&pk->key.rsa);
    #endif
            break;
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
    #ifdef HAVE_ECC
            wc_ecc_free(&pk->key.ecc);
    #endif
            break;

    }
}

int wolfSSL_pk_create_key(wolfSSL_pk_context *pk,
                  const unsigned char *der, size_t derlen)
{
    int ret = -1;
	word32 idx = 0;

    switch (pk->type) {
        case WOLFSSL_PK_RSA:
        case WOLFSSL_PK_RSASSA_PSS:
        #ifndef NO_RSA
            ret = wc_InitRsaKey(&pk->key.rsa, NULL);
            if (ret == 0) {
                ret = wc_RsaPrivateKeyDecode(der, &idx, &pk->key.rsa, derlen);
                if (ret == 0) {
                    /* get key size */
                    ret = wc_RsaEncryptSize(&pk->key.rsa);
                    if (ret > 0) {
                        pk->keyBits = ret * 8;
                        ret = 0;
                    }
                    else {
                        ret = -1;
                    }
                }
                else {
                    wolfSSL_pk_key_free(pk);
                }
            }
        #endif
            break;
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
        #ifdef HAVE_ECC
            ret = wc_ecc_init(&pk->key.ecc);
            if (ret == 0) {
                ret = wc_EccPrivateKeyDecode(der, &idx, &pk->key.ecc, derlen);
                if (ret == 0) {
                    /* get key size */
                    ret = wc_ecc_size(&pk->key.ecc);
                    if (ret > 0) {
                        pk->keyBits = ret * 8;
                        ret = 0;
                    }
                    else {
                        ret = -1;
                    }
                }
                else {
                    wolfSSL_pk_key_free(pk);
                }
            }
        #endif
            break;
    }
    return ret;
}

int wolfSSL_pk_parse_key( wolfSSL_pk_context *pk,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen )
{
    int ret, derLen;
    byte derTmp[DER_TMP_BUFFER_LEN];
    byte* der = derTmp;

    (void)pwdlen;

    if (pk == NULL || key == NULL || keylen <= 0)
        return -1;

    /* convert PEM to der */
    ret = wc_KeyPemToDer(key, keylen, der, sizeof(derTmp), (const char*)pwd);
    if (ret <= 0) {
        /* try using it directly */
        der = (byte*)key;
        derLen = keylen;
    }
    else {
        derLen = ret;
    }

    pk->derLen = derLen;
    pk->der = (byte*)pvPortMalloc(derLen);
    if (pk->der) {
        memcpy(pk->der, der, derLen);
    }

    /* try RSA */
    pk->type = WOLFSSL_PK_RSA;
    ret = wolfSSL_pk_create_key(pk, der, derLen);
    if (ret != 0) {
        /* try ECC */
        pk->type = WOLFSSL_PK_ECDSA;
        ret = wolfSSL_pk_create_key(pk, der, derLen);
    }

    return ret;
}

int wolfSSL_pk_sign(wolfSSL_pk_context *pk,
                    int hashType, int mgf,
                    const unsigned char * pucHash,
                    unsigned int uiHashLen,
                    unsigned char * pucSig,
                    size_t * pxSigLen,
                    WC_RNG* pRng)
{
    int ret = -1;

    switch (pk->type) {
    #ifndef NO_RSA
        case WOLFSSL_PK_RSA:
        #ifdef WC_RSA_PSS
        case WOLFSSL_PK_RSASSA_PSS:
        #endif
        {
            if (pk->type == WOLFSSL_PK_RSA)
                ret = wc_RsaSSL_Sign(pucHash, uiHashLen, pucSig, *pxSigLen,
                    &pk->key.rsa, pRng);
        #ifdef WC_RSA_PSS
            else
                ret = wc_RsaPSS_Sign(pucHash, uiHashLen, pucSig, *pxSigLen,
                    (enum wc_HashType)hashType, mgf, &pk->key.rsa, pRng);
        #endif
            if (ret > 0) {
                *pxSigLen = ret;
                ret = 0;
            }
            else {
                ret = CKR_SIGNATURE_LEN_RANGE;
            }
            break;
        }
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
            ret = wc_ecc_sign_hash(pucHash, uiHashLen, pucSig, pxSigLen, pRng, &pk->key.ecc);
            break;
    #endif /* HAVE_ECC */
        default:
            break;
    }

    (void)pk;
    (void)hashType;
    (void)pucHash;
    (void)uiHashLen;
    (void)pucSig;
    (void)pxSigLen;
    (void)pRng;

    return ret;
}

int wolfSSL_pk_verify(wolfSSL_pk_context *pk,
                      int hashType, int mgf,
                      const unsigned char * pucHash,
                      unsigned int uiHashLen,
                      const unsigned char * pucSig,
                      size_t ulSigLen)
{
    int ret = -1;

    switch (pk->type) {
    #ifndef NO_RSA
        case WOLFSSL_PK_RSA:
        #ifdef WC_RSA_PSS
        case WOLFSSL_PK_RSASSA_PSS:
        #endif
        {
            byte* plain = pvPortMalloc(ulSigLen);
            if (plain == NULL)
                return CKR_HOST_MEMORY;

            if (pk->type == WOLFSSL_PK_RSA)
                ret = wc_RsaSSL_Verify(pucHash, uiHashLen, plain, ulSigLen,
                    &pk->key.rsa);
        #ifdef WC_RSA_PSS
            else
                ret = wc_RsaPSS_Verify((byte*)pucHash, uiHashLen, plain, ulSigLen,
                    (enum wc_HashType)hashType, mgf, &pk->key.rsa);
        #endif
            if ((int)ulSigLen == ret &&
                XMEMCMP(pucSig, plain, ret) == 0) {
                ret = CKR_OK;
            }
            else {
                ret = CKR_SIGNATURE_INVALID;
            }
            vPortFree(plain);
            break;
        }
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        case WOLFSSL_PK_ECKEY:
        case WOLFSSL_PK_ECKEY_DH:
        case WOLFSSL_PK_ECDSA:
        {
            int verify = 0;
            ret = wc_ecc_verify_hash(pucSig, ulSigLen, pucHash, uiHashLen,
                &verify, &pk->key.ecc);
            if (ret == 0 && verify == 1) {
                ret = CKR_OK;
            }
            else {
                ret = CKR_SIGNATURE_INVALID;
            }
            break;
        }
    #endif /* HAVE_ECC */
        default:
            break;
    }

    (void)pk;
    (void)hashType;
    (void)pucHash;
    (void)uiHashLen;
    (void)pucSig;
    (void)ulSigLen;

    return ret;
}


void wolfSSL_pk_free( wolfSSL_pk_context *pk )
{
    if (pk == NULL)
        return;

    /* cleanup keys */
    wolfSSL_pk_key_free(pk);

    if (pk->der) {
        vPortFree(pk->der);
        pk->der = NULL;
    }
}



/**
 * @brief Key structure.
 */
typedef struct P11Key
{
    wolfSSL_pk_context xWolfPkCtx;
    WOLFSSL_X509* xWolfX509Cli;
} P11Key_t, *P11KeyPtr_t;


/**
 * @brief Session structure.
 */
typedef struct P11Session
{
    P11KeyPtr_t pxCurrentKey;
    CK_ULONG ulState;
    CK_BBOOL xOpened;
    CK_BBOOL xFindObjectInit;
    CK_BBOOL xFindObjectComplete;
    CK_OBJECT_CLASS xFindObjectClass;
    WC_RNG   xWolfDrbgCtx;
} P11Session_t, * P11SessionPtr_t;


/**
 * @brief Helper definitions.
 */
#define pkcs11CREATE_OBJECT_MIN_ATTRIBUTE_COUNT 3
#define pkcs11CERTIFICATE_ATTRIBUTE_COUNT 3
#define pkcs11PRIVATE_KEY_ATTRIBUTE_COUNT 4

/*-----------------------------------------------------------*/

/**
 * @brief Maps an opaque caller session handle into its internal state structure.
 */
static P11SessionPtr_t prvSessionPointerFromHandle( CK_SESSION_HANDLE xSession )
{
    return ( P11SessionPtr_t ) xSession; /*lint !e923 Allow casting integer type to pointer for handle. */
}

/*-----------------------------------------------------------*/

/**
 * @brief Writes a file to local storage.
 */
static BaseType_t prvSaveFile( char * pcFileName,
                               uint8_t * pucData,
                               uint32_t ulDataSize )
{
    uint32_t ulStatus = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD lpNumberOfBytesWritten;

    /* Open the file. */
    hFile = CreateFileA( pcFileName,
                         GENERIC_WRITE,
                         0,
                         NULL,
                         CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL );

    if( INVALID_HANDLE_VALUE == hFile )
    {
        ulStatus = GetLastError();
    }

    /* Write the data. */
    if( ERROR_SUCCESS == ulStatus )
    {
        if( FALSE == WriteFile( hFile, pucData, ulDataSize, &lpNumberOfBytesWritten, NULL ) )
        {
            ulStatus = GetLastError();
        }
    }

    /* Clean up. */
    if( INVALID_HANDLE_VALUE != hFile )
    {
        CloseHandle( hFile );
    }

    return 0 == ulStatus;
}

/*-----------------------------------------------------------*/

/**
 * @brief Reads a file from local storage.
 */
static BaseType_t prvReadFile( char * pcFileName,
                               uint8_t ** ppucData,
                               uint32_t * pulDataSize )
{
    uint32_t ulStatus = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    uint32_t ulSize = 0;

    /* Open the file. */
    hFile = CreateFileA( pcFileName,
                         GENERIC_READ,
                         0,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL );

    if( INVALID_HANDLE_VALUE == hFile )
    {
        ulStatus = GetLastError();
    }

    if( 0 == ulStatus )
    {
        /* Get the file size. */
        *pulDataSize = GetFileSize( hFile, ( LPDWORD ) ( &ulSize ) );

        /* Create a buffer. */
        *ppucData = pvPortMalloc( *pulDataSize );

        if( NULL == *ppucData )
        {
            ulStatus = ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    /* Read the file. */
    if( 0 == ulStatus )
    {
        if( FALSE == ReadFile( hFile,
                               *ppucData,
                               *pulDataSize,
                               ( LPDWORD ) ( &ulSize ),
                               NULL ) )
        {
            ulStatus = GetLastError();
        }
    }

    /* Confirm the amount of data read. */
    if( 0 == ulStatus )
    {
        if( ulSize != *pulDataSize )
        {
            ulStatus = ERROR_INVALID_DATA;
        }
    }

    /* Clean up. */
    if( INVALID_HANDLE_VALUE != hFile )
    {
        CloseHandle( hFile );
    }

    return 0 == ulStatus;
}

/*-----------------------------------------------------------*/

/**
 * @brief Initializes a key structure.
 */
static CK_RV prvInitializeKey( P11SessionPtr_t pxSessionObj,
                               const char * pcEncodedKey,
                               const uint32_t ulEncodedKeyLength,
                               const char * pcEncodedCertificate,
                               const uint32_t ulEncodedCertificateLength )
{
    CK_RV xResult = 0;

    /*
     * Create the key structure, but allow an existing one to be used.
     */

    if( NULL == pxSessionObj->pxCurrentKey )
    {
        if( NULL == ( pxSessionObj->pxCurrentKey = ( P11KeyPtr_t ) pvPortMalloc(
                          sizeof( P11Key_t ) ) ) ) /*lint !e9087 Allow casting void* to other types. */
        {
            xResult = CKR_HOST_MEMORY;
        }
    }

    /*
     * Initialize the key field, if requested.
     */

    if( ( CKR_OK == xResult ) && ( NULL != pcEncodedKey ) )
    {
        memset( pxSessionObj->pxCurrentKey, 0, sizeof( P11Key_t ) );
        wolfSSL_pk_init( &pxSessionObj->pxCurrentKey->xWolfPkCtx );

        xResult = wolfSSL_pk_parse_key(
                &pxSessionObj->pxCurrentKey->xWolfPkCtx,
                ( const unsigned char * ) pcEncodedKey,
                ulEncodedKeyLength,
                NULL,
                0 );

        if (xResult != 0) {
            xResult = CKR_FUNCTION_FAILED;
        }
    }

    /*
     * Initialize the certificate field, if requested.
     */

    if( ( CKR_OK == xResult ) && ( NULL != pcEncodedCertificate ) )
    {

        pxSessionObj->pxCurrentKey->xWolfX509Cli =
            wolfSSL_X509_load_certificate_buffer(
                (const unsigned char *)pcEncodedCertificate,
                ulEncodedCertificateLength,
                WOLFSSL_FILETYPE_PEM);
        if (pxSessionObj->pxCurrentKey->xWolfX509Cli == NULL) {
            xResult = CKR_FUNCTION_FAILED;
        }
    }

    return xResult;
}


/*-----------------------------------------------------------*/

/**
 * @brief Load the default key and certificate from storage.
 */
static CK_RV prvLoadAndInitializeDefaultCertificateAndKey( P11SessionPtr_t pxSession )
{
    CK_RV xResult = 0;
    uint8_t * pucCertificateData = NULL;
    uint32_t ulCertificateDataLength = 0;
    BaseType_t xFreeCertificate = pdFALSE;
    uint8_t * pucKeyData = NULL;
    uint32_t ulKeyDataLength = 0;
    BaseType_t xFreeKey = pdFALSE;

    /* Read the certificate from storage. */
    if( pdFALSE == prvReadFile( pkcs11FILE_NAME_CLIENT_CERTIFICATE,
                                &pucCertificateData,
                                &ulCertificateDataLength ) )
    {
        pucCertificateData = ( uint8_t * ) clientcredentialCLIENT_CERTIFICATE_PEM;
        ulCertificateDataLength = clientcredentialCLIENT_CERTIFICATE_LENGTH;
    }
    else
    {
        xFreeCertificate = pdTRUE;
    }

    /* handle cert including null term */
    if (pucCertificateData[ulCertificateDataLength-1] == '\0')
        ulCertificateDataLength--;

    /* Read the private key from storage. */
    if( pdFALSE == prvReadFile( pkcs11FILE_NAME_KEY,
                                &pucKeyData,
                                &ulKeyDataLength ) )
    {
        pucKeyData = ( uint8_t * ) clientcredentialCLIENT_PRIVATE_KEY_PEM;
        ulKeyDataLength = clientcredentialCLIENT_PRIVATE_KEY_LENGTH;
    }
    else
    {
        xFreeKey = pdTRUE;
    }

    /* handle key including null term */
    if (pucKeyData[ulKeyDataLength-1] == '\0')
        ulKeyDataLength--;

    /* Attach the certificate and key to the session. */
    xResult = prvInitializeKey( pxSession,
                                ( const char * ) pucKeyData,
                                ulKeyDataLength,
                                ( const char * ) pucCertificateData,
                                ulCertificateDataLength );

    /* Clean-up. */
    if( ( NULL != pucCertificateData ) && ( pdTRUE == xFreeCertificate ) )
    {
        vPortFree( pucCertificateData );
    }

    if( ( NULL != pucKeyData ) && ( pdTRUE == xFreeKey ) )
    {
        vPortFree( pucKeyData );
    }

    return xResult;
}


/*-----------------------------------------------------------*/

/**
 * @brief Cleans up a key structure.
 */
static void prvFreeKey( P11KeyPtr_t pxKey )
{
    if( NULL != pxKey )
    {
        /* Clean-up. */
        wolfSSL_pk_free( &pxKey->xWolfPkCtx );
        wolfSSL_X509_free(pxKey->xWolfX509Cli);
        vPortFree( pxKey );
    }
}

/*-----------------------------------------------------------*/

/*
 * PKCS#11 module implementation.
 */

/**
 * @brief PKCS#11 interface functions implemented by this Cryptoki module.
 */
static CK_FUNCTION_LIST prvP11FunctionList =
{
    { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
    C_Initialize,
    C_Finalize,
    NULL,
    C_GetFunctionList,
    C_GetSlotList,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    C_OpenSession,
    C_CloseSession,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    C_CreateObject,
    NULL,
    C_DestroyObject,
    NULL,
    C_GetAttributeValue,
    NULL,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    C_SignInit,
    C_Sign,
    NULL,
    NULL,
    NULL,
    NULL,
    C_VerifyInit,
    C_Verify,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    C_GenerateRandom,
    NULL,
    NULL,
    NULL
};

/**
 * @brief Initialize the Cryptoki module for use.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Initialize )( CK_VOID_PTR pvInitArgs )
{   /*lint !e9072 It's OK to have different parameter name. */
    ( void ) ( pvInitArgs );

    return CKR_OK;
}

/**
 * @brief Un-initialize the Cryptoki module.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Finalize )( CK_VOID_PTR pvReserved )
{   /*lint !e9072 It's OK to have different parameter name. */
    ( void ) ( pvReserved );

    return CKR_OK;
}

/**
 * @brief Query the list of interface function pointers.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetFunctionList )( CK_FUNCTION_LIST_PTR_PTR ppxFunctionList )
{   /*lint !e9072 It's OK to have different parameter name. */
    *ppxFunctionList = &prvP11FunctionList;

    return CKR_OK;
}

/**
 * @brief Query the list of slots. A single default slot is implemented.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetSlotList )( CK_BBOOL xTokenPresent,
                                            CK_SLOT_ID_PTR pxSlotList,
                                            CK_ULONG_PTR pulCount )
{   /*lint !e9072 It's OK to have different parameter name. */
    ( void ) ( xTokenPresent );

    if( NULL == pxSlotList )
    {
        *pulCount = 1;
    }
    else
    {
        if( 0u == *pulCount )
        {
            return CKR_BUFFER_TOO_SMALL;
        }

        pxSlotList[ 0 ] = pkcs11SLOT_ID;
        *pulCount = 1;
    }

    return CKR_OK;
}

/**
 * @brief Start a session for a cryptographic command sequence.
 */
CK_DEFINE_FUNCTION( CK_RV, C_OpenSession )( CK_SLOT_ID xSlotID,
                                            CK_FLAGS xFlags,
                                            CK_VOID_PTR pvApplication,
                                            CK_NOTIFY xNotify,
                                            CK_SESSION_HANDLE_PTR pxSession )
{   /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;
    P11SessionPtr_t pxSessionObj = NULL;

    ( void ) ( xSlotID );
    ( void ) ( pvApplication );
    ( void ) ( xNotify );

    /*
     * Make space for the context.
     */
    if( NULL == ( pxSessionObj = ( P11SessionPtr_t ) pvPortMalloc( sizeof( P11Session_t ) ) ) ) /*lint !e9087 Allow casting void* to other types. */
    {
        xResult = CKR_HOST_MEMORY;
    }

    /*
     * Assume that there's no performance tradeoff in loading the default key
     * now, since that's the principal use case for opening a session in this
     * provider anyway. This way, the private key can be used for seeding the RNG,
     * especially if there's no hardware-based alternative.
     */

    if( CKR_OK == xResult )
    {
        memset( pxSessionObj, 0, sizeof( P11Session_t ) );
        xResult = prvLoadAndInitializeDefaultCertificateAndKey( pxSessionObj );
    }

    /*
     * Initialize RNG.
     */

    if( CKR_OK == xResult )
    {
        xResult = wc_InitRng( &pxSessionObj->xWolfDrbgCtx );
        if (xResult != 0)
            xResult = CKR_RANDOM_NO_RNG;
    }

    if( CKR_OK == xResult )
    {
        /*
         * Assign the session.
         */

        pxSessionObj->ulState =
            0u != ( xFlags & CKF_RW_SESSION ) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
        pxSessionObj->xOpened = CK_TRUE;

        /*
         * Return the session.
         */

        *pxSession = ( CK_SESSION_HANDLE ) pxSessionObj; /*lint !e923 Allow casting pointer to integer type for handle. */
    }

    return xResult;
}

/**
 * @brief Terminate a session and release resources.
 */
CK_DEFINE_FUNCTION( CK_RV, C_CloseSession )( CK_SESSION_HANDLE xSession )
{   /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );

    if( NULL != pxSession )
    {
        /*
         * Tear down the session.
         */

        if( NULL != pxSession->pxCurrentKey )
        {
            prvFreeKey( pxSession->pxCurrentKey );
        }

        wc_FreeRng( &pxSession->xWolfDrbgCtx );
        vPortFree( pxSession );
    }

    return xResult;
}

/**
 * @brief Provides import and storage of a single client certificate and
 * associated private key.
 */
CK_DEFINE_FUNCTION( CK_RV, C_CreateObject )( CK_SESSION_HANDLE xSession,
                                             CK_ATTRIBUTE_PTR pxTemplate,
                                             CK_ULONG ulCount,
                                             CK_OBJECT_HANDLE_PTR pxObject )
{   /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;

    ( void )( xSession );

    /*
     * Check parameters.
     */
    if( ( pkcs11CREATE_OBJECT_MIN_ATTRIBUTE_COUNT > ulCount ) ||
        ( NULL == pxTemplate ) ||
        ( NULL == pxObject ) )
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    if( CKR_OK == xResult )
    {
        if( ( CKA_CLASS != pxTemplate[ 0 ].type ) ||
            ( sizeof( CK_OBJECT_CLASS ) != pxTemplate[ 0 ].ulValueLen ) )
        {
            xResult = CKR_ARGUMENTS_BAD;
        }
    }

    /*
     * Handle the object by class.
     */

    if( CKR_OK == xResult )
    {
        switch( *( ( uint32_t * ) pxTemplate[ 0 ].pValue ) )
        {
            case CKO_CERTIFICATE:

                /* Validate the attribute count for this object class. */
                if( pkcs11CERTIFICATE_ATTRIBUTE_COUNT != ulCount )
                {
                    xResult = CKR_ARGUMENTS_BAD;
                    break;
                }

                /* Validate the next attribute type. */
                if( CKA_VALUE )
                {
                    if( CKA_VALUE != pxTemplate[ 1 ].type )
                    {
                        xResult = CKR_ARGUMENTS_BAD;
                        break;
                    }
                }

                if( *( ( uint32_t * )pxTemplate[ 2 ].pValue ) == pkcs11CERTIFICATE_TYPE_USER )
                {
                    /* Write out the client certificate. */
                    if( pdFALSE == prvSaveFile( pkcs11FILE_NAME_CLIENT_CERTIFICATE,
                        pxTemplate[ 1 ].pValue,
                        pxTemplate[ 1 ].ulValueLen ) )
                    {
                        xResult = CKR_DEVICE_ERROR;
                        break;
                    }
                }
                else if( *( ( uint32_t * )pxTemplate[ 2 ].pValue ) == pkcs11CERTIFICATE_TYPE_ROOT )
                {
                    /* Ignore writing the default root certificate. */
                }
                break;

            case CKO_PRIVATE_KEY:

                /* Validate the attribute count for this object class. */
                if( pkcs11PRIVATE_KEY_ATTRIBUTE_COUNT != ulCount )
                {
                    xResult = CKR_ARGUMENTS_BAD;
                    break;
                }

                /* Find the key bytes. */
                if( CKA_VALUE )
                {
                    if( CKA_VALUE != pxTemplate[ 3 ].type )
                    {
                        xResult = CKR_ARGUMENTS_BAD;
                        break;
                    }
                }

                /* Write out the key. */
                if( pdFALSE == prvSaveFile( pkcs11FILE_NAME_KEY,
                                            pxTemplate[ 3 ].pValue,
                                            pxTemplate[ 3 ].ulValueLen ) )
                {
                    xResult = CKR_DEVICE_ERROR;
                    break;
                }
                break;

            default:
                xResult = CKR_ARGUMENTS_BAD;
        }
    }

    return xResult;
}

/**
 * @brief Free resources attached to an object handle.
 */
CK_DEFINE_FUNCTION( CK_RV, C_DestroyObject )( CK_SESSION_HANDLE xSession,
                                              CK_OBJECT_HANDLE xObject )
{   /*lint !e9072 It's OK to have different parameter name. */
    ( void ) ( xSession );
    ( void ) ( xObject );

    /*
     * This implementation uses virtual handles, and the certificate and
     * private key data are attached to the session, so nothing to do here.
     */
    return CKR_OK;
}

/**
 * @brief Query the value of the specified cryptographic object attribute.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GetAttributeValue )( CK_SESSION_HANDLE xSession,
                                                  CK_OBJECT_HANDLE xObject,
                                                  CK_ATTRIBUTE_PTR pxTemplate,
                                                  CK_ULONG ulCount )
{   /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );
    CK_VOID_PTR pvAttr = NULL;
    CK_ULONG ulAttrLength = 0;
    wolfSSL_pk_type_t xWolfPkType;
    CK_ULONG xP11KeyType, iAttrib, xKeyBitLen;
    vedCliKey cliKey;

    ( void ) ( xObject );

    /*
     * Enumerate the requested attributes.
     */

    for( iAttrib = 0; iAttrib < ulCount && CKR_OK == xResult; iAttrib++ )
    {
        /*
         * Get the attribute data and size.
         */

        switch( pxTemplate[ iAttrib ].type )
        {
            case CKA_KEY_TYPE:

                /*
                 * Map the private key type between APIs.
                 */
                xWolfPkType = wolfSSL_pk_get_type( &pxSession->pxCurrentKey->xWolfPkCtx );
                switch( xWolfPkType )
                {
                    case WOLFSSL_PK_RSA:
                    case WOLFSSL_PK_RSASSA_PSS:
                        xP11KeyType = CKK_RSA;
                        break;

                    case WOLFSSL_PK_ECKEY:
                    case WOLFSSL_PK_ECKEY_DH:
                        xP11KeyType = CKK_EC;
                        break;

                    case WOLFSSL_PK_ECDSA:
                        xP11KeyType = CKK_ECDSA;
                        break;

                    default:
                        xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                        break;
                }

                ulAttrLength = sizeof( xP11KeyType );
                pvAttr = &xP11KeyType;
                break;

            case CKA_VALUE:
            {
                /*
                 * Assume that the query is for the encoded client certificate.
                 */
                int derLen = 0;
                pvAttr = ( CK_VOID_PTR )wolfSSL_X509_get_der(
                    pxSession->pxCurrentKey->xWolfX509Cli, &derLen);
                ulAttrLength = derLen;
                break;
            }
            case CKA_MODULUS_BITS:
            case CKA_PRIME_BITS:

                /*
                 * Key strength size query, handled the same for RSA or ECDSA
                 * in this port.
                 */
                xKeyBitLen = wolfSSL_pk_get_bitlen(
                    &pxSession->pxCurrentKey->xWolfPkCtx );
                ulAttrLength = sizeof( xKeyBitLen );
                pvAttr = &xKeyBitLen;
                break;

            case CKA_VENDOR_DEFINED:
            {
                /*
                 * Return the key context for application-layer use.
                 */
                memset(&cliKey, 0, sizeof(cliKey));
				cliKey.der = pxSession->pxCurrentKey->xWolfPkCtx.der;
				cliKey.derLen = pxSession->pxCurrentKey->xWolfPkCtx.derLen;
                ulAttrLength = sizeof(cliKey);
                pvAttr = &cliKey;
                break;
            }

            default:
                xResult = CKR_ATTRIBUTE_TYPE_INVALID;
                break;
        }

        if( CKR_OK == xResult )
        {
            /*
             * Copy out the data and size.
             */

            if( NULL != pxTemplate[ iAttrib ].pValue )
            {
                if( pxTemplate[ iAttrib ].ulValueLen < ulAttrLength )
                {
                    xResult = CKR_BUFFER_TOO_SMALL;
                }
                else
                {
                    memcpy( pxTemplate[ iAttrib ].pValue, pvAttr, ulAttrLength );
                }
            }

            pxTemplate[ iAttrib ].ulValueLen = ulAttrLength;
        }
    }

    return xResult;
}

/**
 * @brief Begin an enumeration sequence for the objects of the specified type.
 */
CK_DEFINE_FUNCTION( CK_RV, C_FindObjectsInit )( CK_SESSION_HANDLE xSession,
                                                CK_ATTRIBUTE_PTR pxTemplate,
                                                CK_ULONG ulCount )
{   /*lint !e9072 It's OK to have different parameter name. */
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );

    ( void ) ( ulCount );

    /*
     * Allow filtering on a single object class attribute.
     */

    pxSession->xFindObjectInit = CK_TRUE;
    pxSession->xFindObjectComplete = CK_FALSE;
    memcpy( &pxSession->xFindObjectClass,
            pxTemplate[ 0 ].pValue,
            sizeof( CK_OBJECT_CLASS ) );

    return CKR_OK;
}

/**
 * @brief Query the objects of the requested type.
 */
CK_DEFINE_FUNCTION( CK_RV, C_FindObjects )( CK_SESSION_HANDLE xSession,
                                            CK_OBJECT_HANDLE_PTR pxObject,
                                            CK_ULONG ulMaxObjectCount,
                                            CK_ULONG_PTR pulObjectCount )
{   /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;
    BaseType_t xDone = pdFALSE;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );

    /*
     * Check parameters.
     */

    if( ( CK_BBOOL ) CK_FALSE == pxSession->xFindObjectInit )
    {
        xResult = CKR_OPERATION_NOT_INITIALIZED;
        xDone = pdTRUE;
    }

    if( ( pdFALSE == xDone ) && ( 0u == ulMaxObjectCount ) )
    {
        xResult = CKR_ARGUMENTS_BAD;
        xDone = pdTRUE;
    }

    if( ( pdFALSE == xDone ) && ( ( CK_BBOOL ) CK_TRUE == pxSession->xFindObjectComplete ) )
    {
        *pulObjectCount = 0;
        xResult = CKR_OK;
        xDone = pdTRUE;
    }

    /*
     * Load the default private key and certificate.
     */

    if( ( pdFALSE == xDone ) && ( NULL == pxSession->pxCurrentKey ) )
    {
        if( CKR_OK != ( xResult = prvLoadAndInitializeDefaultCertificateAndKey( pxSession ) ) )
        {
            xDone = pdTRUE;
        }
    }

    if( pdFALSE == xDone )
    {
        /*
         * Return object handles based on find type.
         */

        switch( pxSession->xFindObjectClass )
        {
            case CKO_PRIVATE_KEY:
                *pxObject = pkcs11OBJECT_HANDLE_PRIVATE_KEY;
                *pulObjectCount = 1;
                break;

            case CKO_PUBLIC_KEY:
                *pxObject = pkcs11OBJECT_HANDLE_PUBLIC_KEY;
                *pulObjectCount = 1;
                break;

            case CKO_CERTIFICATE:
                *pxObject = pkcs11OBJECT_HANDLE_CERTIFICATE;
                *pulObjectCount = 1;
                break;

            default:
                *pxObject = 0;
                *pulObjectCount = 0;
                break;
        }

        pxSession->xFindObjectComplete = CK_TRUE;
    }

    return xResult;
}

/**
 * @brief Terminate object enumeration.
 */
CK_DEFINE_FUNCTION( CK_RV, C_FindObjectsFinal )( CK_SESSION_HANDLE xSession )
{   /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;
    P11SessionPtr_t pxSession = prvSessionPointerFromHandle( xSession );

    /*
     * Check parameters.
     */

    if( ( CK_BBOOL ) CK_FALSE == pxSession->xFindObjectInit )
    {
        xResult = CKR_OPERATION_NOT_INITIALIZED;
    }
    else
    {
        /*
         * Clean-up find objects state.
         */

        pxSession->xFindObjectInit = CK_FALSE;
        pxSession->xFindObjectComplete = CK_FALSE;
        pxSession->xFindObjectClass = 0;
    }

    return xResult;
}

/**
 * @brief Begin a digital signature generation session.
 */
CK_DEFINE_FUNCTION( CK_RV, C_SignInit )( CK_SESSION_HANDLE xSession,
                                         CK_MECHANISM_PTR pxMechanism,
                                         CK_OBJECT_HANDLE xKey )
{   /*lint !e9072 It's OK to have different parameter name. */
    ( void ) ( xSession );
    ( void ) ( pxMechanism );
    ( void ) ( xKey );

    return CKR_OK;
}

/**
 * @brief Digitally sign the indicated cryptographic hash bytes.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Sign )( CK_SESSION_HANDLE xSession,
                                     CK_BYTE_PTR pucData,
                                     CK_ULONG ulDataLen,
                                     CK_BYTE_PTR pucSignature,
                                     CK_ULONG_PTR pulSignatureLen )
{   /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;
    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle( xSession );

    /*
     * Support length check.
     */

    if( NULL == pucSignature )
    {
        *pulSignatureLen = pkcs11SUPPORTED_KEY_BITS / 8;
    }
    else
    {
        /*
         * Check algorithm support.
         */

        if( ( CK_ULONG ) cryptoSHA256_DIGEST_BYTES != ulDataLen )
        {
            xResult = CKR_DATA_LEN_RANGE;
        }

        /*
         * Sign the data.
         */
        if( CKR_OK == xResult )
        {
            if ( 0 != wolfSSL_pk_sign(
                    &pxSessionObj->pxCurrentKey->xWolfPkCtx,
                    WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                    pucData,
                    ulDataLen,
                    pucSignature,
                    ( size_t * ) pulSignatureLen,
                    &pxSessionObj->xWolfDrbgCtx ) )
            {
                xResult = CKR_FUNCTION_FAILED;
            }
        }
    }

    return xResult;
}

/**
 * @brief Begin a digital signature verification session.
 */
CK_DEFINE_FUNCTION( CK_RV, C_VerifyInit )( CK_SESSION_HANDLE xSession,
                                           CK_MECHANISM_PTR pxMechanism,
                                           CK_OBJECT_HANDLE xKey )
{   /*lint !e9072 It's OK to have different parameter name. */
    ( void ) ( xSession );
    ( void ) ( pxMechanism );
    ( void ) ( xKey );

    return CKR_OK;
}

/**
 * @brief Verify the digital signature of the specified data using the public
 * key attached to this session.
 */
CK_DEFINE_FUNCTION( CK_RV, C_Verify )( CK_SESSION_HANDLE xSession,
                                       CK_BYTE_PTR pucData,
                                       CK_ULONG ulDataLen,
                                       CK_BYTE_PTR pucSignature,
                                       CK_ULONG ulSignatureLen )
{   /*lint !e9072 It's OK to have different parameter name. */
    CK_RV xResult = CKR_OK;
    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle( xSession );

    /* Verify the signature. */
    if ( 0 != wolfSSL_pk_verify(
                    &pxSessionObj->pxCurrentKey->xWolfPkCtx,
                    WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                    pucData,
                    ulDataLen,
                    pucSignature,
                    ( size_t ) ulSignatureLen ) )
    {
        xResult = CKR_SIGNATURE_INVALID;
    }

    /* Return the signature verification result. */
    return xResult;
}

/**
 * @brief Generate cryptographically random bytes.
 */
CK_DEFINE_FUNCTION( CK_RV, C_GenerateRandom )( CK_SESSION_HANDLE xSession,
                                               CK_BYTE_PTR pucRandomData,
                                               CK_ULONG ulRandomLen )
{   /*lint !e9072 It's OK to have different parameter name. */
    P11SessionPtr_t pxSessionObj = prvSessionPointerFromHandle( xSession );

    if( 0 != wc_RNG_GenerateBlock( &pxSessionObj->xWolfDrbgCtx, pucRandomData, ulRandomLen ) )
    {
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

#endif /* WOLF_AWSTLS */
