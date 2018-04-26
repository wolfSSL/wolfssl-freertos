/*
 * Amazon FreeRTOS TLS V1.1.0
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
#include "aws_tls.h"
#include "aws_crypto.h"
#include "aws_pkcs11.h"
#include "task.h"
#include "aws_clientcredential.h"
#include "aws_default_root_certificates.h"

#ifdef WOLF_AWSTLS

/* wolfSSL compatibility layer (github.com/wolfSSL/wolfssl) */
#include <wolfssl/wolfcrypt/port/arm/mbedtls.h>

/* C runtime includes. */
#include <string.h>
#include <time.h>
#include <stdio.h>

/**
 * @brief Internal context structure.
 *
 * @param[in] pcDestination Server location, can be a DNS name or IP address.
 * @param[in] pcServerCertificate Server X.509 certificate in PEM format to trust.
 * @param[in] ulServerCertificateLength Length in bytes of the server certificate.
 * @param[in] pxNetworkRecv Callback for receiving data on an open TCP socket.
 * @param[in] pxNetworkSend Callback for sending data on an open TCP socket.
 * @param[in] pvCallerContext Opaque pointer provided by caller for above callbacks.
 * @param[out] ctx wolfSSL context for creating connections
 * @param[out] ssl wolfSSL object for connection
 * @param[out] pxP11FunctionList PKCS#11 function list structure.
 * @param[out] xP11Session PKCS#11 session context.
 * @param[out] xP11PrivateKey PKCS#11 private key context.
 * @param[out] ulP11ModulusBytes Number of bytes in the client private key modulus.
 */
typedef struct TLSContext
{
    const char * pcDestination;
    const char * pcServerCertificate;
    uint32_t ulServerCertificateLength;
    const char ** ppcAlpnProtocols;
    uint32_t ulAlpnProtocolsCount;

    NetworkRecv_t pxNetworkRecv;
    NetworkSend_t pxNetworkSend;
    void * pvCallerContext;

    /* wolfSSL */
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_CERT_MANAGER* cm;

    /* PKCS#11. */
    CK_FUNCTION_LIST_PTR pxP11FunctionList;
    CK_SESSION_HANDLE xP11Session;
    CK_OBJECT_HANDLE xP11PrivateKey;
    CK_ULONG ulP11ModulusBytes;
} TLSContext_t;

/*
 * Helper routines.
 */

/**
 * @brief Network send callback shim.
 *
 * @param[in] pvContext Caller context.
 * @param[in] pucData Byte buffer to send.
 * @param[in] xDataLength Length of byte buffer to send.
 *
 * @return Number of bytes sent, or a negative value on error.
 */
static int prvNetworkSend(WOLFSSL* ssl, char *pucData, int xDataLength,
    void *pvContext)
{
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */
    (void)ssl;

    return ( int ) pCtx->pxNetworkSend( pCtx->pvCallerContext, (const byte*)pucData, xDataLength );
}

/**
 * @brief Network receive callback shim.
 *
 * @param[in] pvContext Caller context.
 * @param[out] pucReceiveBuffer Byte buffer to receive into.
 * @param[in] xReceiveLength Length of byte buffer for receive.
 *
 * @return Number of bytes received, or a negative value on error.
 */
static int prvNetworkRecv(WOLFSSL* ssl, char *pucReceiveBuffer, int xReceiveLength,
    void *pvContext)
{
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */
    (void)ssl;

    return ( int ) pCtx->pxNetworkRecv( pCtx->pvCallerContext, (byte*)pucReceiveBuffer, xReceiveLength );
}


static int prvCheckCertificate(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    (void)preverify;

    printf("In verification callback, error = %d, %s\n", store->error,
                                 wolfSSL_ERR_error_string(store->error, buffer));
    printf("Subject's domain name is %s\n", store->domain);

    if (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E) {
        printf("Overriding cert date error as example for bad clock testing\n");
        return 1;
    }
    printf("Cert error is not date error, not overriding\n");

    return 0;
}


/**
 * @brief Helper for setting up potentially hardware-based cryptographic context
 * for the client TLS certificate and private key.
 *
 * @param Caller context.
 *
 * @return Zero on success.
 */
static int prvInitializeClientCredential( TLSContext_t * pCtx )
{
    BaseType_t xResult = 0;
    CK_C_GetFunctionList pxCkGetFunctionList = NULL;
    CK_SLOT_ID xSlotId = 0;
    CK_ULONG ulCount = 1;
    CK_ATTRIBUTE xTemplate = { 0 };
    CK_OBJECT_CLASS xObjClass = 0;
    CK_OBJECT_HANDLE xCertObj = 0;
    CK_BYTE * pucCertificate = NULL;

    /* Ensure that the PKCS#11 module is initialized. */
    if( 0 == xResult )
    {
        pxCkGetFunctionList = C_GetFunctionList;
        xResult = ( BaseType_t ) pxCkGetFunctionList( &pCtx->pxP11FunctionList );
    }

    if( 0 == xResult )
    {
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_Initialize( NULL );
    }

    /* Get the default private key storage ID. */
    if( 0 == xResult )
    {
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_GetSlotList( CK_TRUE, &xSlotId, &ulCount );
    }

    /* Start a private session with the P#11 module. */
    if( 0 == xResult )
    {
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_OpenSession( xSlotId,
                                                                         0,
                                                                         NULL,
                                                                         NULL,
                                                                         &pCtx->xP11Session );
    }

    /* Enumerate the first private key. */
    if( 0 == xResult )
    {
        xTemplate.type = CKA_CLASS;
        xTemplate.ulValueLen = sizeof( CKA_CLASS );
        xTemplate.pValue = &xObjClass;
        xObjClass = CKO_PRIVATE_KEY;
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_FindObjectsInit( pCtx->xP11Session, &xTemplate, 1 );
    }

    if( 0 == xResult )
    {
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_FindObjects( pCtx->xP11Session, &pCtx->xP11PrivateKey, 1, &ulCount );
    }

    if( 0 == xResult )
    {
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_FindObjectsFinal( pCtx->xP11Session );
    }

    /* Get the internal key context. */
    if( 0 == xResult )
    {
        xTemplate.type = CKA_VENDOR_DEFINED;
        xTemplate.ulValueLen = sizeof( pCtx->cm );
        xTemplate.pValue = &pCtx->cm;
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_GetAttributeValue(
            pCtx->xP11Session, pCtx->xP11PrivateKey, &xTemplate, 1 );
    }

    /* Get the key size. */
    if( 0 == xResult )
    {
        xTemplate.type = CKA_MODULUS_BITS;
        xTemplate.ulValueLen = sizeof( pCtx->ulP11ModulusBytes );
        xTemplate.pValue = &pCtx->ulP11ModulusBytes;
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_GetAttributeValue(
            pCtx->xP11Session, pCtx->xP11PrivateKey, &xTemplate, 1 );
    }

    if( 0 == xResult )
    {
        pCtx->ulP11ModulusBytes /= 8;

        /* Enumerate the first client certificate. */
        xTemplate.type = CKA_CLASS;
        xTemplate.ulValueLen = sizeof( CKA_CLASS );
        xTemplate.pValue = &xObjClass;
        xObjClass = CKO_CERTIFICATE;
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_FindObjectsInit( pCtx->xP11Session, &xTemplate, 1 );
    }

    if( 0 == xResult )
    {
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_FindObjects( pCtx->xP11Session, &xCertObj, 1, &ulCount );
    }

    if( 0 == xResult )
    {
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_FindObjectsFinal( pCtx->xP11Session );
    }

    if( 0 == xResult )
    {
        /* Query the certificate size. */
        xTemplate.type = CKA_VALUE;
        xTemplate.ulValueLen = 0;
        xTemplate.pValue = NULL;
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_GetAttributeValue( pCtx->xP11Session, xCertObj, &xTemplate, 1 );
    }

    if( 0 == xResult )
    {
        /* Create a buffer for the certificate. */
        pucCertificate = ( CK_BYTE_PTR ) pvPortMalloc( xTemplate.ulValueLen ); /*lint !e9079 Allow casting void* to other types. */

        if( NULL == pucCertificate )
        {
            xResult = ( BaseType_t ) CKR_HOST_MEMORY;
        }
    }

    if( 0 == xResult )
    {
        /* Export the certificate. */
        xTemplate.pValue = pucCertificate;
        xResult = ( BaseType_t ) pCtx->pxP11FunctionList->C_GetAttributeValue(
            pCtx->xP11Session, xCertObj, &xTemplate, 1 );
    }

    /* Decode the client certificate. */
    if( 0 == xResult )
    {
        xResult = wolfSSL_CTX_load_verify_buffer(pCtx->ctx,
                (const byte*)pucCertificate, xTemplate.ulValueLen,
                WOLFSSL_FILETYPE_PEM);
    }

    if( NULL != pucCertificate )
    {
        vPortFree( pucCertificate );
    }

    return xResult;
}

/*
 * Interface routines.
 */

BaseType_t TLS_Init( void ** ppvContext,
                     TLSParams_t * pxParams )
{
    BaseType_t xResult = 0;
    TLSContext_t * pCtx = NULL;

    /* Allocate an internal context. */
    pCtx = ( TLSContext_t * ) pvPortMalloc( sizeof( TLSContext_t ) ); /*lint !e9087 !e9079 Allow casting void* to other types. */

    if( NULL != pCtx )
    {
        memset( pCtx, 0, sizeof( TLSContext_t ) );
        *ppvContext = pCtx;

        /* Initialize the context. */
        pCtx->pcDestination = pxParams->pcDestination;
        pCtx->pcServerCertificate = pxParams->pcServerCertificate;
        pCtx->ulServerCertificateLength = pxParams->ulServerCertificateLength;
        pCtx->ppcAlpnProtocols = pxParams->ppcAlpnProtocols;
        pCtx->ulAlpnProtocolsCount = pxParams->ulAlpnProtocolsCount;
        pCtx->pxNetworkRecv = pxParams->pxNetworkRecv;
        pCtx->pxNetworkSend = pxParams->pxNetworkSend;
        pCtx->pvCallerContext = pxParams->pvCallerContext;

        wolfSSL_Init();
    }
    else
    {
        xResult = ( BaseType_t ) CKR_HOST_MEMORY;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t TLS_Connect( void * pvContext )
{
    BaseType_t xResult = pdFREERTOS_ERRNO_NONE;
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    /* Ensure that the FreeRTOS heap is used. */
    CRYPTO_ConfigureHeap();

    /* create wolf context (factory for generating wolfSSL connection objects) */
    pCtx->ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (pCtx->ctx == NULL) {
        xResult = pdFREERTOS_ERRNO_ENOMEM;
    }

    /* load certificate */
    if ( NULL != pCtx->pcServerCertificate )
    {
        xResult = wolfSSL_CTX_load_verify_buffer(pCtx->ctx,
            (const byte*)pCtx->pcServerCertificate,
            pCtx->ulServerCertificateLength, WOLFSSL_FILETYPE_PEM);
    }
    else
    {
        xResult = wolfSSL_CTX_load_verify_buffer(pCtx->ctx,
            (const byte*)tlsVERISIGN_ROOT_CERTIFICATE_PEM,
            tlsVERISIGN_ROOT_CERTIFICATE_LENGTH,
            WOLFSSL_FILETYPE_PEM);

        if( 0 == xResult )
        {
            xResult = wolfSSL_CTX_load_verify_buffer(pCtx->ctx,
                (const byte*)tlsATS1_ROOT_CERTIFICATE_PEM,
                tlsATS1_ROOT_CERTIFICATE_LENGTH,
                WOLFSSL_FILETYPE_PEM);
        }
    }

    if( 0 == xResult )
    {
        wolfSSL_CTX_set_verify(pCtx->ctx, WOLFSSL_VERIFY_PEER,
            prvCheckCertificate);

        /* Setup the client credential. */
        xResult = prvInitializeClientCredential( pCtx );
    }

    /* Set the hostname, if requested. */
    if( ( 0 == xResult ) && ( NULL != pCtx->pcDestination ) )
    {
#ifdef HAVE_SNI
        if (wolfSSL_CTX_UseSNI(pCtx->ctx, 0, pCtx->pcDestination,
                    (word16)XSTRLEN(pCtx->pcDestination)) != WOLFSSL_SUCCESS) {
            xResult = pdFREERTOS_ERRNO_ENOPROTOOPT;
#endif
    }


    /* create connection object */
    if( 0 == xResult )
    {
		pCtx->ssl = wolfSSL_new(pCtx->ctx);
        if (pCtx->ssl == NULL) {
            xResult = pdFREERTOS_ERRNO_ENOMEM;
        }
    }

    if( 0 == xResult && NULL != pCtx->ppcAlpnProtocols )
    {
        /* Include an application protocol list in the TLS ClientHello
         * message. */
#ifdef HAVE_ALPN
        size_t cur_len, tot_len;
        const char **p;
        tot_len = 0;
        for( p = protos; *p != NULL; p++ ) {
            cur_len = strlen( *p );
            tot_len += cur_len;

            if (cur_len > 0 && cur_len <= 255 && tot_len < 65535) {
                wolfSSL_UseALPN(pCtx->ssl, *p, (word32)cur_len, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
            }
            else {
                xResult = pdFREERTOS_ERRNO_EINVAL;
                break;
            }
        }
#endif
    }


    /* Set the socket callbacks. */
    if( 0 == xResult )
    {
        /* Setup the IO callbacks */
        wolfSSL_CTX_SetIORecv(pCtx->ctx, prvNetworkRecv);
        wolfSSL_CTX_SetIOSend(pCtx->ctx, prvNetworkSend);
        wolfSSL_SetIOReadCtx( pCtx->ssl, (void*)pCtx);
        wolfSSL_SetIOWriteCtx(pCtx->ssl, (void*)pCtx);

        /* Negotiate. */
        while( WOLFSSL_SUCCESS != ( xResult = wolfSSL_connect(pCtx->ssl) ) )
        {
            xResult = wolfSSL_get_error(pCtx->ssl, 0);

            if( ( WOLFSSL_ERROR_WANT_READ != xResult ) &&
                ( WOLFSSL_ERROR_WANT_WRITE != xResult ) )
            {
                break;
            }
        }
    }

    return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t TLS_Recv( void * pvContext,
                     unsigned char * pucReadBuffer,
                     size_t xReadLength )
{
    BaseType_t xResult = 0;
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */
    size_t xRead = 0;

    if( NULL != pCtx )
    {
        while( xRead < xReadLength )
        {
            xResult = wolfSSL_read( pCtx->ssl,
                                    pucReadBuffer + xRead,
                                    xReadLength - xRead );

            if( 0 < xResult )
            {
                /* Got data, so update the tally and keep looping. */
                xRead += ( size_t ) xResult;
            }
            else
            {
                if( ( 0 == xResult ) || ( WOLFSSL_ERROR_WANT_READ != xResult ) )
                {
                    /* No data and no error or call read again, if indicated, otherwise return error. */
                    break;
                }
            }
        }
    }

    if( 0 <= xResult )
    {
        xResult = ( BaseType_t ) xRead;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t TLS_Send( void * pvContext,
                     const unsigned char * pucMsg,
                     size_t xMsgLength )
{
    BaseType_t xResult = 0;
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */
    size_t xWritten = 0;

    if( NULL != pCtx )
    {
        while( xWritten < xMsgLength )
        {
            xResult = wolfSSL_write( pCtx->ssl,
                                     pucMsg + xWritten,
                                     xMsgLength - xWritten );

            if( 0 < xResult )
            {
                /* Sent data, so update the tally and keep looping. */
                xWritten += ( size_t ) xResult;
            }
            else
            {
                if( ( 0 == xResult ) || ( WOLFSSL_ERROR_WANT_WRITE != xResult ) )
                {
                    /* No data and no error or call read again, if indicated, otherwise return error. */
                    break;
                }
            }
        }
    }

    if( 0 <= xResult )
    {
        xResult = ( BaseType_t ) xWritten;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

void TLS_Cleanup( void * pvContext )
{
    TLSContext_t * pCtx = ( TLSContext_t * ) pvContext; /*lint !e9087 !e9079 Allow casting void* to other types. */

    if( NULL != pCtx )
    {
        /* Cleanup wolfSSL. */
        wolfSSL_shutdown( pCtx->ssl );
        wolfSSL_free( pCtx->ssl );
        wolfSSL_CTX_free( pCtx->ctx );

        /* Cleanup PKCS#11. */
        if( ( NULL != pCtx->pxP11FunctionList ) &&
            ( NULL != pCtx->pxP11FunctionList->C_CloseSession ) )
        {
            pCtx->pxP11FunctionList->C_CloseSession( pCtx->xP11Session ); /*lint !e534 This function always return CKR_OK. */
            pCtx->pxP11FunctionList->C_Finalize( NULL );                  /*lint !e534 This function always return CKR_OK. */
        }

        /* Free memory. */
        vPortFree( pCtx );
    }
}

#endif /* WOLF_AWSTLS */
