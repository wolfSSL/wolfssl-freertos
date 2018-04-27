# AWS FreeRTOS wolfSSL demo

This demo uses wolfSSL for the TLS, Crypto and PKCS 11 functions of the AWS FreeRTOS project.

## Configuration

The configuration file is located in `demos/pc/windows/common/config_files/user_settings.h`. Use this as a template for your own project.


## Preprocessors

The preprocessor defines required are: `WOLFSSL_USER_SETTINGS` and `WOLF_AWSTLS`.

## Includes

The only include path is `lib\third_party\wolfssl`.

## New Files

The following files were added for the wolf port.

* `lib/tls/wolf_tls.c`
* `lib/crypto/wolf_crypt.c`
* `lib/pkcs11/portable/pc/windows/wolf_pkcs11.c`

## Demo

To run the demo you'll need to configure a few device specific items in the following files:
* `demos/common/include/aws_clientcredential.h`
* `demos/common/include/aws_clientcredential_keys.h`

You are welcome to test using the wolfSSL AWS demo account using credentials located here:
https://github.com/wolfSSL/wolfMQTT/blob/master/examples/aws/awsiot.c#L73

You can enable different parts of the demo by uncommenting lines in `demos/common/demo_runner/aws_demo_runner.c`.

## Support

For questions or feedback please email us at info@wolfssl.com.
