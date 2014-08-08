CPK Toolkit
===========



Description
===========




Architecture
============


	+----------------+------------------+--------------+--------------+
	|     HTML5 App  | Java/Android App |              |  Web Service |
	+----------------+------------------+  C/C++ App   +--------------+
	| JavaScript API |     Java API     |    iOS App   |  RESTful API |
	|     (npapi)    |       (jni)      |              |    (cgi)     |
	+----------------+------------------+--------------+--------------+
	|                          CPK C API                              |
	|             for Crypto, Key Management and Protocol             |
	|                       (cpktool, cpktls)                         |
	+---------------------+--------------------+----------------------+
	|     Core Crypto     |   Hardware Model   |    Key Management    |
	|      (libcpk)       |  (pkcs11_wrapper)  |       (cpkadm)       |
	+---------------------+--------------------+----------------------+
	|       OpenSSL*      |     Cryptoki       |        SQLite        |
	+---------------------+--------------------+----------------------+
	* A patched version of OpenSSL libcrypto is required.



Overview
========
 
The CPK project includes:

## libcpk
    
Implementation of X9.63 Key Derive Function, Elliptic Curve Integrated
Encryption Scheme (ECIES), Combined Public Key (CPK) system setup, public
key derivation, private key derivation, ASN.1/DER encoding on Elliptic
Curve Cryptography (ECC) systems and Descret Logorithm public key systems.

The libcpk.a library is highly integrated with OpenSSL libcrypto.a, with
the OpenSSL Error Stack support and ASN.1 code generation.

pkcs11 wrapper
--------------

An module for the cpktool to access a hardware token with PKCS #11 API.

## cpktool

An easy to use interface together with a default key stoarge based on file
system and PKCS #5 password based private key encryption protection.

## pkcs11_softtoken:
The PKCS #11 interface of this project. Currently implementated as a soft
token.

## cpkadm
Identity and key management, including identity/key database, revocation
and key status. This module is based on SQLite3. 

## cpktls
A SSL/TLS like tranport layer security protocol based on CPK. This
protocol provides much better establishment performance over X.509
certificate based protocols.

## jni
The Java language binding for cpktool interface. This also provides an
interface for Android applications through NDK.

## npapi
The JavaScript language binding and Web browser plugin for CPK. Currently
the NPAPI plugin mechanism is supported by Mozilla Firefox, WebKit, Google
Chrome, Apple Safari and Opera.

## cgi
The CPK Web service scripts for Apache Httpd.

 
 
This project has a long history. It started from 2006 written in C++ and PHP.
For better performance and cross platform reasons, it is re-written in pure C
based on OpenSSL in 2007,
which makes it running on all major operating systems including Windows, Linux,
Mac OS X, HP-UX, Android and iOS. It has also been compiled to X86, PowerPC and
ARM. 


