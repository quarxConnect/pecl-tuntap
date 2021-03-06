/*
  +----------------------------------------------------------------------+
  | PECL TUNTAP                                                          |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016 Bernd Holzmueller <bernd@quarxconnect.de>         |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Bernd Holzmueller                                            |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_TUNTAP_H
#define PHP_TUNTAP_H

extern zend_module_entry tuntap_module_entry;
#define phpext_tuntap_ptr &tuntap_module_entry

#define PHP_TUNTAP_VERSION "0.1"

#ifdef PHP_WIN32
#	error No support for WIN32
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_TUNTAP_API __attribute__ ((visibility("default")))
#else
#	define PHP_TUNTAP_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#if defined(ZTS) && defined(COMPILE_DL_TUNTAP)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif	/* PHP_TUNTAP_H */
