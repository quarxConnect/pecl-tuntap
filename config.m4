dnl $Id$
dnl config.m4 for extension tuntap

PHP_ARG_ENABLE(tuntap, whether to enable tuntap support, [  --enable-tuntap           Enable TUN/TAP support])

if test "$PHP_TUNTAP" != "no"; then
  PHP_NEW_EXTENSION(tuntap, tuntap.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
