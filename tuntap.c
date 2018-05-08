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

# ifdef HAVE_CONFIG_H
#   include "config.h"
# endif

# include "php.h"
# include "php_ini.h"
# include "ext/standard/info.h"
# include "php_tuntap.h"
# include <pwd.h>
# include <grp.h>
# include <stdio.h>
# include <fcntl.h>
# include <sys/ioctl.h>
# include <linux/if.h>
# include <linux/if_tun.h>
  
# define TUNTAP_DEVICE "/dev/net/tun"
  
  /* True global resources - no need for thread safety here */
  static int le_tuntap;
  
  // {{{ PHP_MINIT_FUNCTION
  PHP_MINIT_FUNCTION (tuntap) {
    /* Register TUN/TAP Flags */
    REGISTER_LONG_CONSTANT ("TUNTAP_DEVICE_TUN", IFF_TUN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT ("TUNTAP_DEVICE_TAP", IFF_TAP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT ("TUNTAP_DEVICE_NO_PI", IFF_NO_PI, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT ("TUNTAP_DEVICE_EXCL", IFF_TUN_EXCL, CONST_CS | CONST_PERSISTENT);
    
    return SUCCESS;
  }
  // }}}

  // {{{ PHP_MSHUTDOWN_FUNCTION
  PHP_MSHUTDOWN_FUNCTION (tuntap) {
    return SUCCESS;
  }
  // }}}

  // {{{ PHP_MINFO_FUNCTION
  PHP_MINFO_FUNCTION (tuntap) {
    php_info_print_table_start ();
    php_info_print_table_header (2, "TUN/TAP support", "enabled");
    php_info_print_table_end ();
  }
  // }}}
  
  // {{{ tuntap_new
  /**
   * Create a new TUN/TAP device
   * 
   * @param string $Name
   * @param int $Flags
   * 
   * @access public
   * @return resource
   **/
  PHP_FUNCTION (tuntap_new) {
    /* Retrive function-parameters */
    char *name;
    int name_len;
    long flags = TUN_TUN_DEV;
    
    if (zend_parse_parameters (ZEND_NUM_ARGS (), "|sl", &name, &name_len, &flags) == FAILURE)
      RETURN_FALSE;
    
    /* Try to open TUN/TAP-Device */
    int fd;
    
    if ((fd = open (TUNTAP_DEVICE, O_RDWR)) < 0) {
      zend_error (E_WARNING, "Could not open TUN/TAP-Device");
      
      RETURN_FALSE;
    }
    
    /* Try to create a new network-device */
    struct ifreq ifr;
    memset (&ifr, 0, sizeof (ifr));
    
    if ((flags & IFF_TUN) == IFF_TUN)
      ifr.ifr_flags = IFF_TUN;
    else if ((flags & IFF_TAP) == IFF_TAP)
      ifr.ifr_flags = IFF_TAP;
    
    if ((flags & IFF_TUN_EXCL) == IFF_TUN_EXCL)
      ifr.ifr_flags |= IFF_TUN_EXCL;
    if ((flags & IFF_NO_PI) == IFF_NO_PI)
      ifr.ifr_flags |= IFF_NO_PI;
    
    /*
      IFF_MULTI_QUEUE
      IFF_NOFILTER
    */
    
    if (name_len)
      strncpy (ifr.ifr_name, name, (name_len < IFNAMSIZ ? name_len : IFNAMSIZ));
    
    if (ioctl (fd, TUNSETIFF, (void *)&ifr) < 0) {
      zend_error (E_WARNING, "Failed to setup TUN/TAP-Device");
      close (fd);
      
      RETURN_FALSE;
    }
    
    /* Try to create a stream from FD */
    php_stream *stream;
    
    if ((stream = php_stream_fopen_from_fd (fd, "r+b", NULL)) == NULL) {
      zend_error (E_WARNING, "%s",  strerror (errno));
      
      RETURN_FALSE;
    }
    
    php_stream_to_zval (stream, return_value);
  }
  ZEND_BEGIN_ARG_INFO (tuntap_arginfo_new, 0)
    ZEND_ARG_INFO (0, name)
    ZEND_ARG_INFO (0, flags)
  ZEND_END_ARG_INFO ()
  // }}}

  // {{{ TUNTAP_GET_FD
  /**
   * MACRO: Convert a resource-parameter into a file-descriptor-number usable for ioctl's
   * 
   * @param int fd
   * @param zval res
   **/
# define TUNTAP_GET_FD(fd, res) {\
    php_stream *stream; \
    int stream_fd; \
    php_stream_from_zval (stream, res); \
    if (php_stream_cast (stream, PHP_STREAM_AS_FD, (void**)&stream_fd, REPORT_ERRORS) == FAILURE) \
      RETURN_FALSE; \
    fd = stream_fd; \
  }
  // }}}

  // {{{ tuntap_name
  /**
   * Retrive the device-name of a given TUN/TAP-Resource
   * 
   * @param resource $Device
   * 
   * @access public
   * @return string
   **/
  PHP_FUNCTION (tuntap_name) {
    /* Retrive function-parameters */
    zval *res;
    int fd;
    
    if (zend_parse_parameters (ZEND_NUM_ARGS () TSRMLS_CC, "r", &res) == FAILURE)
      RETURN_FALSE;
    
    TUNTAP_GET_FD (fd, res);
    
    /* Retrive information for the stream */
    struct ifreq ifr;
    
    if (ioctl (fd, TUNGETIFF, (void *)&ifr) < 0)
      RETURN_FALSE;
    
    RETURN_STRING (ifr.ifr_name);
  }
  ZEND_BEGIN_ARG_INFO (tuntap_arginfo_name, 0)
    ZEND_ARG_INFO (0, device)
  ZEND_END_ARG_INFO ()
  // }}}
  
  // {{{ tuntap_owner
  /**
   * Set owner/group of a given TUN/TAP-Device
   * 
   * @param resource $Device
   * @param mixed $User (optional)
   * @param mixed $Group (optional)
   * 
   * @access public
   * @return bool
   **/
  PHP_FUNCTION (tuntap_owner) {
    /* Retrive function-parameters */
    zval *device, *user, *group;
    int fd;   
    
    if (zend_parse_parameters (ZEND_NUM_ARGS () TSRMLS_CC, "r|zz", &device, &user, &group) == FAILURE)
      RETURN_FALSE;
    
    TUNTAP_GET_FD (fd, device);
    
    /* Try to update owner */
    int uid = -1;
    struct passwd *uinfo;
    
    if (Z_TYPE_P (user) == IS_STRING) {
      uinfo = getpwnam (Z_STRVAL_P (user));
      
      if (uinfo)
        uid = uinfo->pw_uid;
    } else if (Z_TYPE_P (user) == IS_LONG) {
      uinfo = getpwuid (Z_LVAL_P (user));
      uid = Z_LVAL_P (user);
    }
    
    if ((uid >= 0) && (ioctl (fd, TUNSETOWNER, &uid) < 0))
      RETURN_FALSE;
    
    /* Try to update group */
    int gid = -1;
    
    if (Z_TYPE_P (group) == IS_STRING) {
      struct group *ginfo = getgrnam (Z_STRVAL_P (group));
      
      if (ginfo)
        gid = ginfo->gr_gid;
    } else if (Z_TYPE_P (group) == IS_LONG)
      gid = Z_LVAL_P (group);
    else if (uinfo)
      gid = uinfo->pw_gid;
    
    if ((gid >= 0) && (ioctl (fd, TUNSETGROUP, &gid) < 0))
      RETURN_FALSE;
    
    RETURN_TRUE;
  }
  ZEND_BEGIN_ARG_INFO (tuntap_arginfo_owner, 0)
    ZEND_ARG_INFO (0, device)
    ZEND_ARG_INFO (0, user)
    ZEND_ARG_INFO (0, group)
  ZEND_END_ARG_INFO ()
  // }}}
  
  // {{{ tuntap_persist
  /**
   * Make a TUN/TAP-Device persistent (or not)
   * 
   * @param resource $Device
   * @param bool $Persist (optional)
   * 
   * @access public
   * @return bool
   **/
  PHP_FUNCTION (tuntap_persist) {
    /* Retrive function-parameters */
    zval *device;
    long persist = 1;
    int fd;
    
    if (zend_parse_parameters (ZEND_NUM_ARGS () TSRMLS_CC, "r|b", &device, &persist) == FAILURE)
      RETURN_FALSE;
    
    TUNTAP_GET_FD (fd, device);
    
    /* Execute ioctl() */
    if (ioctl (fd, TUNSETPERSIST, &persist) < 0)
      RETURN_FALSE;
    
    RETURN_TRUE;
  }
  ZEND_BEGIN_ARG_INFO (tuntap_arginfo_persist, 0)
    ZEND_ARG_INFO (0, device)
    ZEND_ARG_INFO (0, persist)
  ZEND_END_ARG_INFO ()
  // }}}
  
  // {{{ tuntap_functions []
  /**
   * Every user visible function must have an entry in tuntap_functions[].
   **/
  const zend_function_entry tuntap_functions [] = {
    PHP_FE (tuntap_new, tuntap_arginfo_new)
    PHP_FE (tuntap_name, tuntap_arginfo_name)
    PHP_FE (tuntap_owner, tuntap_arginfo_owner)
    PHP_FE (tuntap_persist, tuntap_arginfo_persist)
    /*
      TUNSETDEBUG - Enable/Disable debugging
      TUNSETLINK - Set Link-Type
      TUNSETOFFLOAD
      TUNSETTXFILTER - TAP only 
      TUNGETSNDBUF / TUNSETSNDBUF
      TUNATTACHFILTER
      TUNDETACHFILTER
      TUNGETVNETHDRSZ
      TUNSETVNETHDRSZ
    */
    PHP_FE_END
  };
  // }}}

  // {{{ tuntap_module_entry
  zend_module_entry tuntap_module_entry = {
    STANDARD_MODULE_HEADER,
    "tuntap",
    tuntap_functions,
    PHP_MINIT (tuntap),
    PHP_MSHUTDOWN (tuntap),
    NULL,
    NULL,
    PHP_MINFO (tuntap),
    PHP_TUNTAP_VERSION,
    STANDARD_MODULE_PROPERTIES
  };
 // }}}
 
# ifdef COMPILE_DL_TUNTAP
#   ifdef ZTS
      ZEND_TSRMLS_CACHE_DEFINE ()
#   endif
    ZEND_GET_MODULE (tuntap)
# endif
