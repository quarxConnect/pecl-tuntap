# pecl-tuntap
TUN/TAP ioctls for PHP. Enables PHP-Applications to create and manage
TUN/TAP-Interfaces on Linux.

## Building
This module may be build using the normal PECL-Way:

~~~ {.bash}
phpize
./configure --enable-tuntap
make && make install
~~~

## Usage
### Create a new TUN/TAP-Device
~~~ {.php}
$fd = tuntap_new ([string $Name [, int $Flags = 0]]);
~~~

Returns a new file-stream that may be used with file-stream-functions like
`fread()`, etc.

* `$Name` may be the desired name of the new device, if `NULL` a name is choosen by the kernel.
* `$Flags` may be any OR'ed combination of TUN/TAP-Flags (see Constants)

Both parameters are optional.

### Retrive the name of a TUN/TAP-Device
~~~ {.php}
$name = tuntap_name (resource $fd);
~~~
Returns the name of the TUN/TAP-Device as string.

* `$fd` shall be the file-resource returned by a previous `tuntap_new()`-Call.

### Set the owner of a TUN/TAP-Device
~~~ {.php}
tuntap_owner (resource $fd [, mixed $User = NULL [, mixed $Group = NULL]]);
~~~
Returns a boolean indicating success or failure.

* `$fd` shall be the file-resource returned by a previous `tuntap_new()`-Call.
* `$User` may be NULL, a string containing a Username or an integer containing a User-ID.
* `$Group` may be just like `$User` but for groups.

### Set persistence of a TUN/TAP-Device
~~~ {.php}
tuntap_persist (resource $fd [, bool $Persist = true]);
~~~
Returns a boolean indicating success or failure.

* `$fd` shall be the file-resource returned by a previous `tuntap_new()`-Call.
* `$Persist` Enable or disable persistence (default: Enable)

## Constants
* `TUNTAP_DEVICE_TUN` Creates a TUN-Device
* `TUNTAP_DEVICE_TAP` Creates a TAP-Device
* `TUNTAP_DEVICE_NO_PI` Do not provide packet information
* `TUNTAP_DEVICE_EXCL` Don't remember what this should be, maybe something like exclusive

## Example
Please see the provided `tuntap.php` (including the `lib/`-Folder) for an example.
The script creates a TAP-Interface, assigns the local IP-Adress 10.10.10.1/24
using iproute2 and emulates a virutal peer at 10.10.10.2 that may be pinged
using external tools.

## License
Copyright (C) 2016-17 Bernd Holzmüller

Licensed under the PHP license 3.01. This is free
software: you are free to change and redistribute it. There is NO WARRANTY,
to the extent permitted by law.
