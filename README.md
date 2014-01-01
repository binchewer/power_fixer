power_fixer
===========

OSX command line utility that attempts to restore pre-Mavericks power button behavior. Written in C.
Original paper could be found at http://binchewer.org/blog/index.php?id=1.
Donations are welcome at `1G1RKjYazp8TjxKTC6YpWADZzejQaiCeEc` or `LKqD7vAfWkfDTSzta1YUdGqWkBj1RMf654`.

### Problem in a nutshell

In OSX Mavericks short tap on power button instantly puts the system to sleep. It is very annoying if you _don't_ mean to press power key, but mishit delete key or F12 key. In that case downloads stop, VPN, SSH and RPD sessions break, and all world goes to chaos. This disturbing new feature is implemented in CoreService `loginwindow.app`. power_fixer tries to fix `loginwindow.app` in memory to bring back old behavior - show shutdown dialog instead of instant sleep.

### How to use it

Basically all you have to do is download the project, build it, and run it from superuser (`sudo power_fixer`). If the program succeed, the output should look like this (in this case there are 2 active users in the system, each has its own loginwindow):

    $ sudo ./power_fixer
    power_fixer v0.1, by binchewer
    ------------------------------

    Found loginwindow with PID 59
    loginwindow base_address is 0x0000000101d40000
    loginwindow text section found at offset 0x4e10, 387004 bytes
    Found potential timer setup at 0000000101d8d08f
    Found new timer value at 0000000101d955ca: 0.000153
    Writing value 00008533 to address 101d8d093.

    Found loginwindow with PID 845
    loginwindow base_address is 0x00000001091aa000
    loginwindow text section found at offset 0x4e10, 387004 bytes
    Found potential timer setup at 00000001091f708f
    Found new timer value at 00000001091ff5ca: 0.000153
    Writing value 00008533 to address 1091f7093.

    All done.

### How does it work?

First, it tries to locate all `loginwindow` instances. Then it tries to locate executable Mach-O of each instance, and `__text` section in this Mach-O. Then it tries to find in this section the initialization of `xmm0` register with value of 1.5 (that is the default timeout for showing shutdown dialog). Then it tries to find smaller values (from 0.0001 to 0.005). Finally it fixes the abovementioned intialization of `xmm0` register so it reference the newfound smaller value instead of old one.

All that magic effectively cuts shutdown dialog timeout from 1.5 seconds to milliseconds, therefore shutdown dialog appears _before_ you release the power key, and the system does not screw up anymore.

### Caveats

Of course, messing with programs in memory is never easy and failproof, this is a list of known problems:
- it won't work on 32-bit OSX.
- once applied, fix will only work until restart or logout. You can try to `chmod +s` the utility and put in to autolaunch sequence or in cron, but I didn't try it. Ultimate solution would be to hijack `loginwindow` launch, but I was to lazy to dig that.

The program tries its best not to break your system, but if it does, please don't hesitate to report. Also it may be too scrupulous and deny fixing your `loginwindow` for some reason. Don't hesitate to report that either.