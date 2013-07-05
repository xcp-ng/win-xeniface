XenIface - The XenServer Interface Device Driver
==========================================

XenIface is a device driver which provides userlevel applications WMI and Ioctl
read and write access to information provided to the guest domain by
xenstore and xapi

Quick Start
===========

Prerequisites to build
----------------------

*   Visual Studio 2012 or later 
*   Windows Driver Kit 8 or later
*   Python 3 or later 

Environment variables used in building driver
-----------------------------

MAJOR\_VERSION Major version number

MINOR\_VERSION Minor version number

MICRO\_VERSION Micro version number

BUILD\_NUMBER Build number

SYMBOL\_SERVER location of a writable symbol server directory

KIT location of the Windows driver kit

PROCESSOR\_ARCHITECTURE x86 or x64

VS location of visual studio

Commands to build
-----------------

    git clone http://github.com/xenserver/win-xeniface
    cd win-xeniface 
    .\\build.py [checked | free]


Device tree diagram
-------------------

    XenIface
       |
    XenBus
       |
    PCI Bus

See Also
========

win-xeniface\WmiDocumentation.txt for documentation of the WMI interface

