#!python -u

# Copyright (c) Citrix Systems Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, 
# with or without modification, are permitted provided 
# that the following conditions are met:
#
# *   Redistributions of source code must retain the above 
#     copyright notice, this list of conditions and the 
#     following disclaimer.
# *   Redistributions in binary form must reproduce the above 
#     copyright notice, this list of conditions and the 
#     following disclaimer in the documentation and/or other 
#     materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
# SUCH DAMAGE.


import os, sys
import datetime
import re
import glob
import tarfile
import subprocess

def shell(command):
    print(command)
    sys.stdout.flush()

    pipe = os.popen(command, 'r', 1)

    for line in pipe:
        print(line.rstrip())

    return pipe.close()


class msbuild_failure(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

def msbuild(batfile, projdir, name, sdv_arg):
    cwd = os.getcwd()

    os.environ['CONFIGURATION'] = 'Windows 8 Release'
    os.environ['SDV_PROJ'] = name
    os.environ['SDV_ARG'] = sdv_arg

    os.chdir('proj')
    os.chdir(projdir)
    status = shell(batfile)
    os.chdir(cwd)

#    if (status != None):
#        raise msbuild_failure(sdv_arg)


if __name__ == '__main__':
    msbuild('..\msbuild_sdv.bat', 'xeniface', 'xeniface.vcxproj', '/clean')

    msbuild('..\msbuild_sdv.bat', 'xeniface', 'xeniface.vcxproj', '/check:default.sdv')

    msbuild('..\msbuild_dvl.bat', 'xeniface', 'xeniface.vcxproj', '')
