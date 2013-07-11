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

def make_header():
    now = datetime.datetime.now()

    file = open('include\\version.h', 'w')
    file.write('#define MAJOR_VERSION\t' + os.environ['MAJOR_VERSION'] + '\n')
    file.write('#define MAJOR_VERSION_STR\t"' + os.environ['MAJOR_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define MINOR_VERSION\t' + os.environ['MINOR_VERSION'] + '\n')
    file.write('#define MINOR_VERSION_STR\t"' + os.environ['MINOR_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define MICRO_VERSION\t' + os.environ['MICRO_VERSION'] + '\n')
    file.write('#define MICRO_VERSION_STR\t"' + os.environ['MICRO_VERSION'] + '"\n')
    file.write('\n')

    file.write('#define BUILD_NUMBER\t' + os.environ['BUILD_NUMBER'] + '\n')
    file.write('#define BUILD_NUMBER_STR\t"' + os.environ['BUILD_NUMBER'] + '"\n')
    file.write('\n')

    file.write('#define YEAR\t' + str(now.year) + '\n')
    file.write('#define YEAR_STR\t"' + str(now.year) + '"\n')

    file.write('#define MONTH\t' + str(now.month) + '\n')
    file.write('#define MONTH_STR\t"' + str(now.month) + '"\n')

    file.write('#define DAY\t' + str(now.day) + '\n')
    file.write('#define DAY_STR\t"' + str(now.day) + '"\n')


    file.close()


def get_expired_symbols(age = 30):
    path = os.path.join(os.environ['SYMBOL_SERVER'], '000Admin\\history.txt')

    try:
        file = open(path, 'r')
    except IOError:
        return []

    threshold = datetime.datetime.utcnow() - datetime.timedelta(days = age)

    expired = []

    for line in file:
        item = line.split(',')

        if (re.match('add', item[1])):
            id = item[0]
            date = item[3].split('/')
            time = item[4].split(':')

            age = datetime.datetime(year = int(date[2]),
                                    month = int(date[0]),
                                    day = int(date[1]),
                                    hour = int(time[0]),
                                    minute = int(time[1]),
                                    second = int(time[2]))
            if (age < threshold):
                expired.append(id)

        elif (re.match('del', item[1])):
            id = item[2].rstrip()
            try:
                expired.remove(id)
            except ValueError:
                pass

    file.close()

    return expired

def get_configuration_name(debug):
    configuration = 'WindowsVista'

    if debug:
        configuration += 'Debug'
    else:
        configuration += 'Release'

    return configuration

def get_configuration(debug):
    configuration = 'Windows Vista'

    if debug:
        configuration += ' Debug'
    else:
        configuration += ' Release'

    return configuration


def get_target_path(arch, debug):
    configuration = get_configuration_name(debug)

    target = { 'x86': 'proj', 'x64': os.sep.join(['proj', 'x64']) }
    target_path = os.sep.join([target[arch], configuration])

    return target_path


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

def msbuild(name, arch, debug):
    cwd = os.getcwd()
    configuration = get_configuration(debug)

    os.environ['SOLUTION'] = name

    if arch == 'x86':
        os.environ['PLATFORM'] = 'Win32'
    elif arch == 'x64':
        os.environ['PLATFORM'] = 'x64'

    os.environ['CONFIGURATION'] = configuration
    os.environ['TARGET'] = 'Build'

    os.chdir('proj')
    status = shell('msbuild.bat')
    os.chdir(cwd)

    if (status != None):
        raise msbuild_failure(configuration)


def symstore_del(age):
    symstore_path = [os.environ['KIT'], 'Debuggers']
    if os.environ['PROCESSOR_ARCHITECTURE'] == 'x86':
        symstore_path.append('x86')
    else:
        symstore_path.append('x64')
    symstore_path.append('symstore.exe')

    symstore = os.path.join(*symstore_path)

    for id in get_expired_symbols(age):
        command=['"' + symstore + '"']
        command.append('del')
        command.append('/i')
        command.append(str(id))
        command.append('/s')
        command.append(os.environ['SYMBOL_SERVER'])

        shell(' '.join(command))

def symstore_add(name, arch, debug):
    cwd = os.getcwd()
    configuration = get_configuration_name(debug)
    target_path = get_target_path(arch, debug)

    symstore_path = [os.environ['KIT'], 'Debuggers']
    if os.environ['PROCESSOR_ARCHITECTURE'] == 'x86':
        symstore_path.append('x86')
    else:
        symstore_path.append('x64')
    symstore_path.append('symstore.exe')

    symstore = os.path.join(*symstore_path)

    version = '.'.join([os.environ['MAJOR_VERSION'],
                        os.environ['MINOR_VERSION'],
                        os.environ['MICRO_VERSION'],
                        os.environ['BUILD_NUMBER']])

    os.chdir(target_path)
    command=['"' + symstore + '"']
    command.append('add')
    command.append('/s')
    command.append(os.environ['SYMBOL_SERVER'])
    command.append('/r')
    command.append('/f')
    command.append('*.pdb')
    command.append('/t')
    command.append(name)
    command.append('/v')
    command.append(version)

    shell(' '.join(command))

    os.chdir(cwd)

def callfnout(cmd):
    print(cmd)

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = sub.communicate()[0]
    ret = sub.returncode

    if ret != 0:
        raise(Exception("Error %d in : %s" % (ret, cmd)))
    print("------------------------------------------------------------")
    return output.decode('utf-8')

def archive(filename, files, tgz=False):
    access='w'
    if tgz:
        access='w:gz'
    tar = tarfile.open(filename, access)
    for name in files :
        try:
            print('adding '+name)
            tar.add(name)
        except:
            pass
    tar.close()


if __name__ == '__main__':
    os.environ['MAJOR_VERSION'] = '7'
    os.environ['MINOR_VERSION'] = '1'
    os.environ['MICRO_VERSION'] = '0'

    if 'BUILD_NUMBER' not in os.environ.keys():
        os.environ['BUILD_NUMBER'] = '0'

    if 'GIT_REVISION' in os.environ.keys():
        revision = open('revision', 'w')
        print(os.environ['GIT_REVISION'], file=revision)
        revision.close()

    debug = { 'checked': True, 'free': False }

    make_header()

    symstore_del(30)

    msbuild('xeniface', 'x86', debug[sys.argv[1]])
    msbuild('xeniface', 'x64', debug[sys.argv[1]])

    symstore_add('xeniface', 'x86', debug[sys.argv[1]])
    symstore_add('xeniface', 'x64', debug[sys.argv[1]])



    listfile = callfnout(['git','ls-tree', '-r', '--name-only', 'HEAD'])
    archive('xeniface\\source.tgz', listfile.splitlines(), tgz=True)
    archive('xeniface.tar', ['xeniface', 'revision'])
