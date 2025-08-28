#!/bin/env python3

"""
Loffice - Lazy Office Analyzer

Requirements:
- Microsoft Office
- WinDbg - https://msdn.microsoft.com/en-us/windows/hardware/hh852365
- WinAppDbg - http://winappdbg.sourceforge.net/
- pefile - https://github.com/erocarrera/pefile
- capstone - https://pypi.python.org/pypi/capstone-windows

Author: @tehsyntx
"""

from winappdbg import Debug, EventHandler
from time import strftime, gmtime
import os
import sys
import pefile
import random
import string
import logging
import warnings
import optparse
import mimetypes

try:
    from capstone import Cs, CS_MODE_32, CS_MODE_64, CS_ARCH_X86
    capstone = True
except ImportError:
    print('Could not import capstone, insight to antis limited')
    capstone = False

# Setting up logger facilities.
if not os.path.exists('%s\\logs' % os.getcwd()):
    os.mkdir('%s\\logs' % os.getcwd())

logfile = '%s\\logs\\%s_%s.log' % (
    os.getcwd(),
    sys.argv[-1].split('\\')[-1],
    strftime('%Y%d%m%H%M%S', gmtime())
)
logging.basicConfig(filename=logfile, format='%(asctime)s - %(levelname)s %(message)s')
logging.addLevelName(logging.INFO, '')
logging.addLevelName(logging.DEBUG, '[%s] ' % logging.getLevelName(logging.DEBUG))
logging.addLevelName(logging.ERROR, '[%s] ' % logging.getLevelName(logging.ERROR))
logging.addLevelName(logging.WARNING, '[%s] ' % logging.getLevelName(logging.WARNING))
logger = logging.getLogger()

# Root path to Microsoft Office suite.
DEFAULT_OFFICE_PATH = os.environ['PROGRAMFILES'] + '\\Microsoft Office\\Office14'

results = {'instr': {}, 'filehandle': {}, 'urls': [], 'procs': [], 'wmi': []}
stats = {'str': 0, 'url': 0, 'filew': 0, 'filer': 0, 'wmi': 0, 'proc': 0}

# ---- Callback functions ---- #

def cb_crackurl(event):
    stats['url'] += 1
    proc = event.get_process()
    thread = event.get_thread()

    if proc.get_bits() == 32:
        lpszUrl = thread.read_stack_dwords(2)[1]
    else:
        context = thread.get_context()
        lpszUrl = context['Rcx']

    url = proc.peek_string(lpszUrl, fUnicode=True)
    logger.info('FOUND URL: %s' % url)
    results['urls'].append(url)

    if exit_on == 'url':
        logger.info('Exiting on first URL, bye!')
        safe_exit('Found a URL, exiting as specified exit mode.\nURL: %s' % url)

    print_stats()


def cb_createfilew(event):
    proc = event.get_process()
    thread = event.get_thread()

    if proc.get_bits() == 32:
        lpFileName, dwDesiredAccess = thread.read_stack_dwords(3)[1:]
    else:
        context = thread.get_context()
        lpFileName = context['Rcx']
        dwDesiredAccess = context['Rdx']

    access = ''
    if dwDesiredAccess & 0x80000000:
        access += 'R'
    if dwDesiredAccess & 0x40000000:
        access += 'W'

    filename = proc.peek_string(lpFileName, fUnicode=True)

    if access != '' and '\\\\' not in filename[:2]:
        if writes_only and 'W' in access:
            logger.info('Opened file handle (access: %s): %s' % (access, filename))
        elif not writes_only:
            logger.info('Opened file handle (access: %s): %s' % (access, filename))

        if filename in results['filehandle']:
            results['filehandle'][filename].append(access)
        else:
            results['filehandle'][filename] = [access]

        if 'W' in access:
            stats['filew'] += 1
        else:
            stats['filer'] += 1

    print_stats()


def cb_createprocess(event):
    stats['proc'] += 1
    proc = event.get_process()
    thread = event.get_thread()

    if proc.get_bits() == 32:
        args = thread.read_stack_dwords(8)
        lpApplicationName = args[2]
        lpCommandLine = args[3]
        dwCreationFlags = args[7]
    else:
        context = thread.get_context()
        lpApplicationName = context['Rdx']
        lpCommandLine = context['R8']
        stack = thread.read_stack_qwords(8)
        dwCreationFlags = stack[7] & 0xff

    application = proc.peek_string(lpApplicationName, fUnicode=True)
    cmdline = proc.peek_string(lpCommandLine, fUnicode=True)

    logger.info('CreateProcess: App: "%s" Cmd: %s" CreationFlags: 0x%x' % (application, cmdline, dwCreationFlags))
    results['procs'].append({'cmd': cmdline, 'app': application, 'cflags': dwCreationFlags})

    print_stats()

    if exit_on == 'url' and 'splwow64' not in application and dwCreationFlags != 0x4:
        logger.info('Process created before URL was found, exiting for safety.')
        safe_exit('A process was created before a URL was found, exiting before losing control')

    if exit_on == 'proc' and 'splwow64' not in application:
        logger.info('Exiting on process creation, bye!')
        safe_exit('A process was created, exiting via specified exit mode')


# ... (Other callbacks remain mostly unchanged, just update `has_key` to `in` and `xrange` to `range`)

# ---- Python 3 version of checkRecentDocuments ---- #
def checkRecentDocuments():
    try:
        import winreg as _winreg
    except ImportError:
        print("Can't import winreg (needed for evasion)")
        return

    def addDocuments(existing, fakes):
        version = DEFAULT_OFFICE_PATH[-2:]
        apps = ['Word', 'Excel', 'PowerPoint']

        for app in apps:
            try:
                hKey = _winreg.OpenKey(
                    _winreg.HKEY_CURRENT_USER,
                    f'Software\\Microsoft\\Office\\{version}.0\\{app}\\File MRU',
                    0, _winreg.KEY_SET_VALUE
                )
            except:
                hKey = _winreg.CreateKey(
                    _winreg.HKEY_CURRENT_USER,
                    f'Software\\Microsoft\\Office\\{version}.0\\{app}\\File MRU'
                )

            if existing <= 0:
                existing = 1

            for i in range(existing, fakes):
                name = randomString()
                _winreg.SetValueEx(
                    hKey, f'Item {i}', 0, _winreg.REG_SZ,
                    f'[F00000000][T01D228AEF15B51C0][O00000000]*C:\\Documents\\{name}.doc'
                )
            hKey.Close()

    version = DEFAULT_OFFICE_PATH[-2:]
    apps = ['Word', 'Excel', 'PowerPoint']

    for app in apps:
        try:
            hKey = _winreg.OpenKey(
                _winreg.HKEY_CURRENT_USER,
                f'SOFTWARE\\Microsoft\\Office\\{version}.0\\{app}\\File MRU'
            )
            recent = _winreg.QueryInfoKey(hKey)[1] - 1
            hKey.Close()
        except:
            recent = 0

        fakes = random.randint(10, 15)
        if recent < 3:
            while True:
                choice = input(
                    f'Recent docs < 3:\nWant to add some more, like {fakes} fake ones (for Word, Excel & PowerPoint)? (y/n) '
                )
                if choice.lower() == 'y':
                    addDocuments(recent, fakes)
                    print('Fakes added, moving on :)')
                    return
                elif choice.lower() == 'n':
                    print('Aight, but be aware that the macro might not run as expected... :(')
                    return

# ---- Rest of script remains, mostly unchanged ---- #
# Replace all other raw_input, has_key, long, xrange, exception syntax accordingly

# ---- Main ---- #
if __name__ == "__main__":
    global inject
    global exit_on
    global writes_only

    (opts, args) = options()
    prog = args[0]
    exit_on = args[1]
    filename = args[2]
    writes_only = opts.writes_only
    inject = 0
    print('\n\t\tLazy Office Analyzer\n')

    office_invoke = []
    office_invoke.append(setup_office_path(prog, filename, opts.path))
    logger.info('Using office path: "%s"' % office_invoke[0])
    office_invoke.append(filename)

    logger.info('Invocation command: "%s"' % ' '.join(office_invoke))

    with Debug(EventHandler(), bKillOnExit=True) as debug:
        try:
            debug.execv(office_invoke)
        except Exception as e:
            if not os.path.exists(office_invoke[0]):
                print('Error launching application (%s), correct Office path?' % prog)
            else:
                print('Error launching: %s' % str(e))
            sys.exit()
        try:
            logger.info('Launching...')
            checkRecentDocuments()
            debug.loop()
        except KeyboardInterrupt:
            print('\nExiting, summary below...')
            pass

    display_summary()
    print('Remember to check the runtime log in the "logs" directory')
    print('Goodbye...\n')
