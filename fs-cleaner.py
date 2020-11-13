#! /usr/bin/env python3

# Script to clean out a file system such as scratch based on certain criteria
# (e.g. not accessed or modified in x days)
#
# fs-cleaner dirkpetersen / Sept 2014 - Oct 2017 
#

import sys
import os
import pwd
import argparse
import subprocess
import re
import time
import datetime
import tempfile
import stat

try:
    from scandir import walk
except:
    sys.stderr.write('warning: importing os.walk instead of scandir.walk\n')
    from os import walk

class KeyboardInterruptError(Exception): pass

def main():

    log = logger('fs-cleaner', args.debug)
    log.info('starting to check folder %s for files older than %s days...' % (args.folder, args.days))
    log.debug('Parsed arguments: %s' % args)

    curruser = os.getenv('USER') 

    curruser = pwd.getpwuid(os.getuid()).pw_name

    if args.logdir:
        tmpdir = args.logdir
    else:
        tmpdir = tempfile.gettempdir()

    if args.debug:
        sys.stderr.write('DEBUG: logdir set to {}\n'.format(tmpdir))

    days_back_as_secs = time.time() - (args.days * 24 * 3600)
    days_back_warn_secs = days_back_as_secs + args.warndays * 24 * 3600
    days_back_warn_secs_minus1 = days_back_as_secs + (args.warndays - 1) * 24 * 3600 #  warndays - 1
    days_back_datestr = str(datetime.date.today() + datetime.timedelta(args.days * -1)) # e.g. '2014-07-01'

    if args.debug:
        sys.stderr.write('DEBUG: days_back_as_secs: {}\n'.format(time.ctime(days_back_as_secs)))
        sys.stderr.write('DEBUG: days_back_warn_secs: {}\n'.format(time.ctime(days_back_warn_secs)))

    filedict = {}  # list of files to delete (grouped by key uid)
    warndict = {}  # list of files to warn about (grouped by key uid)
    infodict = {}  # contains list per uid: numfiles, sizefiles, numwarnfiles, sizewarnfiles

    if args.debug:
        sys.stderr.write('DEBUG: Scanning folder {} for files older than {} days...\n'.format(args.folder, args.days))
    if args.folder == '/':
        print('Error: root folder not allowed !')
        return False

    for root, folders, files in mywalk(args.folder):
        if args.debug:
            sys.stderr.write('DEBUG: processing root {} folder {} file {}\n'.format(root, folders, files))
        if args.delete_folders:
            if not folders and not files and root != os.path.normpath(args.folder):
                folder_stat=getstat(root)
                if folder_stat.st_mtime <= days_back_as_secs:
                    if args.dryrun or args.fsdryrun:
                        if args.debug:
                            sys.stderr.write('DEBUG: would delete folder {}\n'.format(root))
                    else:
                        os.rmdir(root)
                        if args.debug:
                            sys.stderr.write('DEBUG: deleted folder {}\n'.format(root))

        for f in files:
            p=os.path.join(root,f)
            file_stat=getstat(p)
            if not file_stat:
                continue
            if file_stat.st_atime <= 0:
                if args.dryrun or args.fsdryrun:
                    if args.debug:
                        sys.stderr.write('DEBUG: would fix atime for {}\n'.format(p))
                setfiletime(p, "atime")
                if args.debug:
                    sys.stderr.write('DEBUG: atime reset to current time on {}\n'.format(p))
                continue
            if file_stat.st_mtime <= 0:
                if args.dryrun or args.fsdryrun:
                    if args.debug:
                        sys.stderr.write('DEBUG: would fix mtime for {}'.format(p))
                setfiletime(p, "mtime")
                if args.debug:
                    sys.stderr.write('DEBUG: mtime reset to current time on {}\n'.format(p))
                continue
            recent_time = file_stat.st_atime
            if file_stat.st_mtime > recent_time:
                recent_time = file_stat.st_mtime
            # ctime cannot easily be faked, so for dryrun and debug, do not check ctime
            if args.debug or args.dryrun or args.fsdryrun:
                pass
            else:
                if file_stat.st_ctime > recent_time:
                    recent_time = file_stat.st_ctime
            if file_stat.st_uid not in infodict:
                infodict[file_stat.st_uid] = [0, 0, 0, 0]
            if recent_time <= days_back_as_secs:
                # file reaches threshold defined by args.days
                if args.debug:
                    sys.stderr.write('DEBUG: owner:{} file:{} atime:{} timeback:{}\n'.format(file_stat.st_uid, p, recent_time, days_back_as_secs))
                if  args.del_adoubles and f.startswith('._'):
                    if args.debug:
                        sys.stderr.write('DEBUG: would delete AppleDouble file {}\n'.format(p))
                    if args.dryrun or args.fsdryrun:
                        pass
                    else:
                        os.remove(p)
                        if os.path.exists(p):
                            sys.stderr.write('warning: AppleDouble file not removed: {}\n'.format(p))
                    continue

                if file_stat.st_uid not in filedict:
                    filedict[file_stat.st_uid] = list()
                if args.dryrun or args.fsdryrun:
                    if args.debug:
                        sys.stderr.write('DEBUG: would delete or touch: {}\n'.format(p))
                else:
                    if args.touchnotdel:
                        #touch a file with current time stamp 
                        setfiletime(p)
                        args.suppress_emails = True
                        if args.debug:
                            sys.stderr.write('DEBUG: atime reset on file {}\n'.format(p))
                    else:
                        #really delete the file
                        if args.debug:
                            sys.stderr.write('DEBUG: would delete path {}\n'.format(p))
                        os.remove(p)
                        if os.path.exists(p):
                            sys.stderr.write('warning: file not removed {}\n'.format(p))

                filedict[file_stat.st_uid].append(p)
                infodict[file_stat.st_uid][0]+=1
                infodict[file_stat.st_uid][1]+=file_stat.st_size

            if args.warndays > 0:
                if (recent_time <= days_back_warn_secs and recent_time >= days_back_warn_secs_minus1):
                    if file_stat.st_uid not in warndict:
                        warndict[file_stat.st_uid] = list()
                    warndict[file_stat.st_uid].append(p)
                    infodict[file_stat.st_uid][2]+=1
                    infodict[file_stat.st_uid][3]+=file_stat.st_size

    script_logdir = tmpdir+'/'+curruser+'_fs-cleaner'
    if not os.path.exists(script_logdir):
        if args.dryrun:
            sys.stderr.write('warning: dryrun not creating dir {}\n'.format(script_logdir))
        else:
            os.mkdir(script_logdir)
            script_logdir_stat = os.stat(script_logdir)
            os.chmod(script_logdir,script_logdir_stat.st_mode | stat.S_IXOTH | stat.S_IROTH)

    # ********************** process notifications for warnings ********************************************
    for k, v in warndict.items():
        user = uid2user(k)
        user_logdir = script_logdir+'/'+user
        if not os.path.exists(user_logdir):
            if args.debug:
                sys.stderr.write('DEUBG: creating user log dir {}\n'.format(user_logdir))
            if args.dryrun:
                sys.stderr.write('warning: dryrun not creating dir {}\n'.format(user_logdir))
            else:
                os.mkdir(user_logdir)
                os.chown(user_logdir,k,k)
        file2send=user_logdir+'/'+user+'-warned-'+days_back_datestr+'.txt'
        if list2file(v,file2send):
            if args.dryrun:
                sys.stderr.write('warning: dryrun not changing ownership of {}\n'.format(file2send))
            else:
                os.chown(file2send, k, k)   # default gid = uid
            if args.dryrun:
                if args.debug:
                    sys.stderr.write('DEBUG: would email warning to {}\n'.format(user))
            else:
                if not args.suppress_emails:
                    email_subject = 'WARNING: In {} days files will be deleted from {}!'.format(args.warndays, args.folder)
                    email_text = "Please see file list here: {}!\n\n" \
                        "The files listed will be deleted in {} days when they will be {} days old.\n\n" \
                        "# of files: {}, total space: {:.3f} GB\n\n" \
                        "Please move important files out of {}.\n\n" \
                        "If you still need these files in {}, you can prevent deletion of these files by using the command 'touch -a <filename>' on each file. This will reset the access time of the file to the current date.\n\n" \
                        "Remember that {} is a shared resource meant for job-related temporary file storage only.\n\n" \
                        "".format(file2send, args.warndays, args.days, infodict[k][2], infodict[k][3]/1024.0/1024.0/1024.0, args.folder, args.folder, args.folder)
                    if args.debug:
                        sys.stderr.write('DEBUG: Send to user {} Subject: {} Text: {}\n'.format(user,email_subject,email_text))
                    try:
                        send_mail([user,], email_subject, email_text)
                        log.info('Sent delete warning for {} files ({:.3f} GB) to {} referencing {}'.format(infodict[k][2], infodict[k][3]/1024.0/1024.0/1024.0, user, file2send))
                    except:
                        e=sys.exc_info()[0]
                        sys.stderr.write('warning: Error in send_mail while sending to {}: {}\n'.format(user, e))
                        log.error("Error in send_mail while sending to '%s': %s" % (user, e))
                        if args.email:
                            send_mail([args.email,], "Error - fs-cleaner",
                                "Please debug email notification to user '%s', Error: %s\n" % (user, e))
                        else:
                            sys.stderr.write('warning: no option --email-notify given, cannot send error status via email\n')

        else:
            sys.stderr.write('warning: Could not save file {}\n'.format(file2send))


    # ******************* process deletions with notification ********************************
    for k, v in filedict.items():
        user = uid2user(k)
        user_logdir = script_logdir+'/'+user
        if not os.path.exists(user_logdir):
            if args.debug:
                sys.stderr.write('DEBUG: making user log dir {}\n'.format(user_logdir))
            if args.dryrun:
                sys.stderr.write('warning: dryrun not creating dir {}\n'.format(user_logdir))
            else:
                os.mkdir(user_logdir)
                os.chown(user_logdir,k,k)
        file2send = user_logdir+'/'+user+'-deleted-'+days_back_datestr+'.txt'
        if list2file(v,file2send):
            if args.dryrun:
                sys.stderr.write('warning: dryrun not chaning ownership of {}\n'.format(file2send))
            else:
                os.chown(file2send,k,k)   # default gid should = uid
            if args.dryrun:
                if args.debug:
                    sys.stderr.write('DEBUG: would email deletion notifiction to {}\n'.format(user))
            else:
                if not args.suppress_emails:
                    email_subject = 'NOTICE: Files deleted in {}'.format(args.folder)
                    email_text = "Please see file list {}.\n\n" \
                        "The files listed were deleted because they were not accessed in the last {} days." \
                        "\n".format(file2send,args.days)
                    if args.debug:
                        sys.stderr.write('Sent to user {} Subject: {} Text: {}\n'.format(user,email_subject,email_text))
                    try:
                        send_mail([user,], email_subject, email_text)
                        log.info('Sent delete note to {} referencing {}'.format(user, file2send))
                    except:
                        if args.debug:
                            sys.stderr.write('DEBUG: user {} subject {} text {}\n'.format(user,email_subject,email_text))
                        e=sys.exc_info()[0]
                        sys.stderr.write("warning: Error in send_mail while sending to {}: {}\n".format(user, e))
                        log.error("Error in send_mail while sending to '%s': %s" % (user, e))
                        if args.email:
                            send_mail([args.email,], "Error - fs-cleaner",
                                "Please debug email notification to user '%s', Error: %s\n" % (user, e))
                        else:
                            sys.stderr.write('warning: no option --email-notify given, cannot send error status via email\n')

        else:
            sys.stderr.write('warning: Could not save file {}\n'.format(file2send))

    log.info('finished checking folder %s for files older than %s days!' % (args.folder, args.days))

def startswithpath(pathlist, pathstr):
    """ checks if at least one of the paths in a list of paths starts with a string """
    for path in pathlist:
        if (os.path.join(pathstr, '')).startswith(path):
            return True
    return False

def getstartpath(pathlist, pathstr):
    """ return the path from pathlist  that is the frist part of pathstr"""
    for path in pathlist:
        if (os.path.join(pathstr, '')).startswith(path):
            return path
    return ''

def getstat(path):
    """ returns the stat information of a file"""
    statinfo=None
    try:
        statinfo=os.lstat(path)
    except (IOError, OSError) as e:   # FileNotFoundError only since python 3.3
        if args.debug:
            sys.stderr.write('DEBUG exception: {}\n'.format(str(e)))
    except:
        raise
    return statinfo

def setfiletime(path,attr="atime"):
    """ sets the a time of a file to the current time """
    try:
        statinfo=getstat(path)
        if attr=="atime":
            os.utime(path,(time.time(),statinfo.st_mtime))
        if attr=="mtime" or attr=="all":
            os.utime(path)
        return True
    except Exception as err:
        sys.stderr.write('error: {}\n'.format(str(err)))
        return False

def uid2user(uidNumber):
    """ attempts to convert uidNumber to username """
    import pwd
    try:
        return pwd.getpwuid(int(uidNumber)).pw_name
    except Exception as err:
        sys.stderr.write('warning: {}\n'.format(str(err)))
        return str(uidNumber)

def list2file(mylist,path):
    """ dumps a list into a text file, one line per item"""
    if args.dryrun:
        sys.stderr.write('warning: dryrun not writing out file {}\n'.format(path))
    else:
        try:
            with open(path,'w') as f:
                for item in mylist:
                    f.write("{}\r\n".format(item))
            return True
        except Exception as err:
            sys.stderr.write('error: {}\n'.format(str(err)))
            return False

def mywalk(top, skipdirs=['.snapshot',]):
    """ returns subset of os.walk  """
    for root, dirs, files in walk(top,topdown=True,onerror=walkerr):
        for skipdir in skipdirs:
            if skipdir in dirs:
                dirs.remove(skipdir)  # don't visit this directory
        yield root, dirs, files

def walkerr(oserr):
    sys.stderr.write('error: {}\n'.format(str(oserr)))
    return False


def send_mail(to, subject, text, attachments=[], cc=[], bcc=[], smtphost="", fromaddr=""):

    if sys.version_info[0] == 2:
        from email.MIMEMultipart import MIMEMultipart
        from email.MIMEBase import MIMEBase
        from email.MIMEText import MIMEText
        from email.Utils import COMMASPACE, formatdate
        from email import Encoders
    else:
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email.mime.text import MIMEText
        from email.utils import COMMASPACE, formatdate
        from email import encoders as Encoders
    from string import Template
    import socket
    import smtplib

    if not isinstance(to,list):
        print("error: the 'to' parameter needs to be a list")
        return False
    if len(to)==0:
        print("error: no 'to' email addresses")
        return False

    myhost=socket.getfqdn()

    if smtphost == '':
        smtphost = get_mx_from_email_or_fqdn(myhost)
    if not smtphost:
        sys.stderr.write('warning: could not determine smtp mail host !\n')

    if fromaddr == '':
        fromaddr = os.path.basename(__file__) + '-no-reply@' + \
           '.'.join(myhost.split(".")[-2:]) #extract domain from host
    tc=0
    for t in to:
        if '@' not in t:
            # if no email domain given use domain from local host
            to[tc]=t + '@' + '.'.join(myhost.split(".")[-2:])
        tc+=1

    message = MIMEMultipart()
    message['From'] = fromaddr
    message['To'] = COMMASPACE.join(to)
    message['Date'] = formatdate(localtime=True)
    message['Subject'] = subject
    message['Cc'] = COMMASPACE.join(cc)
    message['Bcc'] = COMMASPACE.join(bcc)

    body = Template('This is a notification message from $application, running on \n' + \
            'host $host. Please review the following message:\n\n' + \
            '$notify_text\n\nPlease email scicomp@ with any questions.\n'
            )
    host_name = socket.gethostname()
    full_body = body.substitute(host=host_name.upper(), notify_text=text, application=os.path.basename(__file__))

    message.attach(MIMEText(full_body))

    for f in attachments:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(open(f, 'rb').read())
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
        message.attach(part)

    addresses = []
    for x in to:
        addresses.append(x)
    for x in cc:
        addresses.append(x)
    for x in bcc:
        addresses.append(x)

    smtp = smtplib.SMTP(smtphost)
    smtp.sendmail(fromaddr, addresses, message.as_string())
    smtp.close()

    return True

def get_mx_from_email_or_fqdn(addr):
    """retrieve the first mail exchanger dns name from an email address."""
    # Match the mail exchanger line in nslookup output.
    MX = re.compile(r'^.*\s+mail exchanger = (?P<priority>\d+) (?P<host>\S+)\s*$')
    # Find mail exchanger of this email address or the current host
    if '@' in addr:
        domain = addr.rsplit('@', 2)[1]
    else:
        domain = '.'.join(addr.rsplit('.')[-2:])
    p = os.popen('/usr/bin/nslookup -q=mx %s' % domain, 'r')
    mxes = list()
    for line in p:
        m = MX.match(line)
        if m is not None:
            mxes.append(m.group('host')[:-1])  #[:-1] just strips the ending dot
    if len(mxes) == 0:
        return ''
    else:
        return mxes[0]

def logger(name=None, stderr=False):
    import logging, logging.handlers
    # levels: CRITICAL:50,ERROR:40,WARNING:30,INFO:20,DEBUG:10,NOTSET:0
    if not name:
        name=__file__.split('/')[-1:][0]
    l=logging.getLogger(name)
    l.setLevel(logging.INFO)
    f=logging.Formatter('%(name)s: %(levelname)s:%(module)s.%(lineno)d: %(message)s')
    # logging to syslog
    s=logging.handlers.SysLogHandler('/dev/log')
    s.formatter = f
    l.addHandler(s)
    if stderr:
        l.setLevel(logging.DEBUG)
        # logging to stderr
        c=logging.StreamHandler()
        c.formatter = f
        l.addHandler(c)
    return l

def parse_arguments():
    """
    Gather command-line arguments.
    """

    parser = argparse.ArgumentParser(prog='fs-cleaner',
        description='clean out old files on a scratch file system ' + \
        'and notify file owners.')
    parser.add_argument( '--debug', '-g', dest='debug', action='store_true',
        help='show the actual shell commands that are executed (git, chmod, cd)',
        default=False )
    parser.add_argument( '--dryrun', '-n', dest='dryrun', action='store_true',
        help='no touch - do no writes of any kind',
        default=False )
    parser.add_argument( '--fsdryrun', '-t', dest='fsdryrun', action='store_true',
        help='test - do no writes to the file system, but generate logs (and emails potentially)',
        default=False )
    parser.add_argument( '--suppress-emails', '-s', dest='suppress_emails', action='store_true',
        help='do not send any emails to end users',
        default=False )
    parser.add_argument( '--delete-folders', '-x', dest='delete_folders', action='store_true',
        help='remove empty folders',
        default=False )
    parser.add_argument( '--email-notify', '-e', dest='email',
        action='store',
        help='notify this email address of any error ',
        default='' )
    parser.add_argument( '--warn-days', '-w', dest='warndays',
        action='store',
        type=int,
        help='warn user x days before removal of file (default: 0 days = deactivated) ',
        default=0 )
    parser.add_argument( '--days', '-d', dest='days',
        action='store',
        type=int,
        help='remove files older than x days (default: 1461 days or 4 years) ',
        default=1461 )
    parser.add_argument( '--bwlimit', '-b', dest='bwlimit',
        action='store',
        type=int,
        help='maximum bandwidth limit (KB/s) of all parallel rsync sessions combined',
        default=0)
    parser.add_argument( '--touch-instead-delete', '-i', dest='touchnotdel', action='store_true',
        help='Do not delete a file but touch it so atime will be reset to the current time',
        default=False )
    parser.add_argument( '--remove-appledoubles', '-a', dest='del_adoubles', action='store_true',
        help='immediately remove AppleDoubles at the source.',
        default=False )
    parser.add_argument( '--folder', '-f', dest='folder',
        action='store',
        help='search this folder and below for files to remove')
    parser.add_argument( '--logdir', '-l', dest='logdir',
        action='store',
        help='put logs of actions here (you must manage permissions)')
    args = parser.parse_args()
    if not args.folder:
        parser.error('required option --folder not given !')
    if args.debug:
        sys.stderr.write('DEBUG: Arguments/Options: {}\n'.format(args))
    return args

if __name__ == '__main__':
    # Parse command-line arguments
    args = parse_arguments()
    sys.exit(main())
