#! /usr/bin/env python3

# Script to clean out a file system such as scratch based on certain criteria
# (e.g. not accessed or modified in x days)
#
# fs-cleaner dirkpetersen / Sept 2014 - Oct 2017 
#

import sys, os, pwd, argparse, subprocess, re, time, datetime, tempfile, shutil
try:
    from scandir import walk
except:
    #print('importing os.walk instead of scandir.walk')
    from os import walk

class KeyboardInterruptError(Exception): pass

def main():

    log = logger('fs-cleaner', args.debug)
    log.info('starting to check folder %s for files older than %s days...' % (args.folder, args.days))
    log.debug('Parsed arguments: %s' % args)
    
    currdir = os.getcwd()
    #curruser = os.getenv('USER') does not work in many cron jobs
    curruser = pwd.getpwuid(os.getuid()).pw_name
    tmpdir = tempfile.gettempdir()
    days_back_as_secs = time.time() - (args.days * 24 * 3600)
    days_back_warn_secs = days_back_as_secs + args.warndays * 24 * 3600
    days_back_warn_secs_minus1 = days_back_as_secs + (args.warndays - 1) * 24 * 3600 #  warndays - 1
    days_back_datestr = str(datetime.date.today() + datetime.timedelta(args.days * -1)) # e.g. '2014-07-01'

    #print('days_back_as_secs: %s' % time.ctime(days_back_as_secs))
    #print('days_back_warn_secs: %s' % time.ctime(days_back_warn_secs))

    filedict = {}  # list of files to delete (grouped by key uid)
    warndict = {}  # list of files to warn about (grouped by key uid)
    infodict = {}  # contains list per uid: numfiles, sizefiles, numwarnfiles, sizewarnfiles

    #print ('\nScanning folder %s for files older than %s days...' % (args.folder, args.days))
    if args.folder == '/':
        print('root folder not allowed !')
        return False

    for root, folders, files in mywalk(args.folder):
        #print(root)
        #for folder in folders:
            #print ('...folder:%s' % folder)

        if args.delete_folders:
            if not folders and not files and root != os.path.normpath(args.folder):
                stat=getstat(root)
                if stat.st_mtime <= days_back_as_secs:
                    if not args.debug:
                        os.rmdir(root)
                    #print('would delete %s' % root)
                continue
                
        for f in files:
            p=os.path.join(root,f)
            stat=getstat(p)
            if not stat:
                continue
            if stat.st_atime <= 0:
                setfiletime(p, "atime")
                if args.debug:
                    sys.stderr.write('atime reset to current time:\n%s' % p)
                continue
            if stat.st_mtime <= 0:
                setfiletime(p, "mtime")
                if args.debug:
                    sys.stderr.write('atime reset to current time:\n%s' % p)
                continue
            recent_time = stat.st_atime
            if stat.st_mtime > recent_time:
                recent_time = stat.st_mtime
            if stat.st_ctime > recent_time:
                recent_time = stat.st_ctime
            if stat.st_uid not in infodict:
                infodict[stat.st_uid] = [0, 0, 0, 0]
            if recent_time <= days_back_as_secs:
                # file reaches threshold defined by args.days
                #print('owner:%s file:%s atime:%s timeback:%s' % (stat.st_uid, p, recent_time, days_back_as_secs))
                if  args.del_adoubles and f.startswith('._'):
                    if args.debug:
                        print("DEBUG: would delete AppleDouble file '%s' !" % p)
                    else:
                        os.remove(p)
                        if os.path.exists(p):
                            sys.stderr.write('file not removed:%s\n' % p)
                    continue
                #file is deleted
                if stat.st_uid not in filedict:
                    filedict[stat.st_uid] = list()
                if args.touchnotdel:
                    #touch a file with current time stamp 
                    setfiletime(p)
                    args.suppress_emails = True
                    sys.stderr.write('atime reset:\n%s' % p)
                else:
                    #really delete the file
                    if not args.debug:
                        os.remove(p)
                        if os.path.exists(p):
                            sys.stderr.write('file not removed:%s\n' % p)
                filedict[stat.st_uid].append(p)
                infodict[stat.st_uid][0]+=1
                infodict[stat.st_uid][1]+=stat.st_size

            if args.warndays > 0:
                if (recent_time <= days_back_warn_secs and recent_time >= days_back_warn_secs_minus1):
                    if stat.st_uid not in warndict:
                        warndict[stat.st_uid] = list()
                    warndict[stat.st_uid].append(p)
                    infodict[stat.st_uid][2]+=1
                    infodict[stat.st_uid][3]+=stat.st_size

    if not os.path.exists(tmpdir+'/'+curruser+'/fs-cleaner'):
        os.makedirs(tmpdir+'/'+curruser+'/fs-cleaner')
        
    send_emails = True if not args.suppress_emails else False
    warn_only = True if args.warndays else False
    warn_days = args.warndays if warn_only else 0

    # ********************** process file warn and deletion with notifications ********************************************
    process_files(curruser, folder, args.days, days_back_datestr, files, infodict, send_emails, args.email, warn_only, warn_days, args.debug)
    log.info('finished checking folder {args.folder} for files older than {args.days} days!')

def process_files(curruser, folder, days, days_back_date, files, info_user, send_emails = True, email_to = '', warn = True, warndays = 0, debug = False):
    tmpdir = tempfile.gettempdir()
    for uid, userfiles in files.items():
        user = uid2user(uid)
        if not os.path.exists(f'{tmpdir}/{curruser}/fs-cleaner/{user}'):
            os.mkdir(f'{tmpdir}/{curruser}/fs-cleaner/{user}')

        filelist_temp = f'{tmpdir}/{curruser}/fs-cleaner/{user}/{user}-deleted-{days_back_date}.txt'
        filelist_user = f'{os.path.normpath(folder)}/{user}-deleted-{days_back_date}.txt'

        if not list2file(userfiles, filelist_temp):
            print(f"Could not save file '{filelist_temp}'")
            continue

        try:
            shutil.copy(filelist_temp, filelist_user)
        except:
            errmsg = f'Error copying file {filelist_temp} to {filelist_user}'
            sys.stderr.write(errmsg)
            log.error(errmsg)
            continue

    index_numfiles = 2 if warn else 0
    index_totalsize = 3 if warn else 1
    numfiles_user = info_user[uid][index_numfiles]
    totalsize_user = "{0:.3f}".format(info_user[uid][index_totalsize]/float(1073741824)) # TB: 838860 , GB: 1073741824

    # No email is sent in debug mode
    if not debug:
        try:
            if send_emails:
                mail_subject = ''
                summary = ''
                if warn:
                    mail_subject = f"WARNING: In {warndays} days will delete files in {folder}!"
                    mail_body = f"Please see the list of files located at {warnlog_user}\n\n" \
                        "The files listed here\n" \
                        "will be deleted in {warndays} days if they\n" \
                        "not have been touched for {days} days:\n" \
                        "\n# of files: {numfiles_user}, total space: {totalsize_user} GB\n" \
                        "You can prevent deletion of these files\n" \
                        "by using the command 'touch -a filename'\n" \
                        "on each file. This will reset the access \n" \
                        "time of the file to the current date.\n"
                    summary = f'Sent delete warning for {numfiles_warn} files ({totalsize_warn} GB) to {user} with filelist {warnlog_user}'
                else:
                    mail_subject = f"NOTE: Deleted files in {folder} that were not accessed for {days} days"
                    mail_body = f"Please see the list of files located at {filelist_user}\n\n" \
                        "The files listed here\n" \
                        "were deleted because they were not accessed\n" \
                        "in the last {days} days.\n"
                    summary = f'Sent delete notification to {user} with filelist {filelist_user}'

                send_mail([user], mail_subject, mail_body)
                print (f'\n{summary}')
                log.info(summary)
        except:
            error = sys.exc_info()[0]
            sys.stderr.write(f"Error in send_mail while sending to '{user}': {error}\n")
            log.error(f"Error in send_mail while sending to '{user}': {error}")
            if email_to:
                send_mail([email_to], "Error - fs-cleaner",
                    f"Please debug email notification to user '{user}', Error: {error}\n")
            else:
                sys.stderr.write('no option --email-notify given, cannot send error status via email\n')
    else:
        numfiles = max(len(userfiles), 10)
        print("\nDEBUG: ##### DELETE ##########################################################")
        print(f"DEBUG: Would have deleted {numfiles_user} files ({totalsize_user} GB total) owned by '{user}'")
        print(f"DEBUG: Would have sent notification with path to file '{filelist_user}' to user '{user}'")
        print('DEBUG: List of files that would have been deleted (maximum 10 listed):')
        for i in range(numfiles):
            print(userfiles[i])


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
            sys.stderr.write(str(e))            
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
        sys.stderr.write(str(err))
        sys.stderr.write('\n')
        return False

def uid2user(uidNumber):
    """ attempts to convert uidNumber to username """
    import pwd
    try:
        return pwd.getpwuid(int(uidNumber)).pw_name
    except Exception as err:
        sys.stderr.write(str(err))
        sys.stderr.write('\n')
        return str(uidNumber)

def list2file(mylist,path):
    """ dumps a list into a text file, one line per item"""
    try:
        with open(path,'w') as f:
            for item in mylist:
                f.write("{}\r\n".format(item))
        return True
    except Exception as err:
        sys.stderr.write(str(err))
        sys.stderr.write('\n')
        return False

def pathlist2file(mylist,path,root):
    """ dumps a list into a text file, one line per item, but removes
         a root folder from all paths. Used for --files-from feature in rsync"""
    try:
        with open(path,'w') as f:
            for item in mylist:
                f.write("{}\r\n".format(item[len(root):]))
        return True
    except Exception as err:
        sys.stderr.write(str(err))
        sys.stderr.write('\n')
        return False

def mywalk(top, skipdirs=['.snapshot',]):
    """ returns subset of os.walk  """
    for root, dirs, files in walk(top,topdown=True,onerror=walkerr): 
        for skipdir in skipdirs:
            if skipdir in dirs:
                dirs.remove(skipdir)  # don't visit this directory 
        yield root, dirs, files 

def walkerr(oserr):    
    sys.stderr.write(str(oserr))
    sys.stderr.write('\n')
    return 0


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
        print("the 'to' parameter needs to be a list")
        return False    
    if len(to)==0:
        print("no 'to' email addresses")
        return False
    
    myhost=socket.getfqdn()

    if smtphost == '':
        smtphost = get_mx_from_email_or_fqdn(myhost)
    if not smtphost:
        sys.stderr.write('could not determine smtp mail host, using localhost!\n') #XXX
        smtphost = 'localhost' #XXX
        
    if fromaddr == '':
        fromaddr = os.path.basename(__file__) + '-no-reply@' + myhost #XXX
    tc=0
    for t in to:
        if '@' not in t:
            # if no email domain given use domain from local host
            to[tc]=t + '@' + myhost #XXX
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
            '$notify_text\n\nIf output is being captured, you may find additional\n' + \
            'information in your logs.\n'
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
        domain = '.'.join(addr.rsplit('.')[1:]) # XXX
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
    parser.add_argument( '--touch-instead-delete', '-i', dest='touchnotdel', action='store_true',
        help='Do not delete a file but touch it so atime will be reset to the current time',
        default=False )
    parser.add_argument( '--remove-appledoubles', '-a', dest='del_adoubles', action='store_true',
        help='immediately remove AppleDoubles at the source.',
        default=False )
    parser.add_argument( '--folder', '-f', dest='folder',
        action='store', 
        help='search this folder and below for files to remove')
    args = parser.parse_args()
    if not args.folder:
        parser.error('required option --folder not given !')
    if args.debug:
        print('DEBUG: Arguments/Options: %s' % args)    
    return args

if __name__ == '__main__':
    # Parse command-line arguments
    args = parse_arguments()
    sys.exit(main())
