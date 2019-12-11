#! /usr/bin/env python3

# Script to clean out a file system such as scratch based on certain criteria
# (e.g. not accessed or modified in x days)
#
# archiving option
# /scratch/delete30/lastname_f/projectx/.archive-me is archived to
# /economy/lastname_f/archive/delete30/projectx-2014-08-21/
#
# fs-cleaner dirkpetersen / Sept 2014 - Oct 2017 
#

import sys, os, pwd, argparse, subprocess, re, time, datetime, tempfile
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
    archdict = {}  # list of files to archive (grouped by key uid)
    infodict = {}  # contains list per uid: numfiles, sizefiles, numwarnfiles, sizewarnfiles
    arch_roots = [] # direcories that contain a flag file '.archive-me'

    #print ('\nScanning folder %s for files older than %s days...' % (args.folder, args.days))
    if args.folder == '/':
        print('root folder not allowed !')
        return False

    for root, folders, files in mywalk(args.folder):
        #print(root)
        #for folder in folders:
            #print ('...folder:%s' % folder)
        # check if the user wanted to archive

        if args.delete_folders:
            if not folders and not files and root != os.path.normpath(args.folder):
                stat=getstat(root)
                if stat.st_mtime <= days_back_as_secs:
                    if not args.debug:
                        os.rmdir(root)
                    #print('would delete %s' % root)
                continue
                
        if os.path.exists(os.path.join(root, '.archive-me')):
            if not root in arch_roots:
                arch_roots.append(os.path.join(root, ''))  # make sure trailing slash is added
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
                startpath = getstartpath(arch_roots,root)
                if startpath !=  '':
                    #file is archived, dict key is source folder minus root.
                    subpath = startpath[len(os.path.join(args.folder, '')):-1]    #subpath without trailing slashes
                    if subpath not in archdict:
                        archdict[subpath] = list()
                    archdict[subpath].append(p)
                else:
                    #file is deleted
                    if stat.st_uid not in filedict:
                        filedict[stat.st_uid] = list()
                    if args.touchnotdel:
                        #touch a file with current time stamp 
                        os.utime(p, times=(time.time(), stat.st_mtime))
                        args.suppress_emails = True
                    else:
                        #really delete the file
                        if not args.debug:
                            os.remove(p)
                            if os.path.exists(p):
                                sys.stderr.write('file not removed:%s\n' % p)
                    filedict[stat.st_uid].append(p)
                    infodict[stat.st_uid][0]+=1
                    infodict[stat.st_uid][1]+=stat.st_size

            if args.warndays > 0 and not startswithpath(arch_roots,root):
                # no warn if .archive-me path in root
                if (recent_time <= days_back_warn_secs and recent_time >= days_back_warn_secs_minus1):
                    if stat.st_uid not in warndict:
                        warndict[stat.st_uid] = list()
                    warndict[stat.st_uid].append(p)
                    infodict[stat.st_uid][2]+=1
                    infodict[stat.st_uid][3]+=stat.st_size

    #print(len(warndict),len(filedict))
    if not os.path.exists(tmpdir+'/'+curruser+'/fs-cleaner'):
        os.makedirs(tmpdir+'/'+curruser+'/fs-cleaner')
        

    # ********************** process notifications for warnings ********************************************
    for k, v in warndict.items():
        user=uid2user(k)
        if not os.path.exists(tmpdir+'/'+curruser+'/fs-cleaner/'+user):
            os.mkdir(tmpdir+'/'+curruser+'/fs-cleaner/'+user)        
        file2send=tmpdir+'/'+curruser+'/fs-cleaner/'+user+'/'+user+'-warn-delete.txt'
        if list2file(v,file2send):
            if not args.debug:
                try:
                    if not args.suppress_emails:
                        send_mail([user,], "WARNING: In %s days will delete files in %s!" % (args.warndays, args.folder),
                            "Please see attached list of files!\n\n" \
                            "The files listed in the attached text file\n" \
                            "will be deleted in %s days when they will\n" \
                            "not have been touched for %s days:\n" \
                            "\n# of files: %s, total space: %s GB\n" \
                            "You can prevent deletion of these files\n" \
                            "by using the command 'touch -a filename'\n" \
                            "on each file. This will reset the access \n" \
                            "time of the file to the current date.\n" \
                            "\n" % (args.warndays, args.days, infodict[k][2], "{0:.3f}".format(infodict[k][3]/1073741824)), # TB: 838860 , GB: 1073741824
                            [file2send,])
                        print ('\nSent file delete warning to user %s' % user)
                        log.info('Sent delete warning for %s files (%s GB) to %s with filelist %s' % (infodict[k][2], "{0:.3f}".format(infodict[k][3]/1073741824), user, file2send))                    
                except:
                    e=sys.exc_info()[0]
                    sys.stderr.write("Error in send_mail while sending to '%s': %s\n" % (user, e))
                    log.error("Error in send_mail while sending to '%s': %s" % (user, e))
                    if args.email:
                        send_mail([args.email,], "Error - fs-cleaner",
                            "Please debug email notification to user '%s', Error: %s\n" % (user, e))
                    else:
                        sys.stderr.write('no option --email-notify given, cannot send error status via email\n')
                        
            else:
                fn=len(v)
                if fn>10:
                    fn=10
                print("\nDEBUG: ##### WARN ##########################################################")
                print("DEBUG: Will delete %s files (%s GB total) owned by '%s'" % (infodict[k][2], "{0:.3f}".format(infodict[k][3]/float(1073741824)), user))
                print("DEBUG: would send file '%s' to user '%s' !" % (file2send, user))
                print('DEBUG: List of files to delete (maximum 10 listed):')
                for i in range(fn):
                    print(v[i])

        else:
            print("Could not save file '%s'" % file2send)
        

    # ******************* process deletions with notification ********************************
    for k, v in filedict.items():
        user=uid2user(k)
        if not os.path.exists(tmpdir+'/'+curruser+'/fs-cleaner/'+user):
            os.mkdir(tmpdir+'/'+curruser+'/fs-cleaner/'+user)
        file2send=tmpdir+'/'+curruser+'/fs-cleaner/'+user+'/'+user+'-deleted-'+days_back_datestr+'.txt'
        if list2file(v,file2send):
            if not args.debug:
                try:
                    if not args.suppress_emails:
                        send_mail([user,], "NOTE: Deleted files in %s that were not accessed for %s days" % (args.folder, args.days),
                            "Please see attached list of files!\n\n" \
                            "The files listed in the attached text file\n" \
                            "were deleted because they were not accessed\n" \
                            "in the last %s days." \
                            "\n" % args.days, [file2send,])
                        print ('\nSent file delete notification to user %s' % user)
                        log.info('Sent delete note to %s with filelist %s' % (user, file2send))
                except:
                    e=sys.exc_info()[0]
                    sys.stderr.write("Error in send_mail while sending to '%s': %s\n" % (user, e))
                    log.error("Error in send_mail while sending to '%s': %s" % (user, e))
                    if args.email:
                        send_mail([args.email,], "Error - fs-cleaner",
                            "Please debug email notification to user '%s', Error: %s\n" % (user, e))
                    else:
                        sys.stderr.write('no option --email-notify given, cannot send error status via email\n')

            else:
                fn=len(v)
                if fn>10:
                    fn=10
                print("\nDEBUG: ##### DELETE ##########################################################")
                print("DEBUG: would have deleted %s files (%s GB total) owned by '%s'" % (infodict[k][0], "{0:.3f}".format(infodict[k][1]/float(1073741824)), user))
                print("DEBUG: would have sent file '%s' to user '%s' !" % (file2send, user))
                print('DEBUG: List of files that would have been deleted (maximum 10 listed):')
                for i in range(fn):
                    print(v[i])
        else:
            print("Could not save file '%s'" % file2send)

    # ******************* process archiving without notification ********************************
    
    for k, v in archdict.items():
        fldr = k
        if not os.path.exists(tmpdir+'/'+curruser+'/fs-cleaner/'+fldr):
            os.makedirs(tmpdir+'/'+curruser+'/fs-cleaner/'+fldr)
        file2send=tmpdir+'/'+curruser+'/fs-cleaner/'+fldr+'/'+'archived-'+days_back_datestr+'.txt'
        tenant=''
        if args.atenant:  # the first level below the source root represents a tenant that should go before  
            p=fldr.find('/')
            if p>=0:
                tenant=fldr[:p]
                fldr=fldr[p+1:]
            else:
                tenant=fldr
                fldr=''
        rsyncsrcroot = os.path.join(args.folder,tenant,fldr,'')
        if fldr == '':
            rsyncdestroot = os.path.join(args.aroot,tenant,args.aprefix,days_back_datestr)
        else:
            rsyncdestroot = os.path.join(args.aroot,tenant,args.aprefix,fldr+'-'+days_back_datestr)
        if args.debug:
            print('**************************************************************')
            print("DEBUG: rsyncsrcroot",rsyncsrcroot)
            print("DEBUG: rsyncdestroot",rsyncdestroot)
            print('**************************************************************')
        if pathlist2file(v,file2send,rsyncsrcroot):
            bwlimitstr = ''
            if args.bwlimit>0:
                bwlimitstr = '--bwlimit=%i ' % args.bwlimit
            rsync_cmd = '/usr/bin/rsync -av --inplace --remove-source-files --exclude=".archive-me" --exclude=".snapshot" %s--files-from="%s" "%s" "%s"' % (bwlimitstr,file2send,rsyncsrcroot,rsyncdestroot)
            if args.debug:
                print("DEBUG: would have archived files in '%s' to '%s' !" % (file2send, rsyncdestroot))
                print("DEBUG: would have run: '%s' !" % rsync_cmd)
            else:
                if os.path.exists(args.aroot):
                    if not os.path.exists(rsyncdestroot):
                        os.makedirs(rsyncdestroot)
                    print("executing: '%s' !" % rsync_cmd)
                    p = subprocess.Popen(rsync_cmd, shell=True).wait()
                    if p != 0: 
                        print(' **** Warning: Rsync resturned error code %i' % p)
                    else:
                        print('Archiving of folder %s complete !' % fldr)
                else:
                    print('folder %s does not exist. Please execute this manually: %s' % (args.aroot,rsync_cmd))
                    
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
            sys.stderr.write(str(e))            
    except:
        raise
    return statinfo

def setfiletime(path,attr="atime"):
    """ sets the a time of a file to the current time """
    try:
        statinfo=getstat(path)
        if attr=="atime" or attr=="all":
            os.utime(path,(time.time(),statinfo.st_atime))
        if attr=="mtime" or attr=="all":
            os.utime(path,(time.time(),statinfo.st_mtime))        
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
        sys.stderr.write('could not determine smtp mail host !\n')
        
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
        'and notify file owners. Optionally archive files to destination ' + \
        'archive-root/+archive-prefix1level/+archive-prefix2/project-yyyy-mm-dd')
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
    parser.add_argument( '--archive-root', '-r', dest='aroot',
        action='store', 
        help='the root folder of the destination archive file system',
        default='')
    parser.add_argument( '--archive-prefix', '-p', dest='aprefix',
        action='store', 
        help=' fixed string to be added to prefix the target archive project folder with this sub directory',
        default='')
    parser.add_argument( '--archive-tenant', '-t', dest='atenant', action='store_true',
        help='If true treat the first folder level below --folder as group or tenant. In that case the archive ' \
                         'target root directory will be aroot+tenant+aprefix ',
        default=False )
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
