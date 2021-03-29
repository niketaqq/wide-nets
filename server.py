#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pyftpdlib
import hashlib
import logging
import os
from hashlib import md5

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import FTPServer


# In[2]:


class MyHandler(FTPHandler):
    
    def on_connect(self):
        print ("connected, host = ", self.remote_ip,", port = ", self.remote_port)
        
    def on_disconnect(self):
        print("disconnected, host = ", self.remote_ip,", port = ", self.remote_port)
    
    def on_login(self, username):
        print(username, ' was succsessfuly logged in')
    
    def on_logout(self, username):
        print(username, ' was succsessfuly logged out')

    def on_file_sent(self, file):
        print('file succsessfuly sent')
    
    def on_file_received(self, file):
        print('file sucsessfuly received')
        pass
    
    def on_incomplete_file_sent(self, file):
        print('file unsuccsessfuly sent')

    def on_incomplete_file_received(self, file):
        print('file unsuccsessfuly received')
        os.remove(file)
        
    def pre_process_command(self, line, cmd, arg):
        kwargs = {}
        if cmd == "SITE" and arg:
            cmd = "SITE %s" % arg.split(' ')[0].upper()
            arg = line[len(cmd) + 1:]
        if cmd != 'PASS':
            self.logline("<- %s" % line)
        else:
            self.logline("<- %s %s" % (line.split(' ')[0], '*' * 6))
        if not cmd in self.proto_cmds:
            if cmd[-4:] in ('ABOR', 'STAT', 'QUIT'):
                cmd = cmd[-4:]
            else:
                msg = 'Command "%s" not understood.' % cmd
                self.respond('500 ' + msg)
                if cmd:
                    self.log_cmd(cmd, arg, 500, msg)
                return
        if not arg and self.proto_cmds[cmd]['arg'] == True:
            msg = "Syntax error: command needs an argument."
            self.respond("501 " + msg)
            self.log_cmd(cmd, "", 501, msg)
            return
        if arg and self.proto_cmds[cmd]['arg'] == False:
            msg = "Syntax error: command does not accept arguments."
            self.respond("501 " + msg)
            self.log_cmd(cmd, arg, 501, msg)
            return
        if not self.authenticated:
            if self.proto_cmds[cmd]['auth'] or (cmd == 'STAT' and arg):
                msg = "Log in with USER and PASS first."
                self.respond("530 " + msg)
                self.log_cmd(cmd, arg, 530, msg)
            else:
                self.process_command(cmd, arg)
                return
        else:
            if (cmd == 'STAT') and not arg:
                self.ftp_STAT(u(''))
                return
            if self.proto_cmds[cmd]['perm'] and (cmd != 'STOU'):
                if cmd in ('CWD', 'XCWD'):
                    arg = self.fs.ftp2fs(arg or u('/'))
                elif cmd in ('CDUP', 'XCUP'):
                    arg = self.fs.ftp2fs(u('..'))
                elif cmd == 'LIST':
                    if arg.lower() in ('-a', '-l', '-al', '-la'):
                        arg = self.fs.ftp2fs(self.fs.cwd)
                    else:
                        arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'STAT':
                    if glob.has_magic(arg):
                        msg = 'Globbing not supported.'
                        self.respond('550 ' + msg)
                        self.log_cmd(cmd, arg, 550, msg)
                        return
                    arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'SITE CHMOD':
                    if not ' ' in arg:
                        msg = "Syntax error: command needs two arguments."
                        self.respond("501 " + msg)
                        self.log_cmd(cmd, "", 501, msg)
                        return
                    else:
                        mode, arg = arg.split(' ', 1)
                        arg = self.fs.ftp2fs(arg)
                        kwargs = dict(mode=mode)
                else:  
                    arg = self.fs.ftp2fs(arg or self.fs.cwd)
                if not self.fs.validpath(arg):
                    line = self.fs.fs2ftp(arg)
                    msg = '"%s" points to a path which is outside '                           "the user's root directory" % line
                    self.respond("550 %s." % msg)
                    self.log_cmd(cmd, arg, 550, msg)
                    return
            perm = self.proto_cmds[cmd]['perm']
            if perm is not None and cmd != 'STOU':
                if not self.authorizer.has_perm(self.username, perm, arg):
                    print(self.username, "no permission to", cmd)
                    msg = "Not enough privileges."
                    self.respond("550 " + msg)
                    self.log_cmd(cmd, arg, 550, msg)
                    return
                else:
                    print(self.username, "has permission to", cmd)
            self.process_command(cmd, arg, **kwargs)
            
        def handle_error(self):
            try:
                self.log_exception(self)
            except Exception:
                logger.critical(traceback.format_exc())


# In[3]:


class MyAuthorizer(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        if username == 'anonymous':
            return
        if not username in self.user_table:
            print('No such user')
            raise AuthenticationFailed("Authentication failed, no such user")
        if self.user_table[username]['pwd'] != password:
            print('Authentication failed, wrong password')
            raise AuthenticationFailed("Wrong password")


# In[ ]:


if __name__ == '__main__':
    authorizer = MyAuthorizer()
    
    authorizer.add_user('admin', '12345', os.getcwd(), perm='elradfmwMT')
    authorizer.add_user('reader', '54321', os.getcwd(), perm='elr')
    authorizer.add_anonymous(os.getcwd(), perm = 'el')
    
    handler = MyHandler
    handler.authorizer = authorizer
    handler.banner = "pyftpdlib based ftpd ready."    
    
    localhost = '127.0.0.1'
    port = 21
    address = (localhost, port)
    server = FTPServer(address, handler)
    print("server is active, host = ", localhost, "port = ", port)
    server.serve_forever()


# In[ ]:





# In[ ]:




