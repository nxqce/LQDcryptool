#!usr/bin/python
__author='''
S.S.B
surajsinghbisht054@gmail.com
https://hackworldwithssb.blogspot.if __name__ == '__main__':
'''
# Here Importing Module
import AES as AES
import datetime
import time
import os
try:
        import Tkinter, ttk
except:
        import tkinter as Tkinter
        import tkinter.ttk as ttk
# import Modules for Connections'
import socket,threading

# Your Machine Trial Informations 
IP_Address = socket.gethostbyname(socket.gethostname())
PORT_="5000"
# crypto = AES.AESCipher('mysecretpassword')

startTime = datetime.datetime.now()

# ========== Socket Programming ================
class SOCKETS:

        def __init__(self):
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.count = 0
                self.crypto = AES.AESCipher('mysecretpassword')
        
        def load(self, ip_address, port, text, status,client_info):
                self.ip_address=ip_address
                self.port=port
                self.history=text
                self.status=status
                self.client_info=client_info
                return

        def bind(self):
                while True:
                        try:
                                self.s.bind(('', self.port.get()))
                                break
                        except:
                                pass
                self.s.listen(1)
                self.conn, addr = self.s.accept()
                ip,port=addr
                self.status.config(text="Connected", bg='lightgreen')
                self.client_info.config(text="{}:{}".format(ip, self.port.get()))
                threading.Thread(target=self.recv).start()

        def send(self, text):
                try:
                        text = self.crypto.encrypt(text)
                        print text
                        self.conn.sendall(text)
                except Exception as e:
                        print("[=] Server Not Connected Yet ",e)
                        pass
                return

        def recv(self):
                print(" [+] recv start")
                while True:
                        try:
                                data = self.conn.recv(1024)
                                if data:
                                        data=self.crypto.decrypt(data)
                                        print data
                                        data='Other : '+data+'\n'
                                        start=self.history.index('end')+"-1l"
                                        self.history.insert("end", data)
                                        end=self.history.index('end')+"-1l"
                                        self.history.tag_add("SENDBYOTHER",start, end)
                                        self.history.tag_config("SENDBYOTHER", foreground='green')
                        except Exception as e:
                                print(e,"[=] Closing Connection [recv]")
                                self.conn.close()
                                break

        def create_key(self):
            self.count += 1
            print self.count
            duration = datetime.datetime.now() - startTime
            # if duration.seconds == 5:
            #     self.random_key = os.urandom(16)
            #     crypto = AES.AESCipher(self.random_key)
            #
            #     text = 'key:' + self.random_key
            #     self.s.send(text)
            #     print self.random_key
            while True:
                time.sleep(10)
                random_key = os.urandom(16)
                text = "key:" + random_key
                self.send(text)
                self.crypto = AES.AESCipher(random_key)
                print text

            return

        def send_key(self):
            threading.Thread(target=self.create_key()).start()

        def close(self):
                pass
                #=============================================


class ServerMode(Tkinter.Tk):
        def __init__(self, *args, **kwargs):
                Tkinter.Tk.__init__(self, *args, **kwargs)
                self.ip_address=Tkinter.StringVar()
                self.port=Tkinter.IntVar()
                self.port.set(PORT_)
                self.create_additional_panel()
                self.count = 0
                threading.Thread(target=self.socket_connections).start()

        def socket_connections(self):
                self.s=SOCKETS()
                self.s.load(self.ip_address, self.port, self.history, self.status, self.client_info)
                self.s.bind()
                self.s.send_key()

        def create_additional_panel(self):
                self.create_panel_for_widget()
                self.create_panel_for_connections_info()
                self.create_panel_for_chat_history()
                self.create_panel_for_sending_text()
                return


        def send_text_message(self):
                if self.status.cget('text')=='Connected':
                        print(self.status.cget('text'))
                        input_data=self.Sending_data.get('1.0','end')
                        if len(input_data)!=1:
                                input_data_='me: '+input_data+'\n'
                                start=self.history.index('end')+"-1l"
                                self.history.insert("end", input_data_)
                                end=self.history.index('end')+"-1l"
                                self.history.tag_add("SENDBYME",start, end)
                                self.Sending_data.delete('1.0','end')
                                self.s.send(input_data)
                                self.history.tag_config("SENDBYME", foreground='Blue')

                                pass
                        else:
                                print("[=] Input Not Provided")

                else:
                        print("[+] Not Connected")

        def create_panel_for_sending_text(self):
                # Here Creating Sending Panel
                self.Sending_data=Tkinter.Text(self.Sending_panel, font=('arial 12 italic'), width=35, height=5)
                self.Sending_data.pack(side='left')
                self.Sending_Trigger=Tkinter.Button(self.Sending_panel, text='Send', width=15, height=5, bg='orange',command=self.send_text_message ,activebackground='lightgreen')
                self.Sending_Trigger.pack(side='left')
                return


        def create_panel_for_chat_history(self):
                # Here Creating Chat History
                self.history=Tkinter.Text(self.history_frame, font=('arial 12 bold italic'), width=50, height=15)
                self.history.pack()
                return


        def create_panel_for_widget(self):
                # First For Connection Information
                self.Connection_info=Tkinter.LabelFrame(self, text='Connection Informations', fg='green', bg='powderblue')
                self.Connection_info.pack(side='top', expand='yes', fill='both')
                # Creating Second For Chatting History
                self.history_frame=Tkinter.LabelFrame(self, text='Chatting ', fg='green', bg='powderblue')
                self.history_frame.pack(side='top')
                # Creating Third For Sending Text Message
                self.Sending_panel=Tkinter.LabelFrame(self, text='Send Text', fg='green', bg='powderblue')
                self.Sending_panel.pack(side='top')
                return

        def create_panel_for_connections_info(self):
                self.frame=ttk.Frame(self.Connection_info)
                self.frame.pack(side='top', padx=10,pady=10)
                # Creating Main Information Panel
                ttk.Label(self.frame, text='Your IP Address   : '  , relief="groove", anchor='center', width=25).grid(row=1, column=1, ipadx=10, ipady=5)
                ttk.Label(self.frame, text=IP_Address             , relief='sunken', anchor='center', width=25).grid(row=1, column=2, ipadx=10, ipady=5)
                ttk.Label(self.frame, text='Using Port Number  : ' , relief="groove", anchor='center', width=25).grid(row=2, column=1, ipadx=10, ipady=5)
                ttk.Label(self.frame, text=PORT_                  , relief="sunken", anchor="center", width=25).grid(row=2, column=2, ipadx=10, ipady=5)
                ttk.Label(self.frame, text='Status            : ', relief="groove", anchor="center", width=25).grid(row=3, column=1, ipadx=10, ipady=5)
                ttk.Label(self.frame, text='Connected with    : ', relief='groove', anchor='center', width=25).grid(row=4, column=1, ipadx=10, ipady=5)
                self.status=Tkinter.Label(self.frame, text="Not Connected", relief="sunken", anchor='center', width=25, bg="red")
                self.status.grid(row=3, column=2, ipadx=10, ipady=5)
                self.client_info=Tkinter.Label(self.frame, text="192.168.00.12:5000", relief='sunken', anchor='center', width=25)
                self.client_info.grid(row=4, column=2, ipadx=10,ipady=5)
                return



if __name__=='__main__':
        ServerMode(className='Python Chatting [Server Mode]').mainloop()
        print 'acb'
