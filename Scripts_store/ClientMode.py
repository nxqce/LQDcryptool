__author='''
S.S.B
surajsinghbisht054@gmail.com
https://hackworldwithssb.blogspot.if __name__ == '__main__':
'''
# Here Importing Module
import AES as AES
import StringIO
try:
        import Tkinter, ttk
except:
        import tkinter as Tkinter
        import tkinter.ttk as ttk
import Ask_IP,socket, threading


# Your Machine Trial Informations 
IP_Address = socket.gethostbyname(socket.gethostname())
PORT_="5000"

class SOCKETS:
        def __init__(self):
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print("[+] Socket Is Now Created")
                self.crypto = AES.AESCipher('mysecretpassword')
        def load(self, ip_address, port, text,status,server_info):
                self.ip_address=ip_address
                self.port=port
                self.history=text
                self.status=status
                self.server_info=server_info
                print("[=] LOading Attributes Is Completed")
                return
        def bind(self):
                print("[=] Trying To Binds")
                while True:
                        try:
                                self.s.connect((self.ip_address.get(), self.port.get()))
                                print("[+] Connection Server Found")
                                self.server_info.config(text="{}:{}".format(self.ip_address.get(), self.port.get()))
                                self.status.config(text="Connected", bg='lightgreen')
                                threading.Thread(target=self.recv).start()
                                break

                        except:
                                pass
        def recv(self):
                while  True:
                        try:
                                data = self.s.recv(1024)
                                data = self.crypto.decrypt(data)
                                textRecv = StringIO.StringIO(data)
                                prin = textRecv.read(4)
                                print prin
                                if prin == 'key:':
                                    newKey = textRecv.read()
                                    self.crypto = AES.AESCipher(newKey)
                                    print newKey
                                elif data:
                                        data='Other : '+data+'\n'
                                        start=self.history.index('end')+"-1l"
                                        self.history.insert("end", data)
                                        end=self.history.index('end')+"-1l"
                                        self.history.tag_add("SENDBYOTHER",start, end)
                                        self.history.tag_config("SENDBYOTHER", foreground='green')
                        except Exception as e:
                                print(e, 'recv')
                        

        def send(self, text):
                try:
                        text = self.crypto.encrypt(text)
                        self.s.sendall(text)
                except:
                        print("[=] Not Connected")
                        pass









class ClientMode(Tkinter.Tk):
        def __init__(self, *args, **kwargs):
                Tkinter.Tk.__init__(self, *args, **kwargs)
                self.resizable(0,0)
                self.ip_address=Tkinter.StringVar()
                self.ip_address.trace_variable("w", self.update_status_info)
                self.port=Tkinter.IntVar()
                self.create_additional_widgets()
                
        def socket_connections_start(self):
                if len(self.ip_address.get().split('.'))==4:
                        print("Thread Started")
                        threading.Thread(target=self.socket_connections).start()
        def socket_connections(self):
                        print("[+] creating")
                        self.s=SOCKETS()
                        print("[=] Loading Attributes")
                        self.s.load(self.ip_address, self.port, self.history, self.status, self.server_info)
                        print("[=] Bindings")
                        self.s.bind()

        def update_status(self, Connection='Connected', color='lightgreen'):
                self.status.config(text=Connection, bg=color)
                return
                
        def update_status_info(self, *args, **kwargs):
                data="{}:{}".format(self.ip_address.get(), self.port.get())
                self.server_info.config(text=data)
                return

        def create_additional_widgets(self):
                self.create_panel_for_widget()
                self.create_panel_for_connections_info()
                self.create_panel_for_chat_history()
                self.create_panel_for_sending_text()
                self.ask_ip_address()

        def ask_ip_address(self):
                Ask_IP.Ask_Ip(self.ip_address, self.port)
                return


        def send_text_message(self):
                if self.status.cget('text')=='Connected':
                        input_data=self.Sending_data.get('1.0','end')
                        if len(input_data)!=1:
                                self.s.send(input_data)
                                input_data='me: '+input_data
                                start=self.history.index('end')+"-1l"
                                self.history.insert("end", input_data)
                                end=self.history.index('end')+"-1l"
                                self.history.tag_add("SENDBYME",start, end)
                                self.Sending_data.delete('1.0','end')
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
                ttk.Label(self.frame, text='Your Entered Address   : '  , relief="groove", anchor='center', width=25).grid(row=1, column=1, ipadx=10, ipady=5)
                ttk.Label(self.frame, textvariable=self.ip_address          , relief='sunken', anchor='center', width=25).grid(row=1, column=2, ipadx=10, ipady=5)
                ttk.Label(self.frame, text='Your Entered Port Number  : ' , relief="groove", anchor='center', width=25).grid(row=2, column=1, ipadx=10, ipady=5)
                ttk.Label(self.frame, textvariable=self.port                  , relief="sunken", anchor="center", width=25).grid(row=2, column=2, ipadx=10, ipady=5)
                ttk.Label(self.frame, text='Status            : ', relief="groove", anchor="center", width=25).grid(row=3, column=1, ipadx=10, ipady=5)
                ttk.Label(self.frame, text='Connected with    : ', relief='groove', anchor='center', width=25).grid(row=4, column=1, ipadx=10, ipady=5)
                self.status=Tkinter.Button(self.frame, text="Not Connected", anchor='center', width=25, bg="red", command=self.socket_connections)
                self.status.grid(row=3, column=2, ipadx=10, ipady=5)
                self.server_info=Tkinter.Label(self.frame, text="{}:{}".format(self.ip_address.get(), self.port.get()), relief='sunken', anchor='center', width=25)
                self.server_info.grid(row=4, column=2, ipadx=10,ipady=5)
                return






if __name__=='__main__':
        ClientMode(className='Python Chatting [Client Mode]').mainloop()
