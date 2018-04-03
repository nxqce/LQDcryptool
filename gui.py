
import os
from Tkinter import *
import ttk
import tkFileDialog
from PIL import Image, ImageTk

import  cryptf

import time
import threading

from Scripts_store import Ask_Mode as ask, ServerMode as server, ClientMode as client

# class testApp(ttk.Frame):
def startApp():
    storeobj = ask.Ask_Mode_Option()
    if storeobj == 0:
        client.ClientMode(className='Python Chatting [Client Mode]').mainloop()
    elif storeobj == 1:
        server.ServerMode(className='Python Chatting [Server Mode]').mainloop()
        pass
    else:
        pass

class HashTool(Frame):
    def fileBrowse(self, et):
        # print ("Browse window")
        file_path = tkFileDialog.askopenfilename()
        # print (file_path)
        if (et == "file1"):
            self.etFile1.delete(0, END)
            self.etFile1.insert(0, file_path)

            self.etFile1Hash.delete(0, END)

        elif (et == "file2"):
            self.etFile2.delete(0, END)
            self.etFile2.insert(0, file_path)

            self.etFile2Hash.delete(0, END)

        self.lbHashCompare.config(text="")


    def md5Hash(self):
        self.etFile1Hash.delete(0, END)
        self.etFile2Hash.delete(0, END)

        hash1 = cryptf.MD5_hash(self.etFile1.get())
        hash2 = cryptf.MD5_hash(self.etFile2.get())

        self.etFile1Hash.insert(0, hash1)
        self.etFile2Hash.insert(0, hash2)

        if(hash1 == hash2):
            self.lbHashCompare.config(text="File 1 MD5 hash is equal to file 2 MD5 hash")
        else:
            self.lbHashCompare.config(text="File 1 MD5 hash is different from file 2 MD5 hash!")


    def createWidgets(self):
        #Photo background
        self.panel = Label(self)
        self.panel.grid(row=0, rowspan=5, column=0, padx=50)
        self.image = Image.open("bg.gif")
        self.photo = ImageTk.PhotoImage(self.image)
        self.label = Label(self, image=self.photo)
        # self.label.image = self.photo # keep a reference!
        self.label.grid(row=0, rowspan=5, column=0, columnspan=4)
        
        #Quit
        self.QUIT = Button(self, text="Quit", command=self.quit)
        self.QUIT.grid(row=4, column=3)
        
        #Browse file to de/en-crypt
        self.lbFile1 = Label(self, text="File 1:", bg='black', fg='white')
        self.lbFile1.grid(row=0, column=1, sticky=E)

        self.etFile1 = Entry(self, width=50)
        self.etFile1.grid(row=0, column=2, sticky=W+E, padx=5)

        self.btFile1 = Button(self, text="Browse..", width=10, command=lambda: self.fileBrowse("file1"))
        self.btFile1.grid(row=0, column=3)

        #Browse key file
        self.lbFile2 = Label(self, text="File 2:", bg='black', fg='white')
        self.lbFile2.grid(row=1, column=1, sticky=E)

        self.etFile2 = Entry(self, width=50)
        self.etFile2.grid(row=1, column=2, sticky=W+E, padx=5)

        self.btFile2 = Button(self, text="Browse..", width=10, command=lambda: self.fileBrowse("file2"))
        self.btFile2.grid(row=1, column=3)

        #MD5 Hash
        self.lbFile1Hash = Label(self, text="File 1 MD5 Hash:", bg='black', fg='white')
        self.lbFile1Hash.grid(row=2, column=1, sticky=E)

        self.etFile1Hash = Entry(self, width=50)
        self.etFile1Hash.grid(row=2, column=2, sticky=W+E, padx=5)

        self.lbFile2Hash = Label(self, text="File 2 MD5 Hash:", bg='black', fg='white')
        self.lbFile2Hash.grid(row=3, column=1, sticky=E)

        self.etFile2Hash = Entry(self, width=50)
        self.etFile2Hash.grid(row=3, column=2, sticky=W+E, padx=5)

        #Hash Button
        self.btHash = Button(self, text="Hash", width=10, command=lambda: self.md5Hash())
        self.btHash.grid(row=2, rowspan=2, column=3)

        #Hash compare
        self.lbHashCompare = Label(self, text="", bg='black', fg='white')
        self.lbHashCompare.grid(row=4, column=1, columnspan=3)

    def __init__(self, master=None):
        Frame.__init__(self, master)
        # master.minsize(width=500,height=150)
        master.pack()
        # self.winfo_toplevel().title("MD5 Compare - LDQ Cryptool")
        self.createWidgets()

class Application(Frame):
    def fileBrowse(self, et):
        # print ("Browse window")
        self.progress["value"] = 0
        self.lbStatus.config(text="Idle")
        filePath = tkFileDialog.askopenfilename()
        dirPath = os.path.split(filePath)[0]
        if (et == "file"):
            self.etFileDir.delete(0, END)
            self.etFileDir.insert(0, filePath)

            self.etSaveDir.delete(0, END)
            self.etSaveDir.insert(0, dirPath)
        elif (et == "key"):
            self.etKey.delete(0, END)
            self.etKey.insert(0, filePath)

    def dirBrowse(self, et):
        self.progress["value"] = 0
        self.lbStatus.config(text="Idle")
        
        dirPath = tkFileDialog.askdirectory()

        if (et == "dir"):
            self.etFileDir.delete(0, END)
            self.etFileDir.insert(0, dirPath)

            self.etSaveDir.delete(0, END)
            self.etSaveDir.insert(0, dirPath)
        elif (et == "save"):
            self.etSaveDir.delete(0, END)
            self.etSaveDir.insert(0, dirPath)

    def fileStart(self):
        self.timeExecute = 0
        self.bytes = 0
        self.maxbytes = 100
        t = threading.Thread(target=self.timer, args=())
        t.start()

        with open(self.etKey.get(),'rb') as keyFile:
            key = keyFile.read()
        
        if self.cbAlgorithm.current() == 0 and len(key) != 16 and len(key) != 24 and len(key) != 32:
		    print 'sai key 0'
		    tkMessageBox.showerror('Error', 'The key for this algorithm is 16 or 24 or 32 bytes long')
	    elif self.cbAlgorithm.current() == 2 and len(key) != 16 and len(key) != 24 and len(key) != 32:
		    print 'sai key 2'   
		    tkMessageBox.showerror('Error', 'The key for this algorithm is 16 or 24 or 32 bytes long')   
        
        print (key)

        print("Opening file")
        fileName = self.etFileDir.get()
        self.lbStatus.config(text="Opening files...")
        with open(fileName, 'rb') as fileIn:
            l = len(fileIn.read())
        print(l)

        saveDir = self.etSaveDir.get()
        
        self.progress["value"] = 0
        self.bytes = 0
        self.interval = 100
        self.maxbytes = l
        self.progress["maximum"] = self.maxbytes
        
        print("En/De-crypting")
        p = threading.Thread(target=self.read_bytes, args=())
        p.start()
        if self.cbEnDeCrypt.current() == 0:
            self.lbStatus.config(text="Encrypting...")
            newFileName = saveDir + '/' + os.path.split(fileName)[1] + '.ldq'
            if self.cbAlgorithm.current() == 0:
                self.interval = 10000000
                c = threading.Thread(target=cryptf.AES_encrypt_file, args=(key, fileName, newFileName))
            elif self.cbAlgorithm.current() == 1:
                self.interval = 200000
                c = threading.Thread(target=cryptf.DES3_encrypt_file, args=(key, fileName, newFileName))
            else:
                self.interval = 7800
                c = threading.Thread(target= cryptf.encrypt_blob, args=(key, fileName, newFileName))
            c.start()
        else:
            self.lbStatus.config(text="Decrypting...")
            #newFileName = fileName.split('.')[0] + "_decrypted." + fileName.split('.')[1]
            newFileName = saveDir + '/' + os.path.split(fileName)[1].split('.')[0] + fileName.split('.')[1]
            if self.cbAlgorithm.current() == 0:
                self.interval = 15000000
                c = threading.Thread(target=cryptf.AES_decrypt_file, args=(key, fileName, newFileName))
            elif self.cbAlgorithm.current() == 1:
                self.interval = 100000
                c = threading.Thread(target=cryptf.DES3_decrypt_file, args=(key, fileName, newFileName))
            else:
                self.interval = 300
                c = threading.Thread(target=cryptf.decrypt_blob, args=(key, fileName, newFileName))
            c.start()
        
        c.join()
        self.bytes = self.maxbytes
        self.progress["value"] = self.progress["maximum"]
        if self.cbEnDeCrypt.current():
            self.lbStatus.config(text="Decrypted!")
        else:
            self.lbStatus.config(text="Encrypted!")
        print("Completed")

    def dirStart(self):
        self.timeExecute = 0
        self.progress["value"] = 0
        self.bytes = 0
        self.maxbytes = 100
        t = threading.Thread(target=self.timer, args=())
        t.start()

        with open(self.etKey.get(),'rb') as keyFile:
            key = keyFile.read()
        
        if self.cbAlgorithm.current() == 0 and len(key) != 16 and len(key) != 24 and len(key) != 32:
		    print 'sai key 0'
		    tkMessageBox.showerror('Error', 'The key for this algorithm is 16 or 24 or 32 bytes long')
	    elif self.cbAlgorithm.current() == 2 and len(key) != 16 and len(key) != 24 and len(key) != 32:
		    print 'sai key 2'   
		    tkMessageBox.showerror('Error', 'The key for this algorithm is 16 or 24 or 32 bytes long')   
        
        print (key)

        print("Scanning files...")
        dirName = self.etFileDir.get()
        files = []
        self.lbStatus.config(text="Scanning files...")
        files = [dirName + '/' + f for f in os.listdir(dirName) if not os.path.isdir(dirName + '/' + f)]
        
        self.bytes = 0
        self.interval = 1
        self.maxbytes = len(files)
        self.progress["maximum"] = self.maxbytes
        
        print("En/De-crypting")
        # p = threading.Thread(target=self.read_bytes, args=())
        # p.start()
        for fileName in files:
            if self.cbEnDeCrypt.current() == 0:
                self.lbStatus.config(text="Encrypting... " + str(self.progress['value']) + '/' + str(self.progress['maximum']))
                if self.cbAlgorithm.current() == 0:
                    # self.interval = 10000000
                    c = threading.Thread(target=cryptf.AES_encrypt_file, args=(key, fileName))
                elif self.cbAlgorithm.current() == 1:
                    # self.interval = 200000
                    c = threading.Thread(target=cryptf.DES3_encrypt_file, args=(key, fileName))
                else:
                    # self.interval = 7800
                    c = threading.Thread(target= cryptf.encrypt_blob, args=(key, fileName))
                c.start()
            else:
                self.lbStatus.config(text="Decrypting... " + str(self.progress['value']) + '/' + str(self.progress['maximum']))
                newFileName = fileName.split('.')[0] + "_decrypted." + fileName.split('.')[1]
                if self.cbAlgorithm.current() == 0:
                    # self.interval = 15000000
                    c = threading.Thread(target=cryptf.AES_decrypt_file, args=(key, fileName, newFileName))
                elif self.cbAlgorithm.current() == 1:
                    # self.interval = 100000
                    c = threading.Thread(target=cryptf.DES3_decrypt_file, args=(key, fileName, newFileName))
                else:
                    # self.interval = 300
                    c = threading.Thread(target=cryptf.decrypt_blob, args=(key, fileName, newFileName))
                c.start()
            c.join()
            self.progress["value"] += 1
        
        self.bytes = self.maxbytes
        self.progress["value"] = self.progress["maximum"]
        if self.cbEnDeCrypt.current():
            self.lbStatus.config(text="Decrypted!")
        else:
            self.lbStatus.config(text="Encrypted!")
        print("Completed")

    def read_bytes(self):
        # print(".")
        self.bytes += self.interval
        self.progress["value"] = self.bytes
        if (self.bytes < self.maxbytes):
            self.after(100, self.read_bytes)

    def timer(self):
        self.timeExecute += 1
        minute = self.timeExecute / 60
        second = self.timeExecute % 60
        timeDisplay = str(minute / 10) + str(minute % 10) + ":" + str(second / 10) + str(second % 10)
        self.lbTime.config(text="Time: " + timeDisplay)
        if (self.bytes < self.maxbytes):
            self.after(1000, self.timer)

    def startThread(self):
        if (self.intVarFileDir.get() == 0):
            t = threading.Thread(target=self.fileStart, args=())
        elif (self.intVarFileDir.get() == 1):
            t = threading.Thread(target=self.dirStart, args=())
        t.start()

    def selFileDir(self):
        selection = self.intVarFileDir.get()
        if (selection == 0):
            self.lbFileDir.config(text="File:")
            self.btDir.grid_forget()
            self.btFile.grid(row=1, column=4)
        elif (selection == 1):
            self.lbFileDir.config(text="Folder:")
            self.btFile.grid_forget()
            self.btDir.grid(row=1, column=4)

    # def hashTool(self):
    #     self.root = Tk()
    #     # img = Image("photo", file="ico.gif") 
    #     # self.root.call('wm','iconphoto',self.root._w,img)
        
    #     self.root.lift()
    #     self.root.lift()
    #     hashToolWindow = HashTool(self.root)
    #     hashToolWindow.mainloop()
    #     self.root.destroy()

    def createWidgets(self):
        #Photo background
        self.panel = Label(self,bg='black')
        self.panel.grid(row=0, rowspan=5, column=0, padx=50)
        self.imgFile= Image.open('bg.gif')
        self.imgBackground = ImageTk.PhotoImage(self.imgFile)
        self.lbBackground = Label(self, image=self.imgBackground)
        self.lbBackground.grid(row=0, rowspan=7, column=0, columnspan=5)

        #Quit
        self.QUIT = Button(self, text="Quit", command=self.quit)
        self.QUIT.grid(row=4, rowspan=2, column=4)

        #File or directory
        self.intVarFileDir = IntVar()
        self.intVarFileDir.set(0)
        self.rbtFile = Radiobutton(self, text="File", variable=self.intVarFileDir, value=0, bg='black', fg='white', selectcolor='black', command=lambda: self.selFileDir())
        self.rbtFile.select()
        self.rbtFile.grid(row=0, column=2)
        self.rbtDir = Radiobutton(self, text="Folder", variable=self.intVarFileDir, value=1, bg='black', fg='white', selectcolor='black', command=lambda: self.selFileDir())
        self.rbtDir.grid(row=0, column=3)
        
        #Browse file to de/en-crypt
        self.lbFileDir = Label(self, text="File:", bg='black', fg='white')
        self.lbFileDir.grid(row=1, column=1, sticky=E)

        self.etFileDir = Entry(self, width=50)
        self.etFileDir.grid(row=1, column=2, columnspan=2, sticky=W+E, padx=5)

        self.btFile = Button(self, text="Browse..", width=10, command=lambda: self.fileBrowse("file"))
        self.btFile.grid(row=1, column=4)

        #Browse directory to de/en-crypt
        self.btDir = Button(self, text="Browse..", width=10, command=lambda: self.dirBrowse("dir"))
        # self.btDir.grid(row=1, column=4)

        #Save to directory
        self.lbSaveDir = Label(self, text="Save to folder:", bg='black', fg='white')
        self.lbSaveDir.grid(row=2, column=1, sticky=E)

        self.etSaveDir = Entry(self, width=50)
        self.etSaveDir.grid(row=2, column=2, columnspan=2, sticky=W+E, padx=5)

        self.btSaveDir = Button(self, text="Browse..", width=10, command=lambda: self.dirBrowse("save"))
        self.btSaveDir.grid(row=2, column=4)

        #Browse key file
        self.lbKey = Label(self, text="Key:", bg='black', fg='white')
        self.lbKey.grid(row=3, column=1, sticky=E)

        self.etKey = Entry(self, width=50)
        self.etKey.grid(row=3, column=2, columnspan=2, sticky=W+E, padx=5)

        self.btKey = Button(self, text="Browse..", width=10, command=lambda: self.fileBrowse("key"))
        self.btKey.grid(row=3, column=4)
        

        #Algorithm
        self.lbAlgorithm = Label(self, text="Algorithm:", bg='black', fg='white')
        self.lbAlgorithm.grid(row=4, column=1, sticky=E)

        self.cbAlgorithm = ttk.Combobox(self, state="readonly", width=25)
        algorithm = ("AES", "DES", "RSA")
        self.cbAlgorithm["value"] = algorithm
        self.cbAlgorithm.set("AES")
        self.cbAlgorithm.grid(row=4, column=2, sticky=W, padx=5, pady=5)

        #Encrypt/Decrypt
        self.lbEnDeCrypt = Label(self, text="Encrypt/Decrypt:", bg='black', fg='white')
        self.lbEnDeCrypt.grid(row=5, column=1, sticky=E)

        self.cbEnDeCrypt = ttk.Combobox(self, state="readonly", width=25)
        enDeCrypt = ("Encrypt", "Decrypt")
        self.cbEnDeCrypt["value"] = enDeCrypt
        self.cbEnDeCrypt.set("Encrypt")
        self.cbEnDeCrypt.grid(row=5, column=2, sticky=W, padx=5, pady=5)

        #Start button
        self.btStart = Button(self, text="Start", width=10, command= lambda: self.startThread())
        self.btStart.grid(row=4, rowspan=2, column=3, sticky=W)

        #Progress bar
        self.lbProgress = Label(self, text="Progress:", bg='black', fg='white')
        self.lbProgress.grid(row=6, column=1, sticky=E)

        self.progress = ttk.Progressbar(self, orient="horizontal", length=100, mode="determinate")
        self.progress.grid(row=6, column=2, sticky=W+E, padx=5, pady=5)

        self.strVarStatus = StringVar()
        self.lbStatus = Label(self, text="Idle", bg='black', fg='white')
        self.lbStatus.grid(row=6, column=3, sticky=W)

        self.strVarTime = StringVar()
        self.lbTime = Label(self, text="Time: 00:00", bg='black', fg='white')
        self.lbTime.grid(row=6, column=4, sticky=W)

        #Hash tool
        # self.bthHashTool = Button(self, text="Hash Tool", width=10, command=lambda: self.hashTool())
        # self.bthHashTool.grid(row=3, rowspan=2, column=4)



    def __init__(self, master=None):
        Frame.__init__(self, master)
       
        master.pack()
        master.winfo_toplevel().title("LDQ Cryptool")
        self.createWidgets()

        self.bytes = 0
        self.maxbytes = 0

### Start program
# Create the top level root
root = Tk()

# Set favicon
imgFile = Image.open("ico.gif")
img = ImageTk.PhotoImage(imgFile)
root.call('wm', 'iconphoto', root._w, img)

#Set window size
root.minsize(width=710,height=230)
root.resizable(width=False, height=False)

# Create tab
note = ttk.Notebook(root)
appTab = Application(note)
hashTab = HashTool(note)
chatTab = Frame(note)

#Add tab
note.add(appTab, text='En/De-crypt')
note.add(hashTab, text='MD5 Hash')
note.add(chatTab, text='Chat tool')

#Chat tab widget
imageFile = Image.open("bg.gif")
imageBg = ImageTk.PhotoImage(imageFile)
lbBg = Label(chatTab, image=imageBg)
lbBg.grid(row=0, column=0)
btStartChatApp = Button(chatTab, text='Start Chat App', command=lambda: startApp())
btStartChatApp.grid(row=0, column=0)

#Run app and keep app alive
root.mainloop()

#Quit app and destroy root
root.destroy()
