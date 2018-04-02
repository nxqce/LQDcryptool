
import os
from Tkinter import *
import ttk
import tkFileDialog
from PIL import Image, ImageTk

import  cryptf

import time
import threading

class HashTool(Frame):
    def browse(self, et):
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
        self.lbFile1.grid(row=0, column=1, sticky=W)

        self.etFile1 = Entry(self, width=50)
        self.etFile1.grid(row=0, column=2, sticky=W+E, padx=5)

        self.btFile1 = Button(self, text="Browse..", width=10, command=lambda: self.browse("file1"))
        self.btFile1.grid(row=0, column=3)

        #Browse key file
        self.lbFile2 = Label(self, text="File 2:", bg='black', fg='white')
        self.lbFile2.grid(row=1, column=1, sticky=W)

        self.etFile2 = Entry(self, width=50)
        self.etFile2.grid(row=1, column=2, sticky=W+E, padx=5)

        self.btFile2 = Button(self, text="Browse..", width=10, command=lambda: self.browse("file2"))
        self.btFile2.grid(row=1, column=3)

        #MD5 Hash
        self.lbFile1Hash = Label(self, text="File 1 MD5 Hash:", bg='black', fg='white')
        self.lbFile1Hash.grid(row=2, column=1, sticky=W)

        self.etFile1Hash = Entry(self, width=50)
        self.etFile1Hash.grid(row=2, column=2, sticky=W+E, padx=5)

        self.lbFile2Hash = Label(self, text="File 2 MD5 Hash:", bg='black', fg='white')
        self.lbFile2Hash.grid(row=3, column=1, sticky=W)

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
    def browse(self, et):
        # print ("Browse window")
        self.progress["value"] = 0
        self.lbStatus.config(text="Idle")
        file_path = tkFileDialog.askopenfilename()
        # print (file_path)
        if (et == "file"):
            self.etFile.delete(0, END)
            self.etFile.insert(0, file_path)
        elif (et == "key"):
            self.etKey.delete(0, END)
            self.etKey.insert(0, file_path)

    def start(self):
        with open(self.etKey.get(),'rb') as keyFile:
            key = keyFile.read()
       
        print (key)

        print("Opening file")
        fileName = self.etFile.get()
        self.lbStatus.config(text="Opening files...")
        with open(fileName, 'rb') as fileIn:
            l = len(fileIn.read())
        print(l)
        
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
            if self.cbAlgorithm.current() == 0:
                self.interval = 17000000
                c = threading.Thread(target=cryptf.AES_encrypt_file, args=(key, fileName))
            elif self.cbAlgorithm.current() == 1:
                self.interval = 200000
                c = threading.Thread(target=cryptf.DES3_encrypt_file, args=(key, fileName))
            else:
                self.interval = 7800
                c = threading.Thread(target= cryptf.encrypt_blob, args=(key, fileName))
            c.start()
        else:
            self.lbStatus.config(text="Decrypting...")
            newFileName = fileName.split('.')[0] + "_decrypted." + fileName.split('.')[1]
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

    def read_bytes(self):
        # print(".")
        self.bytes += self.interval
        self.progress["value"] = self.bytes
        if (self.bytes < self.maxbytes):
            self.after(100, self.read_bytes)

    def startThread(self):
        t = threading.Thread(target=self.start, args=())
        t.start()

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
        self.lbBackground.grid(row=0, rowspan=5, column=0, columnspan=5)

        #Quit
        self.QUIT = Button(self, text="Quit", command=self.quit)
        self.QUIT.grid(row=2, rowspan=2, column=4)
        
        #Browse file to de/en-crypt
        self.lbFile = Label(self, text="File:", bg='black', fg='white')
        self.lbFile.grid(row=0, column=1, sticky=W)

        self.etFile = Entry(self, width=50)
        self.etFile.grid(row=0, column=2, columnspan=2, sticky=W+E, padx=5)

        self.btFile = Button(self, text="Browse..", width=10, command=lambda: self.browse("file"))
        self.btFile.grid(row=0, column=4)

        #Browse key file
        self.lbKey = Label(self, text="Key:", bg='black', fg='white')
        self.lbKey.grid(row=1, column=1, sticky=W)

        self.etKey = Entry(self, width=50)
        self.etKey.grid(row=1, column=2, columnspan=2, sticky=W+E, padx=5)

        self.btKey = Button(self, text="Browse..", width=10, command=lambda: self.browse("key"))
        self.btKey.grid(row=1, column=4)

        #Algorithm
        self.lbAlgorithm = Label(self, text="Algorithm:", bg='black', fg='white')
        self.lbAlgorithm.grid(row=2, column=1, sticky=W)

        self.cbAlgorithm = ttk.Combobox(self, state="readonly", width=25)
        algorithm = ("AES", "DES", "RSA")
        self.cbAlgorithm["value"] = algorithm
        self.cbAlgorithm.set("AES")
        self.cbAlgorithm.grid(row=2, column=2, sticky=W, padx=5, pady=5)

        #Encrypt/Decrypt
        self.lbEnDeCrypt = Label(self, text="Encrypt/Decrypt:", bg='black', fg='white')
        self.lbEnDeCrypt.grid(row=3, column=1, sticky=W)

        self.cbEnDeCrypt = ttk.Combobox(self, state="readonly", width=25)
        enDeCrypt = ("Encrypt", "Decrypt")
        self.cbEnDeCrypt["value"] = enDeCrypt
        self.cbEnDeCrypt.set("Encrypt")
        self.cbEnDeCrypt.grid(row=3, column=2, sticky=W, padx=5, pady=5)

        #Start button
        self.btStart = Button(self, text="Start", width=10, command= lambda: self.startThread())
        self.btStart.grid(row=2, rowspan=2, column=3, sticky=W)

        #Progress bar
        self.lbProgress = Label(self, text="Progress:", bg='black', fg='white')
        self.lbProgress.grid(row=4, column=1, sticky=W)

        self.progress = ttk.Progressbar(self, orient="horizontal", length=100, mode="determinate")
        self.progress.grid(row=4, column=2, columnspan=2, sticky=W+E, padx=5, pady=5)

        self.strVarStatus = StringVar()
        self.lbStatus = Label(self, text="Idle", bg='black', fg='white')
        self.lbStatus.grid(row=4, column=4, sticky=W)

        #Hash tool
        # self.bthHashTool = Button(self, text="Hash Tool", width=10, command=lambda: self.hashTool())
        # self.bthHashTool.grid(row=2, rowspan=2, column=4)



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

#Add tab
note.add(appTab, text='En/De-crypt')
note.add(hashTab, text='MD5 Hash')

#Run app and keep app alive
root.mainloop()

#Quit app and destroy root
root.destroy()


