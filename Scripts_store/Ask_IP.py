#!usr/bin/python

__author='''
S.S.B
surajsinghbisht054@gmail.com
https://hackworldwithssb.blogspot.if __name__ == '__main__':
'''
# Here Importing Module
try:
        import Tkinter, ttk
except:
        import tkinter as Tkinter
        import tkinter.ttk as ttk

PORT_="5000"
text='''
Server IP Address  : 
		Enter Ip Address Of Server You Want To Connect.
Server PORT Number : 
		Enter PORT Number Of Connection You want to use:
		5000 is default port. if you want to change then change
		from configurations settings.		
'''
def Ask_Ip(var, var1):
	mainroot=Tkinter.Toplevel()
	mainroot.title("Enter Ip Address")
	mainroot.resizable(0,0)
	mainroot.focus_force()
	mainroot.transient()
	root=ttk.Frame(mainroot)
	root.pack(padx=10, pady=10)
	#var=Tkinter.StringVar()
	#var1=Tkinter.IntVar()
	var1.set(PORT_)
	ttk.Label(root, text='Server IP Address  : ', width=25).grid(row=1, column=1)
	ttk.Label(root, text='Server PORT Number : ', width=25).grid(row=2, column=1)
	k=ttk.Entry(root, textvariable=var, width=25)
	k.grid(row=1, column=2)
	k.focus_force()
	Tkinter.Entry(root, text=var1,state='disabled', width=25).grid(row=2, column=2)
	Label=Tkinter.Text(root, width=70, height=4, font=('arial 8 italic'))
	Label.insert('1.0',text,'end')
	Label.grid(row=3, column=1, columnspan=2, rowspan=4)
	Label.config(state='disabled') 
	ttk.Button(root, text="Next", command=lambda: mainroot.destroy(), width=25).grid(row=8, column=2)
	mainroot.mainloop()

if __name__=='__main__':
	Ask_Ip()
