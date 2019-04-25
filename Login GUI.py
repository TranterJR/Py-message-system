from tkinter import *
import sqlite3, hashlib, uuid, random, itertools, time
import tkinter.messagebox as tm

def main_screen():
    global screen
    screen = Tk()
    screen.geometry("300x300")
    clearScreen()
    screen.title("Login into Tool")
    Label(text = "Login into Tool", bg = "grey",width = "300",height = "2", font = ("Calibri", 13)).pack()
    Label(text ="").pack()
    Button(text = "Login", height = "2", width = "30", command = login).pack()
    Label(text="").pack()
    Button(text = "Register", height = "2", width = "30", command=lambda: register()).pack()
    Label(text="").pack()
    Button(text="Wipe DB", height="2", width="30", command=serverWipe).pack()

    screen.mainloop()

def serverWipe():
    conn = sqlite3.connect("Database.db")
    c = conn.cursor()
    c.execute("DELETE FROM users")
    conn.commit()

def login():
    clearScreen()
    screen.title("Login")
    screen.geometry("300x300")
    Label(screen, text="Login", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()

    username = StringVar()
    password = StringVar()

    Label(screen, text="Username *").pack()
    Label(screen, text="").pack()
    Entry(screen, textvariable=username).pack()
    Label(screen, text="").pack()
    Label(screen, text="Password *").pack()
    Entry(screen, textvariable=password).pack()
    Label(screen, text="").pack()

    Button(screen, text="Login", height="2", width="30", command=lambda: loginuser(username, password)).pack()
    Label(screen, text="").pack()

def loginuser(u,p):
    global username_info
    # Convert username and password into strings
    username_info = u.get()
    password_info = p.get()

    # connect to database
    conn = sqlite3.connect("Database.db")
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?",(username_info,))
    # Verify login
    data = c.fetchall()
    for x in data:
        for i in x:
            salt = i[-32:]

    password_info = hashlib.sha256(salt.encode() + password_info.encode()).hexdigest() + ';' + salt
    conn.commit()
    print(data[0][0])
    print(password_info)
    if password_info == data[0][0]:
        print("success")

    navigation()

def register():

    clearScreen()
    screen.title("Register")
    screen.geometry("300x300")
    Label(screen,text="Register", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()

    username = StringVar()
    password = StringVar()

    Label(screen, text="Username *").pack()
    Label(screen, text="").pack()
    Entry(screen, textvariable=username).pack()
    Label(screen, text="").pack()
    Label(screen, text="Password *").pack()
    Entry(screen, textvariable=password).pack()
    Label(screen, text="").pack()

    Button(screen, text="Register", height="2", width="30", command=lambda: registeruser(username, password)).pack()
    Label(screen, text="").pack()

def registeruser(u,p):
    # Convert username and password into strings
    username_info = str(u.get())
    password_info = str(p.get())

    # connect to database
    conn = sqlite3.connect("Database.db")
    c = conn.cursor()
    # Check if username is taken
    c.execute("SELECT username FROM users")
    # print(c.fetchall())
    users = c.fetchall()
    v = True

    for user in users:
       if username_info == str(user[0]):
           tm.showerror("Registration error", "Username taken")
           v = False

    forbidChars = ["SELECT","DELETE","DROP","INSERT","TABLE","UPDATE","*","GRANT","REVOKE"]

    for char in forbidChars:
        if char in username_info or char in password_info or char.lower() in username_info or char.lower() in password_info:
            tm.showerror("Registration error","Invalid input")
            v = False

    if v:
        print("Valid")
        # Encrypt password before adding to table
        # Generate salt
        salt = uuid.uuid4().hex
        # Use hash funtion sha256 to encrypt password with salt
        password_info = hashlib.sha256(salt.encode() + password_info.encode()).hexdigest() + ';' + salt

        # Insert new user into database
        c.execute("INSERT INTO users(username, password) VALUES(?,?)",(username_info,password_info))
        conn.commit()

def navigation():

    clearScreen()
    screen.title("Login")
    screen.geometry("500x500")
    Label(screen, text="Navigation", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    Label(text="").pack()
    Button(text="Compose", height="2", width="30", command=lambda: compose()).pack()
    Label(text="").pack()
    Label(text="").pack()
    Button(text="View Messages", height="2", width="30", command=lambda: viewMessages()).pack()
    Label(text="").pack()
    Label(text="").pack()
    Button(text="Logout", height="2", width="30", command=lambda: logout()).pack()

def compose():

    clearScreen()
    screen.title("Login")
    screen.geometry("500x500")
    Label(screen, text="Compose", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    Button(text="Exit", height="2", width="20", command=lambda: navigation()).pack()
    Label(text="").pack()


    Target = StringVar()
    Message = StringVar()

    Label(screen, text="To:").pack()
    Entry(screen, textvariable=Target).pack()
    Label(screen, text="").pack()
    Label(screen, text="Message:").pack()
    Label(screen, text="").pack()


    # , textvariable=Message
    e = Entry(screen, textvariable=Message, width=50)
    e.pack()
    Label(screen, text="").pack()
    Label(screen, text="").pack()
    Label(screen, text="").pack()
    Button(text="Send", height="2", width="30", command=lambda: send(e)).pack()

def send(m):
    clearScreen()
    print(m.get())

def viewMessages():
    clearScreen()
    screen.title("Login")
    screen.geometry("500x500")
    Label(screen, text="Messages", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()

    """
    grid system shwoing messages ?? 
    text(screen, 
    
    fetch messages as List
    for message in messages:
        T.insert(END, str(message) + "\n"")
    
    """
    T = Text(screen, height=2, width=30)
    T.pack()
    T.insert(END, "Just a text Widget\nin two lines\n")
    Label(text="").pack()
    Button(text="Exit", height="2", width="20", command=lambda: navigation()).pack()
    Label(text="").pack()


def fetchMessages():
    conn = sqlite3.connect("Database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM messages WHERE username=?",(username_info,))
    messages = c.fetchall()

def logout():
    screen.destroy()
    main()

def clearScreen():
    for child in screen.winfo_children():
        child.destroy()

def loadDB():

    conn = sqlite3.connect("Database.db")
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM users")
        users = c.fetchall()
        print(users,"\n")
    except:

        c.execute('''CREATE TABLE users 
                        (ID INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)
                         
                  ''')
        conn.commit()

def main():
    loadDB()
    main_screen()

main()