from tkinter import *
import sqlite3, hashlib, uuid, itertools, datetime, random
import tkinter.messagebox as tm
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

def setScreen():
    global screen
    screen = Tk()

def main_screen():

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
    global USER_ID
    # Convert username and password into strings
    username_info = u.get()
    password_info = p.get()

    # connect to database
    conn = sqlite3.connect("Database.db")
    c = conn.cursor()
    c.execute("SELECT password, ID FROM users WHERE username=?",(username_info,))
    # Verify login
    data = c.fetchall()
    print(data)
    USER_ID = data[0][1]

    salt = data[0][0][-32:]
    print(salt)
    password_info = hashlib.sha256(salt.encode() + password_info.encode()).hexdigest() + ';' + salt
    conn.commit()
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
        clearScreen()
        main_screen()

def navigation():

    clearScreen()
    screen.title("Navigation")
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
    password = StringVar()

    Label(screen, text="To:").pack()
    Entry(screen, textvariable=Target).pack()
    Label(screen, text="").pack()
    Label(screen, text="Message:").pack()
    Label(screen, text="").pack()


    # , textvariable=Message
    e = Entry(screen, textvariable=Message, width=50)
    e.pack()
    Label(screen, text="").pack()
    Label(screen, text="Set password:").pack()
    Label(screen, text="").pack()
    e = Entry(screen, textvariable=password, width=50)
    e.pack()
    Label(screen, text="").pack()
    Label(screen, text="").pack()
    Label(screen, text="").pack()
    Button(text="Send", height="2", width="30", command=lambda: begin(getKey(password), e, Target)).pack()

def getKey(p):
    password = str(p.get())
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def begin(p,m,t):
    write2File(m)
    encrypt(p,"messages/temp.txt",t)

def write2File(m):
    m = m.get()
    with open("messages/temp.txt", "w") as temp:
        temp.write(m)

def wipeTemp():
    os.remove("messages/temp.txt")

def encrypt(key, filename, T):
    T = T.get()
    chunksize = 64*1024                                                                     #how many chunks to read from file
    outputFile = "messages/" + str(random.randint(0,10000)) + ".txt"                       #New fiilename
    filesize = str(os.path.getsize(filename)).zfill(16)                                      #calculates filesize
    IV = Random.new().read(16)                                                  #creates an initial vector for random ciphertext

    encryptor = AES.new(key, AES.MODE_CBC, IV)                  #choses AES chain block cipher mode

    with open(filename, 'rb') as infile:                        #opens file as binary
        with open(outputFile, 'wb') as outfile:                 #creates the outputfile as write binary
            outfile.write(filesize.encode('utf-8'))             #determines file size
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)                  #reads file chunk size

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))    #if chunk is not equal to mod 16 pad the chunk to 16

                outfile.write(encryptor.encrypt(chunk))         #writes encrypted file

    wipeTemp()
    uploadMessage(T,outputFile)

def uploadMessage(reciever, file): #Pass in the reciever and the content for the message, the timestamp and sender is preset

    date = str(datetime.datetime.utcnow())[0:19]
    c.execute('''INSERT INTO messages(receiver, sender, fileName, timestamp)
                   VALUES(:receiver,:sender, :fileName, :timestamp)''',
                   {'receiver':reciever, 'sender':USER_ID, 'fileName':file, 'timestamp':date})
    conn.commit()
    return

def viewMessages():
    clearScreen()
    screen.title("Messages")
    screen.geometry("500x500")
    Label(screen, text="Messages", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    T1 = Text(screen, height=2, width=30)
    T2 = Text(screen, height=2, width=30)
    T3 = Text(screen, height=2, width=30)
    T4 = Text(screen, height=2, width=30)
    T5 = Text(screen, height=2, width=30)

    # T.insert(END, "Just a text Widget\nin two lines\n")

    messages = fetchAll()

    a = [T1,T2,T3,T4,T5]
    b = -1
    for message in messages:
       b += 1

    b = [0,1,2,3]
    zipd = zip(a,b)
    if b != -1:
        for a,b in zipd:
            senderID = messages[b][2]
            sender = getUsername(senderID)
            a.insert(END, "Message from: " + str(sender) + "\n" + "Sent at: " + str(messages[b][4]))
            Button(text="Decrypt", height="1", width="20", command=lambda: getPass(messages[b][3])).pack()
            Label(text="").pack()
            a.pack()
    else:
        Label(text="").pack()
        Label(text="").pack()
        Label(text="NO MESSAGES").pack()
        Label(text="").pack()
        Label(text="").pack()


    Label(text="").pack()
    Button(text="Exit", height="2", width="20", command=lambda: navigation()).pack()
    Label(text="").pack()

def getPass(m):
    clearScreen()
    screen.title("Enter pass")
    screen.geometry("500x500")
    Label(screen, text="Password Entry", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    password = StringVar()
    Entry(screen, textvariable=password, width=50)
    Label(text="").pack()
    Button(text="Submit", height="2", width="20", command=lambda: pass).pack()
    Label(text="").pack()
    Button(text="Cancel", height="2", width="20", command=lambda: viewMessages()).pack()



def getUsername(ID):
    c.execute("SELECT username FROM users WHERE ID = '" + str(ID) + "'")
    user = c.fetchall()

    return user[0][0]

def fetchAll(): #Returns all messages based on the userid in use

    c.execute("SELECT * FROM messages WHERE receiver = '" + str(USER_ID) + "'")
    received = c.fetchall()

    return received

def fetchFrom(sender): #fetches messages only from given sender
    c.execute("SELECT * FROM messages WHERE receiver = '" + USER_ID + "' AND sender = '" + sender + "'")
    received = c.fetchall()

    return received

def decrypt(key, filename):
    chunksize = 64*1024
    outputFile = filename[11:]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)

def logout():
    screen.destroy()
    main()

def clearScreen():
    for child in screen.winfo_children():
        child.destroy()

def loadDB():
    global c, conn
    conn = sqlite3.connect("Database.db")
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM users")
        users = c.fetchall()
        print(users,"\n")
    except:

        c.execute('''CREATE TABLE users (ID INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT
                            )
                         
                  ''')
        c.execute('''CREATE TABLE messages (mess_id INTEGER PRIMARY KEY AUTOINCREMENT, receiver TEXT, sender TEXT, fileName TEXT, timestamp TEXT
                            )
                          ''')
        conn.commit()

def main():
    loadDB()
    setScreen()
    main_screen()

main()


def destroy(): # will delete all messages sent to the user
    c.execute("DELETE  FROM messages WHERE mess_id > 0")
    print("Messages Destroyed")
    conn.commit()
    return

# print(fetchAll()) #Call fetchAll to retrieve all messages sent to the user
# fetchFrom(x)# Call to show only messages received from user x
# destroy() # Call destroy to delete all messages sent to the user
# messageSend() # Call to send a message to another user, receiver must match the recipients username.

""""""