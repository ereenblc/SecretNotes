from tkinter import *
from PIL import ImageTk, Image
import base64
from tkinter import messagebox

#window
window = Tk()
window.title("Secret Notes")
window.geometry("550x800")
FONT = ("Verdena", 12, "bold")

#top secret image
my_image = Image.open("image.png")
resize_my_image = my_image.resize((120, 120))
my_new_image = ImageTk.PhotoImage(resize_my_image)
my_label = Label(window, image=my_new_image)
my_label.pack(padx=20, pady=20)

#enter your title
enter_your_title = Label(text="Enter Your Title", font=FONT,  padx=20, pady=10)
enter_your_title.pack()

user_title = Entry(width=40)
user_title.pack()

#enter your secret
enter_your_secret = Label(text="Enter Your Secret", font=FONT, padx=20, pady=10)
enter_your_secret.pack()

user_secret = Text(width=50)
user_secret.pack()

#enter master key
enter_master_key = Label(text="Enter Master Key", font=FONT, padx=20, pady=10)
enter_master_key.pack()

user_master_key = Entry(width=40)
user_master_key.pack()


#encryption && decryption
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def encryption():
    master_key = user_master_key.get()
    message = user_secret.get("1.0", END)
    title = user_title.get()

    if len(title) == 0 or len(message) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="Missing Info", message="Please enter all info.")

    else:
        message_encrypted = encode(master_key, message)


        try:
            with open("mySecret.txt", "a") as data_file:
                    data_file.write(f"\n{title}\n{message_encrypted}")

        except FileNotFoundError:

            with open("mySecret.txt", "w") as data_file:
                    data_file.write(f"\n{title}\n{message_encrypted}")

        finally:
            user_title.delete(0, END)
            user_master_key.delete(0, END)
            user_secret.delete("1.0", END)


def decryption():
    message_encrypted = user_secret.get("1.0", END)
    master_secret_key = user_master_key.get()

    if len(message_encrypted) == 0 or len(master_secret_key) == 0:
        messagebox.showinfo(title="Missing Info", message="Please enter all info.")

    else:

        try:

            decrypted_message = decode(master_secret_key, message_encrypted)
            user_secret.delete("1.0", END)
            user_secret.insert("1.0", decrypted_message)

        except:
            messagebox.showinfo("Missing Info", message="Please enter encrypted text!")



#buttons
encrypt_button = Button(text="Save & Encrypt", font=("Verdena", 9, "bold"), command=encryption)
encrypt_button.pack()

decrypt_button = Button(text="Decrypt", font=("Verdena", 9, "bold"), command=decryption)
decrypt_button.pack()


window.mainloop()