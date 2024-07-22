import tkinter as tk
from tkinter import messagebox, Listbox, Scrollbar, Canvas
from PIL import Image, ImageTk
import sqlite3
import hashlib
import random
import string
import pyperclip

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# Хэширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Функция для проверки пароля
def check_password(stored_password, provided_password):
    return stored_password == hash_password(provided_password)

# Генератор паролей
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Индикатор силы пароля
def password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    strength = sum([has_upper, has_lower, has_digit, has_special])
    if length >= 12 and strength == 4:
        return "Strong"
    elif length >= 8 and strength >= 3:
        return "Medium"
    else:
        return "Weak"

class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Password Manager")
        self.geometry("320x700")
        self.resizable(False, False)
        self.center_window()

        self.username = None

        self.frames = {}
        for F in (LoginFrame, RegisterFrame, MainFrame):
            page_name = F.__name__
            frame = F(parent=self, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginFrame")

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry('{}x{}+{}+{}'.format(320, 700, x, y))

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

    def set_username(self, username):
        self.username = username

class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.grid_columnconfigure(0, weight=1)
        self.canvas = Canvas(self, width=320, height=700)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.bg_image = ImageTk.PhotoImage(Image.open("background.jpg"))
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.bg_image)

        self.username_label = tk.Label(self, text="Username:")
        self.username_label.place(relx=0.5, rely=0.2, anchor="center")
        self.username_entry = tk.Entry(self, width=25)
        self.username_entry.place(relx=0.5, rely=0.25, anchor="center")

        self.password_label = tk.Label(self, text="Password:")
        self.password_label.place(relx=0.5, rely=0.35, anchor="center")
        self.password_entry = tk.Entry(self, show='*', width=25)
        self.password_entry.place(relx=0.5, rely=0.4, anchor="center")

        self.login_button = tk.Button(self, text="Login", command=self.attempt_login, width=25)
        self.login_button.place(relx=0.5, rely=0.5, anchor="center")
        self.register_button = tk.Button(self, text="Register", command=lambda: controller.show_frame("RegisterFrame"), width=25)
        self.register_button.place(relx=0.5, rely=0.55, anchor="center")

    def attempt_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()

        if result and check_password(result[0], password):
            messagebox.showinfo("Login Successful", "Welcome, " + username + "!")
            self.controller.set_username(username)
            self.controller.show_frame("MainFrame")
        else:
            messagebox.showerror("Login Failed", "Incorrect username or password.")

        conn.close()

class RegisterFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.grid_columnconfigure(0, weight=1)
        self.canvas = Canvas(self, width=320, height=700)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.bg_image = ImageTk.PhotoImage(Image.open("background.jpg"))
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.bg_image)

        self.username_label = tk.Label(self, text="Username:")
        self.username_label.place(relx=0.5, rely=0.2, anchor="center")
        self.username_entry = tk.Entry(self, width=25)
        self.username_entry.place(relx=0.5, rely=0.25, anchor="center")

        self.password_label = tk.Label(self, text="Password:")
        self.password_label.place(relx=0.5, rely=0.35, anchor="center")
        self.password_entry = tk.Entry(self, show='*', width=25)
        self.password_entry.place(relx=0.5, rely=0.4, anchor="center")

        self.register_button = tk.Button(self, text="Register", command=self.attempt_register, width=25)
        self.register_button.place(relx=0.5, rely=0.5, anchor="center")
        self.back_to_login_button = tk.Button(self, text="Back to Login", command=lambda: controller.show_frame("LoginFrame"), width=25)
        self.back_to_login_button.place(relx=0.5, rely=0.55, anchor="center")

    def attempt_register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()

        if result:
            messagebox.showerror("Error", "Username already exists!")
        else:
            password_hash = hash_password(password)
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            messagebox.showinfo("Success", "User registered successfully!")
            self.controller.show_frame("LoginFrame")

        conn.close()


class MainFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.grid_columnconfigure(0, weight=1)

        tk.Label(self, text="Website:").grid(row=0, column=0, pady=5, sticky='ew')
        self.website_entry = tk.Entry(self, width=25)
        self.website_entry.grid(row=1, column=0, pady=5, sticky='ew')
        self.website_entry.insert(0, "Enter website")  # Placeholder text
        self.website_entry.bind("<FocusIn>", self.clear_placeholder)
        self.website_entry.bind("<FocusOut>", self.add_placeholder)

        tk.Label(self, text="Username:").grid(row=2, column=0, pady=5, sticky='ew')
        self.site_username_entry = tk.Entry(self, width=25)
        self.site_username_entry.grid(row=3, column=0, pady=5, sticky='ew')
        self.site_username_entry.insert(0, "Enter username")  # Placeholder text
        self.site_username_entry.bind("<FocusIn>", self.clear_placeholder)
        self.site_username_entry.bind("<FocusOut>", self.add_placeholder)

        tk.Label(self, text="Password:").grid(row=4, column=0, pady=5, sticky='ew')
        self.site_password_entry = tk.Entry(self, show='*', width=25)
        self.site_password_entry.grid(row=5, column=0, pady=5, sticky='ew')
        self.site_password_entry.insert(0, "Enter password")  # Placeholder text
        self.site_password_entry.bind("<FocusIn>", self.clear_placeholder)
        self.site_password_entry.bind("<FocusOut>", self.add_placeholder)

        self.show_password_var = tk.BooleanVar()
        self.show_password_check = tk.Checkbutton(self, text="Show password", variable=self.show_password_var, command=self.toggle_password)
        self.show_password_check.grid(row=6, column=0, pady=5, sticky='w')

        self.password_strength_label = tk.Label(self, text="Strength: Not checked")
        self.password_strength_label.grid(row=7, column=0, pady=5, sticky='w')

        tk.Button(self, text="Save Password", command=self.save_password, width=25).grid(row=8, column=0, pady=10, sticky='ew')

        tk.Button(self, text="Generate Password", command=self.generate_and_set_password, width=25).grid(row=9, column=0, pady=5, sticky='ew')

        tk.Button(self, text="Copy Password", command=self.copy_password, width=25).grid(row=10, column=0, pady=5, sticky='ew')

        self.search_entry = tk.Entry(self, width=25)
        self.search_entry.grid(row=11, column=0, pady=5, sticky='ew')
        self.search_entry.bind('<KeyRelease>', self.filter_passwords)

        self.passwords_listbox = Listbox(self, width=30, height=10)
        self.passwords_listbox.grid(row=12, column=0, pady=10, sticky='ew')
        self.passwords_listbox.bind('<<ListboxSelect>>', self.show_password_details)

        tk.Button(self, text="Delete Selected", command=self.delete_password, width=25).grid(row=13, column=0, pady=5, sticky='ew')
        tk.Button(self, text="Delete User", command=self.delete_user, width=25).grid(row=14, column=0, pady=5, sticky='ew')

        tk.Button(self, text="Logout", command=self.logout, width=25).grid(row=15, column=0, pady=5, sticky='ew')

        self.load_passwords()

    def clear_placeholder(self, event):
        widget = event.widget
        if widget.get() in ["Enter website", "Enter username", "Enter password"]:
            widget.delete(0, tk.END)
            widget.config(fg='black')

    def add_placeholder(self, event):
        widget = event.widget
        if widget.get() == "":
            placeholder_text = {
                self.website_entry: "Enter website",
                self.site_username_entry: "Enter username",
                self.site_password_entry: "Enter password"
            }.get(widget)
            widget.insert(0, placeholder_text)
            widget.config(fg='gray')

    def clear_entries(self):
        self.website_entry.delete(0, tk.END)
        self.site_username_entry.delete(0, tk.END)
        self.site_password_entry.delete(0, tk.END)
        self.add_placeholder_for_widget(self.website_entry)
        self.add_placeholder_for_widget(self.site_username_entry)
        self.add_placeholder_for_widget(self.site_password_entry)

    def add_placeholder_for_widget(self, widget):
        if widget.get() == "":
            placeholder_text = {
                self.website_entry: "Enter website",
                self.site_username_entry: "Enter username",
                self.site_password_entry: "Enter password"
            }.get(widget)
            widget.insert(0, placeholder_text)
            widget.config(fg='gray')

    def toggle_password(self):
        if self.show_password_var.get():
            self.site_password_entry.config(show='')
        else:
            self.site_password_entry.config(show='*')

    def save_password(self):
        website = self.website_entry.get()
        site_username = self.site_username_entry.get()
        password = self.site_password_entry.get()

        # Проверка на пустые поля
        if not website or website == "Enter website":
            messagebox.showwarning("Warning", "Website field cannot be empty.")
            return
        if not site_username or site_username == "Enter username":
            messagebox.showwarning("Warning", "Username field cannot be empty.")
            return
        if not password or password == "Enter password":
            messagebox.showwarning("Warning", "Password field cannot be empty.")
            return

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (self.controller.username,))
        user_id = cursor.fetchone()[0]

        cursor.execute('INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)',
                       (user_id, website, site_username, password))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Password saved successfully!")
        self.clear_entries()
        self.load_passwords()

    def load_passwords(self):
        self.passwords_listbox.delete(0, tk.END)

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('SELECT website FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?)',
                       (self.controller.username,))
        passwords = cursor.fetchall()

        for password in passwords:
            self.passwords_listbox.insert(tk.END, password[0])

        conn.close()

    def show_password_details(self, event):
        if not self.passwords_listbox.curselection():
            return

        selected_website = self.passwords_listbox.get(self.passwords_listbox.curselection())

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute(
            'SELECT username, password FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?) AND website = ?',
            (self.controller.username, selected_website))
        result = cursor.fetchone()

        if result:
            messagebox.showinfo("Details", f"Website: {selected_website}\nUsername: {result[0]}\nPassword: {result[1]}")

        conn.close()

    def delete_password(self):
        if not self.passwords_listbox.curselection():
            messagebox.showwarning("Warning", "Please select a password to delete.")
            return

        selected_website = self.passwords_listbox.get(self.passwords_listbox.curselection())

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?) AND website = ?',
            (self.controller.username, selected_website))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Password deleted successfully!")
        self.load_passwords()

    def delete_user(self):
        result = messagebox.askyesno("Confirm", "Are you sure you want to delete the user and all associated data?")
        if not result:
            return

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username = ?', (self.controller.username,))
        cursor.execute('DELETE FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?)',
                       (self.controller.username,))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "User and all associated data deleted successfully!")
        self.controller.show_frame("LoginFrame")

    def generate_and_set_password(self):
        password = generate_password()
        self.site_password_entry.delete(0, tk.END)
        self.site_password_entry.insert(0, password)
        self.update_password_strength_label(password)

    def copy_password(self):
        password = self.site_password_entry.get()
        if password:
            self.clipboard_clear()  # Очищаем буфер обмена
            self.clipboard_append(password)  # Копируем пароль в буфер обмена
            self.update_idletasks()  # Обновляем все события
            messagebox.showinfo("Success", "Password copied to clipboard!")

    def filter_passwords(self, event):
        search_term = self.search_entry.get().lower()
        self.passwords_listbox.delete(0, tk.END)

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('SELECT website FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?)',
                       (self.controller.username,))
        passwords = cursor.fetchall()

        for password in passwords:
            if search_term in password[0].lower():
                self.passwords_listbox.insert(tk.END, password[0])

        conn.close()

    def update_password_strength_label(self, password):
        strength = password_strength(password)
        self.password_strength_label.config(text=f"Strength: {strength}")

    def logout(self):
        self.controller.show_frame("LoginFrame")
        self.controller.set_username(None)

if __name__ == '__main__':
    init_db()
    app = PasswordManagerApp()
    app.mainloop()
