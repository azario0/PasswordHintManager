import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
from datetime import datetime

class PasswordHintManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Hint Manager")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        self.root.resizable(True, True)
        
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (900 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"900x700+{x}+{y}")
        
        self.db_path = "password_hints.db"
        self.master_key = None
        self.cipher_suite = None
        
        self.setup_styles()
        self.init_database()
        self.create_login_frame()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles for modern look
        style.configure('Title.TLabel', 
                       font=('Segoe UI', 24, 'bold'),
                       background='#2c3e50',
                       foreground='#ecf0f1')
        
        style.configure('Heading.TLabel',
                       font=('Segoe UI', 12, 'bold'),
                       background='#34495e',
                       foreground='#ecf0f1')
        
        style.configure('Modern.TLabel',
                       font=('Segoe UI', 8),
                       background='#34495e',
                       foreground='#ecf0f1')
        
        style.configure('Modern.TButton',
                       font=('Segoe UI', 8, 'bold'),
                       padding=5)
        
        style.configure('Accent.TButton',
                       font=('Segoe UI', 9, 'bold'),
                       padding=8)
        
        style.configure('Modern.TEntry',
                       font=('Segoe UI', 8),
                       padding=5)
        
        style.configure('Modern.TText',
                       font=('Segoe UI', 8),
                       padding=5)
        
        # Configure treeview
        style.configure('Modern.Treeview',
                       background='#ecf0f1',
                       foreground='#2c3e50',
                       font=('Segoe UI', 8),
                       rowheight=25)
        
        style.configure('Modern.Treeview.Heading',
                       font=('Segoe UI', 9, 'bold'),
                       background='#3498db',
                       foreground='white')
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT,
                hint TEXT NOT NULL,
                category TEXT,
                created_date TEXT,
                modified_date TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_login_frame(self):
        self.login_frame = tk.Frame(self.root, bg='#2c3e50')
        self.login_frame.pack(expand=True, fill='both')
        
        # Main container
        container = tk.Frame(self.login_frame, bg='#34495e', padx=40, pady=40)
        container.pack(expand=True)
        
        # Title
        title = ttk.Label(container, text="🔐 Password Hint Manager", style='Title.TLabel')
        title.pack(pady=(0, 30))
        
        # Subtitle
        subtitle = ttk.Label(container, text="Secure your password hints with encryption", 
                           font=('Segoe UI', 12), background='#34495e', foreground='#bdc3c7')
        subtitle.pack(pady=(0, 40))
        
        # Check if master password exists
        if self.check_master_password_exists():
            self.create_login_form(container)
        else:
            self.create_setup_form(container)
    
    def check_master_password_exists(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM master_password")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    
    def create_setup_form(self, container):
        setup_frame = tk.Frame(container, bg='#34495e')
        setup_frame.pack(pady=20)
        
        ttk.Label(setup_frame, text="Create Master Password", style='Heading.TLabel').pack(pady=(0, 20))
        
        ttk.Label(setup_frame, text="Master Password:", style='Modern.TLabel').pack(anchor='w', pady=(0, 5))
        self.setup_password_entry = ttk.Entry(setup_frame, show="*", width=30, style='Modern.TEntry')
        self.setup_password_entry.pack(pady=(0, 15))
        
        ttk.Label(setup_frame, text="Confirm Password:", style='Modern.TLabel').pack(anchor='w', pady=(0, 5))
        self.confirm_password_entry = ttk.Entry(setup_frame, show="*", width=30, style='Modern.TEntry')
        self.confirm_password_entry.pack(pady=(0, 20))
        
        ttk.Button(setup_frame, text="Create Account", command=self.setup_master_password, 
                  style='Accent.TButton').pack(pady=10)
    
    def create_login_form(self, container):
        login_frame = tk.Frame(container, bg='#34495e')
        login_frame.pack(pady=20)
        
        ttk.Label(login_frame, text="Enter Master Password", style='Heading.TLabel').pack(pady=(0, 20))
        
        ttk.Label(login_frame, text="Master Password:", style='Modern.TLabel').pack(anchor='w', pady=(0, 5))
        self.login_password_entry = ttk.Entry(login_frame, show="*", width=30, style='Modern.TEntry')
        self.login_password_entry.pack(pady=(0, 20))
        self.login_password_entry.bind('<Return>', lambda e: self.verify_master_password())
        
        button_frame = tk.Frame(login_frame, bg='#34495e')
        button_frame.pack()
        
        ttk.Button(button_frame, text="Login", command=self.verify_master_password, 
                  style='Accent.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Reset Password", command=self.reset_master_password, 
                  style='Modern.TButton').pack(side='left')
    
    def setup_master_password(self):
        password = self.setup_password_entry.get()
        confirm = self.confirm_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long")
            return
        
        # Generate salt and hash
        salt = os.urandom(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO master_password (id, password_hash, salt) VALUES (1, ?, ?)",
                      (base64.b64encode(password_hash).decode(), base64.b64encode(salt).decode()))
        conn.commit()
        conn.close()
        
        self.master_key = password
        self.setup_encryption()
        messagebox.showinfo("Success", "Master password created successfully!")
        self.show_main_interface()
    
    def verify_master_password(self):
        password = self.login_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter your master password")
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
        result = cursor.fetchone()
        conn.close()
        
        if result:
            stored_hash = base64.b64decode(result[0])
            salt = base64.b64decode(result[1])
            
            # Verify password
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            
            if password_hash == stored_hash:
                self.master_key = password
                self.setup_encryption()
                self.show_main_interface()
            else:
                messagebox.showerror("Error", "Incorrect master password")
        else:
            messagebox.showerror("Error", "No master password found")
    
    def reset_master_password(self):
        if messagebox.askyesno("Warning", "This will delete all stored hints. Continue?"):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM master_password")
            cursor.execute("DELETE FROM hints")
            conn.commit()
            conn.close()
            
            messagebox.showinfo("Reset Complete", "All data has been cleared. Please create a new master password.")
            self.login_frame.destroy()
            self.create_login_frame()
    
    def setup_encryption(self):
        # Create encryption key from master password
        password_bytes = self.master_key.encode()
        salt = b'stable_salt_for_consistency'  # In production, use random salt per user
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        self.cipher_suite = Fernet(key)
    
    def show_main_interface(self):
        self.login_frame.destroy()
        
        # Create main frame
        self.main_frame = tk.Frame(self.root, bg='#2c3e50')
        self.main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(self.main_frame, bg='#34495e', height=80)
        header_frame.pack(fill='x', pady=(0, 20))
        header_frame.pack_propagate(False)
        
        ttk.Label(header_frame, text="🔐 Password Hint Manager", style='Title.TLabel').pack(side='left', padx=20, pady=20)
        ttk.Button(header_frame, text="Logout", command=self.logout, style='Modern.TButton').pack(side='right', padx=20, pady=20)
        
        # Main content area
        content_frame = tk.Frame(self.main_frame, bg='#2c3e50')
        content_frame.pack(fill='both', expand=True)
        
        # Left panel - Add/Edit hints
        left_panel = tk.Frame(content_frame, bg='#34495e', width=350)
        left_panel.pack(side='left', fill='y', padx=(0, 10), pady=0)
        left_panel.pack_propagate(False)
        
        self.create_input_panel(left_panel)
        
        # Right panel - Hints list
        right_panel = tk.Frame(content_frame, bg='#34495e')
        right_panel.pack(side='right', fill='both', expand=True)
        
        self.create_hints_panel(right_panel)
        
        # Load existing hints
        self.refresh_hints_list()
    
    def create_input_panel(self, parent):
        # Title
        ttk.Label(parent, text="Add New Hint", style='Heading.TLabel').pack(pady=20, padx=20)
        
        form_frame = tk.Frame(parent, bg='#34495e')
        form_frame.pack(fill='x', padx=20)
        
        # Service
        ttk.Label(form_frame, text="Service/Website:", style='Modern.TLabel').pack(anchor='w', pady=(0, 5))
        self.service_entry = ttk.Entry(form_frame, width=40, style='Modern.TEntry')
        self.service_entry.pack(fill='x', pady=(0, 15))
        
        # Username
        ttk.Label(form_frame, text="Username/Email:", style='Modern.TLabel').pack(anchor='w', pady=(0, 5))
        self.username_entry = ttk.Entry(form_frame, width=40, style='Modern.TEntry')
        self.username_entry.pack(fill='x', pady=(0, 15))
        
        # Category
        ttk.Label(form_frame, text="Category:", style='Modern.TLabel').pack(anchor='w', pady=(0, 5))
        self.category_var = tk.StringVar()
        category_combo = ttk.Combobox(form_frame, textvariable=self.category_var, 
                                     values=['Work', 'Personal', 'Social Media', 'Banking', 'Shopping', 'Other'],
                                     state='readonly')
        category_combo.pack(fill='x', pady=(0, 15))
        category_combo.set('Personal')
        
        # Hint
        ttk.Label(form_frame, text="Password Hint:", style='Modern.TLabel').pack(anchor='w', pady=(0, 5))
        self.hint_text = tk.Text(form_frame, height=3, width=40, font=('Segoe UI', 8), 
                                bg='white', fg='#2c3e50', relief='flat', padx=6, pady=6)
        self.hint_text.pack(fill='x', pady=(0, 15))
        
        # Buttons
        button_frame = tk.Frame(form_frame, bg='#34495e')
        button_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Button(button_frame, text="Add Hint", command=self.add_hint, 
                  style='Accent.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Update", command=self.update_hint, 
                  style='Modern.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Clear", command=self.clear_form, 
                  style='Modern.TButton').pack(side='left')
        
        # Initialize update button state
        self.update_button_state()
        
    def create_hints_panel(self, parent):
        # Title and search
        header_frame = tk.Frame(parent, bg='#34495e')
        header_frame.pack(fill='x', pady=20, padx=20)
        
        ttk.Label(header_frame, text="Stored Hints", style='Heading.TLabel').pack(side='left')
        
        search_frame = tk.Frame(header_frame, bg='#34495e')
        search_frame.pack(side='right')
        
        ttk.Label(search_frame, text="Search:", style='Modern.TLabel').pack(side='left', padx=(0, 5))
        self.search_entry = ttk.Entry(search_frame, width=20, style='Modern.TEntry')
        self.search_entry.pack(side='left')
        self.search_entry.bind('<KeyRelease>', self.search_hints)
        
        # Treeview frame
        tree_frame = tk.Frame(parent, bg='#34495e')
        tree_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Create treeview
        columns = ('Service', 'Username', 'Category', 'Date')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', style='Modern.Treeview')
        
        # Define headings
        self.tree.heading('Service', text='Service/Website')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Category', text='Category')
        self.tree.heading('Date', text='Created')
        
        # Configure column widths
        self.tree.column('Service', width=200)
        self.tree.column('Username', width=150)
        self.tree.column('Category', width=100)
        self.tree.column('Date', width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Bind events
        self.tree.bind('<Double-1>', self.load_hint_for_editing)
        self.tree.bind('<Button-3>', self.show_context_menu)
        
        # Bottom buttons
        button_frame = tk.Frame(parent, bg='#34495e')
        button_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        ttk.Button(button_frame, text="View Hint", command=self.view_hint, 
                  style='Modern.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Delete", command=self.delete_hint, 
                  style='Modern.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Export", command=self.export_hints, 
                  style='Modern.TButton').pack(side='right')
        
        # Store current editing ID
        self.editing_id = None
    
    def add_hint(self):
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        category = self.category_var.get()
        hint = self.hint_text.get('1.0', 'end-1c').strip()
        
        if not service or not hint:
            messagebox.showerror("Error", "Service and hint are required fields")
            return
        
        # Encrypt the hint
        encrypted_hint = self.cipher_suite.encrypt(hint.encode()).decode()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            INSERT INTO hints (service, username, hint, category, created_date, modified_date)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (service, username, encrypted_hint, category, current_time, current_time))
        
        conn.commit()
        conn.close()
        
        messagebox.showinfo("Success", "Hint added successfully!")
        self.clear_form()
        self.refresh_hints_list()
    
    def update_hint(self):
        if not self.editing_id:
            messagebox.showerror("Error", "No hint selected for editing")
            return
        
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        category = self.category_var.get()
        hint = self.hint_text.get('1.0', 'end-1c').strip()
        
        if not service or not hint:
            messagebox.showerror("Error", "Service and hint are required fields")
            return
        
        # Encrypt the hint
        encrypted_hint = self.cipher_suite.encrypt(hint.encode()).decode()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            UPDATE hints SET service=?, username=?, hint=?, category=?, modified_date=?
            WHERE id=?
        ''', (service, username, encrypted_hint, category, current_time, self.editing_id))
        
        conn.commit()
        conn.close()
        
        messagebox.showinfo("Success", "Hint updated successfully!")
        self.clear_form()
        self.refresh_hints_list()
    
    def clear_form(self):
        self.service_entry.delete(0, 'end')
        self.username_entry.delete(0, 'end')
        self.category_var.set('Personal')
        self.hint_text.delete('1.0', 'end')
        self.editing_id = None
        self.update_button_state()
    
    def update_button_state(self):
        # This would update button states based on whether we're editing
        pass
    
    def refresh_hints_list(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, service, username, category, created_date FROM hints ORDER BY created_date DESC")
        
        for row in cursor.fetchall():
            hint_id, service, username, category, created_date = row
            # Format date
            try:
                date_obj = datetime.strptime(created_date, '%Y-%m-%d %H:%M:%S')
                formatted_date = date_obj.strftime('%m/%d/%Y')
            except:
                formatted_date = created_date
            
            self.tree.insert('', 'end', values=(service, username or '', category, formatted_date), tags=(hint_id,))
        
        conn.close()
    
    def search_hints(self, event=None):
        search_term = self.search_entry.get().lower()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if search_term:
            cursor.execute('''
                SELECT id, service, username, category, created_date 
                FROM hints 
                WHERE LOWER(service) LIKE ? OR LOWER(username) LIKE ? OR LOWER(category) LIKE ?
                ORDER BY created_date DESC
            ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        else:
            cursor.execute("SELECT id, service, username, category, created_date FROM hints ORDER BY created_date DESC")
        
        for row in cursor.fetchall():
            hint_id, service, username, category, created_date = row
            try:
                date_obj = datetime.strptime(created_date, '%Y-%m-%d %H:%M:%S')
                formatted_date = date_obj.strftime('%m/%d/%Y')
            except:
                formatted_date = created_date
            
            self.tree.insert('', 'end', values=(service, username or '', category, formatted_date), tags=(hint_id,))
        
        conn.close()
    
    def load_hint_for_editing(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        hint_id = item['tags'][0]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT service, username, hint, category FROM hints WHERE id = ?", (hint_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            service, username, encrypted_hint, category = result
            
            # Decrypt hint
            try:
                decrypted_hint = self.cipher_suite.decrypt(encrypted_hint.encode()).decode()
            except:
                messagebox.showerror("Error", "Failed to decrypt hint")
                return
            
            # Populate form
            self.clear_form()
            self.service_entry.insert(0, service)
            self.username_entry.insert(0, username or '')
            self.category_var.set(category)
            self.hint_text.insert('1.0', decrypted_hint)
            
            self.editing_id = hint_id
    
    def view_hint(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a hint to view")
            return
        
        item = self.tree.item(selection[0])
        hint_id = item['tags'][0]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT service, username, hint, category FROM hints WHERE id = ?", (hint_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            service, username, encrypted_hint, category = result
            
            # Decrypt hint
            try:
                decrypted_hint = self.cipher_suite.decrypt(encrypted_hint.encode()).decode()
            except:
                messagebox.showerror("Error", "Failed to decrypt hint")
                return
            
            # Show hint in a popup
            popup = tk.Toplevel(self.root)
            popup.title(f"Hint for {service}")
            popup.geometry("400x300")
            popup.configure(bg='#34495e')
            popup.resizable(False, False)
            
            # Center popup
            popup.update_idletasks()
            x = (popup.winfo_screenwidth() // 2) - (400 // 2)
            y = (popup.winfo_screenheight() // 2) - (300 // 2)
            popup.geometry(f"400x300+{x}+{y}")
            
            frame = tk.Frame(popup, bg='#34495e', padx=20, pady=20)
            frame.pack(fill='both', expand=True)
            
            ttk.Label(frame, text=f"Service: {service}", style='Heading.TLabel').pack(anchor='w', pady=(0, 5))
            ttk.Label(frame, text=f"Username: {username or 'N/A'}", style='Modern.TLabel').pack(anchor='w', pady=(0, 5))
            ttk.Label(frame, text=f"Category: {category}", style='Modern.TLabel').pack(anchor='w', pady=(0, 15))
            
            ttk.Label(frame, text="Password Hint:", style='Heading.TLabel').pack(anchor='w', pady=(0, 5))
            
            hint_display = tk.Text(frame, height=6, width=40, font=('Segoe UI', 11), 
                                 bg='#ecf0f1', fg='#2c3e50', relief='flat', padx=10, pady=10)
            hint_display.pack(fill='both', expand=True, pady=(0, 15))
            hint_display.insert('1.0', decrypted_hint)
            hint_display.config(state='disabled')
            
            ttk.Button(frame, text="Close", command=popup.destroy, style='Modern.TButton').pack()
    
    def delete_hint(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a hint to delete")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this hint?"):
            item = self.tree.item(selection[0])
            hint_id = item['tags'][0]
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM hints WHERE id = ?", (hint_id,))
            conn.commit()
            conn.close()
            
            messagebox.showinfo("Success", "Hint deleted successfully!")
            self.refresh_hints_list()
    
    def show_context_menu(self, event):
        # Right-click context menu could be added here
        pass
    
    def export_hints(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT service, username, hint, category, created_date FROM hints")
            
            export_data = []
            for row in cursor.fetchall():
                service, username, encrypted_hint, category, created_date = row
                try:
                    decrypted_hint = self.cipher_suite.decrypt(encrypted_hint.encode()).decode()
                    export_data.append({
                        'service': service,
                        'username': username,
                        'hint': decrypted_hint,
                        'category': category,
                        'created_date': created_date
                    })
                except:
                    continue  # Skip corrupted entries
            
            conn.close()
            
            # Save to file
            filename = f"password_hints_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Export Complete", f"Hints exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export hints: {str(e)}")
    
    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.main_frame.destroy()
            self.master_key = None
            self.cipher_suite = None
            self.create_login_frame()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    # Check if required libraries are installed
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("Please install the cryptography library:")
        print("pip install cryptography")
        exit(1)
    
    app = PasswordHintManager()
    app.run()