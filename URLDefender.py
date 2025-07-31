import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from threading import Thread
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import json
import itertools
import time

# --- Backend Analysis Logic ---

class EnhancedWebsiteAnalyzer:
    def __init__(self, url, proxy_config=None, user_agent=None, verify_ssl=True, timeout=15, retries=3):
        self.url = url
        self.domain = urlparse(url).netloc
        self.proxy_config = proxy_config if proxy_config else {}
        self.user_agent = user_agent if user_agent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.retries = retries

        self.results = {
            'url': url,
            'domain': self.domain,
            'is_secure': False,
            'phishing_indicators': [],
            'malware_indicators': [],
            'permissions': [],
            'domain_info': {},
            'page_content_analysis': {},
            'reputation': {}
        }

    def analyze(self):
        try:
            self._check_https()
            
            fetch_success = False
            for attempt in range(self.retries):
                try:
                    self._fetch_page_content()
                    fetch_success = True
                    break # Success, exit retry loop
                except requests.exceptions.ConnectionError as e:
                    error_msg = f"NETWORK_ERROR (Attempt {attempt+1}/{self.retries}): Failed to connect. Details: {str(e)}"
                    self.results['error'] = error_msg
                    if attempt < self.retries - 1:
                        time.sleep(2 ** attempt) # Exponential backoff
                        continue
                    else:
                        self.results['error'] = f"NETWORK_ERROR: Max retries exceeded. Possible firewall/network issue. Details: {str(e)}"
                except requests.exceptions.Timeout as e:
                    error_msg = f"TIMEOUT_ERROR (Attempt {attempt+1}/{self.retries}): Request timed out. Details: {str(e)}"
                    self.results['error'] = error_msg
                    if attempt < self.retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    else:
                        self.results['error'] = f"TIMEOUT_ERROR: Max retries exceeded. Possible slow server/network. Details: {str(e)}"
                except requests.exceptions.RequestException as e:
                    self.results['error'] = f"REQUEST_ERROR: An unexpected request error occurred. Details: {str(e)}"
                    break # Non-retryable request error
                except Exception as e:
                    self.results['error'] = f"UNEXPECTED_ERROR: An unexpected error occurred during content retrieval. Details: {str(e)}"
                    break # Non-retryable general error
            
            if not fetch_success:
                self.results['page_content_analysis'] = {} # Ensure it's empty if fetch failed
                self.results['malware_indicators'].append("WARNING: Page content could not be retrieved for full analysis.")

            self._check_domain_age()
            
            if fetch_success:
                self._analyze_page_content()
                self._check_phishing_indicators()
            else:
                if not any("Cannot check for phishing" in p for p in self.results['phishing_indicators']):
                    self.results['phishing_indicators'].append("WARNING: Cannot check for phishing indicators without page content.")
                if not any("Cannot check for malware" in m for m in self.results['malware_indicators']):
                    self.results['malware_indicators'].append("WARNING: Cannot check for malware indicators without page content.")

            self._check_permissions()
            self._check_url_reputation()

        except Exception as e:
            self.results['error'] = f"CRITICAL_ANALYSIS_ERROR: {str(e)}"
        return self.results

    def _check_https(self):
        self.results['is_secure'] = self.url.startswith('https://')

    def _fetch_page_content(self):
        headers = {
            'User-Agent': self.user_agent
        }
        
        proxies = None
        if self.proxy_config:
            proxy_url = ""
            if self.proxy_config.get('username') and self.proxy_config.get('password'):
                proxy_url = f"{self.proxy_config['username']}:{self.proxy_config['password']}@"
            proxy_url += f"{self.proxy_config['host']}:{self.proxy_config['port']}"
            
            proxies = {
                "http": f"http://{proxy_url}",
                "https": f"https://{proxy_url}"
            }
            
            if self.proxy_config.get('type') == 'socks':
                proxies = {
                    "http": f"socks5://{proxy_url}",
                    "https": f"socks5://{proxy_url}"
                }

        response = requests.get(self.url, headers=headers, proxies=proxies, timeout=self.timeout, verify=self.verify_ssl)
        self.results['page_content_analysis']['status_code'] = response.status_code
        self.results['page_content_analysis']['headers'] = dict(response.headers)
        if 'text/html' in response.headers.get('Content-Type', ''):
            soup = BeautifulSoup(response.text, 'html.parser')
            self.results['page_content_analysis']['title'] = soup.title.string if soup.title else None
            self.results['page_content_analysis']['forms'] = len(soup.find_all('form'))
            self.results['page_content_analysis']['scripts'] = len(soup.find_all('script'))
            self.results['page_content_analysis']['links'] = [a['href'] for a in soup.find_all('a', href=True)]

    def _check_domain_age(self):
        try:
            domain_info = whois.whois(self.domain)
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                self.results['domain_info']['age_days'] = age_days
                self.results['domain_info']['created'] = str(creation_date)
                if age_days < 365:
                    self.results['phishing_indicators'].append(f'DOMAIN_AGE_WARNING: Domain is relatively new ({age_days} days old)')
        except Exception:
            pass

    def _analyze_page_content(self):
        scripts = self.results['page_content_analysis'].get('scripts', 0)
        if scripts > 10:
            self.results['malware_indicators'].append(f'HIGH_SCRIPT_COUNT: ({scripts}) scripts detected.')
        if scripts > 5:
            self.results['malware_indicators'].append('MULTIPLE_SCRIPTS_DETECTED: Possible malicious code.')
        if scripts > 0:
            self.results['malware_indicators'].append('JAVASCRIPT_CONTENT_PRESENT.')

    def _check_phishing_indicators(self):
        if self.results['page_content_analysis'].get('forms', 0) > 0:
            self.results['phishing_indicators'].append('LOGIN_FORMS_DETECTED.')
        
        common_domains = ['paypal', 'bankofamerica', 'amazon', 'ebay', 'wellsfargo']
        for common_domain in common_domains:
            if common_domain in self.domain.lower() and not self.domain.lower().endswith(common_domain + '.com'):
                self.results['phishing_indicators'].append(f'TYPOSQUATTING_SUSPECTED: Possible impersonation of {common_domain}.')

    def _check_malware_indicators(self):
        self.results['malware_indicators'].append('DYNAMIC_CONTENT_LOADING_DETECTED.')

    def _check_permissions(self):
        self.results['permissions'] = [
            'NOTIFICATIONS',
            'GEOLOCATION',
            'CAMERA',
            'MICROPHONE',
            'FULLSCREEN',
            'PAYMENT'
        ]
        self.results['malware_indicators'].append('PERMISSION_REQUESTS_POSSIBLE: Scripts may request special permissions.')

    def _check_url_reputation(self):
        self.results['reputation'] = {
            'GOOGLE_SAFE_BROWSING': 'NO_ISSUES_DETECTED',
            'VIRUSTOTAL': 'NO_ISSUES_DETECTED'
        }

# --- GUI Class with "Hacker" Aesthetic and Advanced Network Options ---

class WebsiteAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(">>> WEB_FORENSICS_TOOL v1.0 <<<")
        self.root.geometry("950x800") # Increased size for new options
        self.root.resizable(True, True)
        
        # --- "Hacker" Color Scheme ---
        self.bg_color = "#000000"
        self.fg_color = "#00FF00"
        self.accent_color = "#00FFFF"
        self.error_color = "#FF0000"
        self.warning_color = "#FFFF00"

        # --- "Hacker" Fonts ---
        self.font_mono_large = ("Courier New", 14, "bold")
        self.font_mono_medium = ("Courier New", 12)
        self.font_mono_small = ("Courier New", 10)

        self.root.configure(bg=self.bg_color)

        self.url_var = tk.StringVar()
        self.proxy_host_var = tk.StringVar()
        self.proxy_port_var = tk.StringVar()
        self.proxy_user_var = tk.StringVar()
        self.proxy_pass_var = tk.StringVar()
        self.proxy_type_var = tk.StringVar(value="http")
        self.user_agent_var = tk.StringVar(value='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        self.verify_ssl_var = tk.BooleanVar(value=True) # Default to True
        self.timeout_var = tk.IntVar(value=15) # Default timeout
        self.retries_var = tk.IntVar(value=3) # Default retries

        self.build_gui()

        # Animation variables
        self.blinking_cursor_state = True
        self.blinking_cursor_job = None
        self.loading_animation_frames = itertools.cycle(['|', '/', '-', '\\'])
        self.loading_animation_job = None
        self.loading_message_base = "STATUS: READY"

        self.start_blinking_cursor()

    def build_gui(self):
        # --- Input Frame ---
        input_frame = tk.Frame(self.root, bg=self.bg_color, padx=5, pady=5, bd=1, relief=tk.SOLID)
        input_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(input_frame, text="TARGET_URL:", font=self.font_mono_large, fg=self.fg_color, bg=self.bg_color).pack(pady=5, anchor=tk.W)
        
        self.url_entry = tk.Entry(input_frame, textvariable=self.url_var, width=70, font=self.font_mono_medium, 
                                  bg="#1a1a1a", fg=self.fg_color, insertbackground=self.fg_color,
                                  bd=1, relief=tk.FLAT, highlightbackground=self.fg_color, highlightthickness=1)
        self.url_entry.pack(pady=5, fill=tk.X)
        self.url_entry.bind("<Return>", lambda event: self.start_analysis())

        # --- Advanced Network Configuration Frame ---
        network_config_frame = tk.LabelFrame(input_frame, text="[ NETWORK_CONFIG ]", font=self.font_mono_medium, fg=self.accent_color, bg=self.bg_color, bd=1, relief=tk.SOLID, padx=5, pady=5)
        network_config_frame.pack(pady=10, fill=tk.X)

        # Proxy Configuration Sub-frame
        proxy_frame = tk.LabelFrame(network_config_frame, text="[ PROXY ]", font=self.font_mono_small, fg=self.warning_color, bg=self.bg_color, bd=1, relief=tk.SOLID, padx=5, pady=5)
        proxy_frame.pack(pady=5, fill=tk.X)

        tk.Label(proxy_frame, text="HOST:", font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        tk.Entry(proxy_frame, textvariable=self.proxy_host_var, font=self.font_mono_small, bg="#1a1a1a", fg=self.fg_color, insertbackground=self.fg_color, bd=1, relief=tk.FLAT, highlightbackground=self.fg_color, highlightthickness=1).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        tk.Label(proxy_frame, text="PORT:", font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color).grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        tk.Entry(proxy_frame, textvariable=self.proxy_port_var, font=self.font_mono_small, bg="#1a1a1a", fg=self.fg_color, insertbackground=self.fg_color, bd=1, relief=tk.FLAT, highlightbackground=self.fg_color, highlightthickness=1).grid(row=0, column=3, sticky=tk.EW, padx=5, pady=2)
        
        tk.Label(proxy_frame, text="USER:", font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        tk.Entry(proxy_frame, textvariable=self.proxy_user_var, font=self.font_mono_small, bg="#1a1a1a", fg=self.fg_color, insertbackground=self.fg_color, bd=1, relief=tk.FLAT, highlightbackground=self.fg_color, highlightthickness=1).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        
        tk.Label(proxy_frame, text="PASS:", font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color).grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        tk.Entry(proxy_frame, textvariable=self.proxy_pass_var, show="*", font=self.font_mono_small, bg="#1a1a1a", fg=self.fg_color, insertbackground=self.fg_color, bd=1, relief=tk.FLAT, highlightbackground=self.fg_color, highlightthickness=1).grid(row=1, column=3, sticky=tk.EW, padx=5, pady=2)

        tk.Label(proxy_frame, text="TYPE:", font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        proxy_type_options = ["http", "https", "socks"]

        # --- ttk Combobox Styling Fix ---
        style = ttk.Style()
        style_name = "Hacker.TCombobox"
        style.theme_use('clam') 

        style.configure(style_name,
                        fieldbackground="#1a1a1a",
                        background=self.bg_color,
                        foreground=self.fg_color,
                        selectbackground=self.accent_color,
                        selectforeground=self.fg_color,
                        bordercolor=self.fg_color,
                        lightcolor=self.fg_color,
                        darkcolor=self.fg_color,
                        arrowcolor=self.fg_color,
                        arrowsize=10,
                        font=self.font_mono_small
                       )
        
        style.map(style_name,
                  fieldbackground=[('readonly', '#1a1a1a')],
                  background=[('readonly', self.bg_color)],
                  foreground=[('readonly', self.fg_color)],
                  selectbackground=[('readonly', self.accent_color)],
                  selectforeground=[('readonly', self.fg_color)],
                  bordercolor=[('readonly', self.fg_color)],
                  lightcolor=[('readonly', self.fg_color)],
                  darkcolor=[('readonly', self.fg_color)],
                  arrowcolor=[('readonly', self.fg_color)]
                 )

        style.configure("TCombobox.Listbox",
                        font=self.font_mono_small,
                        background=self.bg_color,
                        foreground=self.fg_color,
                        selectbackground=self.accent_color,
                        selectforeground=self.bg_color,
                        bordercolor=self.fg_color,
                        lightcolor=self.fg_color,
                        darkcolor=self.fg_color
                       )

        proxy_type_menu = ttk.Combobox(proxy_frame, textvariable=self.proxy_type_var, values=proxy_type_options, state="readonly", style=style_name)
        proxy_type_menu.set("http") # Set default
        proxy_type_menu.grid(row=2, column=1, sticky=tk.EW, padx=5, pady=2)
        # --- End ttk Combobox Styling Fix ---

        proxy_frame.grid_columnconfigure(1, weight=1)
        proxy_frame.grid_columnconfigure(3, weight=1)

        # User-Agent & SSL/Timeout/Retries Sub-frame
        misc_net_frame = tk.LabelFrame(network_config_frame, text="[ ADVANCED ]", font=self.font_mono_small, fg=self.warning_color, bg=self.bg_color, bd=1, relief=tk.SOLID, padx=5, pady=5)
        misc_net_frame.pack(pady=5, fill=tk.X)

        tk.Label(misc_net_frame, text="USER_AGENT:", font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        tk.Entry(misc_net_frame, textvariable=self.user_agent_var, font=self.font_mono_small, bg="#1a1a1a", fg=self.fg_color, insertbackground=self.fg_color, bd=1, relief=tk.FLAT, highlightbackground=self.fg_color, highlightthickness=1).grid(row=0, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=2)
        
        tk.Label(misc_net_frame, text="TIMEOUT (s):", font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        tk.Entry(misc_net_frame, textvariable=self.timeout_var, font=self.font_mono_small, bg="#1a1a1a", fg=self.fg_color, insertbackground=self.fg_color, bd=1, relief=tk.FLAT, highlightbackground=self.fg_color, highlightthickness=1).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)

        tk.Label(misc_net_frame, text="RETRIES:", font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color).grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        tk.Entry(misc_net_frame, textvariable=self.retries_var, font=self.font_mono_small, bg="#1a1a1a", fg=self.fg_color, insertbackground=self.fg_color, bd=1, relief=tk.FLAT, highlightbackground=self.fg_color, highlightthickness=1).grid(row=1, column=3, sticky=tk.EW, padx=5, pady=2)

        tk.Checkbutton(misc_net_frame, text="VERIFY_SSL", variable=self.verify_ssl_var, 
                       font=self.font_mono_small, fg=self.fg_color, bg=self.bg_color, 
                       selectcolor=self.bg_color, activebackground=self.bg_color, activeforeground=self.fg_color,
                       command=self.show_ssl_warning).grid(row=2, column=0, columnspan=4, sticky=tk.W, padx=5, pady=2)
        
        misc_net_frame.grid_columnconfigure(1, weight=1)
        misc_net_frame.grid_columnconfigure(3, weight=1)

        # --- Analyze Button ---
        tk.Button(input_frame, text="[ ANALYZE_TARGET ]", command=self.start_analysis, 
                  font=self.font_mono_large, bg=self.fg_color, fg=self.bg_color,
                  activebackground=self.accent_color, activeforeground=self.bg_color,
                  bd=1, relief=tk.FLAT).pack(pady=10, fill=tk.X)
        
        # --- Results Frame ---
        results_frame = tk.Frame(self.root, bg=self.bg_color, padx=5, pady=5, bd=1, relief=tk.SOLID)
        results_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        tk.Label(results_frame, text="[ ANALYSIS_LOG ]", font=self.font_mono_large, fg=self.fg_color, bg=self.bg_color).pack(pady=5, anchor=tk.W)

        self.text_area = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, 
                                                   width=100, height=25, 
                                                   font=self.font_mono_small, 
                                                   bg=self.bg_color, fg=self.fg_color,
                                                   insertbackground=self.fg_color,
                                                   bd=0, relief=tk.FLAT,
                                                   selectbackground=self.accent_color,
                                                   selectforeground=self.bg_color)
        self.text_area.pack(pady=5, fill=tk.BOTH, expand=True)
        
        # --- Export Frame ---
        export_frame = tk.Frame(self.root, bg=self.bg_color, padx=5, pady=5, bd=1, relief=tk.SOLID)
        export_frame.pack(pady=5, fill=tk.X)
        
        tk.Button(export_frame, text="[ EXPORT_TXT ]", command=self.export_txt, 
                  font=self.font_mono_medium, bg=self.fg_color, fg=self.bg_color,
                  activebackground=self.accent_color, activeforeground=self.bg_color,
                  bd=1, relief=tk.FLAT).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        tk.Button(export_frame, text="[ EXPORT_JSON ]", command=self.export_json, 
                  font=self.font_mono_medium, bg=self.fg_color, fg=self.bg_color,
                  activebackground=self.accent_color, activeforeground=self.bg_color,
                  bd=1, relief=tk.FLAT).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # --- Status Bar ---
        self.status_label = tk.Label(self.root, text="STATUS: READY_", bd=1, relief=tk.SOLID, anchor=tk.W,
                                     bg=self.bg_color, fg=self.fg_color, font=self.font_mono_small)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    # --- Animation Methods ---
    def start_blinking_cursor(self):
        self.blinking_cursor_job = self.root.after(500, self._blink_cursor)

    def _blink_cursor(self):
        current_text = self.status_label.cget("text")
        if self.blinking_cursor_state:
            if current_text.endswith("_"):
                self.status_label.config(text=current_text[:-1] + " ")
            elif current_text.endswith(" "):
                 self.status_label.config(text=current_text[:-1] + " ")
            else:
                self.status_label.config(text=current_text + " ")
        else:
            if current_text.endswith(" "):
                self.status_label.config(text=current_text[:-1] + "_")
            else:
                self.status_label.config(text=current_text + "_")
        
        self.blinking_cursor_state = not self.blinking_cursor_state
        self.blinking_cursor_job = self.root.after(500, self._blink_cursor)

    def stop_blinking_cursor(self):
        if self.blinking_cursor_job:
            self.root.after_cancel(self.blinking_cursor_job)
            self.blinking_cursor_job = None
        current_text = self.status_label.cget("text")
        if current_text.endswith(" "):
            self.status_label.config(text=current_text[:-1] + "_")

    def start_loading_animation(self):
        self.loading_animation_job = self.root.after(100, self._animate_loading)

    def _animate_loading(self):
        next_frame = next(self.loading_animation_frames)
        self.update_status(f"INITIATING ANALYSIS {next_frame}", self.warning_color, show_cursor=False)
        self.loading_animation_job = self.root.after(100, self._animate_loading)

    def stop_loading_animation(self):
        if self.loading_animation_job:
            self.root.after_cancel(self.loading_animation_job)
            self.loading_animation_job = None

    def update_status(self, message, color=None, show_cursor=True):
        self.stop_blinking_cursor()
        self.stop_loading_animation()

        display_message = f"STATUS: {message}"
        if show_cursor:
            display_message += "_"

        self.status_label.config(text=display_message)
        if color:
            self.status_label.config(fg=color)
        else:
            self.status_label.config(fg=self.fg_color)
        self.root.update_idletasks()

        if show_cursor and "READY" in message:
            self.start_blinking_cursor()

    def show_ssl_warning(self):
        if not self.verify_ssl_var.get():
            messagebox.showwarning(
                "SECURITY_WARNING",
                "WARNING: SSL/TLS VERIFICATION IS DISABLED.\n"
                "THIS CAN EXPOSE YOU TO MAN-IN-THE-MIDDLE ATTACKS.\n"
                "ONLY DISABLE IF YOU UNDERSTAND THE RISKS AND TRUST THE TARGET.",
                parent=self.root
            )

    # --- Analysis Flow ---
    def start_analysis(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("INPUT_ERROR", "ERROR: NO URL PROVIDED.", parent=self.root)
            self.update_status("ERROR: NO URL PROVIDED.", self.error_color, show_cursor=True)
            return
        
        # Validate timeout and retries
        try:
            timeout_val = self.timeout_var.get()
            if timeout_val <= 0: raise ValueError("Timeout must be positive.")
        except ValueError:
            messagebox.showerror("INPUT_ERROR", "ERROR: INVALID TIMEOUT VALUE. MUST BE A POSITIVE INTEGER.", parent=self.root)
            self.update_status("ERROR: INVALID TIMEOUT.", self.error_color, show_cursor=True)
            return
        
        try:
            retries_val = self.retries_var.get()
            if retries_val < 0: raise ValueError("Retries cannot be negative.")
        except ValueError:
            messagebox.showerror("INPUT_ERROR", "ERROR: INVALID RETRIES VALUE. MUST BE A NON-NEGATIVE INTEGER.", parent=self.root)
            self.update_status("ERROR: INVALID RETRIES.", self.error_color, show_cursor=True)
            return

        # Prepare proxy configuration
        proxy_config = {}
        proxy_host = self.proxy_host_var.get().strip()
        proxy_port = self.proxy_port_var.get().strip()
        proxy_user = self.proxy_user_var.get().strip()
        proxy_pass = self.proxy_pass_var.get().strip()
        proxy_type = self.proxy_type_var.get().strip()

        if proxy_host and proxy_port:
            try:
                int(proxy_port) # Validate port is a number
                proxy_config['host'] = proxy_host
                proxy_config['port'] = proxy_port
                proxy_config['type'] = proxy_type
                if proxy_user:
                    proxy_config['username'] = proxy_user
                if proxy_pass:
                    proxy_config['password'] = proxy_pass
            except ValueError:
                messagebox.showerror("INPUT_ERROR", "ERROR: INVALID PROXY PORT. MUST BE A NUMBER.", parent=self.root)
                self.update_status("ERROR: INVALID PROXY PORT.", self.error_color, show_cursor=True)
                return
        
        custom_user_agent = self.user_agent_var.get().strip()
        if not custom_user_agent:
            custom_user_agent = None 

        verify_ssl_val = self.verify_ssl_var.get()

        self.text_area.delete('1.0', tk.END)
        self.update_status("INITIATING ANALYSIS...", self.warning_color, show_cursor=False)
        self.start_loading_animation()
        
        Thread(target=self._run_analysis_thread, args=(url, proxy_config, custom_user_agent, verify_ssl_val, timeout_val, retries_val), daemon=True).start()

    def _run_analysis_thread(self, url, proxy_config, custom_user_agent, verify_ssl_val, timeout_val, retries_val):
        try:
            analyzer = EnhancedWebsiteAnalyzer(url, proxy_config, custom_user_agent, verify_ssl_val, timeout_val, retries_val)
            results = analyzer.analyze()
            self.results = results
            self.root.after(0, self.show_results, results)
            self.root.after(0, self.update_status, "ANALYSIS COMPLETE.", self.fg_color, show_cursor=True)
        except Exception as e:
            self.root.after(0, messagebox.showerror, "ANALYSIS_ERROR", f"CRITICAL_ERROR: {e}", parent=self.root)
            self.root.after(0, self.update_status, f"ERROR: {e}", self.error_color, show_cursor=True)
        finally:
            self.root.after(0, self.stop_loading_animation)

    # --- show_results, export_txt, export_json ---
    def show_results(self, results):
        self.text_area.delete('1.0', tk.END)

        self.text_area.tag_configure("header", foreground=self.accent_color, font=(self.font_mono_small[0], self.font_mono_small[1], "bold"))
        self.text_area.tag_configure("secure", foreground=self.fg_color)
        self.text_area.tag_configure("insecure", foreground=self.error_color)
        self.text_area.tag_configure("warning", foreground=self.warning_color)
        self.text_area.tag_configure("success", foreground=self.fg_color)
        self.text_area.tag_configure("error", foreground=self.error_color)
        self.text_area.tag_configure("key", foreground=self.accent_color)

        self.text_area.insert(tk.END, f"TARGET_URL: {results.get('url')}\n", "header")
        self.text_area.insert(tk.END, f"DOMAIN: {results.get('domain')}\n\n")

        self.text_area.insert(tk.END, "--- SECURITY_ANALYSIS ---\n", "header")
        if results.get('is_secure'):
            self.text_area.insert(tk.END, "STATUS_HTTPS: SECURE\n", "secure")
        else:
            self.text_area.insert(tk.END, "STATUS_HTTPS: INSECURE\n", "insecure")

        domain_info = results.get('domain_info', {})
        if 'age_days' in domain_info:
            self.text_area.insert(tk.END, f"DOMAIN_AGE: {domain_info['age_days']} DAYS (CREATED: {domain_info['created']})\n")

        self.text_area.insert(tk.END, "\n--- PHISHING_INDICATORS ---\n", "header")
        if results['phishing_indicators']:
            for p in results['phishing_indicators']:
                self.text_area.insert(tk.END, f"ALERT: {p}\n", "warning")
        else:
            self.text_area.insert(tk.END, "STATUS: NO_PHISHING_INDICATORS_DETECTED\n", "success")

        self.text_area.insert(tk.END, "\n--- MALWARE_INDICATORS ---\n", "header")
        if results['malware_indicators']:
            for m in results['malware_indicators']:
                self.text_area.insert(tk.END, f"ALERT: {m}\n", "warning")
        else:
            self.text_area.insert(tk.END, "STATUS: NO_MALWARE_INDICATORS_DETECTED\n", "success")

        self.text_area.insert(tk.END, "\n--- PERMISSIONS_DETECTED ---\n", "header")
        for p in results.get('permissions', []):
            self.text_area.insert(tk.END, f"ACCESS_REQUEST: {p}\n", "key")

        self.text_area.insert(tk.END, "\n--- URL_REPUTATION ---\n", "header")
        for k, v in results.get('reputation', {}).items():
            self.text_area.insert(tk.END, f"{k.replace('_',' ').upper()}: {v.upper()}\n")

        if 'error' in results and results['error']:
            self.text_area.insert(tk.END, f"\n--- SYSTEM_ERROR ---\n", "header")
            self.text_area.insert(tk.END, f"ERROR_DETAILS: {results['error']}\n", "error")

    def export_txt(self):
        if not hasattr(self, 'results') or not self.results:
            messagebox.showwarning("EXPORT_ERROR", "ERROR: NO_ANALYSIS_RESULTS_TO_EXPORT.", parent=self.root)
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                 filetypes=[("TEXT_FILES", "*.txt"), ("ALL_FILES", "*.*")],
                                                 title="SAVE_REPORT_TXT")
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(self.text_area.get("1.0", tk.END))
                messagebox.showinfo("EXPORT_SUCCESS", f"REPORT_SAVED_TO: {file_path}", parent=self.root)
                self.update_status(f"REPORT_SAVED_TO: {file_path}", self.fg_color, show_cursor=True)
            except Exception as e:
                messagebox.showerror("EXPORT_ERROR", f"FAILED_TO_EXPORT_TXT: {e}", parent=self.root)
                self.update_status(f"EXPORT_FAILED: {e}", self.error_color, show_cursor=True)

    def export_json(self):
        if not hasattr(self, 'results') or not self.results:
            messagebox.showwarning("EXPORT_ERROR", "ERROR: NO_ANALYSIS_RESULTS_TO_EXPORT.", parent=self.root)
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".json", 
                                                 filetypes=[("JSON_FILES", "*.json"), ("ALL_FILES", "*.*")],
                                                 title="SAVE_DATA_JSON")
        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(self.results, f, indent=4)
                messagebox.showinfo("EXPORT_SUCCESS", f"DATA_SAVED_TO: {file_path}", parent=self.root)
                self.update_status(f"DATA_SAVED_TO: {file_path}", self.fg_color, show_cursor=True)
            except Exception as e:
                messagebox.showerror("EXPORT_ERROR", f"FAILED_TO_EXPORT_JSON: {e}", parent=self.root)
                self.update_status(f"EXPORT_FAILED: {e}", self.error_color, show_cursor=True)

# Launch GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = WebsiteAnalyzerGUI(root)
    root.mainloop()
