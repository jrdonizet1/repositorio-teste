import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import logging
from logging.handlers import RotatingFileHandler
import json
from urllib.parse import urlparse, parse_qs
import queue
from plyer import notification
import hashlib
from ttkbootstrap import Style
from threading import Lock

# Configuração do logging com rotação
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

handler = RotatingFileHandler('download_manager.log', maxBytes=5*1024*1024, backupCount=2)  # 5MB por arquivo
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

CONFIG_FILE = 'config.json'
HASHES_FILE = 'hashes.json'  # Arquivo contendo os hashes esperados

class DownloadManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gerenciador de Downloads de Séries")
        self.root.geometry("1000x800")

        # Inicializar estilo com ttkbootstrap
        style = Style(theme='flatly')  # Escolha o tema que preferir
        style.configure('Treeview', rowheight=25)

        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.load_config()
        self.load_hashes()  # Carregar hashes esperados
        self.setup_ui()
        self.queue = queue.Queue()
        self.root.after(100, self.process_queue)

        # Inicializar dicionários para gerenciar URLs e futuros
        self.download_urls = {}  # Mapeia file_path para video_url
        self.futures = {}        # Mapeia futuros para file_path
        self.file_locks = {}     # Locks para cada arquivo
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Referer': 'http://example.com'
        })
        self.executor = ThreadPoolExecutor(max_workers=self.config.get("max_downloads", 3))
        logging.info("Executor iniciado com max_workers=%d", self.config.get("max_downloads", 3))

        # Criar menu de contexto
        self.create_context_menu()

    def load_config(self):
        self.config = {
            "save_dir": "",
            "max_downloads": 3,  # Valor padrão
            "proxy": "",
            "check_integrity": False
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    loaded_config = json.load(f)
                    # Validação
                    if 'save_dir' in loaded_config and os.path.isdir(loaded_config['save_dir']):
                        self.config['save_dir'] = loaded_config['save_dir']
                    if 'max_downloads' in loaded_config and isinstance(loaded_config['max_downloads'], int) and loaded_config['max_downloads'] > 0:
                        self.config['max_downloads'] = loaded_config['max_downloads']
                    if 'proxy' in loaded_config:
                        self.config['proxy'] = loaded_config['proxy']
                    if 'check_integrity' in loaded_config:
                        self.config['check_integrity'] = loaded_config['check_integrity']
            except json.JSONDecodeError as e:
                logging.error(f"Erro ao decodificar JSON das configurações: {e}")
            except Exception as e:
                logging.error(f"Erro ao carregar configurações: {e}")

    def load_hashes(self):
        self.hashes = {}
        if os.path.exists(HASHES_FILE):
            try:
                with open(HASHES_FILE, 'r') as f:
                    self.hashes = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"Erro ao decodificar JSON dos hashes: {e}")
            except Exception as e:
                logging.error(f"Erro ao carregar hashes: {e}")
        else:
            logging.warning(f"Arquivo {HASHES_FILE} não encontrado. A verificação de integridade não será realizada.")

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Erro ao salvar configurações: {e}")

    def setup_ui(self):
        # Frame para entrada de dados
        frame_input = ttk.Frame(self.root)
        frame_input.pack(pady=10, padx=10, fill='x')

        # URL
        lbl_url = ttk.Label(frame_input, text="URL do vídeo:")
        lbl_url.grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.entry_url = ttk.Entry(frame_input, width=80)
        self.entry_url.grid(row=0, column=1, padx=5, pady=5, sticky='w')

        # Máximo de downloads
        lbl_max_downloads = ttk.Label(frame_input, text="Máximo de downloads simultâneos:")
        lbl_max_downloads.grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.entry_max_downloads = ttk.Entry(frame_input, width=10)
        self.entry_max_downloads.insert(0, str(self.config.get("max_downloads", 3)))
        self.entry_max_downloads.grid(row=1, column=1, padx=5, pady=5, sticky='w')

        # Botão para selecionar pasta de salvamento sem ícone
        btn_select_dir = ttk.Button(
            frame_input,
            text="Selecionar Pasta",
            command=self.select_save_dir,
            bootstyle="info"
        )
        btn_select_dir.grid(row=2, column=1, padx=5, pady=5, sticky='w')

        self.lbl_save_dir = ttk.Label(frame_input, text=f"Pasta Selecionada: {self.config.get('save_dir', 'Nenhuma')}")
        self.lbl_save_dir.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky='w')

        # Checkbox para sobrescrever arquivos existentes
        self.overwrite_var = tk.BooleanVar()
        chk_overwrite = ttk.Checkbutton(frame_input, text="Sobrescrever arquivos existentes", variable=self.overwrite_var)
        chk_overwrite.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky='w')

        # Checkbox para verificação de integridade
        self.integrity_var = tk.BooleanVar(value=self.config.get("check_integrity", False))
        chk_integrity = ttk.Checkbutton(frame_input, text="Verificar integridade dos arquivos baixados", variable=self.integrity_var)
        chk_integrity.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky='w')

        # Campo para Proxy (opcional)
        lbl_proxy = ttk.Label(frame_input, text="Proxy (opcional):")
        lbl_proxy.grid(row=6, column=0, padx=5, pady=5, sticky='e')
        self.entry_proxy = ttk.Entry(frame_input, width=80)
        self.entry_proxy.insert(0, self.config.get("proxy", ""))
        self.entry_proxy.grid(row=6, column=1, padx=5, pady=5, sticky='w')

        # Temporadas
        lbl_start_season = ttk.Label(frame_input, text="Temporada Inicial:")
        lbl_start_season.grid(row=7, column=0, padx=5, pady=5, sticky='e')
        self.entry_start_season = ttk.Entry(frame_input, width=10)
        self.entry_start_season.insert(0, "1")  # Valor padrão
        self.entry_start_season.grid(row=7, column=1, padx=5, pady=5, sticky='w')

        lbl_end_season = ttk.Label(frame_input, text="Temporada Final:")
        lbl_end_season.grid(row=8, column=0, padx=5, pady=5, sticky='e')
        self.entry_end_season = ttk.Entry(frame_input, width=10)
        self.entry_end_season.insert(0, "999")  # Valor padrão para indicar "até o final"
        self.entry_end_season.grid(row=8, column=1, padx=5, pady=5, sticky='w')

        # Formato do arquivo
        lbl_format = ttk.Label(frame_input, text="Formato do arquivo:")
        lbl_format.grid(row=9, column=0, padx=5, pady=5, sticky='e')
        self.combo_format = ttk.Combobox(frame_input, values=["mp4", "mkv", "avi"], state="readonly", width=8)
        self.combo_format.current(0)
        self.combo_format.grid(row=9, column=1, padx=5, pady=5, sticky='w')

        # Frame para botões de controle sem ícones
        frame_buttons = ttk.Frame(self.root)
        frame_buttons.pack(pady=10)

        self.btn_start = ttk.Button(
            frame_buttons,
            text="Iniciar Download",
            command=self.start_download,
            bootstyle="success"
        )
        self.btn_start.grid(row=0, column=0, padx=5)

        self.btn_pause = ttk.Button(
            frame_buttons,
            text="Pausar",
            command=self.pause_download,
            state=tk.DISABLED,
            bootstyle="warning"
        )
        self.btn_pause.grid(row=0, column=1, padx=5)

        self.btn_resume = ttk.Button(
            frame_buttons,
            text="Retomar",
            command=self.resume_download,
            state=tk.DISABLED,
            bootstyle="info"
        )
        self.btn_resume.grid(row=0, column=2, padx=5)

        self.btn_stop = ttk.Button(
            frame_buttons,
            text="Parar",
            command=self.stop_download,
            state=tk.DISABLED,
            bootstyle="danger"
        )
        self.btn_stop.grid(row=0, column=3, padx=5)

        # Barra de progresso global
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", length=900, mode="determinate")
        self.progress_bar.pack(pady=10)

        self.lbl_progress = ttk.Label(self.root, text="0%")
        self.lbl_progress.pack(pady=5)

        self.lbl_status = ttk.Label(self.root, text="", foreground="black")
        self.lbl_status.pack(pady=5)

        # Árvore de downloads
        self.tree = ttk.Treeview(self.root, columns=("File", "Progress", "Status", "Speed", "ETA"), show='headings')
        self.tree.heading("File", text="Arquivo")
        self.tree.heading("Progress", text="Progresso")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Speed", text="Velocidade")
        self.tree.heading("ETA", text="Tempo Restante")
        self.tree.column("File", width=400)
        self.tree.column("Progress", width=100)
        self.tree.column("Status", width=100)
        self.tree.column("Speed", width=100)
        self.tree.column("ETA", width=100)
        self.tree.pack(pady=10, fill='both', expand=True)

        # Scrollbar para a árvore
        scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        # Configurar tags para diferentes status
        self.tree.tag_configure('downloading', background='#FFFACD')  # Amarelo claro
        self.tree.tag_configure('paused', background='#D3D3D3')      # Cinza claro
        self.tree.tag_configure('completed', background='#90EE90')   # Verde claro
        self.tree.tag_configure('failed', background='#FFB6C1')      # Rosa claro
        self.tree.tag_configure('canceled', background='#F08080')    # Vermelho claro

        # Aplicar tema
        # O ttkbootstrap já aplica o tema, então não é necessário adicional aqui

        # Vincular eventos para o menu de contexto
        self.tree.bind("<Button-3>", self.show_context_menu)  # Para sistemas Windows e Linux
        self.tree.bind("<Button-2>", self.show_context_menu)  # Para sistemas macOS

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Reiniciar Download", command=self.restart_download)
        self.context_menu.add_command(label="Cancelar Download", command=self.cancel_download)
        # Você pode adicionar mais opções aqui no futuro

    def show_context_menu(self, event):
        selected_items = self.tree.selection()
        if selected_items:
            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()

    def sanitize_string(self, name):
        name = name.lower()
        name = name.replace(" ", ".")
        name = name.translate(str.maketrans("áàãâäéèêëíìîïóòõôöúùûüç", "aaaaaeeeeiiiiooooouuuuc"))
        name = ''.join(e for e in name if e.isalnum() or e in "._-")
        return name

    def check_internet_connection(self):
        try:
            requests.get("http://www.google.com", timeout=5)
            return True
        except requests.ConnectionError:
            return False

    def get_series_info(self, api_url):
        try:
            response = self.session.get(api_url, timeout=10, proxies=self.get_proxy())
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.queue.put(('update_status', f"Falha ao obter informações da série: {str(e)}", "red"))
            logging.error(f"Falha ao obter informações da série: {e}")
            return None

    def get_proxy(self):
        proxy = self.entry_proxy.get().strip()
        if proxy:
            return {
                "http": proxy,
                "https": proxy
            }
        return None

    def log_error(self, url, error_message):
        logging.error(f"URL: {url} - Erro: {error_message}")

    def select_save_dir(self):
        save_dir = filedialog.askdirectory(title="Selecionar Pasta para Salvar", initialdir=self.config.get("save_dir", os.path.expanduser("~")))
        if save_dir:
            self.config["save_dir"] = save_dir
            self.lbl_save_dir.config(text=f"Pasta Selecionada: {save_dir}")
            self.save_config()

    def download_video(self, url, save_path, progress_callback, stop_event, pause_event, overwrite=False, max_retries=3):
        logging.info(f"Iniciando download para: {save_path}")
        if save_path not in self.file_locks:
            self.file_locks[save_path] = Lock()

        with self.file_locks[save_path]:
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'Referer': 'http://example.com'
                }

                if overwrite and os.path.exists(save_path):
                    os.remove(save_path)
                    logging.info(f"Arquivo existente removido para sobrescrever: {save_path}")

                downloaded_length = 0
                if os.path.exists(save_path):
                    downloaded_length = os.path.getsize(save_path)
                    headers['Range'] = f'bytes={downloaded_length}-'
                    logging.info(f"Retomando download para {save_path} a partir de {downloaded_length} bytes")
                else:
                    logging.info(f"Iniciando novo download para {save_path}")

                DOWNLOAD_SPEED_LIMIT = 1000024 * 1000024  # 1MB/s (ajuste conforme necessário)
                start_time = time.time()
                bytes_downloaded = 0

                for attempt in range(max_retries):
                    try:
                        with self.session.get(url, headers=headers, stream=True, timeout=10, proxies=self.get_proxy()) as response:
                            if response.status_code not in [200, 206]:
                                self.log_error(url, f"Código HTTP {response.status_code}")
                                raise requests.RequestException(f"Código HTTP {response.status_code}")

                            total_size = int(response.headers.get('content-length', 0)) + downloaded_length if 'content-length' in response.headers else None
                            logging.info(f"Total size para {save_path}: {total_size} bytes")

                            with open(save_path, "ab" if downloaded_length > 0 else "wb") as file:
                                for chunk in response.iter_content(chunk_size=1024*1024):  # 1MB
                                    if stop_event.is_set():
                                        self.queue.put(('update_status', "Downloads parados.", "red"))
                                        self.tree.set(save_path, "Status", "Parado")
                                        logging.info(f"Download parado: {save_path}")
                                        return False
                                    while pause_event.is_set():
                                        self.queue.put(('update_status', "Downloads pausados.", "orange"))
                                        self.tree.set(save_path, "Status", "Pausado")
                                        time.sleep(0.5)
                                        if stop_event.is_set():
                                            self.queue.put(('update_status', "Downloads parados durante a pausa.", "red"))
                                            self.tree.set(save_path, "Status", "Parado")
                                            logging.info(f"Download parado durante a pausa: {save_path}")
                                            return False
                                    if chunk:
                                        file.write(chunk)
                                        downloaded_length += len(chunk)
                                        bytes_downloaded += len(chunk)
                                        current_time = time.time()
                                        elapsed_time = current_time - start_time
                                        if elapsed_time > 0:
                                            current_speed = bytes_downloaded / elapsed_time
                                            if current_speed > DOWNLOAD_SPEED_LIMIT:
                                                sleep_time = (bytes_downloaded / DOWNLOAD_SPEED_LIMIT) - elapsed_time
                                                if sleep_time > 0:
                                                    time.sleep(sleep_time)
                                                start_time = time.time()
                                                bytes_downloaded = 0
                                        # Atualização de progresso
                                        progress_callback(save_path, downloaded_length, total_size, current_speed, (total_size - downloaded_length) / current_speed if total_size else None)
                        break  # Sucesso, sair do loop de tentativas
                    except requests.RequestException as e:
                        self.log_error(url, str(e))
                        if attempt < max_retries - 1:
                            logging.warning(f"Tentativa {attempt + 1} falhou. Retentando em 2 segundos...")
                            time.sleep(2)
                        else:
                            self.queue.put(('download_failed', save_path))
                            self.queue.put(('update_status', f"Erro ao baixar o vídeo: {str(e)}", "red"))
                            logging.error(f"Erro ao baixar o vídeo após {max_retries} tentativas: {url}")
                            return False

                # Após o loop de tentativas
                if total_size and downloaded_length < total_size:
                    logging.error(f"Tamanho do arquivo para {save_path} não corresponde ao esperado. Esperado: {total_size}, Obtido: {downloaded_length}")
                    progress_callback(save_path, downloaded_length, total_size, speed=0, eta=0)
                    self.queue.put(('download_failed', save_path))
                    self.queue.put(('update_status', f"Tamanho do arquivo baixado não corresponde ao esperado.", "red"))
                    self.tree.set(save_path, "Status", "Falhou")
                    self.tree.item(save_path, tags=('failed',))
                    return False

                # Verificação de integridade
                if self.integrity_var.get():
                    if not self.verify_integrity(save_path):
                        self.queue.put(('update_status', f"Integridade falhou para: {os.path.basename(save_path)}", "red"))
                        self.tree.set(save_path, "Status", "Falhou")
                        self.tree.item(save_path, tags=('failed',))
                        return False

                logging.info(f"Download concluído para: {save_path}")
                return True

            except Exception as e:
                self.log_error(url, str(e))
                self.queue.put(('download_failed', save_path))
                self.queue.put(('update_status', f"Erro ao baixar o vídeo: {str(e)}", "red"))
                logging.error(f"Erro ao baixar o vídeo: {e}")
                return False

    def verify_integrity(self, file_path):
        """
        Verifica a integridade do arquivo baixado comparando com o hash esperado.
        """
        try:
            file_name = os.path.basename(file_path)
            expected_hash = self.hashes.get(file_name, None)
            if not expected_hash:
                logging.warning(f"Hash esperado não encontrado para o arquivo: {file_name}")
                return True  # Se não houver hash esperado, assume que está correto

            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            calculated_hash = hash_sha256.hexdigest()

            if calculated_hash.lower() != expected_hash.lower():
                logging.error(f"Hash incorreto para {file_name}. Esperado: {expected_hash}, Calculado: {calculated_hash}")
                return False
            return True
        except Exception as e:
            logging.error(f"Erro na verificação de integridade: {e}")
            return False

    def notify_user(self, title, message):
        try:
            notification.notify(
                title=title,
                message=message,
                timeout=5  # Tempo em segundos
            )
        except Exception as e:
            logging.error(f"Erro ao enviar notificação: {e}")

    def start_download(self):
        if not self.check_internet_connection():
            self.queue.put(('update_status', "Sem conexão com a internet.", "red"))
            messagebox.showerror("Erro", "Sem conexão com a internet.")
            return

        url = self.entry_url.get().strip()
        if not url:
            self.queue.put(('update_status', "URL é necessária.", "red"))
            messagebox.showerror("Erro", "Por favor, insira uma URL.")
            return

        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Extrair parâmetros necessários
        username = params.get("username", [None])[0]
        password = params.get("password", [None])[0]
        series_id = params.get("series_id", [None])[0]

        if not all([username, password, series_id]):
            self.queue.put(('update_status', "URL deve conter username, password e series_id.", "red"))
            messagebox.showerror("Erro", "A URL deve conter os parâmetros 'username', 'password' e 'series_id'.")
            return

        api_url = f"{parsed_url.scheme}://{parsed_url.netloc}/player_api.php?username={username}&password={password}&action=get_series_info&series_id={series_id}"
        series_info = self.get_series_info(api_url)
        if not series_info:
            return

        title = self.sanitize_string(series_info["info"]["name"])
        save_dir = self.config.get("save_dir", "")
        if not save_dir:
            messagebox.showwarning("Aviso", "Por favor, selecione uma pasta de salvamento.")
            return

        try:
            max_downloads = int(self.entry_max_downloads.get().strip())
            if max_downloads < 1:
                self.queue.put(('update_status', "Número máximo de downloads deve ser maior que 0.", "red"))
                messagebox.showerror("Erro", "O número máximo de downloads deve ser maior que 0.")
                return
            self.config["max_downloads"] = max_downloads
            self.save_config()

            # Atualizar o executor se necessário
            # Remover o shutdown para manter o executor ativo
            # self.executor.shutdown(wait=False)
            self.executor = ThreadPoolExecutor(max_workers=max_downloads)
            logging.info("Executor atualizado com max_workers=%d", max_downloads)
        except ValueError:
            self.queue.put(('update_status', "Valor inválido para downloads.", "red"))
            messagebox.showerror("Erro", "Por favor, insira um número válido para downloads simultâneos.")
            return

        # Obter as temporadas selecionadas
        try:
            start_season = int(self.entry_start_season.get().strip())
            end_season = int(self.entry_end_season.get().strip())
            if start_season < 1 or end_season < start_season:
                raise ValueError
        except ValueError:
            self.queue.put(('update_status', "Seleção de temporadas inválida.", "red"))
            messagebox.showerror("Erro", "Por favor, insira valores válidos para as temporadas inicial e final.")
            return

        self.btn_start.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.NORMAL)
        self.btn_resume.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)

        self.queue.put(('update_status', "Baixando...", "blue"))
        self.stop_event.clear()
        self.pause_event.clear()

        # Limpar Treeview antes de iniciar novos downloads
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.download_urls.clear()
        self.futures.clear()

        # Obter o estado do checkbox de sobrescrever arquivos
        overwrite_existing = self.overwrite_var.get()

        # Atualizar a configuração de verificação de integridade
        self.config["check_integrity"] = self.integrity_var.get()
        self.save_config()

        # Obter formato do arquivo
        file_format = self.combo_format.get()

        def download_thread():
            with self.executor as executor:
                failed_downloads = []
                total_files = 0
                completed_files = 0

                # Filtrar temporadas dentro do intervalo
                filtered_seasons = {season: episodes for season, episodes in series_info["episodes"].items() if start_season <= int(season) <= end_season}

                if not filtered_seasons:
                    self.queue.put(('update_status', "Nenhuma temporada encontrada no intervalo especificado.", "red"))
                    self.reset_buttons()
                    return

                total_files = sum(len(episodes) for episodes in filtered_seasons.values())

                for season_num, episodes in filtered_seasons.items():
                    for episode in episodes:
                        file_path = self.create_episode_file_path(save_dir, title, season_num, episode, file_format)

                        video_url = f"{parsed_url.scheme}://{parsed_url.netloc}/series/{username}/{password}/{episode['id']}.{file_format}"

                        if not self.tree.exists(file_path):
                            # Adicionar entrada na árvore
                            self.tree.insert("", "end", iid=file_path, values=(os.path.basename(file_path), "0%", "Iniciando", "0 KB/s", "N/A"))
                            self.download_urls[file_path] = video_url  # Armazenar a URL

                            future = self.executor.submit(
                                self.download_video,
                                video_url,
                                file_path,
                                self.update_progress,
                                self.stop_event,
                                self.pause_event,
                                overwrite=overwrite_existing
                            )
                            self.futures[future] = file_path
                        else:
                            if overwrite_existing:
                                # Adicionar entrada na árvore mesmo se o arquivo existir
                                self.tree.insert("", "end", iid=file_path, values=(os.path.basename(file_path), "0%", "Iniciando", "0 KB/s", "N/A"))
                                self.download_urls[file_path] = video_url  # Armazenar a URL

                                future = self.executor.submit(
                                    self.download_video,
                                    video_url,
                                    file_path,
                                    self.update_progress,
                                    self.stop_event,
                                    self.pause_event,
                                    overwrite=True
                                )
                                self.futures[future] = file_path
                            else:
                                logging.info(f"Arquivo já existe e overwrite não está selecionado: {file_path}")
                                self.tree.insert("", "end", iid=file_path, values=(os.path.basename(file_path), "100%", "Existente", "0 KB/s", "N/A"))
                                self.tree.item(file_path, tags=('completed',))
                                completed_files += 1
                                global_progress = (completed_files / total_files) * 100
                                self.queue.put(('update_global_progress', completed_files, total_files))

                for future in as_completed(self.futures):
                    file_path = self.futures[future]
                    result = future.result()
                    completed_files += 1
                    self.queue.put(('update_global_progress', completed_files, total_files))

                    if result:
                        self.queue.put(('download_complete', file_path))
                    else:
                        self.queue.put(('download_failed', file_path))
                        failed_downloads.append(file_path)

                # Notificação após todos os downloads
                if failed_downloads:
                    self.notify_user("Downloads Concluídos com Falhas", f"{len(failed_downloads)} downloads falharam.")
                else:
                    self.notify_user("Downloads Concluídos", "Todos os downloads foram concluídos com sucesso.")

            self.reset_buttons()

        threading.Thread(target=download_thread, daemon=True).start()

    def create_episode_file_path(self, save_dir, title, season_num, episode, file_format):
        season_dir = os.path.join(save_dir, f"{title}.T{season_num}")
        os.makedirs(season_dir, exist_ok=True)
        episode_num = episode["episode_num"]
        episode_id = episode["id"]
        episode_title = self.sanitize_string(episode["title"])
        file_name = f"{episode_title}.T{season_num}E{episode_num}.{file_format}"
        return os.path.join(season_dir, file_name)

    def update_progress(self, file_path, downloaded, total_size, speed, eta):
        # Formatar velocidade e ETA
        speed_str = self.format_speed(speed)
        eta_str = self.format_eta(eta)

        self.queue.put(('update_progress', file_path, downloaded, total_size, speed_str, eta_str))

    def format_speed(self, speed_bytes_per_sec):
        if speed_bytes_per_sec < 1024:
            return f"{int(speed_bytes_per_sec)} B/s"
        elif speed_bytes_per_sec < 1024 * 1024:
            return f"{speed_bytes_per_sec / 1024:.2f} KB/s"
        else:
            return f"{speed_bytes_per_sec / (1024 * 1024):.2f} MB/s"

    def format_eta(self, eta_seconds):
        if eta_seconds is None:
            return "N/A"
        m, s = divmod(int(eta_seconds), 60)
        h, m = divmod(m, 60)
        if h > 0:
            return f"{h}h {m}m {s}s"
        elif m > 0:
            return f"{m}m {s}s"
        else:
            return f"{s}s"

    def pause_download(self):
        self.pause_event.set()
        self.queue.put(('update_status', "Downloads pausados.", "orange"))
        self.btn_resume.config(state=tk.NORMAL)
        self.btn_pause.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        # Atualizar tags na árvore
        for item in self.tree.get_children():
            status = self.tree.set(item, "Status")
            if status == "Baixando":
                self.tree.item(item, tags=('paused',))

    def resume_download(self):
        self.pause_event.clear()
        self.queue.put(('update_status', "Retomando downloads...", "blue"))
        self.btn_resume.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.NORMAL)
        # Atualizar tags na árvore
        for item in self.tree.get_children():
            status = self.tree.set(item, "Status")
            if status == "Pausado":
                self.tree.item(item, tags=('downloading',))

    def stop_download(self):
        self.stop_event.set()
        self.queue.put(('update_status', "Downloads parados.", "red"))
        self.reset_buttons()

    def reset_buttons(self):
        self.btn_start.config(state=tk.NORMAL)
        self.btn_pause.config(state=tk.DISABLED)
        self.btn_resume.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.DISABLED)

    def update_status(self, message, color="black"):
        self.lbl_status.config(text=message, foreground=color)

    def process_queue(self):
        try:
            while True:
                task = self.queue.get_nowait()
                if task[0] == 'update_progress':
                    _, file_path, downloaded, total_size, speed, eta = task
                    if total_size:
                        progress_percentage = (downloaded / total_size) * 100
                        progress_percentage = min(progress_percentage, 100)  # Garantir que não ultrapasse 100%
                        progress_text = f"{int(progress_percentage)}%"
                        self.tree.set(file_path, "Progress", progress_text)
                        self.tree.set(file_path, "Status", "Baixando")
                        self.tree.set(file_path, "Speed", speed)
                        self.tree.set(file_path, "ETA", eta)
                        self.tree.item(file_path, tags=('downloading',))
                    else:
                        self.tree.set(file_path, "Progress", "Indeterminado")
                        self.tree.set(file_path, "Status", "Baixando")
                        self.tree.set(file_path, "Speed", "0 KB/s")
                        self.tree.set(file_path, "ETA", "N/A")
                        self.tree.item(file_path, tags=('downloading',))
                elif task[0] == 'download_complete':
                    _, file_path = task
                    self.tree.set(file_path, "Progress", "100%")
                    self.tree.set(file_path, "Status", "Concluído")
                    self.tree.set(file_path, "Speed", "0 KB/s")
                    self.tree.set(file_path, "ETA", "N/A")
                    self.tree.item(file_path, tags=('completed',))
                elif task[0] == 'download_failed':
                    _, file_path = task
                    self.tree.set(file_path, "Status", "Falhou")
                    self.tree.set(file_path, "Speed", "0 KB/s")
                    self.tree.set(file_path, "ETA", "N/A")
                    self.tree.item(file_path, tags=('failed',))
                elif task[0] == 'update_global_progress':
                    _, completed_files, total_files = task
                    global_progress = (completed_files / total_files) * 100
                    global_progress = min(global_progress, 100)  # Garantir que não ultrapasse 100%
                    self.progress_bar['value'] = global_progress
                    self.lbl_progress.config(text=f"{int(global_progress)}%")
                elif task[0] == 'update_status':
                    _, message, color = task
                    self.update_status(message, color)
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def restart_download(self):
        # Verificar se o executor foi encerrado e recriá-lo, se necessário
        if self.executor._shutdown:
            self.executor = ThreadPoolExecutor(max_workers=self.config.get("max_downloads", 3))
            logging.info("Executor recriado para permitir novos downloads.")

        # Obter os itens selecionados na Treeview
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Aviso", "Nenhum item selecionado para reiniciar o download.")
            return

        for item in selected_items:
            # Obter o status atual do download
            status = self.tree.set(item, "Status")
            
            # Verificar se o download pode ser reiniciado
            if status in ["Falhou", "Parado", "Concluído", "Existente"]:
                # Perguntar se deseja sobrescrever o arquivo existente, se já foi baixado
                overwrite = False
                if status in ["Concluído", "Existente"] and os.path.exists(item):
                    resposta = messagebox.askyesno(
                        "Sobrescrever Arquivo",
                        f"O arquivo '{os.path.basename(item)}' já foi baixado. Deseja baixá-lo novamente e sobrescrevê-lo?"
                    )
                    if resposta:
                        overwrite = True
                    else:
                        continue  # Pular este item se o usuário não deseja sobrescrever

                # Resetar o status e progresso na interface
                self.tree.set(item, "Progress", "0%")
                self.tree.set(item, "Status", "Iniciando")
                self.tree.set(item, "Speed", "0 KB/s")
                self.tree.set(item, "ETA", "N/A")
                self.tree.item(item, tags=('downloading',))

                # Obter a URL do vídeo a partir do dicionário download_urls
                if item in self.download_urls:
                    video_url = self.download_urls[item]
                    # Submeter o download ao executor
                    future = self.executor.submit(
                        self.download_video,
                        video_url,
                        item,
                        self.update_progress,
                        self.stop_event,
                        self.pause_event,
                        overwrite=overwrite
                    )
                    self.futures[future] = item
                    logging.info(f"Download reiniciado para: {item}")
                else:
                    messagebox.showwarning("Aviso", "URL do vídeo não encontrada para reiniciar o download.")

    def cancel_download(self):
        selected_items = self.tree.selection()
        for item in selected_items:
            status = self.tree.set(item, "Status")
            if status in ["Baixando", "Iniciando", "Pausado"]:
                # Remover a URL e cancelar o download
                if item in self.download_urls:
                    del self.download_urls[item]
                # Cancelar o futuro associado
                for future, path in list(self.futures.items()):
                    if path == item:
                        future.cancel()
                        del self.futures[future]
                        break
                self.tree.set(item, "Status", "Cancelado")
                self.tree.set(item, "Speed", "0 KB/s")
                self.tree.set(item, "ETA", "N/A")
                self.tree.item(item, tags=('canceled',))
                logging.info(f"Download cancelado: {item}")
                # Opcional: Notificação de cancelamento
                # self.notify_user("Download Cancelado", f"O download de '{os.path.basename(item)}' foi cancelado.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DownloadManagerApp(root)
    root.mainloop()
