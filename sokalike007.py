import os
import json
from datetime import datetime
import random
from urllib.request import Request, urlopen
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import zlib

class AdvancedEncryption:
    def __init__(self):
        self._k1 = bytes([65, 88, 121, 101, 112, 110, 99, 107, 113, 119, 101, 114, 116, 121, 117, 105])
        self._k2 = bytes([random.randint(1, 255) for _ in range(16)])
        self._k3 = bytes([83, 69, 67, 82, 69, 84, 75, 69, 89, 49, 50, 51, 52, 53, 54, 55])
        self._iv = bytes([random.randint(1, 255) for _ in range(16)])
        self._s1 = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3]
        self._s2 = [2, 7, 1, 8, 2, 8, 1, 8, 4, 5, 9, 0, 4, 5, 2, 3]
        self._xor_key = bytes([0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
        self._url_components = {
            'scheme': [104, 116, 116, 112, 115, 58, 47, 47],
            'domain': [113, 117, 111, 116, 101, 120, 97, 112, 105],
            'tld': [112, 121, 116, 104, 111, 110, 97, 121, 119, 104, 101, 114, 101],
            'path': [113, 117, 111, 116, 101, 120, 46, 105, 110]
        }

    def _xor_encrypt(self, data):
        result = bytearray()
        for i, b in enumerate(data):
            result.append(b ^ self._xor_key[i % len(self._xor_key)])
        return bytes(result)

    def _custom_encode(self, data):
        result = []
        for i, b in enumerate(data):
            x = (b + self._s1[i % 16] + self._s2[i % 16]) % 256
            result.append(x)
        return bytes(result)

    def _custom_decode(self, data):
        result = []
        for i, b in enumerate(data):
            x = (b - self._s1[i % 16] - self._s2[i % 16]) % 256
            result.append(x)
        return bytes(result)

    def _build_url(self):
        url_parts = []
        for component in ['scheme', 'domain', 'tld', 'path']:
            decoded = bytes(self._url_components[component])
            url_parts.append(decoded.decode())

        return f"{url_parts[0]}{url_parts[1]}.{url_parts[2]}.com/{url_parts[3]}"

    def encrypt(self, text):
        data = self._xor_encrypt(text.encode())
        compressed = zlib.compress(data)
        cipher1 = AES.new(self._k1, AES.MODE_CBC, self._iv)
        ct1 = cipher1.encrypt(pad(compressed, AES.block_size))
        ct2 = self._custom_encode(ct1)
        cipher2 = AES.new(self._k2, AES.MODE_CBC, self._iv)
        ct3 = cipher2.encrypt(pad(ct2, AES.block_size))
        cipher3 = AES.new(self._k3, AES.MODE_CBC, self._iv)
        ct4 = cipher3.encrypt(pad(ct3, AES.block_size))
        return base64.b85encode(ct4).decode()

    def decrypt(self, enc_text):
        try:
            ct4 = base64.b85decode(enc_text.encode())
            cipher3 = AES.new(self._k3, AES.MODE_CBC, self._iv)
            ct3 = unpad(cipher3.decrypt(ct4), AES.block_size)
            cipher2 = AES.new(self._k2, AES.MODE_CBC, self._iv)
            ct2 = unpad(cipher2.decrypt(ct3), AES.block_size)
            ct1 = self._custom_decode(ct2)
            cipher1 = AES.new(self._k1, AES.MODE_CBC, self._iv)
            compressed = unpad(cipher1.decrypt(ct1), AES.block_size)
            data = zlib.decompress(compressed)
            text = self._xor_encrypt(data)
            return text.decode()
        except:
            return ""

class SignalGenerator:
    def __init__(self):
        self._security = AdvancedEncryption()
        self._key = bytes([random.randint(1, 255) for _ in range(32)])
        self._otc_pairs = [
            "AMERICAN-OTC", "AUDCHF-OTC", "AUDJPY-OTC", "AUDNZD-OTC", "AUDUSD-OTC",
            "BINANCE-COIN-OTC", "BITCOIN-OTC", "BITCOIN-CASH-OTC", "BOEING-OTC",
            "BONK-OTC", "CADCHF-OTC", "CADJPY-OTC", "CHFJPY-OTC", "DOGECOIN-OTC",
            "DOGWIFHAT-OTC", "ETHEREUM-OTC", "EURAUD-OTC", "EURCAD-OTC", "EURCHF-OTC",
            "EURGBP-OTC", "EURJPY-OTC", "EURNZD-OTC", "EURSGD-OTC", "EURUSD-OTC",
            "FACEBOOK-OTC", "FLOKI-OTC", "GBPAUD-OTC", "GBPCAD-OTC", "GBPCHF-OTC",
            "GBPNZD-OTC", "GBPUSD-OTC", "GOLD-OTC", "INTEL-OTC", "JOHNSON-OTC",
            "LITECOIN-OTC", "MCDONALDS-OTC", "MICROSOFT-OTC", "NZDCAD-OTC", "NZDCHF-OTC",
            "NZDJPY-OTC", "NZDUSD-OTC", "PEPE-OTC", "PFIZER-OTC", "RIPPLE-OTC", "SHIBA-INU-OTC",
            "SILVER-OTC", "SOLANA-OTC", "TONCOIN-OTC", "TRON-OTC", "TRUMP-OTC",
            "UKBRENT-OTC", "USCRUDE-OTC", "USDARS-OTC", "USDBDT-OTC", "USDBRL-OTC",
            "USDCAD-OTC", "USDCHF-OTC", "USDCOP-OTC", "USDDZD-OTC", "USDEGP-OTC",
            "USDIDR-OTC", "USDJPY-OTC", "USDMXN-OTC", "USDNGN-OTC", "USDPHP-OTC",
            "USDPKR-OTC", "USDTRY-OTC"
        ]

        self._real_pairs = [
            "EURGBP", "EURUSD", "USDCAD", "USDJPY", "EURJPY",
            "EURCAD", "GBPAUD", "CADJPY", "AUDJPY", "AUDCAD",
            "AUDUSD", "GBPUSD", "GBPCHF", "USDCHF"
        ]

    def _sign_request(self, data):
        timestamp = str(int(datetime.now().timestamp()))
        nonce = hex(random.getrandbits(128))[2:]
        message = json.dumps(data).encode()
        signature = hmac.new(self._key, message + timestamp.encode() + nonce.encode(), hashlib.sha512).hexdigest()

        return {
            'X-Signature': signature,
            'X-Timestamp': timestamp,
            'X-Nonce': nonce
        }, message

    def _clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def _print_colored(self, text, color=None, style=None):
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'blue': '\033[94m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'purple': '\033[95m'
        }
        styles = {
            'bold': '\033[1m',
            'reset': '\033[0m'
        }

        prefix = ''
        if color in colors:
            prefix += colors[color]
        if style in styles:
            prefix += styles[style]

        suffix = styles['reset'] if prefix else ''
        print(f"{prefix}{text}{suffix}")

    # ==========================================
    # NEW UPDATED BANNER (your custom ASCII art)
    # ==========================================
    def _show_banner(self):
        self._clear()

        banner = r"""
 $$$$$$\            $$\        $$$$$$\  $$\ $$\ $$\                  $$$$$$\   $$$$$$\  $$$$$$$$\ 
$$  __$$\           $$ |      $$  __$$\ $$ |\__|$$ |                $$$ __$$\ $$$ __$$\ \____$$  |
$$ /  \__| $$$$$$\  $$ |  $$\ $$ /  $$ |$$ |$$\ $$ |  $$\  $$$$$$\  $$$$\ $$ |$$$$\ $$ |    $$  / 
\$$$$$$\  $$  __$$\ $$ | $$  |$$$$$$$$ |$$ |$$ |$$ | $$  |$$  __$$\ $$\$$\$$ |$$\$$\$$ |   $$  /  
 \____$$\ $$ /  $$ |$$$$$$  / $$  __$$ |$$ |$$ |$$$$$$  / $$$$$$$$ |$$ \$$$$ |$$ \$$$$ |  $$  /   
$$\   $$ |$$ |  $$ |$$  _$$<  $$ |  $$ |$$ |$$ |$$  _$$<  $$   ____|$$ |\$$$ |$$ |\$$$ | $$  /    
\$$$$$$  |\$$$$$$  |$$ | \$$\ $$ |  $$ |$$ |$$ |$$ | \$$\ \$$$$$$$\ \$$$$$$  /\$$$$$$  /$$  /     
 \______/  \______/ \__|  \__|\__|  \__|\__|\__|\__|  \__| \_______| \______/  \______/ \__/      
"""

        print("\033[96m\033[1m" + banner + "\033[0m")

        self._print_colored("\n╭──────────────────────────────────────────────────────────╮", 'purple')
        self._print_colored("│  WARNING! Check direction before generating signals      │", 'purple')
        self._print_colored("╰──────────────────────────────────────────────────────────╯\n", 'purple')


    # =========================================================

    def _get_user_inputs(self):
        self._clear()
        self._show_banner()

        self._print_colored("\n╭── Select Trading Environment ──╮", 'blue', 'bold')
        self._print_colored("│ 1. Premium Markets", 'green')
        self._print_colored("│ 2. Standard Markets", 'green')
        self._print_colored("╰────────────────────────────────╯", 'blue')

        market_choice = input("\nEnter your selection (1/2): ")

        pairs = self._otc_pairs if market_choice == "1" else self._real_pairs
        market_name = "Premium Markets" if market_choice == "1" else "Standard Markets"

        self._print_colored(f"\n╭── Selected Environment ──╮", 'blue', 'bold')
        self._print_colored(f"│ {market_name}", 'green')
        self._print_colored("╰──────────────────────────╯", 'blue')

        self._print_colored("\nAvailable Trading Pairs:", 'blue', 'bold')
        column_width = len(pairs) // 3 + (len(pairs) % 3 > 0)
        for i in range(column_width):
            row = []
            for j in range(3):
                idx = i + j * column_width
                if idx < len(pairs):
                    row.append(f"{idx + 1}. {pairs[idx]:<20}")
            self._print_colored("".join(row), 'green', 'bold')

        pair_choice = input("\nEnter pair numbers (e.g., 1,2,3) or 'ALL': ")
        if pair_choice.upper() == "ALL":
            selected_pairs = pairs
        else:
            try:
                selected_pairs = [pairs[int(i.strip()) - 1] for i in pair_choice.split(",")]
            except:
                self._print_colored("Invalid selection! Using first pair as default.", 'red')
                selected_pairs = [pairs[0]]

        self._print_colored("\n╭── Trading Mode ──╮", 'blue', 'bold')
        self._print_colored("│ 1. Stealth Mode  │", 'green')
        self._print_colored("│ 2. Classic Mode  │", 'green')
        self._print_colored("╰──────────────────╯", 'blue')
        mode = input("\nSelect mode (1/2): ")
        selected_mode = "Stealth Mode" if mode == "1" else "Classic Mode"

        self._print_colored("\n╭── Signal Filter ──╮", 'blue', 'bold')
        self._print_colored("│ 1. Smart Filter   │", 'green')
        self._print_colored("│ 2. Trend Filter   │", 'green')
        self._print_colored("╰───────────────────╯", 'blue')
        filter_choice = input("\nSelect filter (1/2): ")
        selected_filter = "Smart Filter" if filter_choice == "1" else "Trend Filter"

        self._print_colored("\n╭── Configuration Summary ──╮", 'blue', 'bold')
        self._print_colored(f"│ Mode: {selected_mode}", 'green')
        self._print_colored(f"│ Filter: {selected_filter}", 'green')
        self._print_colored("╰───────────────────────────╯", 'blue')

        self._print_colored("\n╭── Signal Parameters ──╮", 'blue', 'bold')
        try:
            num_signals = int(input("  Number of signals: "))
        except:
            self._print_colored("Invalid number! Using 10 signals as default.", 'red')
            num_signals = 10

        start_time = input("  Start time (HH:MM): ")
        end_time = input("  End time (HH:MM): ")
        trend = input("  Market trend (up/down/neutral): ").strip().lower()
        self._print_colored("╰──────────────────────────────────────╯", 'blue')

        return {
            "selected_pairs": selected_pairs,
            "num_signals": num_signals,
            "start_time": start_time,
            "end_time": end_time,
            "trend": trend
        }

    def _send_request(self, inputs):
        headers, data = self._sign_request(inputs)
        headers['Content-Type'] = 'application/json'

        try:
            self._print_colored("\nConnecting to Quotex server...", 'cyan')
            url = self._security._build_url()
            req = Request(url, data, headers)
            with urlopen(req) as response:
                signals = json.loads(response.read())

                if isinstance(signals, dict) and 'error' in signals:
                    self._print_colored(f"Error: {signals['error']}", 'red')
                    return

                self._print_colored(f"\n{'=' * 45}", 'green')
                self._print_colored("Generating signals for all markets", 'green')
                self._print_colored(f"{'=' * 45}", 'green')

                for signal in signals:
                    self._print_colored(signal, 'white')
                self._print_colored(f"{'=' * 45}", 'green')

        except Exception as e:
            self._print_colored(f"Error: Could not connect to Quotex server - {str(e)}", 'red')

    def run(self):
        inputs = self._get_user_inputs()
        self._send_request(inputs)

if __name__ == "__main__":
    SignalGenerator().run()
