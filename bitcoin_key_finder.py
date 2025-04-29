import time
import secrets
import ecdsa
import hashlib
import base58
import sqlite3
import threading
import os
import sys

# ASCII Banner
from colorama import Fore, Style

def print_banner():
    banner = f"""{Fore.GREEN}
  ____  _     _     _           _           _____  _           _ _           
 | __ )(_) __| |__ (_) ___  ___| |_ ___    |  ___|(_)_ __   __| (_)_ __  ___ 
 |  _ \| |/ _| '_ \| |/ _ \/ __| __/ _ \   | |_   | | '_ \ / _` | | '_ \/ __|
 | |_) | | (_| | | | |  __/ (__| || (_) |  |  _|  | | | | | (_| | | | | \__ \\
 |____/|_|\__,_| |_|_|\___|\___|\__\___( ) |_|    |_|_| |_|\__,_|_|_| |_|___/
                                    |/                        |_|             
    {Style.RESET_ALL}"""
    print(banner)
    print(f"{Fore.GREEN}Bitcoin Private Key FINDER{Style.RESET_ALL}")
    print(f"{Fore.GREEN}==================================={Style.RESET_ALL}")

# Bitcoin address generation from private key
def private_key_to_address(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()

    sha256_1 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_1)
    hashed_public_key = ripemd160.digest()

    versioned_payload = b'\x00' + hashed_public_key
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    address_bytes = versioned_payload + checksum
    address = base58.b58encode(address_bytes).decode()
    return address

# Random private key generator
def generate_private_key():
    return secrets.token_hex(32)  # 32 bytes = 256 bits

# Benchmark function
def benchmark(num_keys=100000):
    start_time = time.time()
    for _ in range(num_keys):
        priv_key = generate_private_key()
        address = private_key_to_address(priv_key)
    end_time = time.time()

    elapsed_time = end_time - start_time
    keys_per_second = num_keys / elapsed_time
    print(f"Benchmark finished. Time taken: {elapsed_time:.2f} seconds")
    print(f"Keys generated per second: {keys_per_second:.2f}")

# Scan for keys in the database
def scan_for_keys(db_file='bitcoin_addresses.db', log_file='found_keys.txt', num_threads=8):
    print(f"Scanning database: {db_file} using {num_threads} threads...")

    # Connect to database (each thread must use its own connection)
    def create_db_connection():
        return sqlite3.connect(db_file, check_same_thread=False)

    # Thread worker
    def worker(thread_id):
        global checked_keys_count, found_keys_count

        conn = create_db_connection()
        cursor = conn.cursor()

        while True:
            priv_key = generate_private_key()
            address = private_key_to_address(priv_key)

            cursor.execute('SELECT 1 FROM addresses WHERE address = ?', (address,))
            found = cursor.fetchone()

            if found:
                found_keys_count += 1
                print(f"[FOUND] Address: {address} | Private Key: {priv_key}")
                with open(log_file, 'a') as f:
                    f.write(f"Address: {address} | Private Key: {priv_key}\n")
            else:
                print(f"[{thread_id}] {address} not found", end='\r')

            checked_keys_count += 1

    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# Command-line menu
def show_menu():
    print("\nChoose an option:")
    print("1. Benchmark (Test private key generation speed)")
    print("2. Scan Bitcoin Addresses in DB")
    print("3. Exit")

# Main function
def main():
    os.system("cls" if os.name == "nt" else "clear")
    print_banner()
    
    while True:
        show_menu()
        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            num_keys = int(input("Enter the number of keys to benchmark: "))
            benchmark(num_keys)

        elif choice == '2':
            scan_for_keys()

        elif choice == '3':
            print("Exiting program...")
            sys.exit()

        else:
            print("Invalid choice, please try again.")

if __name__ == '__main__':
    main()
