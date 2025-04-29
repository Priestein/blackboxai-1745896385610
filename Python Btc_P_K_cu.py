import time
import secrets
import ecdsa
import hashlib
import base58
import sqlite3
import threading
import os
import sys
import atexit
from concurrent.futures import ThreadPoolExecutor # Not strictly used for the main loop, but good practice
from colorama import init, Fore, Style
from tqdm import tqdm
try:
    import msvcrt # For non-blocking input on Windows
except ImportError:
    msvcrt = None # Will be None on non-Windows platforms

# --- Initialize Colorama ---
init(autoreset=True)

# --- Configuration ---
DB_FILE = 'bitcoin_addresses.db'
LOG_FILE = 'found_keys.txt'
NUM_THREADS = 12 # Adjust based on your CPU (consider os.cpu_count())
# tqdm update interval (updates the bar after roughly this many keys are processed *globally*)
TQDM_UPDATE_INTERVAL = 5000

# --- Global Variables & Locks ---
checked_keys_count = 0
found_keys_count = 0
start_scan_time = time.time()
count_lock = threading.Lock()
log_lock = threading.Lock()
stop_event = threading.Event() # For stopping (Ctrl+C or found key)
pause_event = threading.Event() # For pausing/resuming
is_paused = False # Track pause state for status display

# --- Global TQDM Progress Bar ---
pbar = None

# --- ASCII Banner ---
def print_banner():
    banner = f"""
{Fore.GREEN}{Style.BRIGHT}  ____  _     _     _           _           _____        _     _
 | __ )(_) __| |__ (_) ___  ___| |_ ___    |_   _|__     | |__ (_)_ __
 |  _ \| |/ _| '_ \| |/ _ \/ __| __/ _ \    | |/ _ \    | '_ \| | '_ \\
 | |_) | | (_| | | | |  __/ (__| || (_) |   | |  __/    | | | | | |_) |
 |____/|_|\__,_| |_|_|\___|\___|\__\___( )   |_|\___|    |_| |_|_| .__/
{Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}                                    |/                        |_|
    """
    print(banner)
    print(f"{Fore.GREEN}{Style.BRIGHT}Bitcoin Private Key Finder (CPU Multi-Threaded){Style.RESET_ALL}")
    print("==============================================")
    print(f"{Fore.GREEN}{Style.BRIGHT}WARNING: Finding a specific key randomly is computationally infeasible.")
    print(f"{Style.RESET_ALL}This tool is for educational/demonstration purposes.")
    print("==============================================")

# --- Bitcoin Address Generation ---
def private_key_to_address(private_key_hex):
    """Converts a private key hex string to a compressed Bitcoin address."""
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        # Create signing key (uncompressed)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        # Get verifying key (public key)
        vk = sk.get_verifying_key()

        # --- Generate COMPRESSED Public Key ---
        # Check if y-coordinate is even or odd
        if vk.pubkey.point.y() % 2 == 0:
            public_key_bytes_compressed = b'\x02' + vk.pubkey.point.x().to_bytes(32, 'big')
        else:
            public_key_bytes_compressed = b'\x03' + vk.pubkey.point.x().to_bytes(32, 'big')

        # --- Standard Address Derivation Steps (from compressed key) ---
        # 1. SHA-256 hash of the compressed public key
        sha256_1 = hashlib.sha256(public_key_bytes_compressed).digest()
        # 2. RIPEMD-160 hash of the SHA-256 hash
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_1)
        hashed_public_key = ripemd160.digest()
        # 3. Add version byte (0x00 for Mainnet)
        versioned_payload = b'\x00' + hashed_public_key
        # 4. SHA-256 hash of the versioned payload
        sha256_2 = hashlib.sha256(versioned_payload).digest()
        # 5. SHA-256 hash of the previous hash
        sha256_3 = hashlib.sha256(sha256_2).digest()
        # 6. Take the first 4 bytes as checksum
        checksum = sha256_3[:4]
        # 7. Append checksum to the versioned payload
        address_bytes = versioned_payload + checksum
        # 8. Base58Check encode
        address = base58.b58encode(address_bytes).decode('utf-8')
        return address
    except Exception:
        # pbar.write(f"Error generating address for key {private_key_hex}: {e}") # Optional debug
        return None # Return None on any error during generation

# --- Random Private Key Generator ---
def generate_private_key():
    """Generates a cryptographically secure 256-bit private key hex string."""
    return secrets.token_hex(32)

# --- Benchmark Function ---
def benchmark(num_keys=100000):
    """Benchmarks key generation and address derivation speed on a single core."""
    print(f"\n{Fore.CYAN}Starting benchmark with {num_keys:,} keys...{Style.RESET_ALL}")
    start_time = time.time()
    keys_generated = 0
    local_pbar = None # Use a local pbar for benchmark

    try:
        # Use tqdm for benchmark progress too
        with tqdm(total=num_keys, unit=" keys", desc="Benchmarking", dynamic_ncols=True) as local_pbar:
            for _ in range(num_keys):
                priv_key = generate_private_key()
                address = private_key_to_address(priv_key)
                if address: # Only count successful derivations
                    keys_generated += 1
                local_pbar.update(1) # Update bar by 1 for each key attempted
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user.")
    finally:
        if local_pbar:
            local_pbar.close() # Ensure bar is closed

    end_time = time.time()
    elapsed_time = end_time - start_time

    print("-" * 30) # Separator
    if elapsed_time > 0 and keys_generated > 0:
        keys_per_second = keys_generated / elapsed_time
        print(f"{Fore.GREEN}Successfully derived {keys_generated:,} addresses.")
        print(f"Time taken: {elapsed_time:.2f} seconds")
        print(f"Keys/Addresses per second (single core estimate): {keys_per_second:,.2f}")
    elif keys_generated == 0 and elapsed_time > 0:
         print(f"{Fore.YELLOW}Generated {num_keys:,} keys, but failed to derive any addresses in {elapsed_time:.2f}s.")
         print(f"{Fore.YELLOW}Check 'private_key_to_address' function for errors.")
    else:
        print(f"{Fore.RED}Benchmark did not run long enough or failed.")
    print("-" * 30) # Separator

# --- Database Setup ---
def setup_database(db_path=DB_FILE, example_addresses=None):
    """Creates the database and table if they don't exist, adds example addresses."""
    if example_addresses is None:
        # Example: The first Bitcoin address and a known puzzle address
        example_addresses = ["13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"]
    print(f"Setting up database: {db_path}")
    added_count = 0
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS addresses (address TEXT PRIMARY KEY)')
        # Consider adding index after bulk inserts if loading many addresses initially
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_address ON addresses (address)')
        if example_addresses:
            for addr in example_addresses:
                try:
                    # Use INSERT OR IGNORE to avoid errors if address already exists
                    cursor.execute("INSERT OR IGNORE INTO addresses (address) VALUES (?)", (addr,))
                    if cursor.rowcount > 0: # Check if a row was actually inserted
                         added_count += 1
                except sqlite3.Error as e:
                    # Log error but continue trying other addresses
                    print(f"{Fore.YELLOW}Warning: Error inserting address {addr}: {e}")
        conn.commit() # Commit changes
        print(f"Database setup/check complete. Added {added_count} new unique example addresses.")
        print(f"Ensure '{db_path}' contains the target addresses you want to search for.")
    except sqlite3.Error as e:
        print(f"{Fore.RED}Database error during setup: {e}")
        # Optionally exit if DB setup fails critically
        # sys.exit(1)
    finally:
        if conn:
            conn.close()

# --- Scan Function ---
def scan_for_keys():
    """Starts the multi-threaded key generation and database checking process."""
    # Declare globals that this function *assigns* to or modifies state of
    global is_paused, checked_keys_count, found_keys_count, start_scan_time, pbar

    if not os.path.exists(DB_FILE):
        print(f"{Fore.YELLOW}Database file '{DB_FILE}' not found.")
        setup_database(DB_FILE) # Attempt to set it up
        # Check again after setup attempt
        if not os.path.exists(DB_FILE):
            print(f"{Fore.RED}Failed to create or find database '{DB_FILE}'. Exiting scan.")
            return # Exit the scan function

    print(f"\n{Fore.CYAN}Starting scan using {NUM_THREADS} CPU threads...{Style.RESET_ALL}")
    print(f"Checking against addresses in database: {DB_FILE}")
    print(f"Logging found keys to: {LOG_FILE}")
    if msvcrt:
        print(f"{Fore.YELLOW}Press 'P' to Pause/Resume | Press Ctrl+C to Stop{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Press Ctrl+C to Stop (Pause/Resume not available on this OS){Style.RESET_ALL}")

    # Reset counts, timers, and events for a fresh scan
    checked_keys_count = 0
    found_keys_count = 0
    start_scan_time = time.time()
    stop_event.clear()
    pause_event.clear() # Ensure starts in running state (not paused)
    is_paused = False   # Ensure starts in running state

    # Initialize tqdm progress bar for the scan
    # total=0 makes it run indefinitely; smoothing reduces fluctuations in rate estimate
    pbar = tqdm(total=0, unit=" keys", desc="Scanning", dynamic_ncols=True, smoothing=0.05, position=0, leave=True)

    def create_db_connection():
        """Creates a thread-local SQLite connection."""
        # check_same_thread=False is required for separate connections per thread
        # timeout helps prevent deadlocks if the DB is busy (though less common with read-only)
        return sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10)

    # --- Thread worker function ---
    def worker(thread_id):
        global checked_keys_count
        global found_keys_count

        conn = None
        cursor = None
        local_batch_count = 0 # Count keys processed locally before updating global state/pbar

        try:
            conn = create_db_connection()
            cursor = conn.cursor()

            while not stop_event.is_set():
                # --- Pause Handling ---
                if pause_event.is_set():
                    # Efficiently wait until the pause event is cleared
                    pause_event.wait()
                    # Optional: Re-check stop_event immediately after resuming in case Ctrl+C happened during pause
                    if stop_event.is_set():
                        break
                    continue # Go to the start of the loop

                # --- Key Generation and Address Derivation ---
                priv_key = generate_private_key()
                address = private_key_to_address(priv_key)

                # Skip if address generation failed (should be rare)
                if address is None:
                    continue

                # --- Database Check ---
                try:
                    # Check if the derived address exists in the database
                    cursor.execute('SELECT 1 FROM addresses WHERE address = ? LIMIT 1', (address,))
                    found = cursor.fetchone()
                    local_batch_count += 1 # Count keys processed locally before updating global state/pbar

                    # --- Key Found Handling ---
                    if found:
                        current_found_count = 0 # Temp var to hold count safely
                        with count_lock: # --- LOCK START ---
                            found_keys_count += 1          # Modify global count safely
                            current_found_count = found_keys_count # Get the updated value
                        # --- LOCK END ---
                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                        log_message = f"Timestamp: {timestamp} | Address: {address} | Private Key: {priv_key}"

                        # Print to console (using pbar.write to avoid conflicts)
                        pbar.write(f"{Fore.GREEN}\n--- FOUND KEY ({current_found_count}) ---")
                        pbar.write(log_message)
                        pbar.write(f"-----------------{Style.RESET_ALL}")

                        # Log to file safely
                        with log_lock: # --- LOCK START ---
                            with open(LOG_FILE, 'a') as f:
                                f.write(log_message + "\n")
                        # --- LOCK END ---

                        # Update tqdm postfix immediately to show the find
                        # Reading found_keys_count here without lock is usually okay just for display
                        # but using the locked value is safer
                        pbar.set_postfix(found=f"{Fore.GREEN}{current_found_count}{Style.RESET_ALL}", refresh=True)

                        # Optional: Uncomment to stop all threads once a key is found
                        # stop_event.set()
                        # pbar.write(f"{Fore.YELLOW}Key found! Signaling stop to all threads...")

                    # --- Progress Update ---
                    # Update global count and pbar periodically in batches
                    # Adjust threshold for desired update frequency vs lock contention
                    local_update_threshold = max(100, TQDM_UPDATE_INTERVAL // NUM_THREADS)
                    if local_batch_count >= local_update_threshold:
                        batch_to_add = local_batch_count # Store value before lock
                        current_global_checked = 0 # Temp vars
                        current_global_found = 0
                        with count_lock: # --- LOCK START ---
                            checked_keys_count += batch_to_add # Modify global count safely
                            current_global_checked = checked_keys_count # Get updated value
                            current_global_found = found_keys_count # Get current found count
                            local_batch_count = 0 # Reset local counter *inside* lock
                            pbar.update(batch_to_add) # Update tqdm bar safely
                        # --- LOCK END ---
                        # Update postfix outside lock using values captured inside
                        # Only update found count in postfix if it hasn't changed recently by a find
                        if not pbar.postfix or current_global_found != int(pbar.postfix.split('=')[-1].replace(Fore.GREEN,'').replace(Style.RESET_ALL,'')):
                           pbar.set_postfix(found=current_global_found, refresh=False)


                # --- Database Error Handling ---
                except sqlite3.Error as db_err:
                    pbar.write(f"{Fore.RED}\n[Thread {thread_id}] Database Error: {db_err}. Attempting reconnect...{Style.RESET_ALL}")
                    if conn:
                        try: conn.close()
                        except Exception: pass # Ignore error closing faulty connection
                    conn, cursor = None, None # Reset connection variables
                    time.sleep(5) # Wait before retrying
                    try:
                        conn = create_db_connection()
                        cursor = conn.cursor()
                        pbar.write(f"{Fore.GREEN}[Thread {thread_id}] Database Reconnected.{Style.RESET_ALL}")
                    except sqlite3.Error as reconn_err:
                        pbar.write(f"{Fore.RED}\n[Thread {thread_id}] DB Reconnect Failed: {reconn_err}. Stopping thread.{Style.RESET_ALL}")
                        stop_event.set() # Signal stop if reconnect fails persistently
                        break # Exit the while loop for this thread

                # --- Other Unexpected Error Handling ---
                except Exception as e:
                    pbar.write(f"{Fore.RED}\n[Thread {thread_id}] Unexpected Error ({type(e).__name__}): {e}{Style.RESET_ALL}")
                    # For deeper debugging, uncomment the next lines:
                    # import traceback
                    # pbar.write(traceback.format_exc())
                    time.sleep(1) # Avoid busy-looping on unexpected errors

        # --- Thread Initialization Error Handling ---
        except sqlite3.Error as initial_db_err:
            # Handle error if the *initial* connection fails
            err_msg = f"{Fore.RED}\n[Thread {thread_id}] Failed to connect to DB on start: {initial_db_err}{Style.RESET_ALL}"
            if pbar: pbar.write(err_msg)
            else: print(err_msg)
            # Consider stopping if initial connection fails, maybe signal main thread?
            # stop_event.set() # Option: stop everything if one thread can't connect

        # --- Thread Cleanup ---
        finally:
            if conn:
                try: conn.close()
                except Exception: pass # Ignore errors during final close
            # Optional debug message:
            # if pbar: pbar.write(f"[Thread {thread_id}] Worker stopping.")

    # --- Start Worker Threads ---
    threads = []
    for i in range(NUM_THREADS):
        # Create and start each thread
        t = threading.Thread(target=worker, args=(i+1,), daemon=True) # Start thread_id from 1
        t.start()
        threads.append(t)

    # --- Main thread: Handle Input (Pause/Resume/Stop) and Monitor ---
    try:
        while True:
             # Check if any worker thread is still alive
             if not any(t.is_alive() for t in threads):
                  pbar.write("\nAll worker threads seem to have finished.")
                  break # Exit loop if all workers are done

             # Check for keyboard input (non-blocking) - Windows specific
             if msvcrt and msvcrt.kbhit():
                  try:
                      char = msvcrt.getch().decode('utf-8').lower()
                      if char == 'p':
                          if pause_event.is_set(): # If paused -> resume
                              pause_event.clear()
                              is_paused = False # Update state
                              if pbar:
                                  pbar.write(f"{Fore.YELLOW}>>> Scan Resumed <<<")
                                  pbar.set_description("Scanning")
                          else: # If running -> pause
                              pause_event.set()
                              is_paused = True # Update state
                              if pbar:
                                  pbar.write(f"{Fore.YELLOW}>>> Scan Paused <<< (Press 'P' to Resume)")
                                  pbar.set_description(f"{Fore.YELLOW}Paused")
                  except UnicodeDecodeError:
                      pass # Ignore characters that can't be decoded
                  except Exception as input_err:
                      pbar.write(f"\nError processing input: {input_err}")


             # Check if stop event was set (e.g., by a worker finding a key)
             if stop_event.is_set():
                  if not is_paused: # Only print stopping message if not already paused
                       pbar.write(f"\n{Fore.YELLOW}Stop signal received! Stopping threads...{Style.RESET_ALL}")
                  break # Exit main monitoring loop

             # Update pause status in tqdm description if needed (covers cases where state changes without input)
             if pbar:
                 current_desc = pbar.desc or ""
                 if is_paused and "Paused" not in current_desc:
                     pbar.set_description(f"{Fore.YELLOW}Paused")
                 elif not is_paused and "Scanning" not in current_desc:
                     pbar.set_description("Scanning")

             # Sleep briefly to prevent the main thread from consuming 100% CPU
             time.sleep(0.1)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Ctrl+C detected! Stopping threads gracefully...{Style.RESET_ALL}")
        stop_event.set() # Signal threads to stop
        # If paused during Ctrl+C, ensure threads can see the stop_event
        if is_paused:
            pause_event.clear()
            is_paused = False # Update state

    finally:
        # --- Cleanup after loop exits (Ctrl+C, found key, or all threads finish) ---
        if not stop_event.is_set():
            stop_event.set() # Ensure stop is signaled if not already

        if pause_event.is_set(): # If ended while paused, clear event so threads can exit join
            pause_event.clear()

        print("\nWaiting for worker threads to finish...")
        # Wait for all threads to complete, with a timeout
        for t in threads:
            t.join(timeout=5.0) # Give threads a few seconds to finish

        # Close the progress bar cleanly
        if pbar:
            pbar.close()

        print(f"\n{Fore.CYAN}{'-'*10} Scan Summary {'-'*10}{Style.RESET_ALL}")
        final_elapsed = time.time() - start_scan_time
        # Read final counts safely using the lock
        with count_lock:
             final_checked = checked_keys_count
             final_found = found_keys_count

        print(f"Total keys checked: {final_checked:,}")
        print(f"Total keys found: {Fore.GREEN}{final_found}{Style.RESET_ALL}")
        print(f"Total time: {final_elapsed:.2f} seconds")

        # Calculate and display average rate, handle division by zero
        if final_elapsed > 0 and final_checked > 0:
            final_rate = final_checked / final_elapsed
            print(f"Average rate: {final_rate:,.2f} keys/sec")
        else:
            print("Average rate: N/A (Scan too short or no keys checked)")
        print(f"{Fore.CYAN}{'-'*34}{Style.RESET_ALL}")


# --- Cleanup Function ---
def cleanup():
    """Function registered with atexit to run on program exit."""
    print("\nExiting program...")
    # Ensure threads are signaled to stop
    if not stop_event.is_set():
        stop_event.set()
    # If paused on exit, unpause to allow threads to terminate cleanly if waiting
    if is_paused: # Read global is_paused state
        pause_event.clear()

    # Attempt to close progress bar if it exists and wasn't closed
    if pbar and not pbar.disable:
        try:
            pbar.close()
        except Exception:
            pass # Ignore errors closing pbar during exit cleanup

    # Reset terminal colors
    init(autoreset=True)
    print("Cleanup finished.")

# Register the cleanup function to run automatically on exit
atexit.register(cleanup)

# --- Command-line Menu ---
def show_menu():
    """Displays the main menu options."""
    print("\nChoose an option:")
    print("1. Benchmark (Test key/address speed on one CPU core)")
    print("2. Scan Bitcoin Addresses in DB (Multi-Threaded CPU)")
    print("3. Setup/Add Example Addresses to Database")
    print("4. Exit")

# --- Main Execution ---
def main():
    """Main function to handle menu logic and start operations."""
    # Clear screen for better display
    os.system("cls" if os.name == "nt" else "clear")
    print_banner()

    # Initial database check/setup before showing menu
    if not os.path.exists(DB_FILE):
        print(f"{Fore.YELLOW}Database '{DB_FILE}' not found, running initial setup...{Style.RESET_ALL}")
        setup_database(DB_FILE) # Creates with examples if needed
        # Check if setup actually created the file
        if not os.path.exists(DB_FILE):
             print(f"{Fore.RED}Database setup failed. Please check permissions/path. Exiting.")
             sys.exit(1) # Exit if DB is critical and setup failed
    else:
        print(f"Using existing database: {DB_FILE}")
        # Optional: You could add a check here to see if the table exists
        # setup_database(DB_FILE, example_addresses=[]) # Run setup without examples to ensure table/index exist


    # --- Platform Specific Input Handling Check ---
    if os.name != 'nt' or msvcrt is None:
        print(f"\n{Fore.YELLOW}Note: Non-blocking pause/resume ('P' key) requires the 'msvcrt' module")
        print(f"      and is typically only available on Windows.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}      On this system, only Ctrl+C to stop the scan is actively monitored.{Style.RESET_ALL}")


    # --- Main Menu Loop ---
    while True:
        show_menu()
        choice = input("Enter your choice (1/2/3/4): ").strip()

        if choice == '1':
            try:
                # Default benchmark value
                default_bench_keys = 100000
                num_keys_str = input(f"Enter the number of keys to benchmark [default: {default_bench_keys:,}]: ")
                if not num_keys_str:
                    num_keys = default_bench_keys
                else:
                    num_keys = int(num_keys_str)

                if num_keys <= 0:
                    print(f"{Fore.RED}Please enter a positive number of keys.{Style.RESET_ALL}")
                else:
                    benchmark(num_keys)
            except ValueError:
                print(f"{Fore.RED}Invalid number entered. Please enter an integer.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}An error occurred during benchmark: {e}")

        elif choice == '2':
            # Start the main scanning process
            scan_for_keys()
            # After scan finishes (or is stopped), loop back to menu

        elif choice == '3':
            # Run database setup again (useful for adding more examples or ensuring structure)
            print("Re-running database setup...")
            # You might want to prompt the user if they want to add more specific addresses here
            setup_database(DB_FILE) # Re-runs setup, harmlessly adds examples if missing

        elif choice == '4':
            print("Exiting...")
            sys.exit(0) # Normal exit, atexit cleanup will run

        else:
            print(f"{Fore.RED}Invalid choice '{choice}', please try again.{Style.RESET_ALL}")

if __name__ == '__main__':
    # Set higher thread priority (optional, might require admin/root privileges)
    # Be cautious with this, it can make the system unresponsive
    # if os.name == 'nt':
    #     try:
    #         import psutil
    #         p = psutil.Process(os.getpid())
    #         p.nice(psutil.HIGH_PRIORITY_CLASS)
    #         print(f"{Fore.CYAN}Attempted to set high process priority (Windows).{Style.RESET_ALL}")
    #     except Exception as e:
    #         print(f"{Fore.YELLOW}Could not set high priority: {e}{Style.RESET_ALL}")
    # elif os.name == 'posix':
    #      try:
    #          os.nice(10) # Lower nice value = higher priority (range varies, e.g., -20 to 19)
    #          print(f"{Fore.CYAN}Attempted to increase process priority (POSIX nice).{Style.RESET_ALL}")
    #      except Exception as e:
    #          print(f"{Fore.YELLOW}Could not set nice value: {e}{Style.RESET_ALL}")

    main()

# --- END OF FILE Python Btc_P_K_cu.py ---
