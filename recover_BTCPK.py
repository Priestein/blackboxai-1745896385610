# --- START OF FILE Python Btc_P_K_cu.py ---

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
# These variables are shared across threads and need careful handling
checked_keys_count = 0
found_keys_count = 0
start_scan_time = time.time()
count_lock = threading.Lock() # Lock for protecting checked_keys_count and found_keys_count
log_lock = threading.Lock()   # Lock for protecting writes to the LOG_FILE
stop_event = threading.Event() # Event to signal all threads to stop
pause_event = threading.Event() # Event to signal threads to pause
is_paused = False # Global flag to track pause state for UI updates

# --- Global TQDM Progress Bar ---
pbar = None # Initialized when scan starts

# --- ASCII Banner ---
def print_banner():
    banner = f"""
{Fore.YELLOW}  ____  _     _     _           _           _____        _     _
 | __ )(_) __| |__ (_) ___  ___| |_ ___    |_   _|__     | |__ (_)_ __
 |  _ \| |/ _| '_ \| |/ _ \/ __| __/ _ \    | |/ _ \    | '_ \| | '_ \\
 | |_) | | (_| | | | |  __/ (__| || (_) |   | |  __/    | | | | | |_) |
 |____/|_|\__,_| |_|_|\___|\___|\__\___( )   |_|\___|    |_| |_|_| .__/
{Style.RESET_ALL}{Fore.CYAN}                                    |/                        |_|
    """
    print(banner)
    print(f"{Fore.CYAN}Bitcoin Private Key Finder (CPU Multi-Threaded){Style.RESET_ALL}")
    print("==============================================")
    print(f"{Fore.RED}WARNING: Finding a specific key randomly is computationally infeasible.")
    print(f"{Style.RESET_ALL}This tool is for educational/demonstration purposes.")
    print("==============================================")

# --- Bitcoin Address Generation ---
def private_key_to_address(private_key_hex):
    """Converts a private key hex string to a compressed Bitcoin address."""
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        # Create signing key using the SECP256k1 curve
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
        # Get the corresponding verifying key (public key)
        vk = sk.get_verifying_key()

        # Generate COMPRESSED Public Key (starts with 0x02 if y is even, 0x03 if odd)
        if vk.pubkey.point.y() % 2 == 0:
            public_key_bytes_compressed = b'\x02' + vk.pubkey.point.x().to_bytes(32, 'big')
        else:
            public_key_bytes_compressed = b'\x03' + vk.pubkey.point.x().to_bytes(32, 'big')

        # Standard Bitcoin Address Derivation Steps:
        # 1. SHA-256 hash of the compressed public key
        sha256_1 = hashlib.sha256(public_key_bytes_compressed).digest()
        # 2. RIPEMD-160 hash of the SHA-256 hash
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_1)
        hashed_public_key = ripemd160.digest()
        # 3. Add version byte (0x00 for Mainnet P2PKH)
        versioned_payload = b'\x00' + hashed_public_key
        # 4. Double SHA-256 hash for checksum
        sha256_2 = hashlib.sha256(versioned_payload).digest()
        sha256_3 = hashlib.sha256(sha256_2).digest()
        # 5. Take the first 4 bytes as checksum
        checksum = sha256_3[:4]
        # 6. Append checksum to the versioned payload
        address_bytes = versioned_payload + checksum
        # 7. Base58Check encode the result
        address = base58.b58encode(address_bytes).decode('utf-8')
        return address
    except Exception:
        # Silently return None if any error occurs during derivation
        # Could add logging here if needed for debugging invalid keys
        return None

# --- Random Private Key Generator ---
def generate_private_key():
    """Generates a cryptographically secure 256-bit private key hex string."""
    # 32 bytes = 256 bits
    return secrets.token_hex(32)

# --- Benchmark Function ---
def benchmark(num_keys=100000):
    """Benchmarks key generation and address derivation speed on a single core."""
    print(f"\n{Fore.CYAN}Starting benchmark with {num_keys:,} keys...{Style.RESET_ALL}")
    start_time = time.time()
    addresses_derived = 0 # Count successful derivations
    local_pbar = None # Use a local pbar instance for the benchmark

    try:
        # Use tqdm for benchmark progress
        with tqdm(total=num_keys, unit=" keys", desc="Benchmarking", dynamic_ncols=True, leave=False) as local_pbar:
            for i in range(num_keys):
                priv_key = generate_private_key()
                address = private_key_to_address(priv_key)
                if address: # Only count if address derivation was successful
                    addresses_derived += 1
                # Update progress bar based on keys attempted
                local_pbar.update(1)
                # Allow interruption
                if i % 1000 == 0: # Check periodically to avoid blocking Ctrl+C too long
                   time.sleep(0.001) # Tiny sleep to allow context switch for interrupt check
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user.")
    finally:
        if local_pbar:
            local_pbar.close() # Ensure the benchmark progress bar is closed

    end_time = time.time()
    elapsed_time = end_time - start_time

    print("-" * 30) # Separator
    if elapsed_time > 0 and addresses_derived > 0:
        keys_per_second = addresses_derived / elapsed_time
        print(f"{Fore.GREEN}Successfully derived {addresses_derived:,} addresses.")
        print(f"Time taken: {elapsed_time:.2f} seconds")
        print(f"Keys/Addresses per second (single core estimate): {keys_per_second:,.2f}")
    elif addresses_derived == 0 and elapsed_time > 0:
         print(f"{Fore.YELLOW}Attempted {num_keys:,} keys, but failed to derive any addresses in {elapsed_time:.2f}s.")
         print(f"{Fore.YELLOW}Check 'private_key_to_address' function for potential errors.")
    else:
        print(f"{Fore.RED}Benchmark did not run long enough or failed to generate/derive keys.")
    print("-" * 30) # Separator

# --- Database Setup ---
def setup_database(db_path=DB_FILE, example_addresses=None):
    """Creates the database and table if they don't exist, adds example addresses."""
    if example_addresses is None:
        # Example addresses (including a known puzzle address)
        example_addresses = ["13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"]
    print(f"Setting up database: {db_path}")
    added_count = 0
    conn = None
    try:
        # Connect to the database file (will create if it doesn't exist)
        conn = sqlite3.connect(db_path, timeout=10) # Add timeout
        cursor = conn.cursor()
        # Create the 'addresses' table if it's not already there
        # Using TEXT PRIMARY KEY ensures addresses are unique and indexed
        cursor.execute('CREATE TABLE IF NOT EXISTS addresses (address TEXT PRIMARY KEY)')
        # Explicitly create an index (though PRIMARY KEY usually implies one) for clarity/performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_address ON addresses (address)')
        # Add example addresses if provided
        if example_addresses:
            for addr in example_addresses:
                try:
                    # INSERT OR IGNORE prevents errors if the address already exists
                    cursor.execute("INSERT OR IGNORE INTO addresses (address) VALUES (?)", (addr,))
                    # cursor.rowcount tells us if a row was actually inserted (1) or ignored (0)
                    if cursor.rowcount > 0:
                         added_count += 1
                except sqlite3.Error as e:
                    # Log insertion errors but continue with others
                    print(f"{Fore.YELLOW}Warning: Error inserting address {addr}: {e}{Style.RESET_ALL}")
        # Commit all changes made to the database
        conn.commit()
        print(f"Database setup/check complete. Added {added_count} new unique example addresses.")
        print(f"Ensure '{db_path}' contains the target addresses you want to search for.")
    except sqlite3.Error as e:
        print(f"{Fore.RED}Database error during setup: {e}{Style.RESET_ALL}")
        # Depending on severity, you might want to exit here:
        # sys.exit(f"Fatal DB setup error: {e}")
    finally:
        # Ensure the database connection is closed
        if conn:
            conn.close()

# --- Scan Function ---
def scan_for_keys():
    """Starts the multi-threaded key generation and database checking process."""
    # Declare globals that this function *assigns* to or modifies state of (Events, pbar)
    # Note: checked_keys_count, found_keys_count are modified via worker threads using locks
    global is_paused, start_scan_time, pbar

    # --- Pre-Scan Checks ---
    if not os.path.exists(DB_FILE):
        print(f"{Fore.YELLOW}Database file '{DB_FILE}' not found. Attempting setup...{Style.RESET_ALL}")
        setup_database(DB_FILE) # Attempt to set it up with examples
        # Check again after setup attempt
        if not os.path.exists(DB_FILE):
            print(f"{Fore.RED}Failed to create or find database '{DB_FILE}'. Cannot start scan.{Style.RESET_ALL}")
            return # Exit the scan function if DB is missing

    print(f"\n{Fore.CYAN}Starting scan using {NUM_THREADS} CPU threads...{Style.RESET_ALL}")
    print(f"Checking against addresses in database: {DB_FILE}")
    print(f"Logging found keys to: {LOG_FILE}")
    if msvcrt: # Check if non-blocking input is available
        print(f"{Fore.YELLOW}Press 'P' to Pause/Resume | Press Ctrl+C to Stop{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Press Ctrl+C to Stop (Pause/Resume with 'P' not available on this OS){Style.RESET_ALL}")

    # --- Reset State for New Scan ---
    # Use lock temporarily for reset, although main thread owns them before workers start
    with count_lock:
        global checked_keys_count, found_keys_count
        checked_keys_count = 0
        found_keys_count = 0
    start_scan_time = time.time()
    stop_event.clear()   # Reset stop signal
    pause_event.clear()  # Ensure starts in running state (not paused)
    is_paused = False    # Reset paused state flag

    # --- Initialize TQDM Progress Bar ---
    # total=0 for indefinite run, position=0 for top line, leave=True to keep final bar
    pbar = tqdm(total=0, unit=" keys", desc="Scanning", dynamic_ncols=True, smoothing=0.05, position=0, leave=True)

    # --- Helper Function for DB Connection ---
    def create_db_connection():
        """Creates a thread-local SQLite connection."""
        try:
             # check_same_thread=False is mandatory for multi-threaded access
             # timeout helps if DB is locked briefly (less likely for reads)
            return sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10)
        except sqlite3.Error as e:
            # Log error if connection itself fails
            pbar.write(f"{Fore.RED}DB Connect Error: {e}{Style.RESET_ALL}")
            raise # Re-raise the exception so the worker thread knows connection failed

    # --- Thread Worker Function ---
    def worker(thread_id):
        """The function executed by each worker thread."""
        # --- VERY IMPORTANT: Declare use of global variables for assignment ---
        # This tells Python *not* to treat these as local variables when assigned to.
        global checked_keys_count, found_keys_count

        conn = None
        cursor = None
        local_batch_count = 0 # Count keys processed locally before updating global state

        try:
            # --- Thread Initialization ---
            conn = create_db_connection()
            cursor = conn.cursor()
            # Add a print statement here for the verification test if needed:
            # print(f">>> Thread {thread_id}: Running worker with global fix! <<<")

            # --- Main Loop for the Thread ---
            while not stop_event.is_set():
                # --- Pause Handling ---
                if pause_event.is_set():
                    # Wait here until pause_event.clear() is called by the main thread
                    pause_event.wait()
                    # Immediately check if stop was requested *while* paused
                    if stop_event.is_set():
                        break # Exit loop if stopped during pause
                    continue # Resume loop

                # --- Core Logic: Generate -> Derive -> Check ---
                priv_key = generate_private_key()
                address = private_key_to_address(priv_key)

                if address is None:
                    # Skip if address generation failed (e.g., invalid key somehow)
                    continue

                try:
                    # Check if the derived address exists in the database
                    cursor.execute('SELECT 1 FROM addresses WHERE address = ? LIMIT 1', (address,))
                    found = cursor.fetchone() # Returns tuple (1,) if found, None otherwise
                    local_batch_count += 1 # Increment *after* successful DB check attempt

                    # --- Key Found Handling ---
                    if found:
                        current_found_count_display = 0 # Temp var to hold count for display/logging
                        with count_lock: # --- LOCK START (Found Count) ---
                            found_keys_count += 1 # Safely increment global counter
                            current_found_count_display = found_keys_count # Get updated value
                        # --- LOCK END (Found Count) ---

                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                        log_message = f"Timestamp: {timestamp} | Address: {address} | Private Key: {priv_key}"

                        # Print to console (using pbar.write to avoid messing up the bar)
                        pbar.write(f"{Fore.GREEN}\n--- FOUND KEY #{current_found_count_display} ---")
                        pbar.write(log_message)
                        pbar.write(f"-----------------{Style.RESET_ALL}")

                        # Log to file safely
                        with log_lock: # --- LOCK START (Log File) ---
                            try:
                                with open(LOG_FILE, 'a') as f:
                                    f.write(log_message + "\n")
                            except IOError as log_e:
                                pbar.write(f"{Fore.RED}Error writing to log file {LOG_FILE}: {log_e}{Style.RESET_ALL}")
                        # --- LOCK END (Log File) ---

                        # Update tqdm postfix immediately to show the find count prominently
                        pbar.set_postfix(found=f"{Fore.GREEN}{current_found_count_display}{Style.RESET_ALL}", refresh=True)

                        # Optional: Uncomment the next line to stop all threads once a key is found
                        # stop_event.set()

                    # --- Progress Update (Periodic Batch Update) ---
                    # Determine threshold for updating global count and pbar
                    local_update_threshold = max(100, TQDM_UPDATE_INTERVAL // NUM_THREADS)
                    if local_batch_count >= local_update_threshold:
                        batch_to_add = local_batch_count # Store value before lock
                        current_global_checked_display = 0 # Temp vars for display
                        current_global_found_display = 0
                        with count_lock: # --- LOCK START (Batch Count Update) ---
                            checked_keys_count += batch_to_add # Safely update global checked count
                            current_global_checked_display = checked_keys_count # Get updated value
                            current_global_found_display = found_keys_count # Get current found count
                            local_batch_count = 0 # Reset local counter *inside* lock
                            # Update tqdm bar progress *inside* lock to sync with count
                            pbar.update(batch_to_add)
                        # --- LOCK END (Batch Count Update) ---

                        # Update postfix outside lock using values captured inside
                        # Only update 'found' if it hasn't recently been updated by a find event
                        current_postfix = pbar.postfix or ""
                        if f"found={current_global_found_display}" not in current_postfix.replace(Fore.GREEN, '').replace(Style.RESET_ALL, ''):
                           pbar.set_postfix(found=current_global_found_display, refresh=False)

                # --- Database Error Handling (within loop) ---
                except sqlite3.Error as db_err:
                    pbar.write(f"{Fore.RED}\n[Thread {thread_id}] Database Error: {db_err}. Attempting reconnect...{Style.RESET_ALL}")
                    if conn:
                        try: conn.close()
                        except Exception: pass # Ignore error closing faulty connection
                    conn, cursor = None, None # Reset connection variables
                    time.sleep(5 + secrets.randbelow(5)) # Wait with jitter before retrying
                    try:
                        conn = create_db_connection()
                        cursor = conn.cursor()
                        pbar.write(f"{Fore.GREEN}[Thread {thread_id}] Database Reconnected.{Style.RESET_ALL}")
                    except sqlite3.Error as reconn_err:
                        pbar.write(f"{Fore.RED}\n[Thread {thread_id}] DB Reconnect Failed: {reconn_err}. Stopping thread.{Style.RESET_ALL}")
                        stop_event.set() # Signal stop if reconnect fails persistently
                        break # Exit the while loop for this thread

                # --- Other Unexpected Error Handling (within loop) ---
                except Exception as e:
                    pbar.write(f"{Fore.RED}\n[Thread {thread_id}] Unexpected Error ({type(e).__name__}): {e}{Style.RESET_ALL}")
                    # For detailed debugging, uncomment the next two lines:
                    # import traceback
                    # pbar.write(traceback.format_exc())
                    time.sleep(1) # Avoid busy-looping on unexpected errors

        # --- Thread Initialization Error Handling ---
        except sqlite3.Error as initial_db_err:
            # Handle error if the *initial* DB connection fails
            err_msg = f"{Fore.RED}\n[Thread {thread_id}] Failed to connect to DB on start: {initial_db_err}{Style.RESET_ALL}"
            if pbar: pbar.write(err_msg) # Use pbar if available
            else: print(err_msg)
            # Consider stopping if initial connection fails, as the thread can't work
            stop_event.set() # Signal other threads to stop too

        # --- Thread Cleanup ---
        finally:
            if conn:
                try: conn.close()
                except Exception: pass # Ignore errors during final close
            # Optional debug message:
            # if pbar and stop_event.is_set(): pbar.write(f"[Thread {thread_id}] Worker stopping.")

    # --- Start Worker Threads ---
    threads = []
    print(f"Starting {NUM_THREADS} worker threads...")
    for i in range(NUM_THREADS):
        # Create and start each thread, making it a daemon so it exits if main thread exits
        thread_id_num = i + 1
        t = threading.Thread(target=worker, args=(thread_id_num,), name=f"Worker-{thread_id_num}", daemon=True)
        try:
            t.start()
            threads.append(t)
        except RuntimeError as e:
             print(f"{Fore.RED}Error starting thread {thread_id_num}: {e}. Maybe too many threads?{Style.RESET_ALL}")
             # Reduce effective number of threads if one fails to start
             NUM_THREADS = i
             break
    if NUM_THREADS == 0:
        print(f"{Fore.RED}No worker threads started. Aborting scan.{Style.RESET_ALL}")
        if pbar: pbar.close()
        return

    print(f"{NUM_THREADS} worker threads running.")

    # --- Main thread: Handle Input (Pause/Resume/Stop) and Monitor ---
    try:
        while True:
             # Check if any worker threads are still active
             # This is the primary condition for the scan continuing
             if not any(t.is_alive() for t in threads):
                  if pbar: pbar.write("\nAll worker threads have finished.")
                  break # Exit monitoring loop if all workers are done

             # --- Handle Keyboard Input (Windows specific non-blocking) ---
             if msvcrt and msvcrt.kbhit(): # Only check if msvcrt is available and key pressed
                  try:
                      char = msvcrt.getch().decode('utf-8').lower()
                      if char == 'p':
                          if pause_event.is_set(): # If currently paused -> resume
                              pause_event.clear() # Clear event to allow workers to continue
                              is_paused = False   # Update global state flag
                              if pbar:
                                  pbar.write(f"\n{Fore.YELLOW}>>> Scan Resumed <<<")
                                  pbar.set_description("Scanning")
                          else: # If currently running -> pause
                              pause_event.set()   # Set event to make workers wait
                              is_paused = True    # Update global state flag
                              if pbar:
                                  pbar.write(f"\n{Fore.YELLOW}>>> Scan Paused <<< (Press 'P' to Resume)")
                                  pbar.set_description(f"{Fore.YELLOW}Paused")
                  except UnicodeDecodeError:
                      pass # Ignore key presses that can't be decoded (e.g., function keys)
                  except Exception as input_err:
                      # Log errors during input processing but don't crash
                      if pbar: pbar.write(f"\n{Fore.RED}Error processing input: {input_err}{Style.RESET_ALL}")
                      else: print(f"\n{Fore.RED}Error processing input: {input_err}{Style.RESET_ALL}")

             # --- Check if Stop Event was Triggered (e.g., by worker finding key) ---
             if stop_event.is_set():
                  if not is_paused: # Only print stopping message if not already paused
                       if pbar: pbar.write(f"\n{Fore.YELLOW}Stop signal received! Stopping threads...{Style.RESET_ALL}")
                  break # Exit main monitoring loop

             # --- Update TQDM Description Based on Pause State ---
             # This ensures the description stays correct even if state changes without 'P' press
             if pbar:
                 current_desc = pbar.desc or ""
                 expected_desc = f"{Fore.YELLOW}Paused" if is_paused else "Scanning"
                 # Check if current description matches expected to avoid unnecessary updates
                 if expected_desc not in current_desc: # Check if substring exists to handle color codes etc.
                     pbar.set_description(expected_desc)


             # --- Prevent Busy-Waiting ---
             # Sleep briefly to yield CPU time, otherwise this loop runs very hot
             time.sleep(0.1) # Check for input/stop/alive status 10 times per second

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Ctrl+C detected! Stopping threads gracefully...{Style.RESET_ALL}")
        stop_event.set() # Signal threads to stop
        # If paused during Ctrl+C, ensure threads can see the stop_event by clearing pause
        if is_paused:
            pause_event.clear()
            is_paused = False # Update state

    finally:
        # --- Cleanup Logic for Scan Function ---
        # This block runs whether the loop exits normally, via Ctrl+C, or stop_event

        # Ensure stop_event is set if not already (e.g., if all threads finished naturally)
        if not stop_event.is_set():
            stop_event.set()

        # Ensure pause_event is clear so threads waiting on it can exit for join()
        if pause_event.is_set():
            pause_event.clear()

        print("\nWaiting for worker threads to finish...")
        # Wait for all threads to complete their current task and exit
        for t in threads:
            # Add a timeout to join in case a thread hangs indefinitely
            t.join(timeout=5.0) # Wait up to 5 seconds per thread
            # Optional: Check if thread is still alive after timeout
            # if t.is_alive():
            #     print(f"{Fore.YELLOW}Warning: Thread {t.name} did not finish within timeout.{Style.RESET_ALL}")

        # Close the progress bar cleanly now that threads are done
        if pbar:
            pbar.close()
            print("Progress bar closed.") # Confirmation

        print(f"\n{Fore.CYAN}{'-'*10} Scan Summary {'-'*10}{Style.RESET_ALL}")
        final_elapsed = time.time() - start_scan_time
        # Read final counts safely using the lock
        with count_lock:
             final_checked = checked_keys_count
             final_found = found_keys_count

        print(f"Total keys checked: {final_checked:,}")
        print(f"Total keys found: {Fore.GREEN}{final_found}{Style.RESET_ALL}")
        print(f"Total time: {final_elapsed:.2f} seconds")

        # Calculate and display average rate, handle division by zero safely
        if final_elapsed > 0 and final_checked > 0:
            final_rate = final_checked / final_elapsed
            print(f"Average rate: {final_rate:,.2f} keys/sec")
        else:
            print("Average rate: N/A (Scan too short or no keys checked/derived)")
        print(f"{Fore.CYAN}{'-'*34}{Style.RESET_ALL}")


# --- Cleanup Function (Registered with atexit) ---
def cleanup():
    """Function registered with atexit to run on program exit."""
    print("\nInitiating program exit cleanup...")
    # Ensure threads are signaled to stop if not already
    if not stop_event.is_set():
        stop_event.set()
        print("Stop event set during cleanup.")
    # If paused on exit, unpause to allow threads to terminate cleanly if waiting
    if is_paused: # Read global is_paused state
        pause_event.clear()
        print("Pause event cleared during cleanup.")

    # Attempt to close progress bar if it exists and wasn't closed
    # Check pbar exists and is not disabled (already closed)
    global pbar
    if pbar and hasattr(pbar, 'disable') and not pbar.disable:
        try:
            pbar.close()
            print("Progress bar closed during cleanup.")
        except Exception as e:
            # Ignore errors closing pbar during interpreter shutdown
            # print(f"Ignoring error during pbar cleanup: {e}")
            pass

    # Reset terminal colors just in case
    init(autoreset=True)
    print("Cleanup finished.")

# Register the cleanup function to run automatically on normal exit or unhandled exception
atexit.register(cleanup)

# --- Command-line Menu ---
def show_menu():
    """Displays the main menu options."""
    print("\nChoose an option:")
    print("1. Benchmark (Test key/address speed on one CPU core)")
    print("2. Scan Bitcoin Addresses in DB (Multi-Threaded CPU)")
    print("3. Setup/Add Example Addresses to Database")
    print("4. Exit")

# --- Main Execution Logic ---
def main():
    """Main function to handle menu logic and start operations."""
    # Clear screen for better display (OS dependent)
    os.system("cls" if os.name == "nt" else "clear")
    print_banner()

    # --- Initial Database Check/Setup ---
    if not os.path.exists(DB_FILE):
        print(f"{Fore.YELLOW}Database '{DB_FILE}' not found, running initial setup...{Style.RESET_ALL}")
        setup_database(DB_FILE) # Creates with examples if needed
        # Check if setup actually created the file
        if not os.path.exists(DB_FILE):
             print(f"{Fore.RED}Database setup failed. Please check permissions/path. Exiting.{Style.RESET_ALL}")
             sys.exit(1) # Exit if DB is critical and setup failed
    else:
        print(f"Using existing database: {DB_FILE}")
        # Optional: Verify table structure even if file exists
        # setup_database(DB_FILE, example_addresses=[]) # Run setup without examples


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
            # --- Benchmark Option ---
            try:
                # Default benchmark value
                default_bench_keys = 100000
                num_keys_str = input(f"Enter the number of keys to benchmark [default: {default_bench_keys:,}]: ").strip()
                if not num_keys_str: # Use default if empty input
                    num_keys = default_bench_keys
                else:
                    num_keys = int(num_keys_str) # Convert input to integer

                if num_keys <= 0:
                    print(f"{Fore.RED}Please enter a positive number of keys.{Style.RESET_ALL}")
                else:
                    benchmark(num_keys) # Run the benchmark function
            except ValueError:
                print(f"{Fore.RED}Invalid number entered. Please enter an integer.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}An error occurred during benchmark setup or execution: {e}")

        elif choice == '2':
            # --- Scan Option ---
            try:
                scan_for_keys() # Start the main scanning process
                print("Scan finished or stopped. Returning to menu.")
            except Exception as e:
                 print(f"{Fore.RED}An unexpected error occurred during the scan process: {e}{Style.RESET_ALL}")
                 # For debugging:
                 # import traceback
                 # traceback.print_exc()
            # After scan finishes (or is stopped/errors out), loop back to menu

        elif choice == '3':
            # --- Database Setup Option ---
            print("\nRe-running database setup...")
            # You might want to add prompts here to add specific addresses from the user
            # For now, just re-runs the default setup (ensures table exists, adds examples if missing)
            setup_database(DB_FILE)

        elif choice == '4':
            # --- Exit Option ---
            print("Exiting program...")
            sys.exit(0) # Normal exit, atexit cleanup function will run

        else:
            # --- Invalid Choice ---
            print(f"{Fore.RED}Invalid choice '{choice}', please try again.{Style.RESET_ALL}")

# --- Entry Point Guard ---
if __name__ == '__main__':
    # Optional: Attempt to set higher process priority (may require elevated privileges)
    # This can potentially make the script run faster but might impact system responsiveness
    # try:
    #     if os.name == 'nt':
    #         import psutil
    #         p = psutil.Process(os.getpid())
    #         p.nice(psutil.HIGH_PRIORITY_CLASS)
    #         print(f"{Fore.CYAN}Attempted to set high process priority (Windows).{Style.RESET_ALL}")
    #     elif os.name == 'posix': # Linux, macOS, etc.
    #          # Lower nice value = higher priority (e.g., -20 is highest, 19 is lowest)
    #          # Using 10 is a moderate increase, use negative values for more priority
    #          os.nice(10)
    #          print(f"{Fore.CYAN}Attempted to increase process priority (POSIX nice value set).{Style.RESET_ALL}")
    # except ImportError:
    #     # psutil might not be installed
    #     print(f"{Fore.YELLOW}Optional 'psutil' module not found, cannot set high priority on Windows.{Style.RESET_ALL}")
    # except OSError as e:
    #     # May not have permission to change priority
    #     print(f"{Fore.YELLOW}Could not set process priority (permission required?): {e}{Style.RESET_ALL}")
    # except Exception as e:
    #     # Other potential errors
    #      print(f"{Fore.YELLOW}An error occurred while trying to set process priority: {e}{Style.RESET_ALL}")

    # Call the main function to start the program
    main()

# --- END OF FILE Python Btc_P_K_cu.py ---