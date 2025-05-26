#!/usr/bin/env python3
import socket
import re
import time

HOST = "challenge.nahamcon.com"
PORT = 32718
# Standard flag format for NahamCon, looking for "flag{...}" or "naham{...}"
FLAG_REGEX = r"(flag\{[^\}]+\}|naham\{[^\}]+\})"

def solve():
    buffer = "" # Accumulates received data to find flags that might span multiple reads
    client_socket = None # Initialize client_socket to ensure it's defined in finally block

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        print(f"[*] Connected to {HOST}:{PORT}")

        # Attempt to receive any initial data/banner from the server
        try:
            client_socket.settimeout(3.0) # Short timeout for the initial data
            initial_data = client_socket.recv(4096)
            client_socket.settimeout(None) # Reset timeout to blocking for subsequent operations
            if initial_data:
                decoded_initial = initial_data.decode(errors='ignore')
                print(decoded_initial, end='', flush=True)
                buffer += decoded_initial
                # Check for flag in initial data
                match = re.search(FLAG_REGEX, buffer)
                if match:
                    print(f"\n\n[+] Flag found in initial data: {match.group(0)}")
                    return
        except socket.timeout:
            print("[*] No immediate initial data from server, or server is waiting for first input.")
            # This is not an error; some servers wait for client's first newline.
        except Exception as e:
            print(f"[-] Error receiving initial data: {e}")


        # Main loop: send newline, then receive the next chunk of text
        # Max iterations to prevent an infinite loop if flag isn't found or logic is flawed
        for i in range(10000): 
            # Send a newline character to request the next chunk
            client_socket.sendall(b'\n')
            
            try:
                # Set a timeout for receiving data to avoid hanging indefinitely
                client_socket.settimeout(10.0) 
                data = client_socket.recv(4096)
                client_socket.settimeout(None) # Reset to blocking
            except socket.timeout:
                print("\n[*] Socket timed out waiting for data after sending newline. Server may have finished.")
                break
            except ConnectionResetError:
                print("\n[*] Connection reset by server.")
                break
            except Exception as e:
                print(f"\n[*] Error during recv: {e}")
                break

            if not data:
                print("\n[*] No more data received. Server likely closed connection or finished sending content.")
                break
            
            decoded_data = data.decode(errors='ignore')
            print(decoded_data, end='', flush=True) # Print data as it comes, flush to see it immediately
            buffer += decoded_data

            # Search for the flag pattern in the accumulated buffer
            match = re.search(FLAG_REGEX, buffer)
            if match:
                flag_value = match.group(0)
                # Attempt to find the line containing the flag for better context
                flag_context_line = ""
                for line_content in buffer.splitlines():
                    if flag_value in line_content:
                        flag_context_line = line_content.strip()
                        break
                if flag_context_line:
                    print(f"\n\n[+] Flag found: {flag_value} (Context: '{flag_context_line}')")
                else:
                    print(f"\n\n[+] Flag found: {flag_value}")
                return # Exit once the flag is found
            
            time.sleep(0.05) # A small delay to be polite to the server

        # If loop finishes and no flag found
        if not re.search(FLAG_REGEX, buffer):
             print("\n\n[-] Flag not found after exhausting attempts or server stopped responding.")
             # Optional: print a snippet of the end of the buffer for debugging
             # print(f"[*] Last 500 chars of buffer: ...{buffer[-500:]}")


    except socket.gaierror:
        print(f"[-] Address-related error connecting to server. Check HOST: {HOST}.")
    except socket.error as e:
        print(f"[-] Socket error: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
    finally:
        if client_socket:
            try:
                # Gracefully shut down the socket
                client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass # Socket might already be closed
            client_socket.close()
            # print("[*] Connection closed.")

if __name__ == "__main__":
    solve()
