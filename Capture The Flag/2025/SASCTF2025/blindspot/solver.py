import ast
import hashlib
import json
import queue
import secrets
import socket
import threading
import time

from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import Point, PointJacobi
from ecdsa.numbertheory import inverse_mod

# Server connection details
HOST = "tcp.sasc.tf"
PORT = 12610

# Elliptic curve parameters from server.py and client.py
curve = NIST256p
gen = curve.generator
p = gen.order()


def point2bytes(P):
    # Ensure P is affine before converting to bytes
    if isinstance(P, PointJacobi):
        if P.is_point_at_infinity():
            raise ValueError("Point at infinity cannot be converted to bytes for hashing in this context.")
        P = P.to_affine()
    return P.to_bytes()


def hash_func(Rp, m):
    if isinstance(m, str):
        m = m.encode()
    # Rp should be an affine point for point2bytes
    if isinstance(Rp, PointJacobi):
        Rp_affine = Rp.to_affine()
    else:
        Rp_affine = Rp # Assuming it's already affine if not PointJacobi
    return (
        int.from_bytes(hashlib.sha256(point2bytes(Rp_affine) + m).digest(), byteorder="big")
        % p
    )

def convert_point_to_coords(point):
    if isinstance(point, PointJacobi):
        point = point.to_affine()
    return [point.x(), point.y()]

class SocketReader(threading.Thread):
    def __init__(self, sock):
        super().__init__(daemon=True)
        self.sock = sock
        self.response_queue = queue.Queue()
        self.running = True
        self._buffer = b""

    def run(self):
        while self.running:
            try:
                self.sock.settimeout(0.1)
                data = self.sock.recv(65536)
                if not data:
                    if self.running:
                        # print("[!] Socket reader: Connection closed by server.") # Less verbose during normal exit
                        pass
                    self.running = False
                    break
                
                self._buffer += data
                while b'\n' in self._buffer:
                    message_bytes, self._buffer = self._buffer.split(b'\n', 1)
                    message_str = message_bytes.decode().strip()
                    if message_str:
                        try:
                            response = json.loads(message_str)
                            self.response_queue.put(response)
                        except json.JSONDecodeError as e:
                            print(f"[!] Socket reader: JSONDecodeError: {e} for message: '{message_str}'")
                            pass

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[!] Socket reader error: {e}")
                break

    def stop(self):
        self.running = False

    def get_response(self, timeout=10):
        try:
            return self.response_queue.get(timeout=timeout)
        except queue.Empty:
            # print(f"[-] Socket reader: Timeout waiting for response (>{timeout}s).") # Less verbose for short timeouts in loops
            return None

class ExploitClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.reader = None
        self.Q_server = None

    def _send_json(self, data_dict):
        if not self.sock:
            print("[-] Not connected.")
            return False
        try:
            self.sock.sendall(json.dumps(data_dict).encode() + b"\n")
            return True
        except Exception as e:
            print(f"[-] Error sending JSON: {e}")
            return False

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"[+] Connected to server at {self.host}:{self.port}")
            self.reader = SocketReader(self.sock)
            self.reader.start()
            return True
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False

    def close(self):
        if self.reader:
            self.reader.stop()
            self.reader.join(timeout=1)
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            self.sock.close()
            self.sock = None
        print("[+] Connection closed.")

    def reset_server_state(self):
        print("[*] Resetting server state...")
        if not self._send_json({"cmd": "RESET"}): return False
        response = self.reader.get_response()
        if response and response.get("status") == "ok":
            print("[+] Server reset successful.")
            return True
        else:
            print(f"[-] Server reset failed: {response}")
            return False

    def get_server_public_key(self):
        print("[*] Requesting server's public key (Q)...")
        if not self._send_json({"cmd": "GETKEY"}): return False
        response = self.reader.get_response()
        if response and "Q" in response:
            try:
                q_coords = response["Q"]
                self.Q_server = PointJacobi.from_affine(
                    Point(curve.curve, q_coords[0], q_coords[1])
                )
                print(f"[+] Received server's public key Q: ({self.Q_server.x()}, {self.Q_server.y()})")
                return True
            except Exception as e:
                print(f"[-] Error processing server's public key: {e} - Response: {response}")
                return False
        else:
            print(f"[-] Failed to get server's public key: {response}")
            return False

    def get_server_r(self):
        print("[*] Requesting server's R for signing session...")
        if not self._send_json({"cmd": "REQUEST"}): return None
        response = self.reader.get_response()
        if response and "R" in response:
            try:
                r_coords = response["R"]
                R_serv = PointJacobi.from_affine(
                    Point(curve.curve, r_coords[0], r_coords[1])
                )
                print(f"[+] Received server's R_serv: ({R_serv.x()}, {R_serv.y()})")
                if "Q" in response and not self.Q_server:
                     q_coords = response["Q"]
                     self.Q_server = PointJacobi.from_affine(Point(curve.curve, q_coords[0], q_coords[1]))
                     print(f"[+] (Re)captured server's public key Q from REQUEST: ({self.Q_server.x()}, {self.Q_server.y()})")
                return R_serv
            except Exception as e:
                print(f"[-] Error processing server's R_serv: {e} - Response: {response}")
                return None
        else:
            print(f"[-] Failed to get server's R_serv: {response}")
            return None

    def get_challenge_response(self, c_for_server):
        if not self._send_json({"cmd": "CHALLENGE", "c": c_for_server}): return None
        response = self.reader.get_response()
        if response and "s" in response:
            s_serv = response["s"]
            return s_serv
        else:
            print(f"[-] Failed to get s_serv from challenge: {response}")
            return None
            
    def verify_forged_signature(self, msg, R_forge_pt, s_forge):
        R_forge_coords = convert_point_to_coords(R_forge_pt)
        sig_data = (R_forge_coords, s_forge)
        
        # print(f"[*] Verifying forged signature for message: '{msg}'") # Less verbose during rapid verification
        if not self._send_json({"cmd": "VERIFY", "msg": msg, "sig": sig_data}): return False, None
        
        response = self.reader.get_response(timeout=15)
        if response:
            # print(f"[*] Verification response for '{msg}': {response}") # Less verbose
            if response.get("status") == "ok":
                # print(f"[+] Forged signature for '{msg}' VALID!") # Less verbose
                if "msg" in response and "FLAG" in response["msg"].upper():
                    print(f"\n[!!!] FLAG OBTAINED (from verify response for '{msg}'): {response['msg']}\n")
                return True, response
            else:
                print(f"[-] Forged signature for '{msg}' INVALID.")
                return False, response
        else:
            print(f"[-] No response or timeout during verification for '{msg}'.")
            return False, None

    def run_exploit(self):
        if not self.connect():
            return

        if not self.reset_server_state():
            self.close()
            return
        
        if not self.get_server_public_key():
            self.close()
            return
        
        R_serv = self.get_server_r()
        if not R_serv:
            self.close()
            return

        msg1 = "exploit_msg_alpha_k_reuse"
        alpha1 = secrets.randbelow(p - 1) + 1
        beta1 = secrets.randbelow(p - 1) + 1
        
        R_blind1 = R_serv + gen * alpha1 + self.Q_server * beta1
        c_chal1 = hash_func(R_blind1, msg1)
        c_for_server1 = (c_chal1 + beta1) % p
        print(f"[*] Attempting first challenge for '{msg1}' with c_for_server1={c_for_server1}")
        s_serv1 = self.get_challenge_response(c_for_server1)
        if s_serv1 is None:
            print("[-] Failed first challenge.")
            self.close()
            return
        print(f"[+] Got s_serv1: {s_serv1}")

        msg2 = "exploit_msg_beta_k_reuse"
        alpha2 = secrets.randbelow(p - 1) + 1
        beta2 = (beta1 + secrets.randbelow(p-2) + 1) % p
        if beta2 == 0: beta2 = 1

        R_blind2 = R_serv + gen * alpha2 + self.Q_server * beta2
        c_chal2 = hash_func(R_blind2, msg2)
        c_for_server2 = (c_chal2 + beta2) % p
        print(f"[*] Attempting second challenge for '{msg2}' with c_for_server2={c_for_server2}")

        if c_for_server1 == c_for_server2:
            print("[-] c_for_server1 and c_for_server2 are identical. This attempt will fail. Please retry.")
            self.close()
            return

        s_serv2 = self.get_challenge_response(c_for_server2)
        if s_serv2 is None:
            print("[-] Failed second challenge.")
            self.close()
            return
        print(f"[+] Got s_serv2: {s_serv2}")

        delta_s_serv = (s_serv1 - s_serv2 + p) % p
        delta_c_for_server = (c_for_server1 - c_for_server2 + p) % p

        if delta_c_for_server == 0:
            print("[-] delta_c_for_server is zero, cannot compute inverse. Attack failed this run. Try again.")
            self.close()
            return
            
        inv_delta_c = inverse_mod(delta_c_for_server, p)
        d_recovered = (delta_s_serv * inv_delta_c) % p
        print(f"[+] Recovered private key d: {d_recovered}")

        if gen * d_recovered == self.Q_server:
            print("[+] Private key d successfully verified against Q_server!")
        else:
            print("[-] Recovered d does not match Q_server. Attack likely failed.")
            self.close()
            return

        messages_to_forge = ["GetTheFlag1", "GetTheFlag2", "GetTheFlag3"]
        flag_obtained_overall = False

        for i, msg_f in enumerate(messages_to_forge):
            if flag_obtained_overall: break
            print(f"\n--- Forging and Verifying message {i+1}: '{msg_f}' ---")
            k_forge = secrets.randbelow(p - 1) + 1
            R_forge_pt = gen * k_forge
            c_forge = hash_func(R_forge_pt, msg_f)
            s_forge = (k_forge + c_forge * d_recovered) % p
            
            is_valid, response = self.verify_forged_signature(msg_f, R_forge_pt, s_forge)
            
            if is_valid and response:
                print(f"[+] Forged signature for '{msg_f}' VALID!")
                if "msg" in response and "FLAG" in response["msg"].upper():
                    print(f"\n[!!!] FLAG FOUND IN VERIFY RESPONSE for '{msg_f}': {response['msg']}\n")
                    flag_obtained_overall = True
                    break 
                
                if "sign_cnt" in response and "verify_cnt" in response:
                    sc = response["sign_cnt"]
                    vc = response["verify_cnt"]
                    print(f"[*] Server counts after verifying '{msg_f}': Signs={sc}, Verifies={vc}")
                    if vc > sc:
                        print(f"[!!!] Condition met: verified_messages ({vc}) > counter_sign ({sc})")
                        print("[*] Actively listening for the separate flag message for the next ~15 seconds...")
                        
                        flag_found_in_dedicated_listen = False
                        start_time_flag_wait = time.time()
                        while time.time() - start_time_flag_wait < 15:
                            flag_msg_response = self.reader.get_response(timeout=1)
                            if flag_msg_response:
                                print(f"[*] Received potential flag message or other: {flag_msg_response}")
                                if "msg" in flag_msg_response and "FLAG" in flag_msg_response.get("msg", "").upper():
                                    print(f"\n[!!!] FLAG FOUND (dedicated listen): {flag_msg_response['msg']}\n")
                                    flag_found_in_dedicated_listen = True
                                    flag_obtained_overall = True
                                    break 
                            if flag_found_in_dedicated_listen:
                                break
                        
                        if flag_found_in_dedicated_listen:
                            break # Break from messages_to_forge loop
                        elif not flag_obtained_overall : # only print if not found by other means already
                            print("[-] Did not receive the flag message within the dedicated 15s listening period.")
            
            if flag_obtained_overall: # Check again in case inner loop broke
                break

        if not flag_obtained_overall:
            print("\n[*] Flag not obtained after forging loop. Checking queue one last time...")
            # Try to read any remaining messages for a few seconds
            final_listen_duration = 10 # seconds
            print(f"[*] Final listen for {final_listen_duration} seconds...")
            start_final_listen = time.time()
            while time.time() - start_final_listen < final_listen_duration:
                final_check_response = self.reader.get_response(timeout=1)
                if final_check_response:
                    print(f"[*] Final queue check, received: {final_check_response}")
                    if "msg" in final_check_response and "FLAG" in final_check_response.get("msg", "").upper():
                        print(f"\n[!!!] FLAG FOUND (final queue check): {final_check_response['msg']}\n")
                        flag_obtained_overall = True
                        break
                if flag_obtained_overall:
                    break
            if not flag_obtained_overall:
                 print("[-] No flag message found in final queue check.")


        self.close()

if __name__ == "__main__":
    client = ExploitClient(HOST, PORT)
    try:
        client.run_exploit()
    except KeyboardInterrupt:
        print("\n[*] Exiting due to user interruption.")
    except Exception as e:
        print(f"[!!!] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally: # Ensure client connection is closed if it was opened
        if client.sock:
            client.close()
