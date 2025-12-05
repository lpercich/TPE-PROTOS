import socket
import time
import threading
import sys
import struct

SOCKS_HOST = '127.0.0.1'
SOCKS_PORT = 1080
MNG_PORT = 8080
ADMIN_USER = 'admin'
ADMIN_PASS = 'admin'

def get_metrics():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SOCKS_HOST, MNG_PORT))
    s.sendall(f"AUTH {ADMIN_USER}:{ADMIN_PASS}\n".encode())
    resp = s.recv(1024).decode()
    if "+OK" not in resp:
        print(f"Auth failed: {resp}")
        return None
    
    s.sendall(b"METRICS\n")
    resp = ""
    while True:
        chunk = s.recv(1024).decode()
        if not chunk: break
        resp += chunk
        if "bytes_transferidos" in resp: break
    
    s.close()
    
    metrics = {}
    for line in resp.splitlines():
        if ':' in line:
            key, val = line.split(':', 1)
            metrics[key.strip()] = int(val.strip())
    return metrics

def test_proxy_transfer():
    print("--- Testing Proxy Transfer & Metrics ---")
    initial_metrics = get_metrics()
    print(f"Initial Bytes: {initial_metrics.get('bytes_transferidos', 0)}")

    # Connect to SOCKS5
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SOCKS_HOST, SOCKS_PORT))
    
    # 1. Hello
    s.sendall(b'\x05\x01\x02') # Ver 5, 1 method, User/Pass (0x02)
    resp = s.recv(2)
    assert resp == b'\x05\x02'
    
    # 2. Auth
    s.sendall(b'\x01\x05admin\x05admin') # Ver 1, len 5, user, len 5, pass
    resp = s.recv(2)
    assert resp == b'\x01\x00'
    
    # 3. Request (Connect to google.com:80)
    # 142.250.185.142 (google) is hardcoded to avoid DNS in this specific raw test if needed, 
    # but let's use domain to test DNS too.
    # \x05 \x01 \x00 \x03 (domain) \x0A (len 10) google.com \x00\x50 (80)
    domain = b"google.com"
    req = b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + struct.pack("!H", 80)
    s.sendall(req)
    resp = s.recv(1024) # Reply
    if resp[1] != 0:
        print(f"SOCKS Connect failed: {resp[1]}")
        return
        
    # 4. Data Transfer
    msg = b"GET / HTTP/1.0\r\nHost: google.com\r\n\r\n"
    s.sendall(msg)
    
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    
    print(f"Received {len(data)} bytes from Google.")
    s.close()
    
    # Check metrics
    final_metrics = get_metrics()
    print(f"Final Bytes: {final_metrics.get('bytes_transferidos', 0)}")
    
    delta = final_metrics.get('bytes_transferidos', 0) - initial_metrics.get('bytes_transferidos', 0)
    print(f"Delta Bytes: {delta}")
    
    # We sent ~40 bytes, received ~500-1000+. Delta should be > 0.
    if delta > 0:
        print("SUCCESS: Metrics updated.")
    else:
        print("FAILURE: Metrics did not update.")

def slow_client():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SOCKS_HOST, SOCKS_PORT))
        s.sendall(b'\x05') # Partial hello
        time.sleep(2)
        s.sendall(b'\x01\x02') # Finish hello
        resp = s.recv(2)
        s.close()
        return True
    except Exception as e:
        print(f"Slow client error: {e}")
        return False

def fast_client():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SOCKS_HOST, SOCKS_PORT))
        s.sendall(b'\x05\x01\x02')
        resp = s.recv(2)
        s.close()
        return True
    except Exception as e:
        print(f"Fast client error: {e}")
        return False

def test_non_blocking():
    print("\n--- Testing Non-Blocking Behavior ---")
    # Start slow client in thread
    t = threading.Thread(target=slow_client)
    t.start()
    
    time.sleep(0.5) # Wait for slow client to connect and pause
    
    # Try fast client
    start = time.time()
    res = fast_client()
    end = time.time()
    
    if res and (end - start) < 1.0:
        print("SUCCESS: Fast client completed while slow client was paused.")
    else:
        print(f"FAILURE: Fast client took {end - start}s or failed.")
    
    t.join()

def test_management_commands():
    print("\n--- Testing Management Commands ---")
    try:
        # Connect to management port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((MNG_HOST, MNG_PORT))
        
        # Authenticate
        s.sendall(f"AUTH {MNG_USER}:{MNG_PASS}\n".encode())
        resp = s.recv(1024).decode()
        print(f"Auth Response: {resp.strip()}")
        if "+OK" not in resp:
            print("Authentication failed")
            return

        # Test SET_BUFFER
        print("Testing SET_BUFFER...")
        s.sendall(b"SET_BUFFER 1024\n")
        resp = s.recv(1024).decode()
        print(f"SET_BUFFER Response: {resp.strip()}")
        if "+OK" not in resp:
             print("SET_BUFFER failed")

        # Generate some traffic to create logs
        print("Generating traffic for logs...")
        try:
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.connect((PROXY_HOST, PROXY_PORT))
            # Send SOCKS5 handshake
            proxy_sock.sendall(b"\x05\x01\x02") # Version 5, 1 method, USERPASS
            proxy_sock.recv(2)
            # Send Auth
            proxy_sock.sendall(b"\x01\x05admin\x05admin")
            proxy_sock.recv(2)
            # Send Connect Request (to google.com:80)
            # 05 01 00 03 (domain) 0A (len) google.com 00 50 (port 80)
            req = b"\x05\x01\x00\x03\x0agoogle.com\x00\x50"
            proxy_sock.sendall(req)
            proxy_sock.recv(10) # Reply
            proxy_sock.close()
        except Exception as e:
            print(f"Traffic generation failed: {e}")

        # Test SHOW_LOGS
        print("Testing SHOW_LOGS...")
        s.sendall(b"SHOW_LOGS\n")
        # Read potentially large response
        resp = b""
        while True:
            chunk = s.recv(4096)
            resp += chunk
            if len(chunk) < 4096:
                break
        print(f"SHOW_LOGS Response:\n{resp.decode().strip()}")
        
        s.close()

    except Exception as e:
        print(f"Management test failed: {e}")

if __name__ == "__main__":
    try:
        test_proxy_transfer()
        test_non_blocking()
        test_management_commands()
    except Exception as e:
        print(f"Test failed with exception: {e}")