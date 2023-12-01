import socketserver
import os

class MyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print("Connection received from:", self.client_address)

        try:
            # Receive file path length
            path_len_bytes = self.request.recv(8)
            if not path_len_bytes:
                print("Error receiving file path length.")
                return

            path_len = int.from_bytes(path_len_bytes, byteorder='little')  # Change byte order to 'little'
            print(f"Received file path length: {path_len}")

            # Receive file path
            file_path_bytes = b""
            while len(file_path_bytes) < path_len:
                received_data = self.request.recv(path_len - len(file_path_bytes))
                if not received_data:
                    print("Error receiving file path.")
                    return
                file_path_bytes += received_data

            file_name = file_path_bytes.decode('utf-8')
            print("Received file name:", file_name)

            # Check if the file exists
            file_path = os.path.join(os.getcwd(), file_name)
            print("Absolute file path:", file_path)
            if os.path.exists(file_path):
                print("File found:", file_path)

                # Read file data
                with open(file_path, 'rb') as file:
                    file_data = file.read()

                # Print the size before sending
                file_size = len(file_data)
                print("Size of file:", file_size)

                # Send file size to the client
                self.request.sendall(file_size.to_bytes(4, byteorder='big'))

                # Send file data back to the client
                self.request.sendall(file_data)
                print("File data sent successfully.")

            else:
                print("File not found:", file_path)
                self.request.sendall(b"FILE_NOT_FOUND")

        except Exception as e:
            print("Error:", str(e))
            self.request.sendall(b"SERVER_ERROR")

if __name__ == "__main__":
    host, port = "192.168.1.12", 8080
    server = socketserver.TCPServer((host, port), MyHandler)
    print(f"Server listening on {host}:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Server shutting down.")
        server.shutdown()

