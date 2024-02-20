import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import hashlib
import time

# Configurações do chat P2P
LOCAL_HOST = '172.16.103.8'

LOCAL_PORT = 8888  # Porta local para comunicação P2P

BUFFER_SIZE = 1024

# Lista de endereços IP dos destinatários
dest_ips = ['172.16.103.9', '172.16.103.10', '172.16.103.7', '172.16.103.8']  # lista ips

# Porta fixa para todas as mensagens
dest_port = 8888

# Lista para armazenar a conversa
conversa = []

# Dicionário para armazenar mensagens conhecidas por hash
mensagens_conhecidas = {}

# Chave de criptografia
password = b'1234567890123456'

# Função para gerar o hash da mensagem
def generate_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

# Função para derivar a chave usando PBKDF2
def derive_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'6543210987654321',
        iterations=100000,
        length=16,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

# Função para cifrar a mensagem
def encrypt_message(message, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message.ljust(32)  # Preenche a mensagem para o comprimento do bloco
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(ciphertext).decode()

# Função para decifrar a mensagem
def decrypt_message(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(base64.urlsafe_b64decode(ciphertext.encode())) + decryptor.finalize()
    return decrypted_message.decode().rstrip('\0')  # Remover caracteres nulos adicionados pelo padding

relogio_lamport = 0

# Dicionário para armazenar mensagens pendentes de confirmação
mensagens_pendentes = {}

# Dicionário para armazenar mensagens recebidas por cada processo
mensagens_recebidas = {}

# Lock para garantir acesso seguro ao dicionário mensagens_recebidas
lock = threading.Lock()

# Função para receber mensagens P2P
def receive_messages(peer_socket, key):
    timestamp = None
    global relogio_lamport
    while True:
        try:
            data, addr = peer_socket.recvfrom(BUFFER_SIZE)
            if not data or not addr:
                break

            decoded_data = data.decode('utf-8')

            # Verifica se é o timestamp
            if decoded_data.startswith("[RL:") and decoded_data.endswith("]"):
                timestamp = decoded_data[4:-1]
                print(f"Timestamp recebido: {timestamp}")

            # Verifica se é a mensagem cifrada
            elif timestamp is not None:
                remetente = LOCAL_HOST if addr[0] == LOCAL_HOST else f"({addr[0]}:{addr[1]})"
                mensagem = f"{remetente} [{timestamp}] : {decrypt_message(decoded_data, key)}"

                if "HISTORICO" not in decrypt_message(decoded_data, key).upper():
                    hash_message = generate_hash(mensagem)

                    if hash_message not in mensagens_conhecidas:
                        mensagens_conhecidas[hash_message] = True
                        conversa.append((mensagem, addr[0], relogio_lamport))
                        conversa.sort(key=lambda x: (x[2], x[1]))

                        for msg, _, _ in conversa:
                            print(msg)

                        relogio_lamport += 1

                        # Envia confirmação
                        confirmacao_message = f"CONFIRMACAO:{relogio_lamport}"
                        peer_socket.sendto(confirmacao_message.encode('utf-8'), (addr[0], dest_port))

                        # Remove da lista de mensagens pendentes
                        if hash_message in mensagens_pendentes:
                            del mensagens_pendentes[hash_message]

                        # Adiciona a mensagem ao buffer de mensagens recebidas
                        with lock:
                            if hash_message not in mensagens_recebidas:
                                mensagens_recebidas[hash_message] = [addr[0]]
                            else:
                                mensagens_recebidas[hash_message].append(addr[0])

                timestamp = None

            # Verifica se é uma solicitação de histórico
            elif decoded_data == "HISTORICO":
                for mensagem_antiga in conversa:
                    # Envia cada mensagem do histórico
                    peer_socket.sendto(mensagem_antiga[0].encode('utf-8'), (addr[0], dest_port))
                    # Espera um pouco para garantir a ordem
                    #time.sleep(0.1)

                # Indica o fim do histórico
                peer_socket.sendto("[HISTORICO_FIM]".encode('utf-8'), (addr[0], dest_port))

            # Verifica se é uma confirmação
            elif decoded_data.startswith("[CONFIRMACAO:") and decoded_data.endswith("]"):
                _, _, timestamp_confirmacao = decoded_data[1:-1].split(":")
                timestamp_confirmacao = int(timestamp_confirmacao)
                # Remove da lista de mensagens pendentes
                with lock:
                    for hash_message, ts, dest_ip in mensagens_pendentes.copy().items():
                        if ts == timestamp_confirmacao:
                            del mensagens_pendentes[hash_message]
                            print(f"Confirmação recebida para mensagem enviada para {dest_ip}")

                # Verifica se todas as mensagens foram recebidas por todos os destinatários
                if all(len(mensagens_recebidas.get(msg_hash, [])) == len(dest_ips) for msg_hash in mensagens_pendentes):
                    print("Todas as mensagens foram entregues a todos os receptores!")

            # Verifica se é um Nack
            elif decoded_data.startswith("[NACK:") and decoded_data.endswith("]"):
                _, hash_nack = decoded_data[1:-1].split(":")
                if hash_nack in mensagens_recebidas:
                    for dest_ip in mensagens_recebidas[hash_nack]:
                        peer_socket.sendto(mensagens[hash_nack].encode('utf-8'), (dest_ip, dest_port))

            else:
                print(decoded_data)
                #conversa.clear()
                #conversa.append((decoded_data, addr[0], relogio_lamport))

        except Exception as e:
            print(f"Erro ao receber mensagem P2P: {e}")

# Função send_messages para enviar a solicitação de histórico
def send_messages(peer_socket, key):
    while True:
        try:
            mensagem = input()
            if mensagem.lower() == 'sair':
                break

            mensagem_cifrada = encrypt_message(mensagem, key)
            timestamp_message = f"[RL:{relogio_lamport}]"

            # Verifica se algum destinatário não recebeu a mensagem
            send_to_all = True
            for dest_ip in dest_ips:
                if dest_ip != LOCAL_HOST and dest_ip not in mensagens_recebidas.get(generate_hash(mensagem), []):
                    send_to_all = False
                    break

            if send_to_all:
                for dest_ip in dest_ips:
                    peer_socket.sendto(timestamp_message.encode('utf-8'), (dest_ip, dest_port))
                    peer_socket.sendto(mensagem_cifrada.encode('utf-8'), (dest_ip, dest_port))

                # Se o usuário solicitar o histórico
                if mensagem.upper() == 'HISTORICO':
                    # Adiciona uma pequena pausa para dar tempo de receber as mensagens antigas
                    time.sleep(1)
                    # Solicita o histórico a todos os outros usuários
                    for dest_ip in dest_ips:
                        peer_socket.sendto("HISTORICO".encode('utf-8'), (dest_ip, dest_port))
                        # Adiciona um pequeno atraso entre o envio de cada mensagem do histórico
                        time.sleep(0.1)

                # Aguarda a confirmação de todos os receptores
                start_time = time.time()
                while True:
                    if all(len(mensagens_recebidas.get(msg_hash, [])) == len(dest_ips) for msg_hash in mensagens_pendentes):
                        break
                    if time.time() - start_time > 5:  # Timeout de 5 segundos
                        print("Timeout: mensagem não entregue para todos os receptores")
                        break

            else:
                print("Mensagem não entregue para todos os receptores, não será enviada para nenhum.")

        except Exception as e:
            print(f"Erro ao enviar mensagem P2P: {e}")

# Configurar e iniciar o socket UDP para comunicação P2P
peer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
peer_socket.bind((LOCAL_HOST, LOCAL_PORT))

# Derivar a chave de criptografia
key = derive_key(password)

# Iniciar a thread para receber mensagens P2P
receive_thread = threading.Thread(target=receive_messages, args=(peer_socket, key))
receive_thread.start()

# Iniciar a thread para enviar mensagens
send_thread = threading.Thread(target=send_messages, args=(peer_socket, key))
send_thread.start()

print("Bem-vindo ao Chat P2P (UDP)!")
print("Digite 'sair' para encerrar o chat e HISTORICO para carregar as mensagens enquanto estava offline.")

# Aguardar o encerramento do programa
try:
    while True:
        pass
except KeyboardInterrupt:
    peer_socket.close()
