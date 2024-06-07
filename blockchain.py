import hashlib
import json
import time
import base64
import uuid
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

cripto_to_Cop = 4000

class Transaction:
    def __init__(self, transaction_id, amount, sender_id, receiver_id, signature):
        self.transaction_id = transaction_id
        self.amount = amount
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.signature = signature

    def to_dict(self):
        return {
            'transaction_id': self.transaction_id,
            'amount': self.amount,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'signature': base64.b64encode(self.signature).decode('utf-8') if self.signature else None,
        }

    @staticmethod
    def from_dict(data):
        signature = base64.b64decode(data['signature']) if data['signature'] else None
        return Transaction(data['transaction_id'], data['amount'], data['sender_id'], data['receiver_id'], signature)

class Block:
    def __init__(self, index, previous_hash, transactions, nonce, merkle_root, current_hash, proof_of_work):
        self.index = index
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.nonce = nonce
        self.merkle_root = merkle_root
        self.hash = current_hash
        self.proof_of_work = proof_of_work
        

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'nonce': self.nonce,
            'merkle_root': self.merkle_root,
            'hash': self.hash,
            'proof_of_work': self.proof_of_work
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, '0' * 128, [], 0, '', '0' * 128, '')
        self.chain.append(genesis_block)

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine_block(self):
        if len(self.pending_transactions) < 16:
            return False  # Not enough transactions to mine a block

        index = len(self.chain)
        previous_hash = self.chain[-1].hash
        transactions = self.pending_transactions[:16]
        self.pending_transactions = self.pending_transactions[16:]
        
        merkle_root = self.calculate_merkle_root(transactions)
        nonce, proof_of_work = self.proof_of_work(merkle_root, transactions)
                
        current_hash = self.calculate_hash(index, previous_hash, transactions, nonce, merkle_root)
        new_block = Block(index, previous_hash, transactions, nonce, merkle_root, current_hash, proof_of_work)
        
        self.chain.append(new_block)
        return new_block

    def calculate_merkle_root(self, transactions):
        transaction_hashes = [self.hash_transaction(tx) for tx in transactions]
        return self.merkle_root(transaction_hashes)

    def merkle_root(self, hashes):
        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])
            new_hashes = []
            for i in range(0, len(hashes), 2):
                new_hash = hashlib.sha256((hashes[i] + hashes[i + 1]).encode()).hexdigest()
                new_hashes.append(new_hash)
            hashes = new_hashes
        return hashes[0]

    def proof_of_work(self, merkle_root, transactions):
        nonce = 0
        while True:
            hash_candidate = hashlib.md5((str(nonce) + merkle_root + json.dumps([tx.to_dict() for tx in transactions])).encode()).hexdigest()
            if hash_candidate.startswith('000'):
                return nonce, hash_candidate
            nonce += 1

    def calculate_hash(self, index, previous_hash, transactions, nonce, merkle_root):
        block_string = f"{index}{previous_hash}{json.dumps([tx.to_dict() for tx in transactions])}{nonce}{merkle_root}"
        return hashlib.sha512(block_string.encode()).hexdigest()

    def hash_transaction(self, transaction):
        return hashlib.sha256(json.dumps(transaction.to_dict()).encode()).hexdigest()

    def verify_transaction(self, transaction, public_key):
        transaction_data = f"{transaction.transaction_id}{transaction.amount}{transaction.sender_id}{transaction.receiver_id}"
        hashed_data = SHA256.new(transaction_data.encode())
        try:
            pkcs1_15.new(public_key).verify(hashed_data, transaction.signature)
            return True
        except (ValueError, TypeError):
            return False
    def calculate_balance(self, id):
        balance = 0

        for block in self.chain:
            for transaction in block.transactions:
                if transaction.receiver_id == id:
                    balance += transaction.amount

        return balance

# Crear claves RSA
def create_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Firmar una transacción
def sign_transaction(transaction, private_key):
    key = RSA.import_key(private_key)
    transaction_data = f"{transaction.transaction_id}{transaction.amount}{transaction.sender_id}{transaction.receiver_id}"
    hashed_data = SHA256.new(transaction_data.encode())
    signature = pkcs1_15.new(key).sign(hashed_data)
    return signature

# Crear la cadena de bloques
blockchain = Blockchain()

Acafeteria_id = uuid.uuid4().hex
# Crear 16 transacciones y añadirlas al blockchain
for i in range(1, 80):
    private_key, public_key = create_rsa_keys()
    student_id = uuid.uuid4().hex
    cafeteria_id = Acafeteria_id
    transaction_id = i
    amount = 2  # Monto de la transacción

    transaction = Transaction(transaction_id, amount, student_id, cafeteria_id, None)
    transaction.signature = sign_transaction(transaction, private_key)

    if blockchain.verify_transaction(transaction, RSA.import_key(public_key)):
        blockchain.add_transaction(transaction)
    else:
        print(f"Transacción {i} inválida. No se pudo verificar la firma.")

    # Intentar minar el bloque después de cada 6 transacciones
    if i % 16 == 0:
        mined_block = blockchain.mine_block()

        if mined_block:
            print("Bloque minado:", mined_block.to_dict())
        else:
            print("No se pudo minar el bloque, se requieren más transacciones.")


# Imprimir toda la cadena de bloques
for block in blockchain.chain:
    print(json.dumps(block.to_dict(), indent=4)) 


def exchange_cripto_to_COP(cripto_balance):
    exchange = int(cripto_balance) * cripto_to_Cop
    return exchange

# Después de agregar todas las transacciones
cafeteria_balance = blockchain.calculate_balance(Acafeteria_id)
print("IngeCoins actuales de la cafetería:", cafeteria_balance)

cafeteria_balance_COP = exchange_cripto_to_COP(cafeteria_balance)
print(f"Saldo actual de la cafetería en COP para la fecha es: ", cafeteria_balance_COP)