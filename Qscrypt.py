# Qscrypt.py
import hashlib
import time
import json
import scrypt
import logging
import threading
import queue
import os
import psutil
import pyopencl as cl
import numpy as np
import requests
import yaml
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
import socket
import binascii
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from prometheus_client import Counter, Gauge, start_http_server
from kafka import KafkaProducer, KafkaConsumer
import serial.tools.list_ports
import usb.core
import usb.util

# Configuration
CONFIG_PATH = "appsettings.json"
LOG_FILE = "miner.log"
BLOCK_TARGET_TIME = 2.5
DIFFICULTY = 4
MAX_NONCE = 2**32
KAFKA_BOOTSTRAP_SERVERS = ["localhost:9092"]
KAFKA_TOPIC_TASKS = "mining_tasks"
KAFKA_TOPIC_SHARES = "mining_shares"
PROMETHEUS_PORT = 8000
MAX_INVALID_SHARES = 5

# Default pool configurations
DEFAULT_POOLS = {
    "litecoin": [
        "stratum+tcp://pool.litecoin.org:3333",
        "stratum+tcp://litecoin.f2pool.com:3333",
        "stratum+tcp://stratum.viabtc.com:3333"
    ],
    "dogecoin": [
        "stratum+tcp://pool.dogecoin.com:3333",
        "stratum+tcp://dogecoin.f2pool.com:3333",
        "stratum+tcp://stratum.viabtc.com:3256"
    ]
}

# CGMiner Scrypt kernel
SCRYPT_KERNEL = """
#define SCRYPT_N 1024
#define SCRYPT_R 1
#define SCRYPT_P 1
#define SCRYPT_KEYLEN 32

#define rotl(x, n) ((x) << (n)) | ((x) >> (32 - (n)))

static void salsa8(uint *B) {
    uint x0 = B[0], x1 = B[1], x2 = B[2], x3 = B[3], x4 = B[4], x5 = B[5], x6 = B[6], x7 = B[7];
    uint x8 = B[8], x9 = B[9], x10 = B[10], x11 = B[11], x12 = B[12], x13 = B[13], x14 = B[14], x15 = B[15];
    
    for (int i = 0; i < 8; i += 2) {
        x4 ^= rotl(x0 + x12, 7);  x8 ^= rotl(x4 + x0, 9);
        x12 ^= rotl(x8 + x4, 13); x0 ^= rotl(x12 + x8, 18);
        x9 ^= rotl(x5 + x1, 7);   x13 ^= rotl(x9 + x5, 9);
        x1 ^= rotl(x13 + x9, 13); x5 ^= rotl(x1 + x9, 18);
        x14 ^= rotl(x10 + x6, 7); x2 ^= rotl(x14 + x10, 9);
        x6 ^= rotl(x2 + x14, 13); x10 ^= rotl(x6 + x2, 18);
        x3 ^= rotl(x15 + x11, 7); x7 ^= rotl(x3 + x15, 9);
        x11 ^= rotl(x7 + x3, 13); x15 ^= rotl(x11 + x7, 18);
        
        x1 ^= rotl(x0 + x3, 7);   x2 ^= rotl(x1 + x0, 9);
        x3 ^= rotl(x2 + x1, 13);  x0 ^= rotl(x3 + x2, 18);
        x6 ^= rotl(x5 + x4, 7);   x7 ^= rotl(x6 + x5, 9);
        x4 ^= rotl(x7 + x6, 13);  x5 ^= rotl(x4 + x7, 18);
        x11 ^= rotl(x10 + x9, 7); x8 ^= rotl(x11 + x10, 9);
        x9 ^= rotl(x8 + x11, 13); x10 ^= rotl(x9 + x8, 18);
        x12 ^= rotl(x15 + x14, 7); x13 ^= rotl(x12 + x15, 9);
        x14 ^= rotl(x13 + x12, 13); x15 ^= rotl(x14 + x13, 18);
    }
    
    B[0] += x0; B[1] += x1; B[2] += x2; B[3] += x3;
    B[4] += x4; B[5] += x5; B[6] += x6; B[7] += x7;
    B[8] += x8; B[9] += x9; B[10] += x10; B[11] += x11;
    B[12] += x12; B[13] += x13; B[14] += x14; B[15] += x15;
}

static void scrypt_core(__global uint *X, __global uint *V, int N) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < 32; j++) V[i * 32 + j] = X[j];
        salsa8(X);
    }
    for (int i = 0; i < N; i++) {
        int j = X[16] & (N - 1);
        for (int k = 0; k < 32; k++) X[k] ^= V[j * 32 + k];
        salsa8(X);
    }
}

__kernel void scrypt_hash(__global const uchar *input, __global uchar *output, uint nonce, uint N, uint r, uint p) {
    uint idx = get_global_id(0);
    __private uint X[32];
    __private uint V[SCRYPT_N * 32];
    
    for (int i = 0; i < 80; i++) X[i % 32] = input[i];
    X[30] = nonce & 0xFF;
    X[31] = (nonce >> 8) & 0xFF;
    
    for (int i = 0; i < 32; i++) X[i] = X[i] ^ input[i % 80];
    salsa8(X);
    
    scrypt_core(X, V, N);
    
    salsa8(X);
    for (int i = 0; i < SCRYPT_KEYLEN; i++) output[idx * SCRYPT_KEYLEN + i] = X[i];
}
"""

# Prometheus metrics
hashrate_gauge = Gauge("miner_hashrate_khs", "Hashrate in KH/s", ["network", "miner_id"])
solutions_submitted = Counter("miner_solutions_submitted", "Shares submitted", ["network", "miner_id"])
errors_counter = Counter("miner_errors", "Mining errors", ["network", "miner_id"])

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def load_config() -> Dict:
    try:
        with open(CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        logger.error("Config file not found, creating default")
        default_config = {
            "Network": "Litecoin",
            "LitecoinAddress": "YOUR_LITECOIN_ADDRESS",
            "DogecoinAddress": "YOUR_DOGECOIN_ADDRESS",
            "CpuThreads": psutil.cpu_count(logical=True),
            "GpuEnabled": true,
            "AsicEnabled": true,
            "Intensity": 14,
            "ThreadConcurrency": 16384,
            "LitecoinPools": DEFAULT_POOLS["litecoin"],
            "DogecoinPools": DEFAULT_POOLS["dogecoin"],
            "StratumUser": "YOUR_USERNAME",
            "StratumPassword": "YOUR_PASSWORD",
            "TlsEnabled": true,
            "KafkaBootstrapServers": KAFKA_BOOTSTRAP_SERVERS,
            "KafkaTasksTopic": KAFKA_TOPIC_TASKS,
            "KafkaSharesTopic": KAFKA_TOPIC_SHARES,
            "ProfitabilityApi": "https://api.coingecko.com/api/v3/simple/price?ids=litecoin,dogecoin&vs_currencies=usd",
            "CoordinatorMode": false,
            "MinerId": hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        }
        with open(CONFIG_PATH, "w") as f:
            yaml.safe_dump(default_config, f)
        return default_config

class StratumClient:
    def __init__(self, pools: List[str], user: str, password: str, tls_enabled: bool):
        self.pools = pools
        self.current_pool_idx = 0
        self.user = user
        self.password = password
        self.tls_enabled = tls_enabled
        self.sock = None
        self.extranonce1 = ""
        self.extranonce2_size = 0
        self.job_id = None
        self.prevhash = ""
        self.merkle_root = ""
        self.ntime = ""
        self.nbits = ""
        self.target = ""

    def connect(self) -> bool:
        for i in range(len(self.pools)):
            self.current_pool_idx = i
            pool_url = self.pools[i].replace("stratum+tcp://", "")
            try:
                host, port = pool_url.split(":")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.tls_enabled:
                    context = ssl.create_default_context()
                    self.sock = context.wrap_socket(self.sock, server_hostname=host)
                self.sock.connect((host, int(port)))
                logger.info(f"Connected to Stratum pool {pool_url}")
                self._subscribe()
                self._authorize()
                return True
            except Exception as e:
                logger.error(f"Failed to connect to pool {pool_url}: {e}")
                errors_counter.labels(network="stratum", miner_id="standalone").inc()
                self.sock = None
        logger.error("All pools failed, retrying in 30 seconds")
        time.sleep(30)
        return self.connect()

    def _subscribe(self):
        self._send({"id": 1, "method": "mining.subscribe", "params": []})
        response = self._receive()
        if response.get("result"):
            self.extranonce1 = response["result"][1]
            self.extranonce2_size = response["result"][2]
            logger.info("Subscribed to Stratum pool")

    def _authorize(self):
        self._send({"id": 2, "method": "mining.authorize", "params": [self.user, self.password]})
        response = self._receive()
        if response.get("result"):
            logger.info("Authorized with Stratum pool")

    def _send(self, message: Dict):
        self.sock.sendall((json.dumps(message) + "\n").encode())

    def _receive(self) -> Dict:
        data = self.sock.recv(4096).decode().strip()
        return json.loads(data)

    def get_job(self) -> Optional[Dict]:
        try:
            data = self._receive()
            if data.get("method") == "mining.notify":
                params = data["params"]
                self.job_id = params[0]
                self.prevhash = params[1]
                self.merkle_root = params[2]
                self.ntime = params[4]
                self.nbits = params[5]
                self.target = params[7]
                return {
                    "job_id": self.job_id,
                    "prevhash": self.prevhash,
                    "merkle_root": self.merkle_root,
                    "ntime": self.ntime,
                    "nbits": self.nbits,
                    "target": self.target
                }
            return None
        except Exception as e:
            logger.error(f"Stratum job fetch error: {e}")
            errors_counter.labels(network="stratum", miner_id="standalone").inc()
            return None

    def submit_share(self, job_id: str, extranonce2: str, ntime: str, nonce: str) -> bool:
        try:
            self._send({
                "id": 3,
                "method": "mining.submit",
                "params": [self.user, job_id, extranonce2, ntime, nonce]
            })
            response = self._receive()
            if response.get("result"):
                logger.info(f"Share submitted for job {job_id}")
                solutions_submitted.labels(network=self.network, miner_id="standalone").inc()
                return True
            else:
                logger.warning(f"Share rejected: {response.get('error')}")
                return False
        except Exception as e:
            logger.error(f"Share submission error: {e}")
            errors_counter.labels(network=self.network, miner_id="standalone").inc()
            return False

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

class AsicDriver:
    def __init__(self):
        self.devices = []
        self.serial_ports = []

    def detect_asics(self) -> List:
        try:
            for dev in usb.core.find(find_all=True):
                if dev.idVendor in [0x10c4, 0x1a86]:
                    self.devices.append(dev)
                    logger.info(f"Detected ASIC: {dev.idVendor}:{dev.idProduct}")
            for port in serial.tools.list_ports.comports():
                if "USB" in port.description or "ASIC" in port.description:
                    self.serial_ports.append(port.device)
                    logger.info(f"Detected ASIC on serial port: {port.device}")
            return self.devices + self.serial_ports
        except Exception as e:
            logger.error(f"ASIC detection error: {e}")
            return []

    def initialize_asic(self, device):
        try:
            if isinstance(device, usb.core.Device):
                device.set_configuration()
                logger.info(f"Initialized USB ASIC: {device.idVendor}:{device.idProduct}")
            elif isinstance(device, str):
                ser = serial.Serial(device, baudrate=115200, timeout=1)
                ser.write(b"INIT\n")
                response = ser.read(1024).decode()
                logger.info(f"Initialized serial ASIC on {device}: {response}")
                ser.close()
            return True
        except Exception as e:
            logger.error(f"ASIC initialization error: {e}")
            return False

    def hash_asic(self, data: str, nonce: int, device) -> str:
        try:
            if isinstance(device, usb.core.Device):
                data_bytes = f"{data}{nonce}".encode()
                device.write(0x01, data_bytes, timeout=1000)
                hash_output = device.read(0x81, 32, timeout=1000)
                return hashlib.sha256(bytes(hash_output)).hexdigest()
            elif isinstance(device, str):
                ser = serial.Serial(device, baudrate=115200, timeout=1)
                ser.write(f"SCRYPT:{data}:{nonce}\n".encode())
                hash_output = ser.read(32).hex()
                ser.close()
                return hash_output
        except Exception as e:
            logger.error(f"ASIC hash error: {e}")
            return ""

class ScryptMiner:
    def __init__(self, config: Dict):
        self.miner_id = config.get("MinerId", hashlib.sha256(str(time.time()).encode()).hexdigest()[:8])
        self.config = config
        self.coordinator_mode = config.get("CoordinatorMode", False)
        self.network = config.get("Network", "Litecoin").lower()
        self.cpu_threads = config.get("CpuThreads", psutil.cpu_count(logical=True))
        self.gpu_enabled = config.get("GpuEnabled", True)
        self.asic_enabled = config.get("AsicEnabled", True)
        self.intensity = min(max(config.get("Intensity", 14), 8), 20)
        self.thread_concurrency = config.get("ThreadConcurrency", 16384)
        self.litecoin_address = config.get("LitecoinAddress")
        self.dogecoin_address = config.get("DogecoinAddress")
        self.stratum_user = config.get("StratumUser")
        self.stratum_password = config.get("StratumPassword")
        self.litecoin_pools = config.get("LitecoinPools", DEFAULT_POOLS["litecoin"])
        self.dogecoin_pools = config.get("DogecoinPools", DEFAULT_POOLS["dogecoin"])
        self.tls_enabled = config.get("TlsEnabled", True)
        self.kafka_bootstrap = config.get("KafkaBootstrapServers", KAFKA_BOOTSTRAP_SERVERS)
        self.kafka_tasks_topic = config.get("KafkaTasksTopic", KAFKA_TOPIC_TASKS)
        self.kafka_shares_topic = config.get("KafkaSharesTopic", KAFKA_TOPIC_SHARES)
        self.nonce_start = 0
        self.nonce_end = MAX_NONCE
        self.target = "0" * DIFFICULTY
        self.miner_hashrate = 0
        self.task_queue = queue.Queue(maxsize=1000)
        self.running = False
        self.stratum = None
        self.producer = None
        self.consumer = None
        self.contexts = []
        self.queues = []
        self.programs = []
        self.use_opencl = False
        self.gpu_devices = []
        self.asic_driver = AsicDriver()
        self.asic_devices = []
        self.blacklist = set()
        self.invalid_shares = {}
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.public_key = self.private_key.public_key()
        self.public_keys = {}  # MinerId to public_key, load from secure storage
        self._hardware_check()
        self._init_kafka()

    def _hardware_check(self):
        cpu_count = psutil.cpu_count(logical=True)
        mem_info = psutil.virtual_memory()
        available_mem = mem_info.available / 1024**3

        # ASIC detection
        if self.asic_enabled:
            self.asic_devices = self.asic_driver.detect_asics()
            for device in self.asic_devices:
                if not self.asic_driver.initialize_asic(device):
                    self.asic_devices.remove(device)
            logger.info(f"Detected {len(self.asic_devices)} ASICs")

        # GPU detection
        if self.gpu_enabled:
            try:
                platforms = cl.get_platforms()
                for platform in platforms:
                    devices = platform.get_devices()
                    for device in devices:
                        if device.type == cl.device_type.GPU and device.global_mem_size >= 6 * 1024**3 and device.max_compute_units >= 24:
                            self.gpu_devices.append(device)
                logger.info(f"Detected {len(self.gpu_devices)} GPUs")
            except Exception as e:
                logger.warning(f"No OpenCL GPUs detected: {e}")

        if self.asic_devices:
            self.use_opencl = False
            logger.info("Selected ASIC Scrypt kernel")
        elif self.gpu_devices and available_mem >= 3:
            self.use_opencl = True
            self._init_opencl()
            logger.info("Selected OpenCL Scrypt kernel for GPUs")
            for device in self.gpu_devices:
                shaders = min(device.max_compute_units * 256, 4096)
                self.thread_concurrency = min(self.thread_concurrency, shaders * 4)
                self.intensity = min(self.intensity, int(device.global_mem_size / 1024**3 * 2.5))
        else:
            self.use_opencl = False
            self.cpu_threads = max(1, int(cpu_count * 0.8))
            logger.info(f"Selected Python Scrypt kernel for CPU ({self.cpu_threads} threads)")

        if available_mem < 1.5:
            logger.warning("Low system memory (<1.5GB), reducing threads")
            self.cpu_threads = max(1, self.cpu_threads // 2)
            self.gpu_enabled = False
            self.use_opencl = False
            self.asic_enabled = False

    def _init_opencl(self):
        for device in self.gpu_devices:
            try:
                context = cl.Context([device])
                queue = cl.CommandQueue(context)
                program = cl.Program(context, open("scrypt.cl").read() if os.path.exists("scrypt.cl") else SCRYPT_KERNEL).build()
                self.contexts.append(context)
                self.queues.append(queue)
                self.programs.append(program)
                logger.info(f"Initialized OpenCL on {device.name}")
            except Exception as e:
                logger.error(f"Failed to initialize OpenCL for {device.name}: {e}")
                self.gpu_enabled = False
                self.use_opencl = False

    def _init_kafka(self):
        try:
            if self.coordinator_mode:
                self.producer = KafkaProducer(
                    bootstrap_servers=self.kafka_bootstrap,
                    security_protocol="SSL" if self.tls_enabled else "PLAINTEXT",
                    value_serializer=lambda v: json.dumps(v).encode('utf-8')
                )
            else:
                self.consumer = KafkaConsumer(
                    f"{self.kafka_tasks_topic}_{self.miner_id}",
                    bootstrap_servers=self.kafka_bootstrap,
                    security_protocol="SSL" if self.tls_enabled else "PLAINTEXT",
                    value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                    auto_offset_reset='latest',
                    group_id=f"miner_{self.miner_id}"
                )
                self.producer = KafkaProducer(
                    bootstrap_servers=self.kafka_bootstrap,
                    security_protocol="SSL" if self.tls_enabled else "PLAINTEXT",
                    value_serializer=lambda v: json.dumps(v).encode('utf-8')
                )
            logger.info("Initialized Kafka client")
        except Exception as e:
            logger.error(f"Kafka initialization error: {e}")
            errors_counter.labels(network=self.network, miner_id=self.miner_id).inc()

    def _scrypt_hash(self, data: str, nonce: int, device_idx: int = 0) -> str:
        input_data = f"{data}{nonce}".encode()
        try:
            if self.asic_devices and self.asic_enabled:
                device = self.asic_devices[device_idx % len(self.asic_devices)]
                return self.asic_driver.hash_asic(data, nonce, device)
            elif self.use_opencl and self.gpu_enabled and device_idx < len(self.programs):
                data_buf = cl.Buffer(self.contexts[device_idx], cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=input_data)
                output_buf = cl.Buffer(self.contexts[device_idx], cl.mem_flags.WRITE_ONLY, 32 * self.thread_concurrency)
                global_size = (self.thread_concurrency,)
                self.programs[device_idx].scrypt_hash(
                    self.queues[device_idx], global_size, None, data_buf, output_buf, np.uint32(nonce), np.uint32(1024), np.uint32(1), np.uint32(1)
                )
                output = np.zeros(32 * self.thread_concurrency, dtype=np.uint8)
                cl.enqueue_copy(self.queues[device_idx], output, output_buf).wait()
                hash_output = bytes(output[:32])
            else:
                hash_output = scrypt.hash(input_data, salt=input_data, N=1024, r=1, p=1, dkLen=32)
            return hashlib.sha256(hash_output).hexdigest()
        except Exception as e:
            logger.error(f"Scrypt hash error: {e}")
            errors_counter.labels(network=self.network, miner_id=self.miner_id).inc()
            return ""

    def _tune_scrypt_parameters(self):
        if self.asic_enabled and self.asic_devices:
            logger.info("ASIC parameters fixed, no tuning required")
        elif self.use_opencl and self.gpu_enabled:
            for device in self.gpu_devices:
                try:
                    shaders = device.max_compute_units * 256
                    self.thread_concurrency = min(self.thread_concurrency, shaders * 4)
                    mem_info = psutil.virtual_memory()
                    if mem_info.available < 3 * 1024**3:
                        self.intensity = max(8, self.intensity - 2)
                        logger.warning(f"Reduced intensity to {self.intensity} due to low memory")
                    elif self.miner_hashrate < 100:
                        self.intensity = min(20, self.intensity + 1)
                        logger.info(f"Increased intensity to {self.intensity}")
                    logger.info(f"Tuned thread-concurrency to {self.thread_concurrency}")
                except Exception as e:
                    logger.error(f"Tuning error: {e}")
                    errors_counter.labels(network=self.network, miner_id=self.miner_id).inc()
                    self.thread_concurrency = 16384
                    self.intensity = 14
        else:
            cpu_usage = psutil.cpu_percent()
            if cpu_usage > 85:
                self.cpu_threads = max(1, self.cpu_threads - 2)
                logger.info(f"Reduced CPU threads to {self.cpu_threads} due to high load")
            elif self.miner_hashrate < 20 and self.cpu_threads < psutil.cpu_count(logical=True):
                self.cpu_threads += 1
                logger.info(f"Increased CPU threads to {self.cpu_threads}")

    def _connect_to_stratum(self):
        pools = self.litecoin_pools if self.network == "litecoin" else self.dogecoin_pools
        self.stratum = StratumClient(pools, self.stratum_user, self.stratum_password, self.tls_enabled)
        return self.stratum.connect()

    def _fetch_task(self) -> Optional[Dict]:
        if self.coordinator_mode:
            return self.stratum.get_job()
        else:
            try:
                for message in self.consumer:
                    task = message.value
                    if not self.verify_task(task):
                        logger.warning(f"Invalid task checksum for {task.get('job_id')}")
                        continue
                    self.nonce_start = task.get("nonce_start", 0)
                    self.nonce_end = task.get("nonce_end", MAX_NONCE)
                    self.target = task.get("target", "0" * DIFFICULTY)
                    logger.info(f"Fetched task via Kafka: {task.get('job_id')}")
                    return task
            except Exception as e:
                logger.error(f"Kafka task fetch error: {e}")
                errors_counter.labels(network=self.network, miner_id=self.miner_id).inc()
                return None

    def _submit_share(self, solution: Dict):
        if self.coordinator_mode:
            if not self.verify_share(solution):
                return False
            try:
                result = self.stratum.submit_share(
                    solution["job_id"],
                    solution["extranonce2"],
                    solution["ntime"],
                    solution["nonce"]
                )
                if result:
                    solutions_submitted.labels(network=self.network, miner_id=self.miner_id).inc()
                return result
            except Exception as e:
                logger.error(f"Stratum submission error: {e}")
                errors_counter.labels(network=self.network, miner_id=self.miner_id).inc()
                return False
        else:
            try:
                solution = self.sign_share(solution)
                self.producer.send(self.kafka_shares_topic, solution)
                logger.info(f"Share sent to Kafka for job {solution['job_id']}")
                solutions_submitted.labels(network=self.network, miner_id=self.miner_id).inc()
                return True
            except Exception as e:
                logger.error(f"Kafka share submission error: {e}")
                errors_counter.labels(network=self.network, miner_id=self.miner_id).inc()
                return False

    def mine_block(self, task: Dict) -> Optional[Dict]:
        start_time = time.time()
        block_data = {
            "job_id": task["job_id"],
            "prevhash": task["prevhash"],
            "merkle_root": task["merkle_root"],
            "ntime": task["ntime"],
            "nbits": task["nbits"]
        }
        block_str = f"{task['prevhash']}{task['merkle_root']}{task['ntime']}{task['nbits']}"
        self.target = task["target"]

        for nonce in range(self.nonce_start, min(self.nonce_end, MAX_NONCE)):
            if not self.running:
                break
            device_idx = (nonce % (len(self.asic_devices) or len(self.gpu_devices) or 1))
            hash_result = self._scrypt_hash(block_str, nonce, device_idx)
            if hash_result < self.target:
                solution = {
                    "miner_id": self.miner_id,
                    "job_id": block_data["job_id"],
                    "nonce": format(nonce, '08x'),
                    "hash": hash_result,
                    "timestamp": time.time(),
                    "payout_address": self.litecoin_address if self.network == "litecoin" else self.dogecoin_address,
                    "ntime": block_data["ntime"],
                    "extranonce2": binascii.hexlify(os.urandom(self.stratum.extranonce2_size)).decode() if self.stratum else ""
                }
                self.miner_hashrate = (nonce - self.nonce_start + 1) / (time.time() - start_time + 1e-6) * 1000
                hashrate_gauge.labels(network=self.network, miner_id=self.miner_id).set(self.miner_hashrate)
                logger.info(f"Mined share: {hash_result}, hashrate: {self.miner_hashrate:.2f} KH/s")
                return solution
            if time.time() - start_time > BLOCK_TARGET_TIME:
                break
        return None

    def optimize_hardware(self):
        self._tune_scrypt_parameters()
        mem_info = psutil.virtual_memory()
        if mem_info.available < 1.5 * 1024**3:
            logger.warning("Low system memory (<1.5GB), switching to CPU")
            self.gpu_enabled = False
            self.use_opencl = False
            self.asic_enabled = False
            self.cpu_threads = max(1, int(psutil.cpu_count(logical=True) * 0.7))

    def coordinator_loop(self):
        if not self._connect_to_stratum():
            logger.error(f"Failed to connect to {self.network.capitalize()} pools, exiting")
            return
        miner_count = 100000  # Adjust based on expected miners
        nonce_range = MAX_NONCE // miner_count
        while self.running:
            try:
                task = self.stratum.get_job()
                if task:
                    for i in range(miner_count):
                        task_copy = task.copy()
                        task_copy["nonce_start"] = i * nonce_range
                        task_copy["nonce_end"] = (i + 1) * nonce_range
                        task_copy["checksum"] = hashlib.sha256(json.dumps(task_copy, sort_keys=True).encode()).hexdigest()
                        self.producer.send(f"{self.kafka_tasks_topic}_{i}", task_copy)
                    logger.info(f"Distributed task {task['job_id']} to {miner_count} miners")
                for message in KafkaConsumer(self.kafka_shares_topic, bootstrap_servers=self.kafka_bootstrap,
                                            security_protocol="SSL" if self.tls_enabled else "PLAINTEXT",
                                            value_deserializer=lambda x: json.loads(x.decode('utf-8'))):
                    solution = message.value
                    if self.verify_share(solution):
                        self._submit_share(solution)
                    else:
                        logger.warning(f"Invalid share from miner {solution['miner_id']}")
                time.sleep(0.005)
            except Exception as e:
                logger.error(f"Coordinator error: {e}")
                errors_counter.labels(network=self.network, miner_id=self.miner_id).inc()
                if not self._connect_to_stratum():
                    time.sleep(30)

    def worker_thread(self):
        while self.running:
            try:
                task = self._fetch_task()
                if task:
                    self.task_queue.put(task)
                    solution = self.mine_block(task)
                    if solution and self._submit_share(solution):
                        logger.info(f"Share submitted for job {task['job_id']}")
                    else:
                        logger.warning(f"Failed to mine or submit share")
                    self.optimize_hardware()
                time.sleep(0.005)
            except Exception as e:
                logger.error(f"Worker error: {e}")
                errors_counter.labels(network=self.network, miner_id=self.miner_id).inc()
                time.sleep(1)

    def start_mining(self):
        self._init_kafka()
        if self.coordinator_mode:
            self.coordinator_loop()
        else:
            self.running = True
            logger.info(f"Starting miner {self.miner_id} for {self.network.capitalize()} with {self.cpu_threads} threads, "
                        f"OpenCL: {self.use_opencl}, GPUs: {len(self.gpu_devices)}, ASICs: {len(self.asic_devices)}")
            with ThreadPoolExecutor(max_workers=self.cpu_threads) as executor:
                for _ in range(self.cpu_threads):
                    executor.submit(self.worker_thread)
                while self.running:
                    try:
                        time.sleep(1)
                    except KeyboardInterrupt:
                        logger.info("Stopping miner")
                        self.running = False
                        if self.stratum:
                            self.stratum.close()
                        if self.producer:
                            self.producer.close()
                        if self.consumer:
                            self.consumer.close()

def main():
    config = load_config()
    start_http_server(PROMETHEUS_PORT)
    miner = ScryptMiner(config)
    try:
        response = requests.get(config["ProfitabilityApi"])
        prices = response.json()
        ltc_profit = prices.get("litecoin", {}).get("usd", 0)
        doge_profit = prices.get("dogecoin", {}).get("usd", 0)
        if ltc_profit > doge_profit * 100:
            config["Network"] = "litecoin"
        elif doge_profit > 0:
            config["Network"] = "dogecoin"
    except Exception as e:
        logger.warning(f"Profitability check failed: {e}, defaulting to {config['Network']}")
    miner.network = config["Network"].lower()
    miner.start_mining()

if __name__ == "__main__":
    main()
