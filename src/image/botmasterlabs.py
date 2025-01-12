import requests
from concurrent.futures import ThreadPoolExecutor
import time
import random
from queue import Queue
import threading

hosts = ["176.9.22.213:2020", "65.109.110.229:2020"]

class XEvil:
    @staticmethod
    def solveImage(img, var, host=None, key="admin", timeout=30):
        host = host or random.choice(hosts)
        try:
            r = requests.post(f"http://{host}/in.php", data={"method": "base64", "key": key, "imginstructions": var, "body": img})
            if "|" not in r.text: raise ValueError("Invalid response")
            taskId = r.text.split("|")[1]
            start = time.time()
            while time.time() - start < timeout:
                resp = requests.get(f"http://{host}/res.php", params={"action": "get", "key": key, "id": taskId})
                if "OK" in resp.text:
                    return int(resp.text.split("|")[1]) - 1
                if any(x in resp.text for x in ["FAILED", "ERROR"]): break
                time.sleep(0.5)
            return random.randint(0, 4)
        except Exception:
            return random.randint(0, 4)

