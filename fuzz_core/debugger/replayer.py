from __future__ import annotations
import socket, subprocess
from pathlib import Path
from .models import TargetConfig

class Replayer:
    def __init__(self, allow_network: bool=False):
        self.allow_network=allow_network

    def replay(self, target: TargetConfig, artifact_path: str|None):
        mode=target.transport_type
        data=Path(artifact_path).read_bytes() if artifact_path and Path(artifact_path).exists() else b""
        if mode in {"udp","tcp"} and not self.allow_network:
            return {"mode":mode, "sent":False, "reason":"network replay disabled by config", "bytes":len(data)}
        if mode=="udp":
            host=target.transport_config.get("host","127.0.0.1"); port=int(target.transport_config.get("port",0))
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(data,(host,port)); s.close()
            return {"mode":"udp","sent":True,"bytes":len(data),"target":f"{host}:{port}"}
        if mode=="tcp":
            host=target.transport_config.get("host","127.0.0.1"); port=int(target.transport_config.get("port",0))
            with socket.create_connection((host,port), timeout=3) as s: s.sendall(data)
            return {"mode":"tcp","sent":True,"bytes":len(data),"target":f"{host}:{port}"}
        if mode=="custom":
            cmd=target.transport_config.get("command")
            if not cmd: return {"mode":"custom","sent":False,"reason":"missing command"}
            cp=subprocess.run(cmd, shell=True, input=data, cwd=target.cwd, capture_output=True, timeout=10)
            return {"mode":"custom","sent":True,"returncode":cp.returncode,"stdout_tail":cp.stdout[-2000:].decode(errors="ignore"),"stderr_tail":cp.stderr[-2000:].decode(errors="ignore")}
        return {"mode":mode,"sent":bool(data),"bytes":len(data)}
