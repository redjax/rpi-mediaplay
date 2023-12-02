from domain.ssh import RemoteHostSSH
from loguru import logger as log

def dbg_hosts(hosts: list[RemoteHostSSH] = None) -> None:
    if hosts is None:
        raise ValueError("Missing list of RemoteHostSSH objects to debug")   
    if not isinstance(hosts, list):
        raise TypeError(f"Invalid type for 'hosts': ({type(hosts)}). Must be a list of RemoteHostSSH objects")
    for i in hosts:
        if not isinstance(i, RemoteHostSSH):
            raise TypeError(f"Invalid type for list item: ({type(i)}). Must be of type RemoteHostSSH.\nInvalid list item: {i}")
        
    log.debug(f"Loaded [{len(hosts)}] RemoteHostSSH object(s)")
    
    if len(hosts) == 1:
        host: RemoteHostSSH = hosts[0]
    
        log.debug(f"Detected a single host: {host}")
        log.debug(f"Keys in: {host.keyfiles_dir} -- {'exists' if host.keyfiles_dir.exists() else 'does not exist'}")
        log.debug(f"Private key: {host.private_key} -- {'exists' if host.private_key.exists() else 'does not eixst'}")
        log.debug(f"Public key: {host.public_key} -- {'exists' if host.public_key.exists() else 'does not eixst'}")

    else:
        log.debug(f"Hosts: {hosts}")
        for host in hosts:
            log.debug(f"[HOST: {host.name}] Keys in: {host.keyfiles_dir} -- {'exists' if host.keyfiles_dir.exists() else 'does not exist'}")
            log.debug(f"[HOST: {host.name}] Private key: {host.private_key} -- {'exists' if host.private_key.exists() else 'does not eixst'}")
            log.debug(f"[HOST: {host.name}] Public key: {host.public_key} -- {'exists' if host.public_key.exists() else 'does not eixst'}")
