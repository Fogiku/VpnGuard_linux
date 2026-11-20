"""Cloud-init configuration for the live installer, independent of target setup."""
import copy
import json

INSTALLER_USER = "vgrecovery"

def live_seed(autoinstall, public_key, host_private, host_public):
    config = {
        "users": ["default", {"name": INSTALLER_USER, "gecos": "VpnGuard installer recovery",
            "shell": "/bin/bash", "lock_passwd": True,
            "sudo": ["ALL=(ALL) NOPASSWD:ALL"],
            "ssh_authorized_keys": [public_key.strip()]}],
        "ssh_pwauth": False,
        "ssh_keys": {"ed25519_private": host_private, "ed25519_public": host_public.strip()},
        "runcmd": [["bash", "/cdrom/vpnguard/live_start.sh"]],
        "autoinstall": copy.deepcopy(autoinstall["autoinstall"]),
    }
    identity = autoinstall["autoinstall"]["identity"]
    if identity.get("password", "").startswith("$6$"):
        config["users"].append({"name":identity["username"], "shell":"/bin/bash", "lock_passwd":False,
            "hashed_passwd":identity["password"], "sudo":["ALL=(ALL) NOPASSWD:ALL"], "ssh_authorized_keys":[public_key.strip()]})
        config["ssh_pwauth"] = True
    return "#cloud-config\n" + json.dumps(config, indent=2) + "\n"
