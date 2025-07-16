import xml.etree.ElementTree as ET

CONFIG_PATH = "/conf/config.xml"

def _get_config_value(xpath, default=None):
    """
    Recupera un valore da config.xml partendo da /OPNsense/AdvInspector
    """
    try:
        tree = ET.parse(CONFIG_PATH)
        root = tree.getroot()
        # Cerca sotto il nodo corretto
        node = root.find(f".//OPNsense/AdvInspector{xpath}")
        return node.text.strip() if node is not None and node.text else default
    except Exception as e:
        print(f"[ERROR] _get_config_value({xpath}): {e}")
        return default

def _resolve_physical_interfaces(logical_ifnames):
    """
    Traduci i nomi logici (es. lan, opt1) nei nomi fisici (es. em0, igb1)
    """
    try:
        tree = ET.parse(CONFIG_PATH)
        root = tree.getroot()
        result = []
        for ifname in logical_ifnames:
            node = root.find(f".//interfaces/{ifname}/if")
            if node is not None and node.text:
                result.append(node.text.strip())
            else:
                print(f"[WARN] Interfaccia logica '{ifname}' non trovata in <interfaces>")
        return result
    except Exception as e:
        print(f"[ERROR] Errore durante la risoluzione delle interfacce: {e}")
        return []

def load_enabled():
    return _get_config_value("/general/enabled", "0") == "1"

def load_inspection_mode():
    return _get_config_value("/general/inspection_mode", "stateless")

def load_interfaces():
    val = _get_config_value("/general/interfaces", "")
    logical = [i.strip() for i in val.split(",") if i.strip()]
    return _resolve_physical_interfaces(logical)

def load_home_networks():
    val = _get_config_value("/general/homenet", "")
    return [n.strip() for n in val.split(",") if n.strip()]

def load_promiscuous_mode():
    return _get_config_value("/general/promisc", "0") == "1"

def load_verbosity():
    return _get_config_value("/general/verbosity", "default")

def load_ips_mode():
    return _get_config_value("/general/ips", "0") == "1"

