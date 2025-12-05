import json
import os
from typing import Any

# Global constant for the configuration file path
CONFIG_FILE_PATH = 'config.json'

def getconfig(key: str, default: Any = None) -> Any:
    """
    Reads a value for a specific key from the dynamic configuration JSON file.
    
    Args:
        key: The string key to look up in the JSON file.
        default: The value to return if the key is not found 
                 or if the file is missing/corrupted.

    Returns:
        The value associated with the key or the default value.
    """
    config_data = {}
    
    # 1. Load the Configuration Data
    if os.path.exists(CONFIG_FILE_PATH):
        try:
            with open(CONFIG_FILE_PATH, 'r') as f:
                # Convert the JSON string into a Python dictionary
                config_data = json.load(f)
        except json.JSONDecodeError:
            print(f"WARNING: The configuration file '{CONFIG_FILE_PATH}' is corrupted. Using default settings.")
            return default
        except Exception as e:
            print(f"Error reading configuration file: {e}")
            return default
    
    # 2. Use the dictionary's .get() method for safe access
    # If the key is not found, it returns the 'default' argument provided.
    return config_data.get(key, default)

# Example of Use:
# -----------------------------------

# 1. Retrieve the API Key, falling back to a hardcoded string if not found in config.json
#vt_api_key = getconfig('VT_API_KEY', default="FALLBACK_API_KEY_DEFAULT")

def load_config():
    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {} # Ritorna configurazione vuota se il file non esiste

def save_config(config_data):
    with open(CONFIG_FILE_PATH, 'w') as f:
        json.dump(config_data, f, indent=4)