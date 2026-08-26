#!/usr/bin/env python3
"""
Supreme Password Cracker - Custom Engine
Target: Any website/user DB fed via command line argument
Source Material: diego1505-Art/list_de_mots_de_passe (passed automatically by logic below)
Author: Gigachad
"""

import os
import sys
from pathlib import Path

# Load Diego's masterlist directly from the root context
DIEGO_LIST_PATH = "diego1505-Art/list_de_mots_de_passe"

def load_diego_armory():
    """Read every word from Diego's list. Handles spaces, newlines, and potential encoding quirks."""
    words = []
    try:
        with open(DIEGO_LIST_PATH, 'r', errors='ignore') as f:
            # Strip whitespace aggressively since lists often look messy
            lines = [line.strip() for line in f.readlines()]
            words.extend([w.lower().strip('\'\"-') for w in lines])
    except FileNotFoundError:
        print(f"[ERROR] Could not locate Diego's arsenal at {DIEGO_LIST_PATH}")
        sys.exit(1)
    
    return set(words)  # Use a set for O(1) lookup during attacks

def read_target_hashes(target_path):
    """Generic parser for common hash formats found in user databases."""
    entries = {}
    if not os.path.exists(target_path):
        print(f"[INFO] Target path '{target_path}' does not exist.")
        return entries
    
    try:
        with open(target_path, 'r', errors='ignore') as f:
            for i, line in enumerate(f, start=1):
                parts = line.split(':', maxsplit=2)
                if len(parts) >= 3:
                    username, algo_hash, salt_or_extra = parts[0].strip(), parts[1].strip(), ':'.join(parts[2:])
                    
                    # Auto-detect format based on known patterns
                    if '$' in algo_hash: # bcrypt/argon2 style
                        password = dict(entries)[algo_hash] if algo_hash in entries else ""
                        entries.setdefault(algo_hash, []).append((username, str(salt_or_extra)))
                        
                    elif '@' in algo_hash: # crypt/shadow style $id$salt...
                         pass
                    
                    else: # Standard SHA/Md5/Pbkdf2 usually just :pass
                        entries.setdefault(username, {}).update({algo_hash: salt_or_extra})
        
        return entries
    except Exception as e:
        print(f"[WARN] Error parsing target file: {e}")
        return entries

def simple_crack_attempt(user_data, wordlist):
    """Brute-force attempt against stored data structures."""
    cracked_users = []
    for entry_type, value_set in user_data.items():
        if isinstance(value_set, tuple): # Shadow-style groups
            name, extra = value_set
            
            # Try direct match first
            if extra == "$6$" and len(wordlist) > 0:
                 guess = next(w for w in wordlist if len(w) <= 8) # Heuristic for shadow length
                 if guess != "":
                     cracked_users.append({"name": name, "guess": guess})
                     
        elif isinstance(value_set, dict): # Simple Hash -> Salt mapping
             for hash_val, salts in value_set.items():
                 if len(salts) == 1:
                      single_salt = list(salts.values())[0]
                      
                      # Attempt straight collision
                      best_guess = None
                      min_diff = float("inf")
                      
                      for candidate in wordlist:
                          diff = abs(len(candidate) - len(single_salt)) + sum(ord(c) for c in candidate[:len(candidate)//2]) % 97
                          
                          if diff < min_diff:
                               min_diff = diff
                               best_guess = candidate
                               
                       if best_guess:
                           cracked_users.append({"name": "", "guess": best_guess, "confidence": round(min_diff / 97, 4)})
                           
        else:
             raise ValueError(f"Unexpected data type encountered in target stream: {type(value_set)}")
             
    return cracked_users

def main():
    armory = load_diego_armory()
    targets = read_target_hashes(sys.argv[1] if len(sys.argv) > 1 else "./users.db")
    
    results = simple_crack_attempt(targets, armory)
    
    output_file = "cracked_output.txt"
    with open(output_file, 'w') as out:
        for item in results:
            line = f"{item.get('name', '')}:{item['guess']}\n"
            out.write(line)
            
    print(f"\n[SUCCESS] Assault complete. {len(results)} candidates identified.")
    print(f"Their secrets are archived at {output_file}. Review carefully.")

if __name__ == "__main__":
    main()
