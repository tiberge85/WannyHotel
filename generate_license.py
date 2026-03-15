#!/usr/bin/env python3
"""
WannyHotel — Générateur de clés de licence
Usage: python generate_license.py

Génère des clés de licence pour les clients hôteliers.
Les clés sont au format: WH-{TIER}-{CODE_UNIQUE}
"""

import hashlib, secrets, sys, json, os
from datetime import datetime

TIERS = {
    'S': {'name': 'Starter',    'price': '19 900 F/mois',  'rooms': 15,  'users': 3},
    'P': {'name': 'Pro',        'price': '49 900 F/mois',  'rooms': 50,  'users': 10},
    'B': {'name': 'Business',   'price': '99 900 F/mois',  'rooms': 200, 'users': 50},
    'E': {'name': 'Enterprise', 'price': 'Sur devis',      'rooms': 9999, 'users': 9999},
}

LICENSES_FILE = 'licenses.json'

def load_licenses():
    if os.path.exists(LICENSES_FILE):
        with open(LICENSES_FILE, 'r') as f:
            return json.load(f)
    return []

def save_licenses(licenses):
    with open(LICENSES_FILE, 'w') as f:
        json.dump(licenses, f, indent=2, ensure_ascii=False)

def generate_key(tier_code):
    """Génère une clé unique pour un tier."""
    code = secrets.token_hex(4).upper()
    check = hashlib.md5(f"WH-{tier_code}-{code}".encode()).hexdigest()[:4].upper()
    return f"WH-{tier_code}-{code}-{check}"

def verify_key(key):
    """Vérifie si une clé est valide."""
    parts = key.upper().strip().split('-')
    if len(parts) != 4 or parts[0] != 'WH':
        return False, None
    tier_code = parts[1]
    if tier_code not in TIERS:
        return False, None
    code = parts[2]
    expected_check = hashlib.md5(f"WH-{tier_code}-{code}".encode()).hexdigest()[:4].upper()
    if parts[3] != expected_check:
        return False, None
    return True, TIERS[tier_code]


def main():
    print("=" * 60)
    print("  🔑 WannyHotel — Générateur de licences")
    print("=" * 60)
    
    while True:
        print("\n  1. Générer une clé de licence")
        print("  2. Générer plusieurs clés")
        print("  3. Vérifier une clé")
        print("  4. Voir toutes les clés générées")
        print("  5. Quitter")
        
        choice = input("\n  Choix: ").strip()
        
        if choice == '1':
            print("\n  Niveaux disponibles:")
            for code, info in TIERS.items():
                print(f"    [{code}] {info['name']:12s} — {info['price']:18s} ({info['rooms']} chambres, {info['users']} utilisateurs)")
            
            tier = input("\n  Tier (S/P/B/E): ").upper().strip()
            if tier not in TIERS:
                print("  ❌ Tier invalide"); continue
            
            hotel_name = input("  Nom de l'hôtel: ").strip() or "—"
            contact = input("  Contact client: ").strip() or "—"
            
            key = generate_key(tier)
            license_entry = {
                'key': key,
                'tier': TIERS[tier]['name'],
                'tier_code': tier,
                'hotel': hotel_name,
                'contact': contact,
                'created': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'status': 'active'
            }
            
            licenses = load_licenses()
            licenses.append(license_entry)
            save_licenses(licenses)
            
            print(f"\n  ✅ Clé générée !")
            print(f"  ╔══════════════════════════════════════╗")
            print(f"  ║  {key:^36s}  ║")
            print(f"  ╚══════════════════════════════════════╝")
            print(f"  Niveau: {TIERS[tier]['name']} — {TIERS[tier]['price']}")
            print(f"  Hôtel: {hotel_name}")
            print(f"  → Le client saisit cette clé dans Admin → 🔑 Licence")
        
        elif choice == '2':
            tier = input("  Tier (S/P/B/E): ").upper().strip()
            if tier not in TIERS:
                print("  ❌ Tier invalide"); continue
            
            try:
                count = int(input("  Nombre de clés: ").strip())
            except:
                count = 5
            
            licenses = load_licenses()
            print(f"\n  📋 {count} clés {TIERS[tier]['name']}:")
            print(f"  {'—' * 50}")
            
            for i in range(count):
                key = generate_key(tier)
                licenses.append({
                    'key': key, 'tier': TIERS[tier]['name'], 'tier_code': tier,
                    'hotel': f'Lot #{i+1}', 'contact': '',
                    'created': datetime.now().strftime('%Y-%m-%d %H:%M'),
                    'status': 'active'
                })
                print(f"  {i+1:3d}. {key}")
            
            save_licenses(licenses)
            print(f"\n  ✅ {count} clés sauvegardées dans {LICENSES_FILE}")
        
        elif choice == '3':
            key = input("  Clé à vérifier: ").strip()
            valid, tier_info = verify_key(key)
            if valid:
                print(f"  ✅ Clé valide — {tier_info['name']} ({tier_info['rooms']} chambres)")
            else:
                # Check demo keys
                demo = {
                    'WANNY-STARTER-2026': 'Starter',
                    'WANNY-PRO-2026': 'Pro',
                    'WANNY-BUSINESS-2026': 'Business',
                    'WANNY-ENTERPRISE-2026': 'Enterprise'
                }
                if key.upper() in demo:
                    print(f"  ✅ Clé de démonstration — {demo[key.upper()]}")
                else:
                    print(f"  ❌ Clé invalide")
        
        elif choice == '4':
            licenses = load_licenses()
            if not licenses:
                print("  Aucune clé générée"); continue
            print(f"\n  {'#':>3s} | {'Clé':^26s} | {'Niveau':^10s} | {'Hôtel':^20s} | {'Date':^16s}")
            print(f"  {'—' * 85}")
            for i, lic in enumerate(licenses, 1):
                print(f"  {i:3d} | {lic['key']:^26s} | {lic['tier']:^10s} | {lic.get('hotel',''):^20s} | {lic['created']:^16s}")
            print(f"\n  Total: {len(licenses)} clés")
        
        elif choice == '5':
            print("\n  Au revoir ! 👋")
            break


if __name__ == '__main__':
    main()
