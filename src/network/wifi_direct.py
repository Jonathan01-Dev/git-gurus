import subprocess
import string
import random
import sys


class WiFiDirectIsland:
    """Provides a zero-infrastructure Wi-Fi Direct connection mechanism on Windows.
    
    Strategy (ordered by reliability):
    1. Try legacy Hosted Network (netsh) — works on older drivers.
    2. Try WinRT Mobile Hotspot using ANY available Wi-Fi adapter profile (not just internet).
    3. If both fail, offer a guided manual setup via Windows Settings.
    """

    DEFAULT_SSID = "Archipel-Island"
    DEFAULT_PASSWORD_LENGTH = 12

    def __init__(self, ssid=None, password=None):
        self.ssid = ssid or f"DIRECT-{self.DEFAULT_SSID}-{self._rand(4)}"
        self.password = password or self._rand(self.DEFAULT_PASSWORD_LENGTH, chars=string.ascii_letters + string.digits)

    @staticmethod
    def _rand(length, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choices(chars, k=length))

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────
    def create_island(self) -> bool:
        print(f"[WIFI-ISLAND] Setting up Zero-Internet Wi-Fi Direct Island...")
        print(f"  SSID: {self.ssid}")
        print(f"  PASS: {self.password}")
        print()

        # Strategy 1: Legacy Hosted Network
        if self._try_hosted_network():
            return True

        # Strategy 2: WinRT Tethering with Wi-Fi adapter enumeration
        if self._try_winrt_tethering():
            return True

        # Strategy 3: Manual guide
        self._print_manual_guide()
        return False

    def check_status(self):
        """Check the current state of the island network."""
        # Check hosted network
        r = self._ps("netsh wlan show hostednetwork")
        if "actif" in r.lower() or "started" in r.lower():
            print("[WIFI-ISLAND] Hosted Network island is ACTIVE.")
            print(r)
            return

        # Check mobile hotspot
        r = self._ps(self._tethering_status_script())
        print(f"[WIFI-ISLAND] Status: {r.strip() if r.strip() else 'Island is offline.'}")

    # ──────────────────────────────────────────────
    # Strategy 1: Legacy Hosted Network (netsh)
    # ──────────────────────────────────────────────
    def _try_hosted_network(self) -> bool:
        print("[WIFI-ISLAND] Strategy 1: Trying legacy Hosted Network (netsh)...")
        script = f"""
$ErrorActionPreference = "Continue"
$r1 = netsh wlan set hostednetwork mode=allow ssid="{self.ssid}" key="{self.password}" 2>&1
$r2 = netsh wlan start hostednetwork 2>&1
if ($LASTEXITCODE -eq 0) {{
    Write-Output "OK"
}} else {{
    Write-Output "FAIL:$r2"
}}
"""
        out = self._ps(script)
        if "OK" in out:
            print("[WIFI-ISLAND] Hosted Network island created successfully!")
            self._print_connect_info()
            return True
        print(f"[WIFI-ISLAND]   -> Hosted Network not supported by driver.")
        return False

    # ──────────────────────────────────────────────
    # Strategy 2: WinRT Tethering (enumerate ALL adapters)
    # ──────────────────────────────────────────────
    def _try_winrt_tethering(self) -> bool:
        print("[WIFI-ISLAND] Strategy 2: Trying WinRT Mobile Hotspot (Wi-Fi adapter enumeration)...")
        script = """
$ErrorActionPreference = "Continue"
Add-Type -AssemblyName System.Runtime.WindowsRuntime

[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null

# Try internet profile first
$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()

# If no internet profile, enumerate ALL connection profiles and pick the Wi-Fi one
if ($profile -eq $null) {
    $allProfiles = [Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles()
    foreach ($p in $allProfiles) {
        try {
            if ($p.IsWlanConnectionProfile) {
                $profile = $p
                break
            }
        } catch {}
    }
}

# If still no profile, try to get the Wi-Fi adapter directly
if ($profile -eq $null) {
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Wi-Fi" -and $_.Status -eq "Up" }
        if ($adapters) {
            # Use TetheringManager without a profile (some Windows versions support this)
            $manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile(
                ([Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles() | Select-Object -First 1)
            )
        }
    } catch {}
}

if ($profile -ne $null) {
    try {
        $manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
    } catch {
        Write-Output "FAIL:MANAGER_CREATE"
        exit 1
    }
} elseif (-not $manager) {
    Write-Output "FAIL:NO_ADAPTER"
    exit 1
}

if ($manager) {
    try {
        $cfg = $manager.GetCurrentAccessPointConfiguration()
        Write-Output "HOTSPOT_SSID:$($cfg.Ssid)"
    } catch {}
    
    if ($manager.TetheringOperationalState -eq "On") {
        Write-Output "ALREADY_ON"
        exit 0
    }
    
    $asyncOp = $manager.StartTetheringAsync()
    $result = $asyncOp.GetAwaiter().GetResult()
    Write-Output "STATUS:$($result.Status)"
    if ($result.Status -eq "Success" -or $result.Status -eq 0) {
        exit 0
    }
}
Write-Output "FAIL:TETHERING"
exit 1
"""
        out = self._ps(script)

        if "ALREADY_ON" in out:
            print("[WIFI-ISLAND] Mobile Hotspot is already active!")
            self._extract_hotspot_ssid(out)
            return True

        if "STATUS:Success" in out or "STATUS:0" in out:
            print("[WIFI-ISLAND] Mobile Hotspot island created successfully!")
            self._extract_hotspot_ssid(out)
            return True

        reason = "Unknown"
        if "NO_ADAPTER" in out:
            reason = "No Wi-Fi adapter found or all are disconnected"
        elif "MANAGER_CREATE" in out:
            reason = "Cannot initialize tethering manager without any network profile"
        elif "FAIL:TETHERING" in out:
            reason = "Tethering start failed (possibly need admin rights)"
        print(f"[WIFI-ISLAND]   -> WinRT Tethering failed: {reason}.")
        return False

    # ──────────────────────────────────────────────
    # Strategy 3: Manual guide
    # ──────────────────────────────────────────────
    def _print_manual_guide(self):
        print()
        print("=" * 70)
        print("  GUIDE MANUEL - Creer un reseau local sans Internet")
        print("=" * 70)
        print()
        print("  Votre carte Wi-Fi (Intel AX203) bloque la creation")
        print("  automatique de reseau Ad Hoc. Voici comment le faire")
        print("  manuellement en 30 secondes :")
        print()
        print("  1. Ouvrir Parametres Windows (Win + I)")
        print("  2. Reseau et Internet -> Point d'acces sans fil mobile")
        print("  3. Activer le Point d'acces sans fil mobile")
        print("     (peu importe s'il n'y a pas d'Internet !)")
        print("  4. Cliquer 'Modifier' pour choisir le SSID et mot de passe")
        print(f"     Suggestion : SSID = {self.ssid}")
        print(f"                  Pass = {self.password}")
        print("  5. L'autre machine se connecte a ce Wi-Fi")
        print()
        print("  Apres connexion, trouvez votre IP locale :")
        print("    > ipconfig")
        print("    (cherchez l'adaptateur 'Local Area Connection*' ou similaire)")
        print()
        print("  Puis lancez Archipel normalement :")
        print("    > python -m src.cli.main start --port 7777")
        print()
        print("=" * 70)

    # ──────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────
    def _ps(self, script: str) -> str:
        """Run a PowerShell script and return stdout."""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            return r.stdout
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except Exception as e:
            return f"ERROR:{e}"

    def _print_connect_info(self):
        print()
        print(f"  Les autres machines peuvent maintenant se connecter :")
        print(f"    SSID : {self.ssid}")
        print(f"    PASS : {self.password}")
        print()
        print(f"  Puis lancez : python -m src.cli.main start --port 7777")
        print()

    def _extract_hotspot_ssid(self, output: str):
        for line in output.splitlines():
            if line.startswith("HOTSPOT_SSID:"):
                ssid = line.split(":", 1)[1].strip()
                if ssid:
                    print(f"  SSID du Hotspot : {ssid}")
                    print(f"  (Voir le mot de passe dans Parametres -> Reseau -> Point d'acces)")
                return

    @staticmethod
    def _tethering_status_script() -> str:
        return """
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($profile) {
    $m = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
    Write-Output $m.TetheringOperationalState
} else {
    $all = [Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles()
    foreach ($p in $all) {
        try {
            $m = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($p)
            Write-Output $m.TetheringOperationalState
            break
        } catch {}
    }
}
"""
