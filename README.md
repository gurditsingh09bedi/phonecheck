# PhoneGuard: Android privacy checker

Ye tool aapke Android phone ko **computer se USB ke through** scan karta hai aur batata hai:

- Phone me kaun kaun se **3rd-party apps** hain, aur kahan se install hue (Play Store ya bahar se APK)
- **Hidden apps**: aise apps jinka home screen par icon nahi hai (spy apps aksar aise hote hain)
- Har app ke paas kaunsi **permission** hai: Camera, Mic, Location, SMS, Contacts, Call log, Photos...
- **Powerful access**: Accessibility, Device Admin, Notification reading, Keyboard, Draw-over-apps, Usage access, Install apps
- **History**: kis app ne camera/mic/location/clipboard **kab** use kiya, aur kya wo app us time **background me** tha
- Phone security: purana security patch, root, unlocked bootloader, proxy, VPN
- **LIVE MONITOR**: real time me koi bhi app camera/mic/GPS chalu kare to turant alert. Agar app screen par nahi hai ya screen band hai, to **laal ALERT + beep**

Sab kuch **sirf padha** jaata hai. Ye tool phone me kuch change, delete ya upload nahi karta. Report aapke computer par hi banti hai.

---

## Setup (ek baar, ~5 minute)

### 1. Computer par
1. **Python 3** install karo: https://www.python.org/downloads/ (Windows par install ke time **"Add Python to PATH"** tick karna)
2. **Android Platform-Tools (adb)** download karo: https://developer.android.com/tools/releases/platform-tools
3. Zip extract karo aur **`platform-tools` folder ko isi folder me** rakh do (jahan `phoneguard.py` hai):
   ```
   PhoneGuard/
     phoneguard.py
     START_PhoneGuard_Windows.bat
     platform-tools/
        adb.exe ...
   ```

### 2. Phone par
1. **Settings > About phone > Build number** par **7 baar tap** karo, isse "Developer options" ON ho jaata hai
   (Samsung: About phone > Software information > Build number · Xiaomi: About phone > MIUI/OS version)
2. **Settings > System > Developer options > USB debugging** ON karo
3. Phone ko **data cable** se computer se jodo
4. Phone par popup aayega **"Allow USB debugging?"**, usme **Allow** dabao (aur "Always allow from this computer" tick kar sakte ho)

---

## Chalana

**Windows:** `START_PhoneGuard_Windows.bat` par double-click karo.

**Mac / Linux / Windows terminal:**
```
python phoneguard.py            # menu
python phoneguard.py scan       # full scan + HTML report
python phoneguard.py monitor    # live camera / mic / GPS monitor
python phoneguard.py both       # pehle scan, phir live monitor
```

Options:
| Option | Kaam |
|---|---|
| `--include-system` | pre-installed system apps bhi report me dikhao |
| `--interval 1` | live monitor har 1 second check kare (default 2s) |
| `--minutes 120` | live monitor 2 ghante baad khud band ho |
| `--no-gps` | live monitor me sirf camera + mic |
| `--no-beep` | alert par awaaz nahi |
| `--serial XYZ` | agar ek se zyada phone jude hain |

Reports `reports/` folder me bante hain:
- `PhoneGuard_<model>_<time>.html`: full report (browser me apne aap khulti hai, search/filter ke saath)
- `PhoneGuard_<model>_<time>.json`: raw data
- `PhoneGuard_live_<time>.csv` / `.html`: live monitor ka log

---

## "Mera phone kabhi kabhi camera/mic khud le leta hai", isko kaise pakdein

1. Pehle `scan` chalao. Report ke **Section 3** me dekho kis app ne camera/mic kab use kiya. **BACKGROUND** wale tag par sabse zyada dhyan do.
2. Phir `monitor` chalao aur phone ko side me rakh do (cable laga rehne do, 1-2 ghante ya raat bhar).
   Jaise hi koi app camera/mic kholega, screen par uska **package name** aa jayega, aur log file me time ke saath save hoga.
3. Package name ko report ke **"Google it"** link se search karke pata karo ki wo app kis company ka hai.

**Aksar ye normal hota hai:** Google app / Assistant ("Hey Google"), Samsung Bixby, WhatsApp/Instagram jab background me call ya voice note handle karte hain, keyboard ka voice-typing, face-unlock. **Suspicious hota hai:** anjaan naam wala app, Play Store ke bahar se aaya app, hidden app, ya aisa app jise camera ki zaroorat hi nahi (torch, cleaner, game).

## Kuch milne par kya karein
- Settings > Apps > [app] > **Permissions** > Camera / Microphone > **Don't allow**
- Unknown app ko **uninstall** karo. Agar uninstall nahi ho raha, to pehle Settings > Security > **Device admin apps** se uska admin hatao
- Settings > **Accessibility** aur **Notification access** me koi anjaan app ho to OFF karo
- Android 12+: **Privacy dashboard** aur Quick Settings me **Camera access / Microphone access** toggle
- Screen ke kone me **green dot** = camera/mic abhi chal raha hai
- Kaam khatam hone ke baad **USB debugging OFF** kar do

## Limits (imaandaari se)
- Sirf **Android** par chalta hai. iPhone kisi script ko doosre apps ki permissions padhne nahi deta. iPhone par **Settings > Privacy & Security > App Privacy Report** ON karo, ye har app ka camera/mic/location use dikhata hai.
- Live monitor phone ke andar ke system records padhta hai. Alag-alag phone companies (Samsung, Xiaomi, etc.) ka output thoda alag hota hai, isliye kuch phones par koi event miss ho sakta hai. Android 12+ ka green dot hi final sach hai.
- History phone khud kuch ghanton se kuch dinon tak hi rakhta hai.
- Ye antivirus nahi hai. Ye aapko clear jaankari deta hai, faisla aapka hai.
