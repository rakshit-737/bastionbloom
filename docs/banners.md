# BastionBloom terminal identity

Three ASCII-only, 76-column designs are included in `src/bastionbloom/banner.py`.
The premium design is the default. Plain exports contain no ANSI escapes and
preserve every space. Startup banners use a compact identity below 76 columns.

## 1. Minimal and professional

```text
+--------------------------------------------------------------------------+
|                                                                          |
|       ___   _   ___ _____ ___ ___  _  _ ___ _    ___   ___  __  __       |
|      | _ ) /_\ / __|_   _|_ _/ _ \| \| | _ ) |  / _ \ / _ \|  \/  |      |
|      | _ \/ _ \\__ \ | |  | | (_) | .` | _ \ |_| (_) | (_) | |\/| |      |
|      |___/_/ \_\___/ |_| |___\___/|_|\_|___/____\___/ \___/|_|  |_|      |
|                                                                          |
+--------------------------------------------------------------------------+
```

## 2. Aggressive cybersecurity style

```text
+--[ SECURITY AUDIT // LOCAL CONTROL ]-------------------------------------+
|                                                                          |
|      ___  ___   __________________  _  _____  __   ____  ____  __  ___   |
|     / _ )/ _ | / __/_  __/  _/ __ \/ |/ / _ )/ /  / __ \/ __ \/  |/  /   |
|    / _  / __ |_\ \  / / _/ // /_/ /    / _  / /__/ /_/ / /_/ / /|_/ /    |
|   /____/_/ |_/___/ /_/ /___/\____/_/|_/____/____/\____/\____/_/  /_/     |
|                                                                          |
|                       >> SCAN / CORRELATE / HARDEN                       |
|                                                                          |
+--------------------------------------------------------------------------+
```

## 3. Futuristic premium security-tool style

```text
+--[ BB / LOCAL SECURITY INTELLIGENCE ]------------------------------------+
|                                                                          |
|         ___  ____ ____ ___ _ ____ _  _ ___  _    ____ ____ _  _          |
|         |__] |__| [__   |  | |  | |\ | |__] |    |  | |  | |\/|          |
|         |__] |  | ___]  |  | |__| | \| |__] |___ |__| |__| |  |          |
|                                                                          |
|     o----o  SECRETS  o----o  DEPLOYMENTS  o----o  WORKFLOWS  o----o      |
|                                                                          |
+--------------------------------------------------------------------------+
```

## Startup example

```text
+--[ BB / LOCAL SECURITY INTELLIGENCE ]------------------------------------+
|                                                                          |
|         ___  ____ ____ ___ _ ____ _  _ ___  _    ____ ____ _  _          |
|         |__] |__| [__   |  | |  | |\ | |__] |    |  | |  | |\/|          |
|         |__] |  | ___]  |  | |__| | \| |__] |___ |__| |__| |  |          |
|                                                                          |
|     o----o  SECRETS  o----o  DEPLOYMENTS  o----o  WORKFLOWS  o----o      |
|                                                                          |
+--------------------------------------------------------------------------+
BastionBloom v0.1.0
Local security auditing. Connected risks. Actionable fixes.
----------------------------------------------------------------------------
```

## Usage

```bash
bastionbloom --banner-style minimal scan .
bastionbloom --banner-style aggressive scan .
bastionbloom --banner-style premium scan .
bastionbloom --no-banner scan .

bastionbloom banner --style minimal
bastionbloom banner --style aggressive
bastionbloom banner --style premium --startup
```

Global options belong before the command. Raw JSON/HTML stdout never contains a
startup banner. Reports written to files still show normal terminal startup
output unless `--no-banner` is selected. No font-rendering dependency is needed.
