# Secure Counter (Zephyr)

Minimal Zephyr app demonstrating a user-mode consumer reading a privileged counter via IPC.

## Build locally (example)
```bash
west build -b qemu_x86 -s apps/secure_counter -d build/secure_counter_x86
ninja -C build/secure_counter_x86 run
