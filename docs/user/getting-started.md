# Getting started

From a bare ESP32 board to an auto-unlocking LUKS disk in four steps.

## 1. Flash

Use the [web flasher](../flasher.md) (Chrome or Edge on desktop): plug the board in with a data
USB cable, click **Install**, pick the serial port. Alternatively flash a
[release image](https://github.com/BoniFederico/pocket-tang/releases) with esptool:

```sh
pip install esptool
esptool --chip esp32 --port /dev/ttyUSB0 write-flash 0x0 pocket-tang-v1.0.0-esp32.bin
```

Details: [Flashing](flashing.md).

## 2. Set up

1. Open a serial monitor at 115200 baud (the web flasher has *Logs & Console*). On boot the
   device prints its setup access point and password:

    ```text
    W (1625) pocket-tang: PT_SETUP_AP ssid=PocketTang-A1B2 password=k7mnp3qrs8tv url=http://192.168.4.1/admin
    ```

2. Join `PocketTang-XXXX` from a phone or laptop with that password. A captive-portal page opens
   (otherwise browse to `http://192.168.4.1/admin`).
3. Choose your **2.4 GHz** Wi-Fi network, enter its password, pick a hostname and an admin
   password, then press **Save and restart**.

The device restarts, joins your network and serves Tang at `http://<hostname>.local` on port 80.
Give it a fixed address in your router (DHCP reservation): the initramfs on your Linux machine
usually cannot resolve `.local` names.

Details: [First setup and admin page](setup.md).

## 3. Get the signing-key thumbprint

The thumbprint lets Clevis verify that it talks to *your* Tang server. It is shown on the admin
page (Keys → signing) and on the serial console at boot (`key ES512 …`). From a Linux machine
with `jose` you can also compute it:

```sh
curl -s http://192.168.1.214/adv | jose fmt -j- -g payload -y -o- \
  | jose jwk use -i- -r -u verify -o- | jose jwk thp -i-
```

Compare it with the one on the admin page or serial console before trusting it.

## 4. Bind a LUKS volume

On the Linux machine (Debian/Ubuntu shown; see [Clevis](clevis.md) for Fedora/RHEL):

```sh
sudo apt install clevis clevis-luks clevis-initramfs
sudo clevis luks bind -d /dev/nvme0n1p3 tang '{"url":"http://192.168.1.214","thp":"<thumbprint>"}'
sudo update-initramfs -u
```

`clevis luks bind` asks for an existing LUKS passphrase once. Reboot: the disk unlocks
automatically while Pocket Tang is reachable.

!!! tip "Keep a fallback"
    Keep your LUKS passphrase. For availability, bind to two Tang servers with Shamir secret
    sharing (`sss`, see [Clevis](clevis.md#multiple-tang-servers-sss)).
