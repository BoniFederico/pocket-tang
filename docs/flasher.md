# Web flasher

Install the latest Pocket Tang release directly from the browser. You need **Chrome, Edge or
Opera on a desktop** (Web Serial). Connect the board with a data-capable USB cable.

<script type="module" src="https://unpkg.com/esp-web-tools@10.5.2/dist/web/install-button.js?module"></script>

<esp-web-install-button manifest="../firmware/manifest.json">
  <button slot="activate" class="md-button md-button--primary">Install Pocket Tang</button>
  <span slot="unsupported">Your browser does not support Web Serial. Use Chrome or Edge on a
  desktop, or flash with esptool (see <a href="../user/flashing/">Flashing</a>).</span>
  <span slot="not-allowed">The flasher needs a secure context (HTTPS).</span>
</esp-web-install-button>

The installer:

1. asks for the serial port;
2. detects the chip (ESP32, ESP32-C3 or ESP32-S3) and picks the matching image;
3. offers to **erase** the device. Choose erase for a first installation. **Erasing destroys
   existing Tang keys**, so for an update of a device in use, flash only the application image
   with esptool (see [Flashing](user/flashing.md));
4. opens *Logs & Console*, where the setup access point and its password are printed at boot.

Images come from the latest [GitHub release](https://github.com/BoniFederico/pocket-tang/releases)
and are served from this site, because the flasher needs same-origin files. Their SHA-256 checksums
are in <a href="../firmware/SHA256SUMS"><code>SHA256SUMS</code></a>.
