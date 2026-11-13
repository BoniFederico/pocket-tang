# Binding disks with Clevis

[Clevis](https://github.com/latchset/clevis) is the client side of NBDE. Pocket Tang works with the
`tang` pin exactly like upstream tang. Interoperability is tested with clevis 20, jose 13 and
tang 14.

## Packages

=== "Debian / Ubuntu"

    ```sh
    sudo apt install clevis clevis-luks clevis-initramfs
    ```

=== "Fedora / RHEL / CentOS Stream"

    ```sh
    sudo dnf install clevis clevis-luks clevis-dracut
    ```

## Bind

Use the IP address (or a DNS name your initramfs can resolve) and pin the signing-key thumbprint
from the admin page:

```sh
sudo clevis luks bind -d /dev/nvme0n1p3 tang \
  '{"url":"http://192.168.1.214","thp":"oKmaqxTeemoyU-9C_6CwNtVgHrf8mjT2JepCtNa-7-c"}'
```

`clevis luks bind` asks for an existing LUKS passphrase and adds a new key slot. Then update the
initramfs:

=== "Debian / Ubuntu"

    ```sh
    sudo update-initramfs -u -k all
    ```

=== "Fedora / RHEL"

    ```sh
    sudo dracut -fv --regenerate-all
    # networking in early boot, e.g. on the kernel command line:  rd.neednet=1 ip=dhcp
    ```

Check it:

```sh
sudo clevis luks list -d /dev/nvme0n1p3
sudo clevis luks unlock -d /dev/nvme0n1p3 -n test   # opens /dev/mapper/test
sudo cryptsetup close test
```

!!! warning "Use an IP address or a real DNS name"
    The early-boot environment (initramfs) usually has no mDNS resolver, so
    `http://pocket-tang.local` works on a running system but **not at boot**. Reserve a fixed IP
    for the device in your router and use that.

## Encrypting a file (no LUKS)

```sh
echo secret | clevis encrypt tang '{"url":"http://192.168.1.214","thp":"…"}' > secret.jwe
clevis decrypt < secret.jwe
```

## Multiple Tang servers (sss)

Shamir secret sharing lets you require `t` of `n` servers. With `t = 1` the disk unlocks when
*any* server is reachable (availability). With `t = 2` both are needed (security).

```sh
sudo clevis luks bind -d /dev/nvme0n1p3 sss '{"t":1,"pins":{"tang":[
  {"url":"http://192.168.1.214","thp":"<pocket tang thumbprint>"},
  {"url":"http://192.168.1.10","thp":"<second tang thumbprint>"}]}}'
```

You can mix Pocket Tang with upstream tang, or combine Tang with the TPM (`"tpm2":{}`) inside
`sss`. Combinations across Pocket Tang and upstream tang are covered by the interop tests.

## Removing a binding

```sh
sudo clevis luks list -d /dev/nvme0n1p3      # shows the slot, e.g. "1: tang '{...}'"
sudo clevis luks unbind -d /dev/nvme0n1p3 -s 1
```
