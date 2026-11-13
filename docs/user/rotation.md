# Key rotation

Rotation replaces the Tang keys while existing bindings keep working, exactly like upstream tang:

- the device generates a new signing key (ES512) and a new exchange key (ECMR) on P-521;
- the old keys become **rotated**: they are no longer advertised by `/adv`, so new bindings use
  the new keys, but `/rec` still answers for them, so existing bindings keep unlocking;
- `/adv/{old signing thumbprint}` keeps working, so clients that pinned the old thumbprint can
  still fetch a signed advertisement.

## Rotate

On the admin page press **Rotate keys**. The new thumbprints appear in the key list. The device
stores up to 8 keys (4 generations). When the store is full, delete rotated keys first.

## Move bindings to the new keys

On every client, re-bind with the new advertisement. `clevis luks report` shows bindings whose
keys are no longer advertised, and `clevis luks regen` re-binds them in place:

```sh
sudo clevis luks report -d /dev/nvme0n1p3 -s 1
sudo clevis luks regen  -d /dev/nvme0n1p3 -s 1
```

Alternatively, `clevis luks unbind` the old slot and `clevis luks bind` again with the new
signing thumbprint.

## Delete rotated keys

When every client uses the new keys, press **Delete rotated keys**. From then on, bindings to the
old keys **cannot unlock any more**, which is the point of rotating: a copy of an old LUKS header
and an old key are no longer enough.
