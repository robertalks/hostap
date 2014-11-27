hostap for Realtek RTL8192CU
============================

This is a latest version of hostap patches to support Realtek's own
kernel module which doesn't uses nl80211.

The kernel module can be found at: `https://github.com/robertalks/rt8192cu <https://github.com/robertalks/rt8192cu>`


**Instructions:**

        $ git clone https://github.com/robertalks/hostap
        $ cd hostap/hostapd
        $ cp defconfig .config
        $ make
        $ make install


