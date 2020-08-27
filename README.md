# Duo Authproxy patched for building on FreeBSD

I spend several hours to make these sources building on FreeBSD 11.2-RELEASE to be able run duo auth proxy on pfSense

I hope this repo can save some time to others

## Some steps that I remember:

  - remove `comp.h` from Makefiles
  - comment out `depend` targets from Makefiles

