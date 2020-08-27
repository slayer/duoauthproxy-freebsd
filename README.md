# Duo Authproxy patched for building on FreeBSD

I spend several hours to make these sources building on FreeBSD 11.2-RELEASE

## Some steps that I remember:

  - remove `comp.h` from Makefiles
  - comment out `depend` targets from Makefiles

