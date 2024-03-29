# Duo Remote Procedure Call (DRPC)
## Overview
DRPC is a protocol through which Duo services may communicate with one another.
It was originally created to allow for customers to perform an AD Sync
(https://docs.google.com/presentation/d/1yHvhVl8aBrjPW0-txfBF3kJ_wwdfJa2xQ6qZAH0iw5w/edit#slide=id.ga38edfaff_0_82)
but is now also being used as an internal message passing protocol.

## Structure
This repository contains multiple version of DPRC inside of the `/drpc` folder.
Each directory represents a major (non-backward compatible) version of the DPRC
protocol. This major versions must exist alongside one another so that trustedpath
can easily support new versions going forward and old appliances in the field.

## Versioning
The major version of any DPRC _package_ should be the greatest _protocol_ version
supported by the package. The minor version of the package should be bumped during
any substantial change or revision of any protocol therein. The patch version
should be increased for bugfixes and small changes in keeping with semantic versioning.

## Building
Building the authproxy can be done with `make sdist` or just `make` as it is the
default goal. This will create a drpc-<version>.tar.gz inside of the `dist`
folder at the root of the repo which is the suitable for use as a third-party
package in other repos. 

The version used for the package is controlled by the `__version__` inside of
`drpc/__init__.py`.

## CI
CI is done by the drpc repo in ci.duosec.org (https://ci.duosec.org/mirrors/drpc/pipelines).
If you add a requirement to requirements.txt you may need to generate a new builder
manually through the manual "builder" stage in gitlab.

## Testing
DRPC tests can be run with `make test`.
