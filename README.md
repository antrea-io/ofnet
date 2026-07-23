# Ofnet

Ofnet is a Golang networking library to help write Openflow controllers to
manage Openflow switches.

This repository started as a fork of
[contiv/ofnet](https://github.com/contiv/ofnet), as the Contiv project is no
longer actively maintained. This repository is mainly used by Antrea, and a lot
of code that is not needed in Antrea has been removed compared to the original
Contiv repository.

# Ofctrl

This library implements a simple Openflow1.5 controller API

You can see docs here: [Ofctrl Documentation](ofctrl/README.md)