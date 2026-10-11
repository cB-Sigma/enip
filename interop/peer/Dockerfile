# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# cpppo (GPL, github.com/pjkundert/cpppo) as an interop peer: its
# EtherNet/IP server simulates a Logix controller. It is installed from
# PyPI at build time, used only as a test peer and not redistributed.
FROM python:3.12.10-slim
RUN pip install --no-cache-dir cpppo==5.2.5
WORKDIR /peer
EXPOSE 44818
