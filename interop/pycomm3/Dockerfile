# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# pycomm3 (MIT, github.com/ottowayi/pycomm3) as an interop peer for the
# server role; installed from PyPI at build time, not redistributed.
FROM python:3.12.10-slim
RUN pip install --no-cache-dir pycomm3==1.2.16
COPY browse.py /peer/browse.py
WORKDIR /peer
