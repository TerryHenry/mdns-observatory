# Third-party notices

mDNS Observatory's own source code is licensed under the MIT License (see [LICENSE](LICENSE)). The components below are separate works under their own licenses. The MIT License does not change their terms.

## Components bundled in the release builds

The macOS and Windows release builds are packaged with PyInstaller and include these runtime components. Each keeps its own license.

| Component | License | Source |
| --- | --- | --- |
| [Python](https://www.python.org/) runtime and standard library | Python Software Foundation License 2.0 | https://github.com/python/cpython |
| [Qt for Python](https://doc.qt.io/qtforpython-6/) (PySide6, Shiboken6) and the Qt 6 libraries | GNU LGPL v3 | https://code.qt.io/cgit/pyside/pyside-setup.git/ and https://download.qt.io/ |
| [Scapy](https://scapy.net/) | GNU GPL v2 | https://github.com/secdev/scapy |

- **Qt / PySide6 (LGPL v3):** Qt and PySide6 are shipped as separate shared libraries in the application folder, so you can replace them with compatible versions you build yourself. The LGPL v3 text is at https://www.gnu.org/licenses/lgpl-3.0.html.
- **Scapy (GPL v2):** The release builds include Scapy, so these binaries are distributed under the terms of the GPL v2 as well. The complete corresponding source is this repository at the release tag, together with the upstream Scapy release that build bundles (Scapy 2.8.0 for v2.24.20). The GPL v2 text is at https://www.gnu.org/licenses/old-licenses/gpl-2.0.html. Running mDNS Observatory from source does not bundle Scapy; `pip` installs it separately under its own license.
- The Windows build also includes the Microsoft Visual C++ runtime DLLs that ship with Python. These are redistributed under Microsoft's redistribution terms.
- [Npcap](https://npcap.com/) is not bundled. Windows users install it separately under its own license.

## mDNS service reference

The bundled community service names and descriptions are derived from [bbusse/mdns-discover](https://github.com/bbusse/mdns-discover), Copyright (c) 2023 Björn Busse. Upstream source is licensed under the BSD 3-Clause License. The app's curated additions and explanations are maintained separately. Community descriptions are reference material and may be incomplete or outdated.

BSD 3-Clause License

Copyright (c) 2023, Björn Busse

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
