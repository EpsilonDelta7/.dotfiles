Package: adduser
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 608
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.118ubuntu5
Depends: passwd, debconf (>= 0.5) | debconf-2.0
Suggests: liblocale-gettext-perl, perl, ecryptfs-utils (>= 67-1)
Conffiles:
/etc/deluser.conf 773fb95e98a27947de4a95abb3d3f2a2
Description: add and remove users and groups
This package includes the 'adduser' and 'deluser' commands for creating
and removing users.
.

- 'adduser' creates new users and groups and adds existing users to
  existing groups;
- 'deluser' removes users and groups and removes users from a given
  group.
  .
  Adding users with 'adduser' is much easier than adding them manually.
  Adduser will choose appropriate UID and GID values, create a home
  directory, copy skeletal user configuration, and automate setting
  initial values for the user's password, real name and so on.
  .
  Deluser can back up and remove users' home directories
  and mail spool or all the files they own on the system.
  .
  A custom script can be executed after each of the commands.
  Original-Maintainer: Debian Adduser Developers <adduser@packages.debian.org>

Package: adwaita-icon-theme
Status: install ok installed
Priority: optional
Section: gnome
Installed-Size: 5234
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 41.0-1ubuntu1
Replaces: adwaita-icon-theme-full (<< 41.0-1ubuntu1), gnome-themes-standard-data (<< 3.18.0-2~)
Depends: hicolor-icon-theme, gtk-update-icon-cache, ubuntu-mono | adwaita-icon-theme-full
Recommends: librsvg2-common
Breaks: adwaita-icon-theme-full (<< 41.0-1ubuntu1), gnome-themes-standard-data (<< 3.18.0-2~)
Description: default icon theme of GNOME (small subset)
This package contains the default icon theme used by the GNOME desktop.
The icons are used in many of the official gnome applications like eog,
evince, system monitor, and many more.
.
This package only contains a small subset of the original GNOME icons which
are not provided by the Humanity icon theme, to avoid installing many
duplicated icons. Please install adwaita-icon-theme-full if you want the full
set.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: apparmor
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 2664
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 3.0.4-2ubuntu2.1
Replaces: fcitx-data (<< 1:4.2.9.1-1ubuntu2)
Depends: debconf, lsb-base, debconf (>= 0.5) | debconf-2.0, libc6 (>= 2.34)
Suggests: apparmor-profiles-extra, apparmor-utils
Breaks: apparmor-profiles-extra (<< 1.21), fcitx-data (<< 1:4.2.9.1-1ubuntu2), snapd (<< 2.44.3+20.04~)
Conffiles:
/etc/apparmor.d/abi/3.0 f97e410509c5def279aa227c7de12e06
/etc/apparmor.d/abi/kernel-5.4-outoftree-network 57b68acd4e6418fe5a06dc8c04713e3d
/etc/apparmor.d/abi/kernel-5.4-vanilla 77047e6f0b014fa8bf27681998382044
/etc/apparmor.d/abstractions/X e08b3a65c568c19b5922de1db3df0d92
/etc/apparmor.d/abstractions/apache2-common 8608b847edc519a5733e97ba1f6311cb
/etc/apparmor.d/abstractions/apparmor_api/change_profile 4e10aac635b960dd6a2a94330d9dc4ce
/etc/apparmor.d/abstractions/apparmor_api/examine db7f9bf417820acdfc4c6386c749582d
/etc/apparmor.d/abstractions/apparmor_api/find_mountpoint 0380ddf9878be96962df2e81dc74f867
/etc/apparmor.d/abstractions/apparmor_api/introspect ca4db5b278f4c08892c2ef7027495051
/etc/apparmor.d/abstractions/apparmor_api/is_enabled ca0172ca6c89703ff9d8f4bc50998ddc
/etc/apparmor.d/abstractions/aspell f8676bccab5b82b0b6d723549b3a1a83
/etc/apparmor.d/abstractions/audio ee487ce12dc8194a58ca0aad23452923
/etc/apparmor.d/abstractions/authentication b3238cd14352633630d980a6e3b43613
/etc/apparmor.d/abstractions/base 9ac9a0b72f34936db683f2b4fa94c891
/etc/apparmor.d/abstractions/bash bc217483455477e1431f9e0b14fe2caf
/etc/apparmor.d/abstractions/consoles bea9fc84b0a5d025b0baa2012fb5f187
/etc/apparmor.d/abstractions/crypto 35881757d4885bde7e6d8b3c4285e9a4
/etc/apparmor.d/abstractions/cups-client b34dde998ba9e2008a449b7e806b4e8a
/etc/apparmor.d/abstractions/dbus a940df2475b2aadae7f0f352426ac0eb
/etc/apparmor.d/abstractions/dbus-accessibility 26e593998ef58a443df94b30c462969c
/etc/apparmor.d/abstractions/dbus-accessibility-strict 373b1eb5eab3ed798b87b63f395e59ec
/etc/apparmor.d/abstractions/dbus-network-manager-strict 2faa81c15df866984bbefe675dd7c535
/etc/apparmor.d/abstractions/dbus-session aae714455fab265eeaf1b6a8e347895a
/etc/apparmor.d/abstractions/dbus-session-strict 92b0802aa074d2fa736e6a34fb21dae6
/etc/apparmor.d/abstractions/dbus-strict 40f5d3c55ee978c6741d4d489357661c
/etc/apparmor.d/abstractions/dconf 7c1eb2f1eb19d459e86f262c0e682107
/etc/apparmor.d/abstractions/dovecot-common dc5a9e349cdac4d77aa883777c523c5a
/etc/apparmor.d/abstractions/dri-common 82e78cab7a0b877758d8d6a3dce1f50d
/etc/apparmor.d/abstractions/dri-enumerate 94c00f262a2e2ecc567417dd655bf06b
/etc/apparmor.d/abstractions/enchant 4b0d599339d403df6444e116f3b49095
/etc/apparmor.d/abstractions/exo-open c02b86d89bdf4954faecdc39bbe8da40
/etc/apparmor.d/abstractions/fcitx a272b0bc5d085b59eafdb3e91662ce1a
/etc/apparmor.d/abstractions/fcitx-strict ae494d8b71f3074ce9ae46d08c895113
/etc/apparmor.d/abstractions/fonts 8594bed8b12b8b8d531c9614a2e03b75
/etc/apparmor.d/abstractions/freedesktop.org 32548dac6ed1ea81e602e2890fbad4b1
/etc/apparmor.d/abstractions/gio-open e1170caef97ca7544f73394db5f29fd6
/etc/apparmor.d/abstractions/gnome 2693f4227aa0b4d6ee4ee33e29f541a4
/etc/apparmor.d/abstractions/gnupg 28bb447b06d329b9a0307fa3957738a9
/etc/apparmor.d/abstractions/gtk 73b9515d686c1763983d749b74930d90
/etc/apparmor.d/abstractions/gvfs-open 75e1db87e189996c93b7f6a54898027d
/etc/apparmor.d/abstractions/hosts_access 77d68b32a830118794977e7d9685e41e
/etc/apparmor.d/abstractions/ibus 3ccdcd8334042d7abc1691235d14a0e8
/etc/apparmor.d/abstractions/kde 1d25d6b22172fcd8f3707856d33a2bd0
/etc/apparmor.d/abstractions/kde-globals-write aa5efc180fc7f48e257e3a745525bb10
/etc/apparmor.d/abstractions/kde-icon-cache-write 0fe4c3bfdccd6098242ac94efb132a13
/etc/apparmor.d/abstractions/kde-language-write f6419d3ec59c4f72af6ff62c85e6b50f
/etc/apparmor.d/abstractions/kde-open5 719648196aaa5921cbbee56884ed0a0a
/etc/apparmor.d/abstractions/kerberosclient 9eec8b4b7751bfc24c7527366652332b
/etc/apparmor.d/abstractions/ldapclient 2d5fbb27b438f3a723af1bd0ec6589cc
/etc/apparmor.d/abstractions/libpam-systemd 54f5c7966013802550bcd298093356a8
/etc/apparmor.d/abstractions/likewise 5b5adaa576726b606437def545b213d9
/etc/apparmor.d/abstractions/mdns 97550547e53831aed4566fe0412f7fae
/etc/apparmor.d/abstractions/mesa ef72c67323d760811583c38d0aaaaa71
/etc/apparmor.d/abstractions/mir c04cae04705882b43888b8bdad39ab7c
/etc/apparmor.d/abstractions/mozc 51778ed730a4ad9d06ad39a848f98ae3
/etc/apparmor.d/abstractions/mysql d0220787933388d0a1ee1e641ecdeb8d
/etc/apparmor.d/abstractions/nameservice a04a23c6142943ef595564b806c4d2d0
/etc/apparmor.d/abstractions/nis 42d818438562ff0a7d21566c52bdf373
/etc/apparmor.d/abstractions/nss-systemd e51b32af03e4b39ad223a921fc08daf2
/etc/apparmor.d/abstractions/nvidia 536d7728a8b0b3d3e63c2135c2f5307f
/etc/apparmor.d/abstractions/opencl 390dd92d75c06bf01a0b380fa279816f
/etc/apparmor.d/abstractions/opencl-common eddad0564696b2ecab52f34c4cb0bf44
/etc/apparmor.d/abstractions/opencl-intel 5a07573a7082eb6906c62707415f86b7
/etc/apparmor.d/abstractions/opencl-mesa d847b3acc2ba5df53309564428b32c5e
/etc/apparmor.d/abstractions/opencl-nvidia 7a28b9490805d8d885c118004584fd63
/etc/apparmor.d/abstractions/opencl-pocl 45de7095b4df796a2a49a1f50bc6af83
/etc/apparmor.d/abstractions/openssl eebb603cd3a947c952ae9e7b2a21176a
/etc/apparmor.d/abstractions/orbit2 3243686cfb77b2eb8ddf4dd9b1dacf51
/etc/apparmor.d/abstractions/p11-kit 66b3abf2da8bd45e868a97a8b5c1c2de
/etc/apparmor.d/abstractions/perl 831a9730e6f5901c26e7370e72d6e4ca
/etc/apparmor.d/abstractions/php c906277ad06598dfea024d4e879e6b61
/etc/apparmor.d/abstractions/php-worker d63894f8faa7f2f4fe6616f9aa6c66fa
/etc/apparmor.d/abstractions/php5 349438200b0b1be7b44f44d2a8edb2d8
/etc/apparmor.d/abstractions/postfix-common 43269973845c1185a9a49dc989e46885
/etc/apparmor.d/abstractions/private-files ed54f0bf093512ab1278415225bd7c76
/etc/apparmor.d/abstractions/private-files-strict 863e1204a719f9d3ef434c51d10c9aae
/etc/apparmor.d/abstractions/python 085157c119b1c08179d0df54243879a8
/etc/apparmor.d/abstractions/qt5 82345ad67eb8610fd5416145758802b5
/etc/apparmor.d/abstractions/qt5-compose-cache-write d9590e9a862c5475024675006bf2b0ad
/etc/apparmor.d/abstractions/qt5-settings-write 08e907106f6afdd628ce7953d6804264
/etc/apparmor.d/abstractions/recent-documents-write 8e878574cc41a1db88eadc9c2386a323
/etc/apparmor.d/abstractions/ruby a376a4d9edd9b6e95196f04316846410
/etc/apparmor.d/abstractions/samba a93d8363540e7bca0fbf28873757fbfa
/etc/apparmor.d/abstractions/smbpass 22d2a76d6718f69140430f2e4160a17c
/etc/apparmor.d/abstractions/ssl_certs 613bf1b6aa1abb7e3c964725f0fb8050
/etc/apparmor.d/abstractions/ssl_keys 8610f0658edabc1b88a71676f0f5831b
/etc/apparmor.d/abstractions/svn-repositories ff8e52c4e1962b96d234dd7a67f1d8f8
/etc/apparmor.d/abstractions/ubuntu-bittorrent-clients d7c1be4622fa1a1a95cc710157495a8b
/etc/apparmor.d/abstractions/ubuntu-browsers 4637c1d896dc3f2348636d216f57b12d
/etc/apparmor.d/abstractions/ubuntu-browsers.d/chromium-browser 153113ed58cd2b82ae59e3cf99e3df49
/etc/apparmor.d/abstractions/ubuntu-browsers.d/java 6e3557f9b8d6d7bfa53e5773a1d1701c
/etc/apparmor.d/abstractions/ubuntu-browsers.d/kde 079bbcda041f2ab3b28a0aa73e808779
/etc/apparmor.d/abstractions/ubuntu-browsers.d/mailto 2d485cfd81cbaa43ea61d754f937f722
/etc/apparmor.d/abstractions/ubuntu-browsers.d/multimedia 975af60c3988f0f29bc7650281add89d
/etc/apparmor.d/abstractions/ubuntu-browsers.d/plugins-common 109801b1eeb3215b1940302855106050
/etc/apparmor.d/abstractions/ubuntu-browsers.d/productivity f7141d1791df3cd70f1f1ffc598357de
/etc/apparmor.d/abstractions/ubuntu-browsers.d/text-editors 530a78215e8a637dee7df2dc06bef104
/etc/apparmor.d/abstractions/ubuntu-browsers.d/ubuntu-integration c36564692bd37edd33abe677b820aa0a
/etc/apparmor.d/abstractions/ubuntu-browsers.d/ubuntu-integration-xul 24a74fcfac9a35ff3213b5cf861f894b
/etc/apparmor.d/abstractions/ubuntu-browsers.d/user-files 6a97ede75f91e3ffadd94c192b47d203
/etc/apparmor.d/abstractions/ubuntu-console-browsers 449cc0ce0d1645dfe750bc59286f3ac4
/etc/apparmor.d/abstractions/ubuntu-console-email 5df8527a131f6073c0105e55855921c2
/etc/apparmor.d/abstractions/ubuntu-email 4ed454816879d62df7390b625196eef8
/etc/apparmor.d/abstractions/ubuntu-feed-readers 652ddbb016d2970643ac0854be6afb7b
/etc/apparmor.d/abstractions/ubuntu-gnome-terminal 4a73e5a52f0aa3155b3ce5ce3f0b88a1
/etc/apparmor.d/abstractions/ubuntu-helpers 7a0554ba395711b18681b1b1615e15a0
/etc/apparmor.d/abstractions/ubuntu-konsole 49c45901c2aa6522869f6ecd11fc4885
/etc/apparmor.d/abstractions/ubuntu-media-players 1cc28886d11782d036f5ad31c1fe6c0e
/etc/apparmor.d/abstractions/ubuntu-unity7-base 76a91b15a0ac3045947dfb417f4be4e9
/etc/apparmor.d/abstractions/ubuntu-unity7-launcher 71beb26198b3834a8cf87cb3958ce49e
/etc/apparmor.d/abstractions/ubuntu-unity7-messaging d9524c849811152e7aaabfcac5bcd1ad
/etc/apparmor.d/abstractions/ubuntu-xterm bed284d239d3fad55ec4138c1db49b1d
/etc/apparmor.d/abstractions/user-download b0084d0cf20ab46c99a443d0bf4293e8
/etc/apparmor.d/abstractions/user-mail 93afccf07c25a810459abb567bdf0ccd
/etc/apparmor.d/abstractions/user-manpages 9f157582739dc69c3f2c092aa4cb76a2
/etc/apparmor.d/abstractions/user-tmp 7adbf0673a8185216a529092e1bafe25
/etc/apparmor.d/abstractions/user-write a35ac2aa74b253ad4d48c52d3e58e86c
/etc/apparmor.d/abstractions/video cc02171362a3819ae3ec5e041afe46ef
/etc/apparmor.d/abstractions/vulkan 6dc5c9c5fb65ea32f7dd3f20314fd9fe
/etc/apparmor.d/abstractions/wayland 0dc88e01e40a1f7710cde25cf2d3e665
/etc/apparmor.d/abstractions/web-data cb78fbb2953fa52805f371c166fd4fbd
/etc/apparmor.d/abstractions/winbind 456c2a26ca32421ac44bd8924fbf55a8
/etc/apparmor.d/abstractions/wutmp 5c2b39fe9978bb8b5e9637519c522c7f
/etc/apparmor.d/abstractions/xad 4716a62377ebebbe55f0246c35591485
/etc/apparmor.d/abstractions/xdg-desktop d0833b7462602d6008ad86a9ba724a1e
/etc/apparmor.d/abstractions/xdg-open 79c6f5afd2a89b7fbc53d23cbba367ea
/etc/apparmor.d/local/README e3739c14b4f8bb9b1934d7a4cdbf72c5
/etc/apparmor.d/lsb_release 4161e668a50a4548271937b6b41d3f0d
/etc/apparmor.d/nvidia_modprobe 89b64f211a74288347bd148f64a4623c
/etc/apparmor.d/tunables/alias 45dca5dd72a6c862d27caa936e6c00ad
/etc/apparmor.d/tunables/apparmorfs 99b56bc365d01a8d83cc60c359eb8184
/etc/apparmor.d/tunables/dovecot 1b0d5ec63a9c87387142bdb2c94e7ede
/etc/apparmor.d/tunables/etc e31a6ae15aa518bb5b826db5f6aaf9ff
/etc/apparmor.d/tunables/global bf4f0b3b17bf1625879e7e90cbe7f8a7
/etc/apparmor.d/tunables/home 7294038da607cb4310d40dc1cb89f398
/etc/apparmor.d/tunables/home.d/site.local 3b274206fb06833ee3e151e351dad51b
/etc/apparmor.d/tunables/kernelvars 5d30bf3c3c6e33927ba26784985ed8ab
/etc/apparmor.d/tunables/multiarch b484327cecfb698fc83ac505699b255a
/etc/apparmor.d/tunables/multiarch.d/site.local 3c9eef1fbfb41fc452060086262e7bcb
/etc/apparmor.d/tunables/proc ffaa055ceb36031c973ffaece22a5fc0
/etc/apparmor.d/tunables/run 780b70bb51fba582c115b085a962373b
/etc/apparmor.d/tunables/securityfs 45d73edb5f03d141634ec6a5ba2b10f3
/etc/apparmor.d/tunables/share a15f039c6615aa63acbec04b313f08f2
/etc/apparmor.d/tunables/sys 30f2fdf4695c26642ea02b5a2063cfbc
/etc/apparmor.d/tunables/xdg-user-dirs 6d1a4ea99a9af4cbab2255535a1c7077
/etc/apparmor/parser.conf 692c8fdebfbe29293c4c94053bc1d013
/etc/init.d/apparmor 42e157dc91f6554abefa2160c2bc42db
Description: user-space parser utility for AppArmor
apparmor provides the system initialization scripts needed to use the
AppArmor Mandatory Access Control system, including the AppArmor Parser
which is required to convert AppArmor text profiles into machine-readable
policies that are loaded into the kernel for use with the AppArmor Linux
Security Module.
Homepage: https://apparmor.net/
Original-Maintainer: Debian AppArmor Team <pkg-apparmor-team@lists.alioth.debian.org>

Package: apport
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 812
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.20.11-0ubuntu82.1
Replaces: core-dump-handler, python-apport (<< 2.2-0ubuntu1)
Provides: core-dump-handler
Depends: python3, python3-apport (>= 2.20.11-0ubuntu82.1), lsb-base (>= 3.0-6), python3-gi, gir1.2-glib-2.0 (>= 1.29.17)
Recommends: apport-symptoms, python3-systemd
Suggests: apport-gtk | apport-kde, policykit-1
Breaks: python-apport (<< 2.2-0ubuntu1)
Conflicts: core-dump-handler
Conffiles:
/etc/apport/blacklist.d/README.blacklist c2ed1eb9a17ec2550747b4960cf4b73c
/etc/apport/blacklist.d/apport 44503501302b80099552bac0204a45c1
/etc/apport/crashdb.conf 4202dae3eccfa5bbb33a0a9acfcd3724
/etc/bash_completion.d/apport_completion dfe766d9328bb5c895038b44185133f9
/etc/cron.daily/apport df5d3bc9ab3a67b58156376318077304
/etc/default/apport 3446c6cac185f44237f59786e006ebe4
/etc/init.d/apport 3d51dc9135014bb49b4a19ff8dab61f1
/etc/logrotate.d/apport fa54dab59ef899b48d5455c976008df4
Description: automatically generate crash reports for debugging
apport automatically collects data from crashed processes and
compiles a problem report in /var/crash/. This utilizes the crashdump
helper hook provided by the Ubuntu kernel.
.
This package also provides a command line frontend for browsing and
handling the crash reports. For desktops, you should consider
installing the GTK+ or Qt user interface (apport-gtk or apport-kde).
Homepage: https://wiki.ubuntu.com/Apport

Package: apport-symptoms
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 61
Maintainer: Ubuntu Developers <ubuntu-motu@lists.ubuntu.com>
Architecture: all
Version: 0.24
Recommends: apport
Description: symptom scripts for apport
Apport intercepts program crashes, collects debugging information about the
crash and the operating system environment, and sends it to bug trackers in a
standardized form. It also offers the user to report a bug about a package,
with again collecting as much information about it as possible.
.
This package extends Apport by some "symptom" scripts, so that bug reporters
do not have to guess the correct package, but report problems based on
symptoms that they have (like "sound problem"), through an interactive process.
Homepage: https://wiki.ubuntu.com/Apport

Package: apt
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 4156
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2.4.7
Replaces: apt-transport-https (<< 1.5~alpha4~), apt-utils (<< 1.3~exp2~)
Provides: apt-transport-https (= 2.4.7)
Depends: adduser, gpgv | gpgv2 | gpgv1, libapt-pkg6.0 (>= 2.4.7), ubuntu-keyring, libc6 (>= 2.34), libgcc-s1 (>= 3.3.1), libgnutls30 (>= 3.7.0), libseccomp2 (>= 2.4.2), libstdc++6 (>= 11), libsystemd0
Recommends: ca-certificates
Suggests: apt-doc, aptitude | synaptic | wajig, dpkg-dev (>= 1.17.2), gnupg | gnupg2 | gnupg1, powermgmt-base
Breaks: apt-transport-https (<< 1.5~alpha4~), apt-utils (<< 1.3~exp2~), aptitude (<< 0.8.10)
Conffiles:
/etc/apt/apt.conf.d/01-vendor-ubuntu c69ce53f5f0755e5ac4441702e820505
/etc/apt/apt.conf.d/01autoremove ab6540f7278a05a4b7f9e58afcaa5f46
/etc/cron.daily/apt-compat 1400ab07a4a2905b04c33e3e93d42b7b
/etc/logrotate.d/apt 179f2ed4f85cbaca12fa3d69c2a4a1c3
Description: commandline package manager
This package provides commandline tools for searching and
managing as well as querying information about packages
as a low-level access to all features of the libapt-pkg library.
.
These include:

- apt-get for retrieval of packages and information about them
  from authenticated sources and for installation, upgrade and
  removal of packages together with their dependencies
- apt-cache for querying available information about installed
  as well as installable packages
- apt-cdrom to use removable media as a source for packages
- apt-config as an interface to the configuration settings
- apt-key as an interface to manage authentication keys
  Original-Maintainer: APT Development Team <deity@lists.debian.org>

Package: apt-utils
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 788
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: apt
Version: 2.4.7
Depends: apt (= 2.4.7), libapt-pkg6.0 (>= 2.4.7), libc6 (>= 2.34), libdb5.3, libgcc-s1 (>= 3.3.1), libstdc++6 (>= 11)
Description: package management related utility programs
This package contains some less used commandline utilities related
to package management with APT.
.

- apt-extracttemplates is used by debconf to prompt for configuration
  questions before installation.
- apt-ftparchive is used to create Packages and other index files
  needed to publish an archive of Debian packages
- apt-sortpkgs is a Packages/Sources file normalizer.
  Original-Maintainer: APT Development Team <deity@lists.debian.org>

Package: at-spi2-core
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 276
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.44.0-3
Depends: libatspi2.0-0 (>= 2.9.90), libc6 (>= 2.34), libdbus-1-3 (>= 1.9.14), libglib2.0-0 (>= 2.67.4), libsystemd0, libx11-6, libxtst6, gsettings-desktop-schemas
Conffiles:
/etc/X11/Xsession.d/90qt-a11y afc7b6dfce4d98efa295023045b20424
/etc/environment.d/90qt-a11y.conf 4f76c97d1817370071bed644d921f142
/etc/xdg/Xwayland-session.d/00-at-spi da53e8f602edbb788b3cd6dbb056e45d
/etc/xdg/autostart/at-spi-dbus-bus.desktop b97f071f92cfc4af379984b27cbb7304
Description: Assistive Technology Service Provider Interface (dbus core)
This package contains the core components of GNOME Accessibility.
Original-Maintainer: Debian Accessibility Team <pkg-a11y-devel@alioth-lists.debian.net>
Homepage: https://wiki.gnome.org/Accessibility

Package: base-files
Essential: yes
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 394
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 12ubuntu4.2
Replaces: base, dpkg (<= 1.15.0), miscutils
Provides: base
Depends: libc6 (>= 2.34), libcrypt1 (>= 1:4.4.10-10ubuntu3)
Pre-Depends: awk
Breaks: debian-security-support (<< 2019.04.25), initscripts (<< 2.88dsf-13.3), sendfile (<< 2.1b.20080616-5.2~), ubuntu-server (<< 1.453)
Conffiles:
/etc/debian_version 62f807f9edf48f460110889c2ecc3db6
/etc/dpkg/origins/debian c47b6815f67ad1aeccb0d4529bd0b990
/etc/dpkg/origins/ubuntu ea35901c45553c3451f60476be94d2d8
/etc/host.conf 89408008f2585c957c031716600d5a80
/etc/issue 2add67d6ac37b5acd2c31e0458419dda
/etc/issue.net dfec4d84febb304708cd3acdb1eaae78
/etc/legal 0110925f6e068836ef2e09356e3651d9
/etc/lsb-release c035065b580e9cc645082241eca33cc6
/etc/profile.d/01-locale-fix.sh 870346d97b16faac4a371b04ffe4cc2f
/etc/update-motd.d/00-header 4a1e6eed7a59f200b4267085721750a3
/etc/update-motd.d/10-help-text d95d18b11ac12cf6582d08a1643034f3
/etc/update-motd.d/50-motd-news 54567afa89b3a7983d05ff217fe4a9fd
Description: Debian base system miscellaneous files
This package contains the basic filesystem hierarchy of a Debian system, and
several important miscellaneous files, such as /etc/debian_version,
/etc/host.conf, /etc/issue, /etc/motd, /etc/profile, and others,
and the text of several common licenses in use on Debian systems.
Original-Maintainer: Santiago Vila <sanvila@debian.org>

Package: base-passwd
Essential: yes
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 243
Maintainer: Colin Watson <cjwatson@debian.org>
Architecture: amd64
Multi-Arch: foreign
Version: 3.5.52build1
Replaces: base
Depends: libc6 (>= 2.34), libdebconfclient0 (>= 0.145)
Recommends: debconf (>= 0.5) | debconf-2.0
Description: Debian base system master password and group files
These are the canonical master copies of the user database files
(/etc/passwd and /etc/group), containing the Debian-allocated user and
group IDs. The update-passwd tool is provided to keep the system databases
synchronized with these master files.

Package: bash
Essential: yes
Status: install ok installed
Priority: required
Section: shells
Installed-Size: 1864
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 5.1-6ubuntu1
Replaces: bash-completion (<< 20060301-0), bash-doc (<= 2.05-1)
Depends: base-files (>= 2.1.12), debianutils (>= 2.15)
Pre-Depends: libc6 (>= 2.34), libtinfo6 (>= 6)
Recommends: bash-completion (>= 20060301-0)
Suggests: bash-doc
Conflicts: bash-completion (<< 20060301-0)
Conffiles:
/etc/bash.bashrc 3aa8b92d1dd6ddf4daaedc019662f1dc
/etc/skel/.bash_logout 22bfb8c1dd94b5f3813a2b25da67463f
/etc/skel/.bashrc 1f98b8f3f3c8f8927eca945d59dcc1c6
/etc/skel/.profile f4e81ade7d6f9fb342541152d08e7a97
Description: GNU Bourne Again SHell
Bash is an sh-compatible command language interpreter that executes
commands read from the standard input or from a file. Bash also
incorporates useful features from the Korn and C shells (ksh and csh).
.
Bash is ultimately intended to be a conformant implementation of the
IEEE POSIX Shell and Tools specification (IEEE Working Group 1003.2).
.
The Programmable Completion Code, by Ian Macdonald, is now found in
the bash-completion package.
Homepage: http://tiswww.case.edu/php/chet/bash/bashtop.html
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: bash-completion
Status: install ok installed
Priority: standard
Section: shells
Installed-Size: 1464
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1:2.11-5ubuntu1
Provides: dh-sequence-bash-completion
Conffiles:
/etc/bash_completion a81b3f1cb197219b815942f4fc7fa94e
/etc/profile.d/bash_completion.sh 4257431f99f10e5fbe86b39b6b9e5002
Description: programmable completion for the bash shell
bash completion extends bash's standard completion behavior to achieve
complex command lines with just a few keystrokes. This project was
conceived to produce programmable completion routines for the most
common Linux/UNIX commands, reducing the amount of typing sysadmins
and programmers need to do on a daily basis.
Homepage: https://github.com/scop/bash-completion
Original-Maintainer: Gabriel F. T. Gomes <gabriel@inconstante.net.br>

Package: bc
Status: install ok installed
Priority: standard
Section: math
Installed-Size: 215
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.07.1-3build1
Depends: libc6 (>= 2.34), libreadline8 (>= 6.0)
Description: GNU bc arbitrary precision calculator language
GNU bc is an interactive algebraic language with arbitrary precision which
follows the POSIX 1003.2 draft standard, with several extensions including
multi-character variable names, an `else' statement and full Boolean
expressions. GNU bc does not require the separate GNU dc program.
Original-Maintainer: Ryan Kavanagh <rak@debian.org>
Homepage: https://www.gnu.org/software/bc/

Package: bcache-tools
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 107
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.0.8-4ubuntu3
Depends: libblkid1 (>= 2.17.2), libc6 (>= 2.34), libuuid1 (>= 2.16), gawk
Recommends: initramfs-tools | linux-initramfs-tool
Description: bcache userspace tools
Bcache allows the use of SSDs to cache other block devices.
.
Documentation for the run-time interface is included in the kernel tree; in
Documentation/bcache.txt.
.
This package includes udev rules, initramfs support, and the utilities to
create a new bcache as well as inspect existing bcache partitions.
Homepage: https://bcache.evilpiepirate.org/
Original-Maintainer: David Mohr <david@mcbf.net>

Package: bind9-dnsutils
Status: install ok installed
Priority: standard
Section: net
Installed-Size: 484
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: bind9
Version: 1:9.18.1-1ubuntu1.1
Provides: dnsutils
Depends: bind9-host | host, bind9-libs (= 1:9.18.1-1ubuntu1.1), libc6 (>= 2.34), libedit2 (>= 2.11-20080614-0), libidn2-0 (>= 2.0.0), libkrb5-3 (>= 1.6.dfsg.2)
Breaks: bind-dnsutils (<< 1:9.13.6~), dnsutils (<< 1:9.13.6~)
Conflicts: bind-dnsutils (<< 1:9.13.6~), dnsutils (<< 1:9.13.6~)
Description: Clients provided with BIND 9
The Berkeley Internet Name Domain (BIND 9) implements an Internet domain
name server. BIND 9 is the most widely-used name server software on the
Internet, and is supported by the Internet Software Consortium, www.isc.org.
.
This package delivers various client programs related to DNS that are
derived from the BIND 9 source tree.
.

- dig - query the DNS in various ways
- nslookup - the older way to do it
- nsupdate - perform dynamic updates (See RFC2136)
  Homepage: https://www.isc.org/downloads/bind/
  Original-Maintainer: Debian DNS Team <team+dns@tracker.debian.org>

Package: bind9-host
Status: install ok installed
Priority: standard
Section: net
Installed-Size: 156
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: bind9
Version: 1:9.18.1-1ubuntu1.1
Replaces: bind-host (<< 1:9.13.6~)
Provides: host
Depends: bind9-libs (= 1:9.18.1-1ubuntu1.1), libc6 (>= 2.34), libidn2-0 (>= 2.0.0)
Breaks: bind-host (<< 1:9.13.6~)
Description: DNS Lookup Utility
This package provides the 'host' DNS lookup utility in the form that
is bundled with the BIND 9 sources.
Homepage: https://www.isc.org/downloads/bind/
Original-Maintainer: Debian DNS Team <team+dns@tracker.debian.org>

Package: bind9-libs
Status: install ok installed
Priority: standard
Section: libs
Installed-Size: 8492
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: bind9
Version: 1:9.18.1-1ubuntu1.1
Replaces: bind-libs (<< 1:9.13.6~)
Depends: libc6 (>= 2.34), libgssapi-krb5-2 (>= 1.17), libjson-c5 (>= 0.15), libkrb5-3 (>= 1.6.dfsg.2), liblmdb0 (>= 0.9.7), libmaxminddb0 (>= 1.3.0), libnghttp2-14 (>= 1.12.0), libssl3 (>= 3.0.0~~alpha1), libuv1 (>= 1.34.2), libxml2 (>= 2.7.4), zlib1g (>= 1:1.1.4)
Breaks: bind-libs (<< 1:9.13.6~)
Description: Shared Libraries used by BIND 9
The Berkeley Internet Name Domain (BIND 9) implements an Internet domain
name server. BIND 9 is the most widely-used name server software on the
Internet, and is supported by the Internet Software Consortium, www.isc.org.
.
This package contains a bundle of shared libraries used by BIND 9.
Homepage: https://www.isc.org/downloads/bind/
Original-Maintainer: Debian DNS Team <team+dns@tracker.debian.org>

Package: binutils
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 111
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2.38-3ubuntu1
Provides: binutils-gold, elf-binutils
Depends: binutils-common (= 2.38-3ubuntu1), libbinutils (= 2.38-3ubuntu1), binutils-x86-64-linux-gnu (= 2.38-3ubuntu1)
Suggests: binutils-doc (>= 2.38-3ubuntu1)
Conflicts: binutils-mingw-w64-i686 (<< 2.23.52.20130612-1+3), binutils-mingw-w64-x86-64 (<< 2.23.52.20130612-1+3), binutils-multiarch (<< 2.27-8), modutils (<< 2.4.19-1)
Description: GNU assembler, linker and binary utilities
The programs in this package are used to assemble, link and manipulate
binary and object files. They may be used in conjunction with a compiler
and various libraries to build programs.
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://www.gnu.org/software/binutils/

Package: binutils-common
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 504
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: binutils
Version: 2.38-3ubuntu1
Replaces: binutils (<< 2.29.1-3.1~)
Breaks: binutils (<< 2.29.1-3.1~)
Description: Common files for the GNU assembler, linker and binary utilities
This package contains the localization files used by binutils packages for
various target architectures and parts of the binutils documentation. It is
not useful on its own.
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://www.gnu.org/software/binutils/

Package: binutils-x86-64-linux-gnu
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 10439
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: binutils
Version: 2.38-3ubuntu1
Replaces: binutils (<< 2.29-6)
Depends: binutils-common (= 2.38-3ubuntu1), libbinutils (= 2.38-3ubuntu1), libc6 (>= 2.34), libctf-nobfd0 (>= 2.36), libctf0 (>= 2.36), libgcc-s1 (>= 4.2), zlib1g (>= 1:1.1.4)
Suggests: binutils-doc (= 2.38-3ubuntu1)
Breaks: binutils (<< 2.29-6)
Description: GNU binary utilities, for x86-64-linux-gnu target
This package provides GNU assembler, linker and binary utilities
for the x86-64-linux-gnu target.
.
You don't need this package unless you plan to cross-compile programs
for x86-64-linux-gnu and x86-64-linux-gnu is not your native platform.
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://www.gnu.org/software/binutils/

Package: bolt
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 469
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.9.2-1
Depends: libc6 (>= 2.34), libglib2.0-0 (>= 2.56), libpolkit-gobject-1-0 (>= 0.99), libudev1 (>= 183)
Description: system daemon to manage thunderbolt 3 devices
Thunderbolt 3 features different security modes that require
devices to be authorized before they can be used. The D-Bus API can be
used to list devices, enroll them (authorize and store them in the
local database) and forget them again (remove previously enrolled
devices). It also emits signals if new devices are connected (or
removed). During enrollment devices can be set to be automatically
authorized as soon as they are connected. A command line tool, called
boltctl, can be used to control the daemon and perform all the above
mentioned tasks.
Original-Maintainer: Debian freedesktop.org maintainers <pkg-freedesktop-maintainers@lists.alioth.debian.org>
Homepage: https://gitlab.freedesktop.org/bolt/bolt

Package: bsdextrautils
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 337
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: util-linux
Version: 2.37.2-4ubuntu3
Replaces: bsdmainutils (<< 12.1.3)
Depends: libc6 (>= 2.34), libsmartcols1 (>= 2.31.1), libtinfo6 (>= 6)
Breaks: bsdmainutils (<< 12.1.3)
Description: extra utilities from 4.4BSD-Lite
This package contains some extra BSD utilities: col, colcrt, colrm, column,
hd, hexdump, look, ul and write.
Other BSD utilities are provided by bsdutils and calendar.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: bsdutils
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 334
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: util-linux (2.37.2-4ubuntu3)
Version: 1:2.37.2-4ubuntu3
Pre-Depends: libc6 (>= 2.34), libsystemd0
Recommends: bsdextrautils
Description: basic utilities from 4.4BSD-Lite
This package contains the bare minimum of BSD utilities needed for a Debian
system: logger, renice, script, scriptlive, scriptreplay and wall. The
remaining standard BSD utilities are provided by bsdextrautils.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: btrfs-progs
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 4190
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 5.16.2-1
Depends: libblkid1 (>= 2.17.2), libc6 (>= 2.34), libcom-err2 (>= 1.43.9), libext2fs2 (>= 1.42), liblzo2-2 (>= 2.02), libudev1 (>= 183), libuuid1 (>= 2.16), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.2.0)
Suggests: duperemove
Breaks: initramfs-tools (<< 0.137~), libgcc-s1 (<< 10-20200211)
Description: Checksumming Copy on Write Filesystem utilities
Btrfs is a copy on write filesystem for Linux aimed at implementing
advanced features while focusing on fault tolerance, repair and easy
administration.
.
This package contains utilities (mkfs, fsck) used to work with btrfs
and an utility (btrfs-convert) to make a btrfs filesystem from an ext3.
Original-Maintainer: Adam Borowski <kilobyte@angband.pl>
Homepage: http://btrfs.wiki.kernel.org/

Package: build-essential
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 12.9ubuntu3
Depends: libc6-dev | libc-dev, gcc (>= 4:10.2), g++ (>= 4:10.2), make, dpkg-dev (>= 1.17.11)
Description: Informational list of build-essential packages
If you do not plan to build Debian packages, you don't need this
package. Starting with dpkg (>= 1.14.18) this package is required
for building Debian packages.
.
This package contains an informational list of packages which are
considered essential for building Debian packages. This package also
depends on the packages on that list, to make it easy to have the
build-essential packages installed.
.
If you have this package installed, you only need to install whatever
a package specifies as its build-time dependencies to build the
package. Conversely, if you are determining what your package needs
to build-depend on, you can always leave out the packages this
package depends on.
.
This package is NOT the definition of what packages are
build-essential; the real definition is in the Debian Policy Manual.
This package contains merely an informational list, which is all
most people need. However, if this package and the manual disagree,
the manual is correct.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: busybox-initramfs
Status: install ok installed
Priority: optional
Section: shells
Installed-Size: 361
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: busybox
Version: 1:1.30.1-7ubuntu3
Depends: libc6 (>= 2.34)
Description: Standalone shell setup for initramfs
BusyBox combines tiny versions of many common UNIX utilities into a single
small executable. It provides minimalist replacements for the most common
utilities you would usually find on your desktop system (i.e., ls, cp, mv,
mount, tar, etc.). The utilities in BusyBox generally have fewer options than
their full-featured GNU cousins; however, the options that are included
provide the expected functionality and behave very much like their GNU
counterparts.
.
busybox-initramfs provides a simple stand alone shell that provides
only the basic utilities needed for the initramfs.
Homepage: http://www.busybox.net
Original-Maintainer: Debian Install System Team <debian-boot@lists.debian.org>

Package: busybox-static
Status: install ok installed
Priority: optional
Section: shells
Installed-Size: 2245
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: busybox
Version: 1:1.30.1-7ubuntu3
Replaces: busybox
Provides: busybox
Conflicts: busybox
Description: Standalone rescue shell with tons of builtin utilities
BusyBox combines tiny versions of many common UNIX utilities into a single
small executable. It provides minimalist replacements for the most common
utilities you would usually find on your desktop system (i.e., ls, cp, mv,
mount, tar, etc.). The utilities in BusyBox generally have fewer options than
their full-featured GNU cousins; however, the options that are included
provide the expected functionality and behave very much like their GNU
counterparts.
.
busybox-static provides you with a statically linked simple stand alone shell
that provides all the utilities available in BusyBox. This package is
intended to be used as a rescue shell, in the event that you screw up your
system. Invoke "busybox sh" and you have a standalone shell ready to save
your system from certain destruction. Invoke "busybox", and it will list the
available builtin commands.
Built-Using: glibc (= 2.35-0ubuntu1)
Homepage: http://www.busybox.net
Original-Maintainer: Debian Install System Team <debian-boot@lists.debian.org>

Package: byobu
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 624
Maintainer: Dustin Kirkland <kirkland@ubuntu.com>
Architecture: all
Version: 5.133-1
Replaces: bikeshed (<< 1.64), byobu-extras (<< 2.17), screen-profiles (<< 2.0), screen-profiles-extras (<< 2.0)
Provides: byobu-extras, screen-profiles, screen-profiles-extras
Depends: debconf (>= 0.5) | debconf-2.0, python3:any, gettext-base, iproute2, python3, python3-newt, tmux (>= 1.5), gawk
Recommends: less, pastebinit, sensible-utils, run-one
Suggests: apport, ccze, gnome-terminal | xterm, gnupg, lsb-release, po-debconf, screen, speedometer, ttf-ubuntu-font-family (>= 0.80-0ubuntu1~medium), update-notifier-common, vim, wireless-tools
Breaks: bikeshed (<< 1.64), byobu-extras (<< 2.17), screen-profiles (<< 2.0), screen-profiles-extras (<< 2.0)
Enhances: screen
Conffiles:
/etc/byobu/backend 9f19a0102abedf38ec2174039d0d0d6d
/etc/byobu/socketdir 774a796c75a097ffd7c5c7492cb39568
/etc/profile.d/Z97-byobu.sh d3fffff67e2a324cc1111f05cb9cc53b
Description: text window manager, shell multiplexer, integrated DevOps environment
Byobu is Ubuntu's powerful text-based window manager, shell multiplexer, and
integrated DevOps environment.
.
Using Byobu, you can quickly create and move between different windows
over a single SSH connection or TTY terminal, split each of those windows into
multiple panes, monitor dozens of important statistics about your system,
detach and reattach to sessions later while your programs continue to run in
the background.
Homepage: http://byobu.org

Package: bzip2
Status: install ok installed
Priority: standard
Section: utils
Installed-Size: 114
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.0.8-5build1
Replaces: libbz2 (<< 0.9.5d-3)
Depends: libbz2-1.0 (= 1.0.8-5build1), libc6 (>= 2.34)
Suggests: bzip2-doc
Description: high-quality block-sorting file compressor - utilities
bzip2 is a freely available, patent free, data compressor.
.
bzip2 compresses files using the Burrows-Wheeler block-sorting text
compression algorithm, and Huffman coding. Compression is generally
considerably better than that achieved by more conventional
LZ77/LZ78-based compressors, and approaches the performance of the PPM
family of statistical compressors.
.
The archive file format of bzip2 (.bz2) is incompatible with that of its
predecessor, bzip (.bz).
Original-Maintainer: Anibal Monsalve Salazar <anibal@debian.org>
Homepage: https://sourceware.org/bzip2/

Package: ca-certificates
Status: install ok installed
Priority: important
Section: misc
Installed-Size: 375
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 20211016
Depends: openssl (>= 1.1.1), debconf (>= 0.5) | debconf-2.0
Breaks: ca-certificates-java (<< 20121112+nmu1)
Enhances: openssl
Description: Common CA certificates
Contains the certificate authorities shipped with Mozilla's browser to allow
SSL-based applications to check for the authenticity of SSL connections.
.
Please note that Debian can neither confirm nor deny whether the
certificate authorities whose certificates are included in this package
have in any way been audited for trustworthiness or RFC 3647 compliance.
Full responsibility to assess them belongs to the local system
administrator.
Original-Maintainer: Julien Cristau <jcristau@debian.org>

Package: cloud-guest-utils
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 65
Maintainer: Scott Moser <smoser@ubuntu.com>
Architecture: all
Source: cloud-utils
Version: 0.32-22-g45fe84a5-0ubuntu1
Replaces: cloud-utils (<< 0.27-0ubuntu3)
Depends: fdisk | gdisk, python3:any
Breaks: cloud-utils (<< 0.27-0ubuntu3)
Description: cloud guest utilities
This package contains programs useful inside cloud instance.
It contains 'growpart' for resizing a partition during boot.
Homepage: https://launchpad.net/cloud-utils

Package: cloud-init
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 2563
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 22.2-0ubuntu1~22.04.3
Depends: cloud-guest-utils | cloud-utils, isc-dhcp-client, iproute2, netplan.io, procps, python3, python3-netifaces, python3-requests, python3-serial, debconf (>= 0.5) | debconf-2.0, python3-configobj, python3-jinja2, python3-jsonpatch, python3-jsonschema, python3-oauthlib, python3-yaml, python3:any
Recommends: eatmydata, gdisk, gnupg, software-properties-common
Suggests: openssh-server, ssh-import-id
Conffiles:
/etc/NetworkManager/dispatcher.d/hook-network-manager 5fe06610f28360e90a8c04febddd384b
/etc/cloud/cloud.cfg d1b008b8a98ce2f5ca2e17e6dd4cffe5
/etc/cloud/cloud.cfg.d/05_logging.cfg b772a8bc0c407baba78b88e89d8fc743
/etc/cloud/cloud.cfg.d/README f5175bd4df5c37ce781f93d20f59561a
/etc/cloud/templates/chef_client.rb.tmpl a0844ddc9a42776d41a03d62d10ea139
/etc/cloud/templates/chrony.conf.alpine.tmpl 9b5c5b4a39ae11562a5013812c11121d
/etc/cloud/templates/chrony.conf.debian.tmpl f6afc8fb02df02a7fad7672a67d34320
/etc/cloud/templates/chrony.conf.fedora.tmpl 8f56d3a782ade6693badf3832775fc82
/etc/cloud/templates/chrony.conf.opensuse.tmpl b7ff0b11f9bded1fc0be5f8806152541
/etc/cloud/templates/chrony.conf.photon.tmpl 8f56d3a782ade6693badf3832775fc82
/etc/cloud/templates/chrony.conf.rhel.tmpl 65413a48dedb31d23c93ac417e1a35e8
/etc/cloud/templates/chrony.conf.sles.tmpl b7ff0b11f9bded1fc0be5f8806152541
/etc/cloud/templates/chrony.conf.ubuntu.tmpl 1ce60fc8d7ab2a82cdf3e572fb9709ff
/etc/cloud/templates/hosts.alpine.tmpl b376c1ff07007f078ee9580cca61432f
/etc/cloud/templates/hosts.arch.tmpl 8721e41953e3d91348b3bb9a17208c1a
/etc/cloud/templates/hosts.debian.tmpl 941773df489d046d87ae491c3c95d8ec
/etc/cloud/templates/hosts.freebsd.tmpl b93d8b13209900227fd7e1731ae23b0c
/etc/cloud/templates/hosts.gentoo.tmpl de3df962ed420b5fa8ad0b338b8f262b
/etc/cloud/templates/hosts.photon.tmpl 236edf211d757237c91834a5316dd083
/etc/cloud/templates/hosts.redhat.tmpl bd5a1edd50c1d8b27c5f51ed44040c19
/etc/cloud/templates/hosts.suse.tmpl 7a535f28d538e6bccaaa4dd7b9dd13c8
/etc/cloud/templates/ntp.conf.alpine.tmpl f7a7c7a340e07e36af23248317fb0c09
/etc/cloud/templates/ntp.conf.debian.tmpl 4234ee67d84a3da62e0d97c7329668df
/etc/cloud/templates/ntp.conf.fedora.tmpl eb6d3fe3d4ddebfe0e310843e8bbc82b
/etc/cloud/templates/ntp.conf.opensuse.tmpl e4bb5100b2dc442b6237ac7e1635acaa
/etc/cloud/templates/ntp.conf.photon.tmpl 86295b29892a099d2b0a87461e81cf31
/etc/cloud/templates/ntp.conf.rhel.tmpl 3437363e2f2dd82c94f8c787fc957ee8
/etc/cloud/templates/ntp.conf.sles.tmpl e4bb5100b2dc442b6237ac7e1635acaa
/etc/cloud/templates/ntp.conf.ubuntu.tmpl 645795fb4ef5d9801111f7d1eb27d91d
/etc/cloud/templates/resolv.conf.tmpl a32413c9f622d5dfa784ef43e3e9e2be
/etc/cloud/templates/sources.list.debian.tmpl a7e69f77a32f15648cee0423fd1ed2bd
/etc/cloud/templates/sources.list.ubuntu.tmpl d6b118c48d33b72eb035f8c673292923
/etc/cloud/templates/systemd.resolved.conf.tmpl a454bfaea86f3758d0078819985d711c
/etc/cloud/templates/timesyncd.conf.tmpl 9c6b3af8058efc219987863f45bb9198
/etc/dhcp/dhclient-exit-hooks.d/hook-dhclient aa6f407b6895c130f2809755373e739f
/etc/profile.d/Z99-cloud-locale-test.sh d21d24035fbd71d94b167aebc2385be3
/etc/profile.d/Z99-cloudinit-warnings.sh 0c6c968d0de8a9141d8ae0a87c5f0293
/etc/rsyslog.d/21-cloudinit.conf d4cf2e5d3cb9914cf7e6cdc08d298339
/etc/systemd/system/sshd-keygen@.service.d/disable-sshd-keygen-if-cloud-init-active.conf e7c2c31c4ceae9e9a4a5c4ef1c165727
Description: initialization and customization tool for cloud instances
Cloud-init is the industry standard multi-distribution method for
cross-platform cloud instance initialization. It is supported across all major
public cloud providers, provisioning systems for private cloud infrastructure,
and bare-metal installations.
.
Cloud instances are initialized from a disk image and instance data:
.

- Cloud metadata
- User data (optional)
- Vendor data (optional)
  .
  Cloud-init will identify the cloud it is running on during boot, read any
  provided metadata from the cloud and initialize the system accordingly. This
  may involve setting up the network and storage devices to configuring SSH
  access key and many other aspects of a system. Later on the cloud-init will
  also parse and process any optional user or vendor data that was passed to
  the instance.
  Homepage: https://cloud-init.io/

Package: cloud-initramfs-copymods
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 25
Maintainer: Scott Moser <smoser@ubuntu.com>
Architecture: all
Source: cloud-initramfs-tools
Version: 0.47ubuntu1
Depends: initramfs-tools
Description: copy initramfs modules into root filesystem for later use
When booting with an external-to-root kernel and initramfs, you need
to ensure that /lib/modules contains any necessary modules not already
loaded.
.
This package arranges for the modules in the initramfs to be placed
into /lib/modules after the switchroot is done.
Homepage: http://launchpad.net/cloud-initramfs-tools

Package: cloud-initramfs-dyn-netconf
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 31
Maintainer: Scott Moser <smoser@ubuntu.com>
Architecture: all
Source: cloud-initramfs-tools
Version: 0.47ubuntu1
Depends: initramfs-tools
Description: write a network interface file in /run for BOOTIF
This package provides an initramfs module that will write a simple
network interfaces formatted file to /run/network/interfaces with
entries for any devices that were configured during initramfs.
Homepage: http://launchpad.net/cloud-initramfs-tools

Package: command-not-found
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 37
Maintainer: Michael Vogt <michael.vogt@ubuntu.com>
Architecture: all
Version: 22.04.0
Depends: python3-commandnotfound (= 22.04.0)
Suggests: snapd
Conffiles:
/etc/apt/apt.conf.d/50command-not-found 9bf399a111915919e5c6952f64a6f5eb
/etc/zsh_command_not_found 81c5c243d61731a56db6670038bf8509
Description: Suggest installation of packages in interactive bash sessions
This package will install a handler for command_not_found that looks up
programs not currently installed but available from the repositories.
Original-Maintainer: Zygmunt Krynicki <zkrynicki@gmail.com>

Package: console-setup
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 426
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.205ubuntu3
Depends: console-setup-linux | console-setup-freebsd | hurd, xkb-data (>= 0.9), keyboard-configuration (= 1.205ubuntu3)
Pre-Depends: debconf (>= 1.5.34)
Suggests: lsb-base (>= 3.0-6), locales
Breaks: lsb (<< 2.0-6), lsb-base (<< 3.0-6), lsb-core (<< 2.0-6)
Conflicts: console-setup-mini
Description: console font and keymap setup program
This package provides the console with the same keyboard
configuration scheme as the X Window System. As a result, there is no
need to duplicate or change the keyboard files just to make simple
customizations such as the use of dead keys, the key functioning as
AltGr or Compose key, the key(s) to switch between Latin and
non-Latin mode, etc.
.
The package also installs console fonts supporting many of the
world's languages. It provides an unified set of font faces - the
classic VGA, the simplistic Fixed, and the cleaned Terminus,
TerminusBold and TerminusBoldVGA.
Original-Maintainer: Debian Install System Team <debian-boot@lists.debian.org>

Package: console-setup-linux
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 2171
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: console-setup
Version: 1.205ubuntu3
Replaces: console-setup (<< 1.71), console-terminus
Provides: console-terminus
Depends: kbd (>= 0.99-12) | console-tools (>= 1:0.2.3-16), keyboard-configuration (= 1.205ubuntu3), init-system-helpers (>= 1.29~) | initscripts
Suggests: console-setup
Breaks: console-cyrillic (<= 0.9-11), console-setup (<< 1.71), console-terminus
Conflicts: console-setup-freebsd
Conffiles:
/etc/console-setup/compose.ARMSCII-8.inc fef36b61fb8b1cacc151ad3db127f777
/etc/console-setup/compose.CP1251.inc fef88d8c8dd4c726498003fd3cd84a7f
/etc/console-setup/compose.CP1255.inc c972a2e90938657e97b643366b98b2ed
/etc/console-setup/compose.CP1256.inc 5ea5e4d41da7a88f742863810e86144b
/etc/console-setup/compose.GEORGIAN-ACADEMY.inc b6d80f40abff7e8af236796ebaca0247
/etc/console-setup/compose.GEORGIAN-PS.inc cf45272b6bf35a22223b132600dc36c3
/etc/console-setup/compose.IBM1133.inc a31102602f7e7cab9738022b6c5469ae
/etc/console-setup/compose.ISIRI-3342.inc 5ada7fbba750192f11fa238add232ba9
/etc/console-setup/compose.ISO-8859-1.inc 28f20a64f3f0b175cfaec4bce07465c2
/etc/console-setup/compose.ISO-8859-10.inc e5fce59617c839b56574c9e323d34686
/etc/console-setup/compose.ISO-8859-11.inc ad2f3cc7ee64602a790bad8a2a989243
/etc/console-setup/compose.ISO-8859-13.inc 5e9ad266f17ff2a0281a870079bc8284
/etc/console-setup/compose.ISO-8859-14.inc 360a44f83e8f8c9d463c9400dcc60de4
/etc/console-setup/compose.ISO-8859-15.inc 695ec832355223fb036629e4e6a9a963
/etc/console-setup/compose.ISO-8859-16.inc 8245c19b5262d8d23ca856587739eb20
/etc/console-setup/compose.ISO-8859-2.inc c93ffa7f80e22c04c94e89a0cd742458
/etc/console-setup/compose.ISO-8859-3.inc 67b8fafc842a4dc9b3bc0c06af394834
/etc/console-setup/compose.ISO-8859-4.inc aba127ff3df5159c3070617a7efac46c
/etc/console-setup/compose.ISO-8859-5.inc f861a4b0403490677e6d400f2d7129da
/etc/console-setup/compose.ISO-8859-6.inc 41ea36ea1c1a1c0c9bebdf0016395e1f
/etc/console-setup/compose.ISO-8859-7.inc 8f48a9f7c9f69ca828edbd7b276fe406
/etc/console-setup/compose.ISO-8859-8.inc 9cceaa9f3312f89aba371d3c893f4e7b
/etc/console-setup/compose.ISO-8859-9.inc 05aae7589b5062a53f346f721cb0f7d3
/etc/console-setup/compose.KOI8-R.inc 8cfd7766b86e5e55d6e71d0d95519c92
/etc/console-setup/compose.KOI8-U.inc 217ee62f6982736276f41f760f8622f8
/etc/console-setup/compose.TIS-620.inc 31b73af83ef3993c128e2b983b9eaf89
/etc/console-setup/compose.VISCII.inc e4ffc74868adf4cc39ba61dd99581899
/etc/console-setup/remap.inc b72cfe32ffa93987f74c5cec9ac180fd
/etc/console-setup/vtrgb 1fb3c13c4fcfa8cc4131aba905df559e
/etc/console-setup/vtrgb.vga 302837772c14006c7956211e184acfbd
/etc/init.d/console-setup.sh 510488b5120b580b673a15b75a5498b0
/etc/init.d/keyboard-setup.sh b868200c6e36ef87e27ead9a3ddad2db
Description: Linux specific part of console-setup
This package includes fonts in psf format and definitions of various
8-bit charmaps.
Original-Maintainer: Debian Install System Team <debian-boot@lists.debian.org>

Package: coreutils
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 7112
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 8.32-4.1ubuntu1
Pre-Depends: libacl1 (>= 2.2.23), libattr1 (>= 1:2.4.44), libc6 (>= 2.34), libgmp10 (>= 2:6.2.1+dfsg), libselinux1 (>= 3.1~)
Description: GNU core utilities
This package contains the basic file, shell and text manipulation
utilities which are expected to exist on every operating system.
.
Specifically, this package includes:
arch base64 basename cat chcon chgrp chmod chown chroot cksum comm cp
csplit cut date dd df dir dircolors dirname du echo env expand expr
factor false flock fmt fold groups head hostid id install join link ln
logname ls md5sum mkdir mkfifo mknod mktemp mv nice nl nohup nproc numfmt
od paste pathchk pinky pr printenv printf ptx pwd readlink realpath rm
rmdir runcon sha\*sum seq shred sleep sort split stat stty sum sync tac
tail tee test timeout touch tr true truncate tsort tty uname unexpand
uniq unlink users vdir wc who whoami yes
Homepage: http://gnu.org/software/coreutils
Original-Maintainer: Michael Stone <mstone@debian.org>

Package: cpio
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 324
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.13+dfsg-7
Replaces: cpio-mt
Depends: libc6 (>= 2.34)
Suggests: libarchive1
Conflicts: cpio-mt, mt-st (<< 0.6)
Description: GNU cpio -- a program to manage archives of files
GNU cpio is a tool for creating and extracting archives, or copying
files from one place to another. It handles a number of cpio formats
as well as reading and writing tar files.
Original-Maintainer: Anibal Monsalve Salazar <anibal@debian.org>
Homepage: https://www.gnu.org/software/cpio/

Package: cpp
Status: install ok installed
Priority: optional
Section: interpreters
Installed-Size: 67
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: gcc-defaults (1.193ubuntu1)
Version: 4:11.2.0-1ubuntu1
Depends: cpp-11 (>= 11.2.0-1~)
Suggests: cpp-doc
Conflicts: cpp-doc (<< 1:2.95.3)
Description: GNU C preprocessor (cpp)
The GNU C preprocessor is a macro processor that is used automatically
by the GNU C compiler to transform programs before actual compilation.
.
This package has been separated from gcc for the benefit of those who
require the preprocessor but not the compiler.
.
This is a dependency package providing the default GNU C preprocessor.
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: cpp-11
Status: install ok installed
Priority: optional
Section: interpreters
Installed-Size: 26208
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: gcc-11
Version: 11.2.0-19ubuntu1
Depends: gcc-11-base (= 11.2.0-19ubuntu1), libc6 (>= 2.34), libgmp10 (>= 2:6.2.1+dfsg), libisl23 (>= 0.15), libmpc3 (>= 1.1.0), libmpfr6 (>= 3.1.3), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Suggests: gcc-11-locales (>= 11)
Breaks: hardening-wrapper (<< 2.8+nmu3), libmagics++-dev (<< 2.28.0-4)
Description: GNU C preprocessor
A macro processor that is used automatically by the GNU C compiler
to transform programs before actual compilation.
.
This package has been separated from gcc for the benefit of those who
require the preprocessor but not the compiler.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: cron
Status: install ok installed
Priority: standard
Section: admin
Installed-Size: 255
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 3.0pl1-137ubuntu3
Provides: cron-daemon
Depends: libc6 (>= 2.34), libpam0g (>= 0.99.7.1), libselinux1 (>= 3.1~), debianutils (>= 1.7), sensible-utils, adduser, lsb-base (>= 3.0-10), libpam-runtime (>= 1.0.1-11)
Pre-Depends: init-system-helpers (>= 1.54~)
Suggests: anacron (>= 2.0-1), logrotate, checksecurity, default-mta | mail-transport-agent
Conffiles:
/etc/cron.d/.placeholder e5e12910bf011222160404d7bdb824f2
/etc/cron.daily/.placeholder e5e12910bf011222160404d7bdb824f2
/etc/cron.hourly/.placeholder e5e12910bf011222160404d7bdb824f2
/etc/cron.monthly/.placeholder e5e12910bf011222160404d7bdb824f2
/etc/cron.weekly/.placeholder e5e12910bf011222160404d7bdb824f2
/etc/crontab e57fd77c50de7b8a8eec19de0ec3f4f3
/etc/default/cron bc9ab63f9e143d7338909d50494d552f
/etc/init.d/cron 2a663c89329b71c3659e7601fdb80c92
/etc/pam.d/cron 11e788a7f7cd5477b10da2c7fd5ecdf0
Description: process scheduling daemon
The cron daemon is a background process that runs particular programs at
particular times (for example, every minute, day, week, or month), as
specified in a crontab. By default, users may also create crontabs of
their own so that processes are run on their behalf.
.
Output from the commands is usually mailed to the system administrator
(or to the user in question); you should probably install a mail system
as well so that you can receive these messages.
.
This cron package does not provide any system maintenance tasks. Basic
periodic maintenance tasks are provided by other packages, such
as checksecurity.
Homepage: https://ftp.isc.org/isc/cron/
Original-Maintainer: Javier Fernández-Sanguino Peña <jfs@debian.org>

Package: cryptsetup
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 475
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2:2.4.3-1ubuntu1.1
Replaces: cryptsetup-run (<< 2:2.1.0-6)
Depends: cryptsetup-bin (>= 2:1.6.0), dmsetup, debconf (>= 0.5) | debconf-2.0, libc6 (>= 2.34), libcryptsetup12 (>= 2:2.4), libjson-c5 (>= 0.15), libssh-4 (>= 0.8.0)
Recommends: cryptsetup-initramfs
Suggests: dosfstools, keyutils, liblocale-gettext-perl
Breaks: cryptsetup-run (<< 2:2.1.0-6)
Conffiles:
/etc/default/cryptdisks 3e3b2248193105b5ecd9456c01ef3736
/etc/init.d/cryptdisks 8dd64a17dcefb1dd1a60eec286a6b502
/etc/init.d/cryptdisks-early 9c68271b34d88afd2764cdb203af9bd1
Description: disk encryption support - startup scripts
Cryptsetup provides an interface for configuring encryption on block
devices (such as /home or swap partitions), using the Linux kernel
device mapper target dm-crypt. It features integrated Linux Unified Key
Setup (LUKS) support.
.
Cryptsetup is backwards compatible with the on-disk format of cryptoloop,
but also supports more secure formats. This package includes support for
automatically configuring encrypted devices at boot time via the config
file /etc/crypttab. Additional features are cryptoroot support through
initramfs-tools and several supported ways to read a passphrase or key.
.
This package provides the cryptdisks_start and \_stop wrappers, as well as
luksformat.
Homepage: https://gitlab.com/cryptsetup/cryptsetup
Original-Maintainer: Debian Cryptsetup Team <pkg-cryptsetup-devel@alioth-lists.debian.net>

Package: cryptsetup-bin
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 584
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: cryptsetup
Version: 2:2.4.3-1ubuntu1.1
Depends: libblkid1 (>= 2.24.2), libc6 (>= 2.34), libcryptsetup12 (>= 2:2.4), libjson-c5 (>= 0.15), libpopt0 (>= 1.14), libssh-4 (>= 0.8.0), libuuid1 (>= 2.16)
Description: disk encryption support - command line tools
Cryptsetup provides an interface for configuring encryption on block
devices (such as /home or swap partitions), using the Linux kernel
device mapper target dm-crypt. It features integrated Linux Unified Key
Setup (LUKS) support.
.
This package provides cryptsetup, cryptsetup-reencrypt, integritysetup
and veritysetup.
Homepage: https://gitlab.com/cryptsetup/cryptsetup
Original-Maintainer: Debian Cryptsetup Team <pkg-cryptsetup-devel@alioth-lists.debian.net>

Package: cryptsetup-initramfs
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 157
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: cryptsetup
Version: 2:2.4.3-1ubuntu1.1
Replaces: cryptsetup (<< 2:2.0.3-1)
Depends: busybox-initramfs, cryptsetup (>= 2:2.4.3-1ubuntu1.1), initramfs-tools (>= 0.137) | linux-initramfs-tool, debconf (>= 0.5) | debconf-2.0
Recommends: console-setup, kbd, plymouth
Breaks: cryptsetup (<< 2:2.0.3-1)
Conffiles:
/etc/cryptsetup-initramfs/conf-hook 9a127a9edfca239740eba9197b0b901f
Description: disk encryption support - initramfs integration
Cryptsetup provides an interface for configuring encryption on block
devices (such as /home or swap partitions), using the Linux kernel
device mapper target dm-crypt. It features integrated Linux Unified Key
Setup (LUKS) support.
.
This package provides initramfs integration for cryptsetup.
Homepage: https://gitlab.com/cryptsetup/cryptsetup
Original-Maintainer: Debian Cryptsetup Team <pkg-cryptsetup-devel@alioth-lists.debian.net>

Package: curl
Status: install ok installed
Priority: optional
Section: web
Installed-Size: 442
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 7.81.0-1ubuntu1.4
Depends: libc6 (>= 2.34), libcurl4 (= 7.81.0-1ubuntu1.4), zlib1g (>= 1:1.1.4)
Description: command line tool for transferring data with URL syntax
curl is a command line tool for transferring data with URL syntax, supporting
DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3,
POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
.
curl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form
based upload, proxies, cookies, user+password authentication (Basic, Digest,
NTLM, Negotiate, kerberos...), file transfer resume, proxy tunneling and a
busload of other useful tricks.
Homepage: https://curl.haxx.se
Original-Maintainer: Alessandro Ghedini <ghedo@debian.org>

Package: dash
Essential: yes
Status: install ok installed
Priority: required
Section: shells
Installed-Size: 214
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 0.5.11+git20210903+057cd650a4ed-3build1
Depends: debianutils (>= 2.15), dpkg (>= 1.19.1), debconf (>= 0.5) | debconf-2.0
Pre-Depends: libc6 (>= 2.34)
Description: POSIX-compliant shell
The Debian Almquist Shell (dash) is a POSIX-compliant shell derived
from ash.
.
Since it executes scripts faster than bash, and has fewer library
dependencies (making it more robust against software or hardware
failures), it is used as the default system shell on Debian systems.
Original-Maintainer: Andrej Shadura <andrewsh@debian.org>
Homepage: http://gondor.apana.org.au/~herbert/dash/

Package: dbus
Status: install ok installed
Priority: important
Section: devel
Installed-Size: 582
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.12.20-2ubuntu4
Provides: dbus-bin (= 1.12.20-2ubuntu4), dbus-daemon (= 1.12.20-2ubuntu4), dbus-session-bus-common (= 1.12.20-2ubuntu4), dbus-system-bus (= 1.12.20-2ubuntu4), dbus-system-bus-common (= 1.12.20-2ubuntu4), default-dbus-system-bus
Depends: adduser, libapparmor1 (>= 2.8.94), libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), libcap-ng0 (>= 0.7.9), libdbus-1-3 (= 1.12.20-2ubuntu4), libexpat1 (>= 2.1~beta3), libselinux1 (>= 3.1~), libsystemd0
Suggests: default-dbus-session-bus | dbus-session-bus
Conffiles:
/etc/default/dbus 0d0f25a2f993509c857eb262f6e22015
/etc/init.d/dbus d78b20b35de983cf6f1475dcf8cb21a1
Description: simple interprocess messaging system (daemon and utilities)
D-Bus is a message bus, used for sending messages between applications.
Conceptually, it fits somewhere in between raw sockets and CORBA in
terms of complexity.
.
D-Bus supports broadcast messages, asynchronous messages (thus
decreasing latency), authentication, and more. It is designed to be
low-overhead; messages are sent using a binary protocol, not using
XML. D-Bus also supports a method call mapping for its messages, but
it is not required; this makes using the system quite simple.
.
It comes with several bindings, including GLib, Python, Qt and Java.
.
This package contains the D-Bus daemon and related utilities.
.
The client-side library can be found in the libdbus-1-3 package, as it is no
longer contained in this package.
Homepage: https://dbus.freedesktop.org/
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: dbus-user-session
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 130
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: dbus
Version: 1.12.20-2ubuntu4
Provides: dbus-session-bus, default-dbus-session-bus
Depends: dbus (>= 1.12.20-2ubuntu4), libpam-systemd, systemd
Recommends: systemd-sysv
Breaks: dbus-x11 (<< 1.9.10-2~), policykit-1 (<< 0.105-12~), udisks2 (<< 2.1.5-2~)
Conffiles:
/etc/X11/Xsession.d/20dbus_xdg-runtime a10c47d15857ae4b557dc7e062f6e6f1
Description: simple interprocess messaging system (systemd --user integration)
D-Bus is a message bus, used for sending messages between applications.
Conceptually, it fits somewhere in between raw sockets and CORBA in
terms of complexity.
.
On systemd systems, this package opts in to the session model in which
a user's session starts the first time they log in, and does not end
until all their login sessions have ended. This model merges all
parallel non-graphical login sessions (text mode, ssh, cron, etc.), and up
to one graphical session, into a single "user-session" or "super-session"
within which all background D-Bus services are shared.
.
Multiple graphical sessions per user are not currently supported in this
mode; as a result, it is particularly suitable for gdm, which responds to
requests to open a parallel graphical session by switching to the existing
graphical session and unlocking it.
.
To retain dbus' traditional session semantics, in which login sessions
are artificially isolated from each other, remove this package and install
dbus-x11 instead.
.
See the dbus package description for more information about D-Bus in general.
Homepage: https://dbus.freedesktop.org/
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: dbus-x11
Status: install ok installed
Priority: optional
Section: x11
Installed-Size: 161
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: dbus
Version: 1.12.20-2ubuntu4
Provides: dbus-session-bus
Depends: dbus, libc6 (>= 2.34), libdbus-1-3 (= 1.12.20-2ubuntu4), libx11-6
Conffiles:
/etc/X11/Xsession.d/75dbus_dbus-launch 7e16a9fa2ead9d6596b655e417fda3ba
/etc/X11/Xsession.d/95dbus_update-activation-env a97a2e4a0193d85e7646a2de721d09a2
Description: simple interprocess messaging system (X11 deps)
D-Bus is a message bus, used for sending messages between applications.
Conceptually, it fits somewhere in between raw sockets and CORBA in
terms of complexity.
.
This package contains the dbus-launch utility which is necessary for
packages using a D-Bus session bus.
.
See the dbus description for more information about D-Bus in general.
Homepage: https://dbus.freedesktop.org/
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: dconf-gsettings-backend
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 83
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: dconf
Version: 0.40.0-3
Provides: gsettings-backend
Depends: dconf-service (<< 0.40.0-3.1~), dconf-service (>= 0.40.0-3), libdconf1 (= 0.40.0-3), libc6 (>= 2.14), libglib2.0-0 (>= 2.55.2)
Description: simple configuration storage system - GSettings back-end
DConf is a low-level key/value database designed for storing desktop
environment settings.
.
This package contains a back-end for GSettings. It is needed by
applications accessing settings through GSettings to set custom values
and listen for changes.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Projects/dconf

Package: dconf-service
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 102
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: dconf
Version: 0.40.0-3
Depends: default-dbus-session-bus | dbus-session-bus, libdconf1 (= 0.40.0-3), libc6 (>= 2.34), libglib2.0-0 (>= 2.55.2)
Recommends: dconf-gsettings-backend
Description: simple configuration storage system - D-Bus service
DConf is a low-level key/value database designed for storing desktop
environment settings.
.
This package contains the DConf service, which applications talk to
using D-Bus in order to obtain their settings. It is mostly used by the
GSettings backend.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Projects/dconf

Package: debconf
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 512
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.5.79ubuntu1
Replaces: debconf-tiny
Provides: debconf-2.0
Pre-Depends: perl-base (>= 5.20.1-3~)
Recommends: apt-utils (>= 0.5.1), debconf-i18n
Suggests: debconf-doc, debconf-utils, whiptail | dialog, libterm-readline-gnu-perl, libgtk3-perl, libnet-ldap-perl, perl, debconf-kde-helper (>= 0.1+git20110702)
Breaks: apt-listchanges (<< 3.14), ubiquity (<< 17.10.2), update-notifier-common (<< 3.187~)
Conflicts: apt (<< 0.3.12.1), cdebconf (<< 0.96), debconf-tiny, debconf-utils (<< 1.3.22), dialog (<< 0.9b-20020814-1), menu (<= 2.1.3-1), whiptail (<< 0.51.4-11), whiptail-utf8 (<= 0.50.17-13)
Conffiles:
/etc/apt/apt.conf.d/70debconf 7e9d09d5801a42b4926b736b8eeabb73
/etc/debconf.conf 8c0619be413824f1fc7698cee0f23811
Description: Debian configuration management system
Debconf is a configuration management system for debian packages. Packages
use Debconf to ask questions when they are installed.
Original-Maintainer: Debconf Developers <debconf-devel@lists.alioth.debian.org>

Package: debconf-i18n
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 787
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: debconf
Version: 1.5.79ubuntu1
Replaces: debconf (<< 1.3.0), debconf-utils (<< 1.3.22)
Depends: debconf (= 1.5.79ubuntu1), liblocale-gettext-perl, libtext-iconv-perl, libtext-wrapi18n-perl, libtext-charwidth-perl
Conflicts: debconf-english, debconf-utils (<< 1.3.22)
Description: full internationalization support for debconf
This package provides full internationalization for debconf, including
translations into all available languages, support for using translated
debconf templates, and support for proper display of multibyte character
sets.
Original-Maintainer: Debconf Developers <debconf-devel@lists.alioth.debian.org>

Package: debianutils
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 243
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 5.5-1ubuntu2
Pre-Depends: libc6 (>= 2.34)
Breaks: ifupdown (<< 0.8.36+nmu1), printer-driver-pnm2ppa (<< 1.13-12), x11-common (<< 1:7.7+23~)
Description: Miscellaneous utilities specific to Debian
This package provides a number of small utilities which are used
primarily by the installation scripts of Debian packages, although
you may use them directly.
.
The specific utilities included are:
add-shell installkernel ischroot remove-shell run-parts savelog
tempfile update-shells which
Original-Maintainer: Clint Adams <clint@debian.org>

Package: dictionaries-common
Status: install ok installed
Priority: optional
Section: text
Installed-Size: 765
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.28.14
Replaces: openoffice.org-updatedicts
Provides: openoffice.org-updatedicts
Depends: debconf (>= 0.5) | debconf-2.0, libtext-iconv-perl, emacsen-common
Suggests: ispell | aspell | hunspell, wordlist
Breaks: hunspell-da (<= 1:3.1.0), hunspell-de-at (<= 20100727-1), hunspell-de-ch (<= 20100727-1), hunspell-de-de (<= 20100727-1), hunspell-eu-es (<= 0.4.20081029-4), hunspell-ko (<= 0.5.3-1), hunspell-uz (<= 0.6-3.1), hyphen-en-us (<< 2.8.3-1), myspell-bg (<= 3.0-12), myspell-ca (<= 0.6-10), myspell-cs (<= 20040229-5), myspell-cs-cz (<= 20040229-5), myspell-da (<= 1.6.25-1), myspell-de-at (<= 20100727-1), myspell-de-ch (<= 20100727-1), myspell-de-de (<= 20100727-1), myspell-de-de-oldspell (<= 1:2-27), myspell-en-au (<= 2.1-5), myspell-eo (<= 2.1.2000.02.25-42), myspell-es (<= 1.11-1), myspell-et (<= 1:20030606-12.1), myspell-eu-es (<= 0.4.20081029-4), myspell-fi (<= 0.7-17.3), myspell-fo (<= 0.2.44-2), myspell-fr (<= 1.4-25), myspell-fr-gut (<= 1:1.0-28), myspell-ga (<= 2.0-20), myspell-gd (<= 0.50-7), myspell-gl-es (<= 2.2a-8), myspell-gv (<= 0.50-9), myspell-he (<= 1.1-1), myspell-hu (<= 0.99.4-2), myspell-ku (<= 0.20.0-1.1), myspell-nb (<= 2.0.10-3.2), myspell-nl (<= 1:2.0-1), myspell-nn (<= 2.0.10-3.2), myspell-nr (<< 20070206-4ubuntu1), myspell-ns (<< 20070206-4ubuntu1), myspell-pl (<= 20100612-1), myspell-pt-pt (<= 20091013-2), myspell-ru (<= 0.99g5-8.1), myspell-sl (<< 1.0-3ubuntu1), myspell-ss (<< 20070206-4ubuntu1), myspell-sv-se (<= 1.3.8-6-2.2), myspell-tn (<< 20070206-4ubuntu1), myspell-ts (<< 20070207-4ubuntu1), myspell-uk (<= 1.6.0-1), myspell-ve (<< 20070206-3ubuntu1), myspell-xh (<< 20070206-4ubuntu1), myspell-zu (<< 20070207-5ubuntu1), mythes-it (<= 2.0.7.gh.deb1-3), openoffice.org-thesaurus-it (<< 2.0.7.gh.deb1-1.1ubuntu3)
Conffiles:
/etc/emacs/site-start.d/50dictionaries-common.el 6e5295d702ddc90ac894acba3c2961b0
Description: spelling dictionaries - common utilities
This package provides utilities shared between all wordlists and spelling
dictionaries for Ispell, Aspell, or MySpell/Hunspell. It also includes
support infrastructure for software using them (such as JED and Mutt),
and some patched spell-checking Lisp files for better Emacs integration.
.
More information about the availability of these dictionaries and their
naming conventions is available in the README.Debian file.
Original-Maintainer: Agustin Martin Domingo <agmartin@debian.org>
Homepage: https://salsa.debian.org/debian/dictionaries-common

Package: diffutils
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 424
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1:3.8-0ubuntu2
Replaces: diff
Pre-Depends: libc6 (>= 2.34)
Suggests: diffutils-doc, wdiff
Description: File comparison utilities
The diffutils package provides the diff, diff3, sdiff, and cmp programs.
.
`diff' shows differences between two files, or each corresponding file in two directories. `cmp' shows the offsets and line numbers where
two files differ. `cmp' can also show all the characters that differ between the two files, side by side. `diff3' shows differences
among three files. `sdiff' merges two files interactively. . The set of differences produced by `diff' can be used to distribute
updates to text files (such as program source code) to other people.
This method is especially useful when the differences are small compared
to the complete files. Given `diff' output, the `patch' program can
update, or "patch", a copy of the file.
Homepage: https://www.gnu.org/software/diffutils/
Original-Maintainer: Santiago Vila <sanvila@debian.org>

Package: dirmngr
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 676
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg2 (<< 2.1.10-2)
Depends: adduser, gpgconf (= 2.2.27-3ubuntu2.1), lsb-base (>= 3.2-13), init-system-helpers (>= 1.52), libassuan0 (>= 2.5.0), libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgnutls30 (>= 3.7.2), libgpg-error0 (>= 1.42), libksba8 (>= 1.3.5), libldap-2.5-0 (>= 2.5.4), libnpth0 (>= 0.90)
Recommends: gnupg (= 2.2.27-3ubuntu2.1)
Suggests: dbus-user-session, libpam-systemd, pinentry-gnome3, tor
Breaks: gnupg2 (<< 2.1.10-2)
Enhances: gpg, gpgsm, squid
Description: GNU privacy guard - network certificate management service
dirmngr is a server for managing and downloading OpenPGP and X.509
certificates, as well as updates and status signals related to those
certificates. For OpenPGP, this means pulling from the public
HKP/HKPS keyservers, or from LDAP servers. For X.509 this includes
Certificate Revocation Lists (CRLs) and Online Certificate Status
Protocol updates (OCSP). It is capable of using Tor for network
access.
.
dirmngr is used for network access by gpg, gpgsm, and dirmngr-client,
among other tools. Unless this package is installed, the parts of
the GnuPG suite that try to interact with the network will fail.
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: distro-info
Status: install ok installed
Priority: important
Section: devel
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.1build1
Depends: distro-info-data (>= 0.46), libc6 (>= 2.34)
Suggests: shunit2 (>= 2.1.6)
Description: provides information about the distributions' releases
Information about all releases of Debian and Ubuntu. The distro-info script
will give you the codename for e.g. the latest stable release of your
distribution. To get information about a specific distribution there are the
debian-distro-info and the ubuntu-distro-info scripts.
Original-Maintainer: Benjamin Drung <bdrung@debian.org>

Package: distro-info-data
Status: install ok installed
Priority: important
Section: devel
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.52ubuntu0.1
Breaks: distro-info (<< 1.0~)
Description: information about the distributions' releases (data files)
Information about all releases of Debian and Ubuntu. The distro-info script
will give you the codename for e.g. the latest stable release of your
distribution. To get information about a specific distribution there are the
debian-distro-info and the ubuntu-distro-info scripts.
.
This package contains the data files.
Original-Maintainer: Benjamin Drung <bdrung@debian.org>

Package: dmeventd
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 245
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: lvm2 (2.03.11-2.1ubuntu4)
Version: 2:1.02.175-2.1ubuntu4
Depends: libc6 (>= 2.34), libdevmapper-event1.02.1 (>= 2:1.02.110), libdevmapper1.02.1 (>= 2:1.02.110), liblvm2cmd2.03 (>= 2.03.11)
Description: Linux Kernel Device Mapper event daemon
The Linux Kernel Device Mapper is the LVM (Linux Logical Volume Management)
Team's implementation of a minimalistic kernel-space driver that handles
volume management, while keeping knowledge of the underlying device layout
in user-space. This makes it useful for not only LVM, but software raid,
and other drivers that create "virtual" block devices.
.
This package contains a daemon to monitor events of devmapper devices.
Homepage: https://sourceware.org/lvm2/
Original-Maintainer: Debian LVM Team <team+lvm@tracker.debian.org>

Package: dmidecode
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 208
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 3.3-3ubuntu0.1
Depends: libc6 (>= 2.34)
Description: SMBIOS/DMI table decoder
Dmidecode reports information about the system's hardware as described in the
system BIOS according to the SMBIOS/DMI standard.
.
This information typically includes system manufacturer, model name, serial
number, BIOS version, asset tag as well as a lot of other details of varying
level of interest and reliability depending on the manufacturer. This will
often include usage status for the CPU sockets, expansion slots (e.g. AGP, PCI,
ISA) and memory module slots, and the list of I/O ports (e.g. serial, parallel,
USB).
.
Beware that DMI data have proven to be too unreliable to be blindly trusted.
Dmidecode does not scan the hardware, it only reports what the BIOS told it to.
Homepage: https://nongnu.org/dmidecode/
Original-Maintainer: Jörg Frings-Fürst <debian@jff.email>

Package: dmsetup
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 273
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: lvm2 (2.03.11-2.1ubuntu4)
Version: 2:1.02.175-2.1ubuntu4
Depends: libc6 (>= 2.34), libdevmapper1.02.1 (>= 2:1.02.138)
Description: Linux Kernel Device Mapper userspace library
The Linux Kernel Device Mapper is the LVM (Linux Logical Volume Management)
Team's implementation of a minimalistic kernel-space driver that handles
volume management, while keeping knowledge of the underlying device layout
in user-space. This makes it useful for not only LVM, but software raid,
and other drivers that create "virtual" block devices.
.
This package contains a utility for modifying device mappings.
Homepage: https://sourceware.org/lvm2/
Original-Maintainer: Debian LVM Team <team+lvm@tracker.debian.org>

Package: dosfstools
Status: install ok installed
Priority: optional
Section: otherosfs
Installed-Size: 245
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 4.2-1build3
Depends: libc6 (>= 2.34)
Description: utilities for making and checking MS-DOS FAT filesystems
The dosfstools package includes the mkfs.fat and fsck.fat utilities, which
respectively make and check MS-DOS FAT filesystems.
Original-Maintainer: Andreas Bombe <aeb@debian.org>
Homepage: https://github.com/dosfstools/dosfstools

Package: dpkg
Essential: yes
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 6733
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.21.1ubuntu2.1
Depends: tar (>= 1.28-1)
Pre-Depends: libbz2-1.0, libc6 (>= 2.34), liblzma5 (>= 5.2.2), libselinux1 (>= 3.1~), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Suggests: apt, debsig-verify
Breaks: libapt-pkg5.0 (<< 1.7~b), lsb-base (<< 10.2019031300)
Conffiles:
/etc/alternatives/README 7be88b21f7e386c8d5a8790c2461c92b
/etc/cron.daily/dpkg 94bb6c1363245e46256908a5d52ba4fb
/etc/dpkg/dpkg.cfg f4413ffb515f8f753624ae3bb365b81b
/etc/logrotate.d/alternatives 5fe0af6ce1505fefdc158d9e5dbf6286
/etc/logrotate.d/dpkg 9e25c8505966b5829785f34a548ae11f
Description: Debian package management system
This package provides the low-level infrastructure for handling the
installation and removal of Debian software packages.
.
For Debian package development tools, install dpkg-dev.
Homepage: https://wiki.debian.org/Teams/Dpkg
Original-Maintainer: Dpkg Developers <debian-dpkg@lists.debian.org>

Package: dpkg-dev
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 2488
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: dpkg
Version: 1.21.1ubuntu2.1
Depends: perl:any, libdpkg-perl (= 1.21.1ubuntu2.1), tar (>= 1.28-1), bzip2, xz-utils, patch (>= 2.7), make, binutils, lto-disabled-list
Recommends: build-essential, gcc | c-compiler, fakeroot, gnupg, gpgv, libalgorithm-merge-perl
Suggests: debian-keyring
Breaks: debhelper (<< 10.10.1~)
Conffiles:
/etc/dpkg/shlibs.default 1a2b9d0a869e2aa885ae3621c557fb95
/etc/dpkg/shlibs.override 84b1e69080569cc5c613a50887af5200
Description: Debian package development tools
This package provides the development tools (including dpkg-source)
required to unpack, build and upload Debian source packages.
.
Most Debian source packages will require additional tools to build;
for example, most packages need make and the C compiler gcc.
Homepage: https://wiki.debian.org/Teams/Dpkg
Original-Maintainer: Dpkg Developers <debian-dpkg@lists.debian.org>

Package: e2fsprogs
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 1516
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.46.5-2ubuntu1.1
Depends: logsave
Pre-Depends: libblkid1 (>= 2.36), libc6 (>= 2.34), libcom-err2 (>= 1.43.9), libext2fs2 (= 1.46.5-2ubuntu1.1), libss2 (>= 1.38), libuuid1 (>= 2.16)
Recommends: e2fsprogs-l10n
Suggests: gpart, parted, fuse2fs, e2fsck-static
Conffiles:
/etc/cron.d/e2scrub_all bc533e09f3b3d96bfe1633ad57eb7026
/etc/e2scrub.conf df38534cc670c70a91cf9b035845d244
/etc/mke2fs.conf 6e57073b9789a67a66b4681739445a38
Description: ext2/ext3/ext4 file system utilities
The ext2, ext3 and ext4 file systems are successors of the original ext
("extended") file system. They are the main file system types used for
hard disks on Debian and other Linux systems.
.
This package contains programs for creating, checking, and maintaining
ext2/3/4-based file systems. It also includes the "badblocks" program,
which can be used to scan for bad blocks on a disk or other storage device.
Homepage: http://e2fsprogs.sourceforge.net
Important: yes
Original-Maintainer: Theodore Y. Ts'o <tytso@mit.edu>

Package: eatmydata
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 25
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: libeatmydata
Version: 130-2build1
Depends: libeatmydata1 (>= 130-2build1)
Description: Library and utilities designed to disable fsync and friends
This package contains a small LD_PRELOAD library (libeatmydata) and a couple
of helper utilities designed to transparently disable fsync and friends (like
open(O_SYNC)). This has two side-effects: making software that writes data
safely to disk a lot quicker and making this software no longer crash safe.
.
You will find eatmydata useful if particular software calls fsync(), sync()
etc. frequently but the data it stores is not that valuable to you and you may
afford losing it in case of system crash. Data-to-disk synchronization calls
are typically very slow on modern file systems and their extensive usage might
slow down software significantly. It does not make sense to accept such a hit
in performance if data being manipulated is not very important.
.
On the other hand, do not use eatmydata when you care about what software
stores or it manipulates important components of your system. The library is
called libEAT-MY-DATA for a reason.
Homepage: https://www.flamingspork.com/projects/libeatmydata/
Original-Maintainer: Mattia Rizzolo <mattia@debian.org>

Package: ed
Status: install ok installed
Priority: optional
Section: editors
Installed-Size: 108
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.18-1
Depends: libc6 (>= 2.34)
Description: classic UNIX line editor
ed is a line-oriented text editor. It is used to
create, display, modify and otherwise manipulate text
files.
.
red is a restricted ed: it can only edit files in the
current directory and cannot execute shell commands.
Original-Maintainer: Martin Zobel-Helas <zobel@debian.org>
Homepage: https://www.gnu.org/software/ed/

Package: eject
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 152
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: util-linux
Version: 2.37.2-4ubuntu3
Depends: libc6 (>= 2.34), libmount1 (>= 2.24.2)
Description: ejects CDs and operates CD-Changers under Linux
This program will eject CD-ROMs (assuming your drive supports the CDROMEJECT
ioctl). It also allows setting the autoeject feature.
.
On supported ATAPI/IDE multi-disc CD-ROM changers, it allows changing
the active disc.
.
You can also use eject to properly disconnect external mass-storage
devices like digital cameras or portable music players.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: emacsen-common
Status: install ok installed
Priority: optional
Section: editors
Installed-Size: 62
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.4
Conflicts: emacs19, emacs20, emacs21-common, emacs22-common, emacs23-common, emacs24-common, emacs25-common, xemacs21-support (<< 21.4.24-6~)
Description: Common facilities for all emacsen
This package contains code that is needed by all the (x)emacs
packages. It will be automatically installed when needed.
Original-Maintainer: Rob Browning <rlb@defaultvalue.org>

Package: ethtool
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 630
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1:5.16-1
Depends: libc6 (>= 2.34), libmnl0 (>= 1.0.3-4~)
Conffiles:
/etc/network/if-pre-up.d/ethtool 39693276fe35fccec75f610cb71d3e85
/etc/network/if-up.d/ethtool b0d11ba5983c8c5990bb9933c35a3ec5
Description: display or change Ethernet device settings
ethtool can be used to query and change settings such as speed, auto-
negotiation and checksum offload on many network devices, especially
Ethernet devices.
Original-Maintainer: Debian Kernel Team <debian-kernel@lists.debian.org>
Homepage: https://www.kernel.org/pub/software/network/ethtool/

Package: fakeroot
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 220
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.28-1ubuntu1
Depends: libfakeroot (>= 1.28-1ubuntu1), libc6 (>= 2.34)
Description: tool for simulating superuser privileges
fakeroot provides a fake "root environment" by means of LD_PRELOAD and
SysV IPC (or TCP) trickery. It puts wrappers around getuid(), chown(),
stat(), and other file-manipulation functions, so that unprivileged
users can (for instance) populate .deb archives with root-owned files;
various build tools use fakeroot for this by default.
.
This package contains fakeroot command and the daemon that remembers
fake ownership/permissions of files manipulated by fakeroot
processes.
Original-Maintainer: Clint Adams <clint@debian.org>

Package: fdisk
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 437
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: util-linux
Version: 2.37.2-4ubuntu3
Depends: libc6 (>= 2.34), libfdisk1 (>= 2.36), libmount1 (>= 2.24.2), libncursesw6 (>= 6), libreadline8 (>= 6.0), libsmartcols1 (>= 2.28~rc1), libtinfo6 (>= 6)
Description: collection of partitioning utilities
This package contains the classic fdisk, sfdisk and cfdisk partitioning
utilities from the util-linux suite.
.
The utilities included in this package allow you to partition
your hard disk. The utilities supports both modern and legacy
partition tables (eg. GPT, MBR, etc).
.
The fdisk utility is the classical text-mode utility.
The cfdisk utilitity gives a more userfriendly curses based interface.
The sfdisk utility is mostly for automation and scripting uses.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: file
Status: install ok installed
Priority: standard
Section: utils
Installed-Size: 83
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1:5.41-3
Depends: libc6 (>= 2.34), libmagic1 (= 1:5.41-3)
Breaks: debhelper (<< 12.2~)
Description: Recognize the type of data in a file using "magic" numbers
The file command is "a file type guesser", a command-line tool that
tells you in words what kind of data a file contains.
.
This package contains the file program itself.
Original-Maintainer: Christoph Biedl <debian.axhn@manchmal.in-ulm.de>
Homepage: https://www.darwinsys.com/file/

Package: finalrd
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 30
Maintainer: Dimitri John Ledkov <xnox@ubuntu.com>
Architecture: all
Version: 9build1
Recommends: initramfs-tools-core
Description: final runtime directory for shutdown
Generates a systemd compatible shutdown runtime directory. This
enables to execute scripts and binaries to clean up shutdown.
.
Also supports hookless operation, to simply facilitate clean shutdowns.
.
Approximate tmpfs RAM requirement is 14MB on shutdown.
Homepage: https://launchpad.net/finalrd

Package: findutils
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 620
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 4.8.0-1ubuntu3
Pre-Depends: libc6 (>= 2.34), libselinux1 (>= 3.1~)
Suggests: mlocate | locate
Breaks: binstats (<< 1.08-8.1), guilt (<< 0.36-0.2), libpython3.4-minimal (<< 3.4.4-2), libpython3.5-minimal (<< 3.5.1-3), lsat (<< 0.9.7.1-2.1), mc (<< 3:4.8.11-1), switchconf (<< 0.0.9-2.1)
Description: utilities for finding files--find, xargs
GNU findutils provides utilities to find files meeting specified
criteria and perform various actions on the files which are found.
This package contains 'find' and 'xargs'; however, 'locate' has
been split off into a separate package.
Homepage: https://savannah.gnu.org/projects/findutils/
Original-Maintainer: Andreas Metzler <ametzler@debian.org>

Package: fontconfig
Status: install ok installed
Priority: optional
Section: fonts
Installed-Size: 375
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.13.1-4.2ubuntu5
Depends: libc6 (>= 2.34), libfontconfig1 (>= 2.13.0), libfreetype6 (>= 2.8.1), fontconfig-config
Description: generic font configuration library - support binaries
Fontconfig is a font configuration and customization library, which
does not depend on the X Window System. It is designed to locate
fonts within the system and select them according to requirements
specified by applications.
.
Fontconfig is not a rasterization library, nor does it impose a
particular rasterization library on the application. The X-specific
library 'Xft' uses fontconfig along with freetype to specify and
rasterize fonts.
.
This package contains a program to maintain the fontconfig cache
(fc-cache), a sample program to list installed fonts (fc-list), a program
to test the matching rules (fc-match) and a program to dump the binary
cache files in string form (fc-cat). It no longer makes fonts managed by defoma
available to fontconfig applications.
Homepage: https://www.freedesktop.org/wiki/Software/fontconfig/
Original-Maintainer: Debian freedesktop.org maintainers <pkg-freedesktop-maintainers@lists.alioth.debian.org>

Package: fontconfig-config
Status: install ok installed
Priority: optional
Section: fonts
Installed-Size: 172
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: fontconfig
Version: 2.13.1-4.2ubuntu5
Depends: ucf (>= 0.29), fonts-dejavu-core | ttf-bitstream-vera | fonts-liberation | fonts-liberation2 | fonts-croscore | fonts-freefont-otf | fonts-freefont-ttf | fonts-urw-base35 | fonts-texgyre
Breaks: libfontconfig1 (<< 2.13.0)
Conffiles:
/etc/fonts/conf.avail/10-antialias.conf 3629dcc380ac8c5b0306febc33b5667b
/etc/fonts/conf.avail/10-autohint.conf b64114e5af24e4cdfc5bd5023f280287
/etc/fonts/conf.avail/10-hinting-full.conf a5bec12a811215bb09bd0e0a58469918
/etc/fonts/conf.avail/10-hinting-medium.conf 03715b87280da58cfe9d4c4f4d6d0488
/etc/fonts/conf.avail/10-hinting-none.conf 709229aa350cfaf1eb59cbc4ab5f2377
/etc/fonts/conf.avail/10-hinting-slight.conf 690acea9572bf68b0ef975636002e4f3
/etc/fonts/conf.avail/10-no-sub-pixel.conf 1a29e6674047b54b5d240e30807fab0e
/etc/fonts/conf.avail/10-scale-bitmap-fonts.conf 7bf8b372085774e6cbdae99235624440
/etc/fonts/conf.avail/10-sub-pixel-bgr.conf c7aea7a564a5ec98b76d8ef1c6791ee3
/etc/fonts/conf.avail/10-sub-pixel-rgb.conf 8bcf6192e90c1b3d0972eb1657b87e0c
/etc/fonts/conf.avail/10-sub-pixel-vbgr.conf aee77dfa949e40dd1a2309bfae59f7c6
/etc/fonts/conf.avail/10-sub-pixel-vrgb.conf c7c6b8d23a8a25d68b71a7d63c4d2d29
/etc/fonts/conf.avail/10-unhinted.conf 9e2da80ad573a4c8cf582b3b63a54ed7
/etc/fonts/conf.avail/11-lcdfilter-default.conf f4229be8b8d744a07bd153804cc89510
/etc/fonts/conf.avail/11-lcdfilter-legacy.conf 74c9020e8ca6b87ee60b919219cbbb6e
/etc/fonts/conf.avail/11-lcdfilter-light.conf ac0f49d468587a5db0a7e96700c9a159
/etc/fonts/conf.avail/20-unhint-small-vera.conf 8b4b489882181273bb954bbeca039706
/etc/fonts/conf.avail/25-unhint-nonlatin.conf a755ea93d91a116223ee0a6f2179e7da
/etc/fonts/conf.avail/30-metric-aliases.conf 75c9e9472b8d86398bb90aad2f9f33ef
/etc/fonts/conf.avail/40-nonlatin.conf 20ee0ed0c5d5ec9e1cf840861654e5b9
/etc/fonts/conf.avail/45-generic.conf e5a3f4b8d89676c4f6e24e78fa0ab226
/etc/fonts/conf.avail/45-latin.conf 78e96661b2e081a6855194cdbfbd414b
/etc/fonts/conf.avail/49-sansserif.conf ddb0852326b96387179f833fce3fff61
/etc/fonts/conf.avail/50-user.conf ef75f810654a94c9735c63ba050c3000
/etc/fonts/conf.avail/51-local.conf 05120737595ec804f105e86a2c2f10df
/etc/fonts/conf.avail/53-monospace-lcd-filter.conf 94669e241a96e50d95cdd4b126e43ec6
/etc/fonts/conf.avail/60-generic.conf 36818672366678a1242830b5e7829aef
/etc/fonts/conf.avail/60-latin.conf 4b9c621952455f0e19eaa91fe40ab01b
/etc/fonts/conf.avail/65-fonts-persian.conf 3c3369d2e5cddac97685a35f923cd8ae
/etc/fonts/conf.avail/65-khmer.conf 2c60845ccef2f9fb278dbc776f852e7b
/etc/fonts/conf.avail/65-nonlatin.conf b4b7785deb1beea8d134f47f5230ba36
/etc/fonts/conf.avail/69-unifont.conf d01fe25b8869985f337a7d90704cefe6
/etc/fonts/conf.avail/70-force-bitmaps.conf 05da482c17d5c285ec2cf7134c8f6c5a
/etc/fonts/conf.avail/70-no-bitmaps.conf 1b7c38fe5f2e26c4581332c90cc1277f
/etc/fonts/conf.avail/70-yes-bitmaps.conf 91c414090c7d8bfe557785fe845cb6bd
/etc/fonts/conf.avail/80-delicious.conf ddad25ea4458fffa36d7a1f2f53bc5e9
/etc/fonts/conf.avail/90-synthetic.conf e79defb0b94fe9d0a9af39c83e48b9dc
/etc/fonts/conf.d/README 42d13304ed2e9e5b60b74d6ed29b3729
/etc/fonts/fonts.conf 1a6ebc792c61d5944c30e1696446f5d4
Description: generic font configuration library - configuration
Fontconfig is a font configuration and customization library, which
does not depend on the X Window System. It is designed to locate
fonts within the system and select them according to requirements
specified by applications.
.
This package contains the configuration files and scripts for fontconfig.
Homepage: https://www.freedesktop.org/wiki/Software/fontconfig/
Original-Maintainer: Debian freedesktop.org maintainers <pkg-freedesktop-maintainers@lists.alioth.debian.org>

Package: fonts-dejavu-core
Status: install ok installed
Priority: optional
Section: fonts
Installed-Size: 2954
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: fonts-dejavu
Version: 2.37-2build1
Conffiles:
/etc/fonts/conf.avail/20-unhint-small-dejavu-lgc-sans-mono.conf 10d6f2176d76ee9b89a19a17811257f2
/etc/fonts/conf.avail/20-unhint-small-dejavu-lgc-sans.conf 6488b24401e477e35aa71237054c8ada
/etc/fonts/conf.avail/20-unhint-small-dejavu-lgc-serif.conf 0b01522fe76b4e5b8ab3d12383371348
/etc/fonts/conf.avail/20-unhint-small-dejavu-sans-mono.conf 0cbf30e4580c5a8570da071ab12c5e4d
/etc/fonts/conf.avail/20-unhint-small-dejavu-sans.conf f7df7bba810dd953dd78212900f4dcad
/etc/fonts/conf.avail/20-unhint-small-dejavu-serif.conf e90c678d46f49bb9d6ba469b64e80c0c
/etc/fonts/conf.avail/57-dejavu-sans-mono.conf b9a76edd2aeb35cd1095e378963e2cdd
/etc/fonts/conf.avail/57-dejavu-sans.conf 2156c2353cfcc81f33150cf889193c28
/etc/fonts/conf.avail/57-dejavu-serif.conf 2604487cb2eee1bdb7010ea716faf408
/etc/fonts/conf.avail/58-dejavu-lgc-sans-mono.conf d2ee39274982cb4f831783cff742c8bc
/etc/fonts/conf.avail/58-dejavu-lgc-sans.conf b4a8f51e45aa24fdee47b3f838cc0205
/etc/fonts/conf.avail/58-dejavu-lgc-serif.conf 5f0b00e681b1f40b65dd336696ee0bbb
Description: Vera font family derivate with additional characters
DejaVu provides an expanded version of the Vera font family aiming for
quality and broader Unicode coverage while retaining the original Vera
style. DejaVu currently works towards conformance with the Multilingual
European Standards (MES-1 and MES-2) for Unicode coverage. The DejaVu
fonts provide serif, sans and monospaced variants.
.
This package only contains the sans, sans-bold, serif, serif-bold,
mono and mono-bold variants. For additional variants, see the
fonts-dejavu-extra package.
.
DejaVu fonts are intended for use on low-resolution devices (mainly
computer screens) but can be used in printing as well.
Original-Maintainer: Debian Fonts Task Force <debian-fonts@lists.debian.org>
Homepage: https://dejavu-fonts.github.io/

Package: fonts-firacode
Status: install ok installed
Priority: optional
Section: fonts
Installed-Size: 2927
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 6.2-1
Description: Monospaced font with programming ligatures
Fira Code is an extension of the Fira Mono font containing a set of
ligatures for common programming multi-character combinations. This is
just a font rendering feature: underlying code remains ASCII-compatible.
This helps to read and understand code faster. For some frequent sequences
like .. or //, the ligatures allow one to correct spacing.
.
This font is expected to work in most text editors but won't work in most
(especially VTE-based) terminal emulators. A detailed list is available on
https://github.com/tonsky/FiraCode#terminal-support
Original-Maintainer: Debian Fonts Task Force <debian-fonts@lists.debian.org>
Homepage: https://github.com/tonsky/FiraCode

Package: fonts-powerline
Status: install ok installed
Priority: optional
Section: fonts
Installed-Size: 26
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: powerline
Version: 2.8.2-1
Depends: fontconfig
Conffiles:
/etc/fonts/conf.avail/10-powerline-symbols.conf 69822158b0cc8af0bef456d684200882
Description: prompt and statusline utility (symbols font)
Powerline is a statusline plugin for vim, and provides statuslines and prompts
for several other applications, including zsh, bash, tmux, IPython, Awesome and
Qtile.
.
This package contains the font which provides symbols used by Powerline. It
also contains the fontconfig settings that makes these symbols available as
part of other installed fonts.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/powerline/powerline

Package: fonts-ubuntu
Status: install ok installed
Priority: optional
Section: fonts
Installed-Size: 4339
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.83-6ubuntu1
Description: sans-serif font set from Ubuntu
The Ubuntu Font Family is a set of contemporary sans-serif fonts developed
between 2010-2011. Dalton Maag performed the font design work and
implementation with funding from Canonical. The fonts have been the default
fonts for Ubuntu since 2010.
Homepage: https://design.ubuntu.com/font/
Original-Maintainer: Debian Fonts Task Force <pkg-fonts-devel@lists.alioth.debian.org>

Package: fonts-ubuntu-console
Status: install ok installed
Priority: optional
Section: fonts
Installed-Size: 63
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: fonts-ubuntu
Version: 0.83-6ubuntu1
Description: console version of the Ubuntu Mono font
The Ubuntu Font Family is a set of contemporary sans-serif fonts developed
between 2010-2011. Dalton Maag performed the font design work and
implementation with funding from Canonical. The fonts have been the default
fonts for Ubuntu since 2010.
.
This package contains the "Ubuntu Mono" font converted to a bitmap version
for Linux console use. These fonts can be loaded from a virtual terminal by
executing "setfont /usr/share/consolefonts/UbuntuMono\*.psf" .
Homepage: https://design.ubuntu.com/font/
Original-Maintainer: Debian Fonts Task Force <pkg-fonts-devel@lists.alioth.debian.org>

Package: friendly-recovery
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.2.42
Depends: systemd-sysv, whiptail
Recommends: gettext-base, update-manager-core
Breaks: grub2 (<< 1.99-12ubuntu4), initramfs-tools (<< 0.99ubuntu4), upstart (<< 1.3-0ubuntu9)
Description: Make recovery boot mode more user-friendly
Make the recovery boot mode more user-friendly by providing a menu
with pluggable options.
Original-Maintainer: Debian QA Group <packages@qa.debian.org>

Package: ftp
Status: install ok installed
Priority: optional
Section: oldlibs
Installed-Size: 26
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: tnftp
Version: 20210827-4build1
Replaces: ftp (<= 0.17-35)
Depends: tnftp
Description: dummy transitional package for tnftp
This is a dummy transitional package transitioning ftp to tnftp.
Homepage: http://en.wikipedia.org/wiki/Tnftp
Original-Maintainer: xiao sheng wen <atzlinux@sina.com>

Package: fuse3
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 90
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 3.10.5-1build1
Replaces: fuse
Provides: fuse (= 3.10.5-1build1)
Depends: libc6 (>= 2.34), libfuse3-3 (= 3.10.5-1build1), adduser, mount (>= 2.19.1), sed (>= 4), lsb-base (>= 3.2-14)
Breaks: fuse
Conffiles:
/etc/fuse.conf ba9c9667f7df01ae7081d2c05d1d24e6
Description: Filesystem in Userspace (3.x version)
Filesystem in Userspace (FUSE) is a simple interface for userspace programs to
export a virtual filesystem to the Linux kernel. It also aims to provide a
secure method for non privileged users to create and mount their own filesystem
implementations.
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>
Homepage: https://github.com/libfuse/libfuse/wiki

Package: fwupd
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 6648
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.7.5-3
Replaces: fwupdate (<< 12-7), gir1.2-dfu-1.0 (<< 0.9.7-1), libdfu-dev (<< 0.9.7-1), libdfu1 (<< 0.9.7-1)
Provides: fwupdate
Depends: libfwupd2 (= 1.7.5-3), libfwupdplugin5 (= 1.7.5-3), libc6 (>= 2.34), libcurl3-gnutls (>= 7.63.0), libefiboot1 (>= 37), libflashrom1, libglib2.0-0 (>= 2.70.0), libgnutls30 (>= 3.7.3), libgudev-1.0-0 (>= 165), libgusb2 (>= 0.3.6), libjcat1 (>= 0.1.3), libjson-glib-1.0-0 (>= 1.5.2), libmbim-glib4 (>= 1.26.0), libmbim-proxy, libmm-glib0 (>= 1.10.0), libpolkit-gobject-1-0 (>= 0.99), libqmi-glib5 (>= 1.18.0), libqmi-proxy, libsmbios-c2, libsqlite3-0 (>= 3.6.1), libsystemd0, libtss2-esys-3.0.2-0 (>= 2.3.1), libxmlb2 (>= 0.3.2), shared-mime-info
Recommends: python3, bolt, dbus, secureboot-db, udisks2, fwupd-signed
Suggests: gir1.2-fwupd-2.0
Breaks: fwupdate (<< 12-7), gir1.2-dfu-1.0 (<< 0.9.7-1), libdfu-dev (<< 0.9.7-1), libdfu1 (<< 0.9.7-1)
Conflicts: fwupdate-amd64-signed, fwupdate-arm64-signed, fwupdate-armhf-signed, fwupdate-i386-signed
Conffiles:
/etc/fwupd/daemon.conf 377ba3fdc58ecf45cb0083b2841edc7b
/etc/fwupd/redfish.conf f13ccd1c92550da7538c8643af44a906
/etc/fwupd/remotes.d/dell-esrt.conf 71236e67e6fd095c771f9312cbae0382
/etc/fwupd/remotes.d/lvfs-testing.conf 29d484b5d5c374ba278eba49ab28e40b
/etc/fwupd/remotes.d/lvfs.conf 03115854971bef4f13b16729e9c107ad
/etc/fwupd/remotes.d/vendor-directory.conf f65a59cfb87730fb523910f492dbceb6
/etc/fwupd/remotes.d/vendor.conf b54e960f98c71d49af9421cf8e9cf7b9
/etc/fwupd/thunderbolt.conf ecd9f08e4e9382b959e8604758ce71b3
/etc/fwupd/uefi_capsule.conf ef3a1b12a9884d69456c137193c7d72f
/etc/grub.d/35_fwupd d35ffdb3ab8eef4d4fa9f916ff621b55
/etc/pki/fwupd-metadata/GPG-KEY-Linux-Foundation-Metadata 2ace8894994764ae32e391bc0c68e398
/etc/pki/fwupd-metadata/GPG-KEY-Linux-Vendor-Firmware-Service 5abbdc42a8e3d9e60039ab658700ec71
/etc/pki/fwupd-metadata/LVFS-CA.pem d9dff488bd9051268984da014f0be43d
/etc/pki/fwupd/GPG-KEY-Linux-Foundation-Firmware de0622638572a2f6a6e29fa83f387eea
/etc/pki/fwupd/GPG-KEY-Linux-Vendor-Firmware-Service 5abbdc42a8e3d9e60039ab658700ec71
/etc/pki/fwupd/LVFS-CA.pem d9dff488bd9051268984da014f0be43d
/etc/update-motd.d/85-fwupd ded254e025601b203abb19ef3fdc88b9
Description: Firmware update daemon
fwupd is a daemon to allow session software to update device firmware.
You can either use a GUI software manager like GNOME Software to view and
apply updates, the command-line tool or the system D-Bus interface directly.
Firmware updates are supported for a variety of technologies.
See <https://github.com/fwupd/fwupd> for details
Original-Maintainer: Debian EFI <debian-efi@lists.debian.org>
Homepage: https://github.com/fwupd/fwupd

Package: fwupd-signed
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 77
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: fwupd-signed (1.44)
Version: 1.44+1.2-3
Recommends: secureboot-db, fwupd
Description: Linux Firmware Updater EFI signed binary
fwupd provides functionality to update system firmware. It has been
initially designed to update firmware using UEFI capsule updates, but
it is designed to be extensible to other firmware update standards.
.
This package contains a version of the fwupd binary signed with
Canonical's UEFI signing key.
Built-Using: fwupd-efi (= 1:1.2-3)

Package: g++
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: gcc-defaults (1.193ubuntu1)
Version: 4:11.2.0-1ubuntu1
Provides: c++-compiler, g++-x86-64-linux-gnu (= 4:11.2.0-1ubuntu1)
Depends: cpp (= 4:11.2.0-1ubuntu1), gcc (= 4:11.2.0-1ubuntu1), g++-11 (>= 11.2.0-1~), gcc-11 (>= 11.2.0-1~)
Suggests: g++-multilib
Description: GNU C++ compiler
This is the GNU C++ compiler, a fairly portable optimizing compiler for C++.
.
This is a dependency package providing the default GNU C++ compiler.
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: g++-11
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 28780
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: gcc-11
Version: 11.2.0-19ubuntu1
Provides: c++-compiler, c++abi2-dev
Depends: gcc-11-base (= 11.2.0-19ubuntu1), gcc-11 (= 11.2.0-19ubuntu1), libstdc++-11-dev (= 11.2.0-19ubuntu1), libc6 (>= 2.34), libgmp10 (>= 2:6.2.1+dfsg), libisl23 (>= 0.15), libmpc3 (>= 1.1.0), libmpfr6 (>= 3.1.3), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Suggests: g++-11-multilib, gcc-11-doc (>= 11)
Description: GNU C++ compiler
This is the GNU C++ compiler, a fairly portable optimizing compiler for C++.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: gawk
Status: install ok installed
Priority: optional
Section: interpreters
Installed-Size: 1680
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1:5.1.0-1build3
Provides: awk
Pre-Depends: libc6 (>= 2.34), libgmp10 (>= 2:6.2.1+dfsg), libmpfr6 (>= 3.1.3), libreadline8 (>= 6.0), libsigsegv2 (>= 2.9)
Suggests: gawk-doc
Conffiles:
/etc/profile.d/gawk.csh b3d9e29a36f945b2065b2f88d18dadaa
/etc/profile.d/gawk.sh bfc054c0862d0fad98ca641b951c7061
Description: GNU awk, a pattern scanning and processing language
`awk', a program that you can use to select particular records in a
file and perform operations upon them.
.
Gawk is the GNU Project's implementation of the AWK programming language.
It conforms to the definition of the language in the POSIX 1003.2 Command
Language And Utilities Standard. This version in turn is based on the
description in The AWK Programming Language, by Aho, Kernighan, and
Weinberger, with the additional features defined in the System V Release
4 version of UNIX awk. Gawk also provides more recent Bell Labs awk
extensions, and some GNU-specific extensions.
Homepage: http://www.gnu.org/software/gawk/
Original-Maintainer: Adrian Bunk <bunk@debian.org>

Package: gcc
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 50
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: gcc-defaults (1.193ubuntu1)
Version: 4:11.2.0-1ubuntu1
Provides: c-compiler, gcc-x86-64-linux-gnu (= 4:11.2.0-1ubuntu1)
Depends: cpp (= 4:11.2.0-1ubuntu1), gcc-11 (>= 11.2.0-1~)
Recommends: libc6-dev | libc-dev
Suggests: gcc-multilib, make, manpages-dev, autoconf, automake, libtool, flex, bison, gdb, gcc-doc
Conflicts: gcc-doc (<< 1:2.95.3)
Description: GNU C compiler
This is the GNU C compiler, a fairly portable optimizing compiler for C.
.
This is a dependency package providing the default GNU C compiler.
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: gcc-11
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 52559
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 11.2.0-19ubuntu1
Replaces: cpp-11 (<< 7.1.1-8)
Provides: c-compiler
Depends: cpp-11 (= 11.2.0-19ubuntu1), gcc-11-base (= 11.2.0-19ubuntu1), libcc1-0 (>= 11.2.0-19ubuntu1), binutils (>= 2.38), libgcc-11-dev (= 11.2.0-19ubuntu1), libc6 (>= 2.34), libgcc-s1 (>= 3.0), libgmp10 (>= 2:6.2.1+dfsg), libisl23 (>= 0.15), libmpc3 (>= 1.1.0), libmpfr6 (>= 3.1.3), libstdc++6 (>= 5), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Recommends: libc6-dev (>= 2.13-0ubuntu6)
Suggests: gcc-11-multilib, gcc-11-doc (>= 11), gcc-11-locales (>= 11)
Description: GNU C compiler
This is the GNU C compiler, a fairly portable optimizing compiler for C.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: gcc-11-base
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 270
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-11
Version: 11.2.0-19ubuntu1
Breaks: gnat (<< 7)
Description: GCC, the GNU Compiler Collection (base package)
This package contains files common to all languages and libraries
contained in the GNU Compiler Collection (GCC).
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: gcc-12-base
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 266
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Breaks: gnat (<< 7)
Description: GCC, the GNU Compiler Collection (base package)
This package contains files common to all languages and libraries
contained in the GNU Compiler Collection (GCC).
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: gdisk
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 726
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.0.8-4build1
Depends: libc6 (>= 2.34), libgcc-s1 (>= 3.3.1), libncursesw6 (>= 6), libpopt0 (>= 1.14), libstdc++6 (>= 9), libtinfo6 (>= 6), libuuid1 (>= 2.16)
Recommends: groff-base
Description: GPT fdisk text-mode partitioning tool
GPT fdisk (aka gdisk) is a text-mode partitioning
tool that provides utilities for Globally Unique
Identifier (GUID) Partition Table (GPT) disks.
.
Features:
.

- Edit GUID partition table definitions
- In place conversion of BSD disklabels to GPT
- In place conversion of MBR to GPT
- In place conversion of GPT to MBR
- Create hybrid MBR/GPT layouts
- Repair damaged GPT data structures
- Repair damaged MBR structures
- Back up GPT data to a file (and restore from file)
  Original-Maintainer: Jonathan Carter <jcc@debian.org>
  Homepage: http://sourceforge.net/projects/gptfdisk/

Package: gettext-base
Status: install ok installed
Priority: standard
Section: utils
Installed-Size: 284
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gettext
Version: 0.21-4ubuntu4
Depends: libc6 (>= 2.34)
Description: GNU Internationalization utilities for the base system
This package includes the gettext and ngettext programs which allow
other packages to internationalize the messages given by shell scripts.
Homepage: https://www.gnu.org/software/gettext/
Original-Maintainer: Santiago Vila <sanvila@debian.org>

Package: gir1.2-glib-2.0
Status: install ok installed
Priority: important
Section: introspection
Installed-Size: 677
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gobject-introspection
Version: 1.72.0-1
Provides: gir1.2-gio-2.0 (= 1.72.0-1), gir1.2-girepository-2.0 (= 1.72.0-1), gir1.2-gmodule-2.0 (= 1.72.0-1), gir1.2-gobject-2.0 (= 1.72.0-1)
Depends: libgirepository-1.0-1 (>= 1.72.0), libglib2.0-0 (>= 2.71.2)
Description: Introspection data for GLib, GObject, Gio and GModule
GObject Introspection is a project for providing machine readable
introspection data of the API of C libraries. This introspection
data can be used in several different use cases, for example
automatic code generation for bindings, API verification and documentation
generation.
.
GObject Introspection contains tools to generate and handle the
introspection data.
.
This package contains the introspection data for the GLib, GObject,
GModule and Gio libraries.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/GObjectIntrospection

Package: gir1.2-packagekitglib-1.0
Status: install ok installed
Priority: optional
Section: introspection
Installed-Size: 123
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: packagekit
Version: 1.2.5-2ubuntu2
Depends: gir1.2-glib-2.0 (>= 1.36), libpackagekit-glib2-18 (>= 1.2.5)
Description: GObject introspection data for the PackageKit GLib library
PackageKit allows performing simple software management tasks over a DBus
interface e.g. refreshing the cache, updating, installing and removing
software packages or searching for multimedia codecs and file handlers.
.
This package contains introspection data for the PackageKit
GLib interface library.
.
It can be used by packages using the GIRepository format to generate
dynamic bindings.
Homepage: https://www.freedesktop.org/software/PackageKit/
Original-Maintainer: Matthias Klumpp <mak@debian.org>

Package: git
Status: install ok installed
Priority: optional
Section: vcs
Installed-Size: 18344
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1:2.34.1-1ubuntu1.4
Provides: git-completion, git-core
Depends: libc6 (>= 2.34), libcurl3-gnutls (>= 7.56.1), libexpat1 (>= 2.0.1), libpcre2-8-0 (>= 10.34), zlib1g (>= 1:1.2.0), perl, liberror-perl, git-man (>> 1:2.34.1), git-man (<< 1:2.34.1-.)
Recommends: ca-certificates, patch, less, ssh-client
Suggests: gettext-base, git-daemon-run | git-daemon-sysvinit, git-doc, git-email, git-gui, gitk, gitweb, git-cvs, git-mediawiki, git-svn
Breaks: bash-completion (<< 1:1.90-1), cogito (<= 0.18.2+), dgit (<< 5.1~), git-buildpackage (<< 0.6.5), git-el (<< 1:2.32.0~rc2-1~), gitosis (<< 0.2+20090917-7), gitpkg (<< 0.15), guilt (<< 0.33), openssh-client (<< 1:6.8), stgit (<< 0.15), stgit-contrib (<< 0.15)
Conffiles:
/etc/bash_completion.d/git-prompt 7baac5c3ced94ebf2c0e1dde65c3b1a6
Description: fast, scalable, distributed revision control system
Git is popular version control system designed to handle very large
projects with speed and efficiency; it is used for many high profile
open source projects, most notably the Linux kernel.
.
Git falls in the category of distributed source code management tools.
Every Git working directory is a full-fledged repository with full
revision tracking capabilities, not dependent on network access or a
central server.
.
This package provides the git main components with minimal dependencies.
Additional functionality, e.g. a graphical user interface and revision
tree visualizer, tools for interoperating with other VCS's, or a web
interface, is provided as separate git\* packages.
Homepage: https://git-scm.com/
Original-Maintainer: Jonathan Nieder <jrnieder@gmail.com>

Package: git-man
Status: install ok installed
Priority: optional
Section: doc
Installed-Size: 1957
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: git
Version: 1:2.34.1-1ubuntu1.4
Description: fast, scalable, distributed revision control system (manual pages)
Git is popular version control system designed to handle very large
projects with speed and efficiency; it is used for many high profile
open source projects, most notably the Linux kernel.
.
Git falls in the category of distributed source code management tools.
Every Git working directory is a full-fledged repository with full
revision tracking capabilities, not dependent on network access or a
central server.
.
This package provides reference documentation for use by the 'man'
utility and the 'git help' command.
Homepage: https://git-scm.com/
Original-Maintainer: Jonathan Nieder <jrnieder@gmail.com>

Package: gnupg
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 473
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg2 (<< 2.1.11-7+exp1)
Depends: dirmngr (<< 2.2.27-3ubuntu2.1.1~), dirmngr (>= 2.2.27-3ubuntu2.1), gnupg-l10n (= 2.2.27-3ubuntu2.1), gnupg-utils (<< 2.2.27-3ubuntu2.1.1~), gnupg-utils (>= 2.2.27-3ubuntu2.1), gpg (<< 2.2.27-3ubuntu2.1.1~), gpg (>= 2.2.27-3ubuntu2.1), gpg-agent (<< 2.2.27-3ubuntu2.1.1~), gpg-agent (>= 2.2.27-3ubuntu2.1), gpg-wks-client (<< 2.2.27-3ubuntu2.1.1~), gpg-wks-client (>= 2.2.27-3ubuntu2.1), gpg-wks-server (<< 2.2.27-3ubuntu2.1.1~), gpg-wks-server (>= 2.2.27-3ubuntu2.1), gpgsm (<< 2.2.27-3ubuntu2.1.1~), gpgsm (>= 2.2.27-3ubuntu2.1), gpgv (<< 2.2.27-3ubuntu2.1.1~), gpgv (>= 2.2.27-3ubuntu2.1)
Suggests: parcimonie, xloadimage
Breaks: debsig-verify (<< 0.15), dirmngr (<< 2.2.27-3ubuntu2.1), gnupg2 (<< 2.1.11-7+exp1), libgnupg-interface-perl (<< 0.52-3), libgnupg-perl (<= 0.19-1), libmail-gnupg-perl (<= 0.22-1), monkeysphere (<< 0.38~), php-crypt-gpg (<= 1.4.1-1), python-apt (<= 1.1.0~beta4), python-gnupg (<< 0.3.8-3), python3-apt (<= 1.1.0~beta4)
Description: GNU privacy guard - a free PGP replacement
GnuPG is GNU's tool for secure communication and data storage.
It can be used to encrypt data and to create digital signatures.
It includes an advanced key management facility and is compliant
with the proposed OpenPGP Internet standard as described in RFC4880.
.
This package contains the full suite of GnuPG tools for cryptographic
communications and data storage.
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gnupg-l10n
Status: install ok installed
Priority: optional
Section: localization
Installed-Size: 392
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg (<< 2.1.14-2~), gnupg2 (<< 2.1.14-2~)
Breaks: gnupg (<< 2.1.14-2~), gnupg2 (<< 2.1.14-2~)
Enhances: dirmngr, gpg, gpg-agent
Description: GNU privacy guard - localization files
GnuPG is GNU's tool for secure communication and data storage.
It can be used to encrypt data and to create digital signatures.
It includes an advanced key management facility and is compliant
with the proposed OpenPGP Internet standard as described in RFC 4880.
.
This package contains the translation files for the use of GnuPG in
non-English locales.
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gnupg-utils
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 787
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg (<< 2.1.21-4), gnupg-agent (<< 2.1.21-4)
Depends: libassuan0 (>= 2.5.0), libbz2-1.0, libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgpg-error0 (>= 1.42), libksba8 (>= 1.3.5), libreadline8 (>= 6.0), zlib1g (>= 1:1.1.4)
Recommends: gpg, gpg-agent, gpgconf, gpgsm
Breaks: gnupg (<< 2.1.21-4), gnupg-agent (<< 2.1.21-4)
Description: GNU privacy guard - utility programs
GnuPG is GNU's tool for secure communication and data storage.
.
This package contains several useful utilities for manipulating
OpenPGP data and other related cryptographic elements. It includes:
.

- addgnupghome -- create .gnupg home directories
- applygnupgdefaults -- run gpgconf --apply-defaults for all users
- gpgcompose -- an experimental tool for constructing arbitrary
  sequences of OpenPGP packets (e.g. for testing)
- gpgparsemail -- parse an e-mail message into annotated format
- gpgsplit -- split a sequence of OpenPGP packets into files
- gpgtar -- encrypt or sign files in an archive
- kbxutil -- list, export, import Keybox data
- lspgpot -- convert PGP ownertrust values to GnuPG
- migrate-pubring-from-classic-gpg -- use only "modern" formats
- symcryptrun -- use simple symmetric encryption tool in GnuPG framework
- watchgnupg -- watch socket-based logs
  Homepage: https://www.gnupg.org/
  Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gpg
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 1121
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg (<< 2.1.21-4)
Depends: gpgconf (= 2.2.27-3ubuntu2.1), libassuan0 (>= 2.5.0), libbz2-1.0, libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgpg-error0 (>= 1.42), libreadline8 (>= 6.0), libsqlite3-0 (>= 3.7.15), zlib1g (>= 1:1.1.4)
Recommends: gnupg (= 2.2.27-3ubuntu2.1)
Breaks: gnupg (<< 2.1.21-4)
Description: GNU Privacy Guard -- minimalist public key operations
GnuPG is GNU's tool for secure communication and data storage.
It can be used to encrypt data and to create digital signatures.
It includes an advanced key management facility and is compliant
with the proposed OpenPGP Internet standard as described in RFC4880.
.
This package contains /usr/bin/gpg itself, and is useful on its own
only for public key operations (encryption, signature verification,
listing OpenPGP certificates, etc). If you want full capabilities
(including secret key operations, network access, etc), please
install the "gnupg" package, which pulls in the full suite of tools.
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gpg-agent
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 595
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg-agent (<< 2.1.21-4)
Provides: gnupg-agent
Depends: gpgconf (= 2.2.27-3ubuntu2.1), pinentry-curses | pinentry, init-system-helpers (>= 1.52), libassuan0 (>= 2.5.1), libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgpg-error0 (>= 1.42), libnpth0 (>= 0.90)
Recommends: gnupg (= 2.2.27-3ubuntu2.1)
Suggests: dbus-user-session, libpam-systemd, pinentry-gnome3, scdaemon
Breaks: gnupg-agent (<< 2.1.21-4)
Conffiles:
/etc/X11/Xsession.d/90gpg-agent fbb9ce5e8e4ba5727090f0aa51b61a82
/etc/logcheck/ignore.d.server/gpg-agent 2d0fbc91a955ba69408ca033d7ae2455
Description: GNU privacy guard - cryptographic agent
GnuPG is GNU's tool for secure communication and data storage.
It can be used to encrypt data and to create digital signatures.
It includes an advanced key management facility and is compliant
with the proposed OpenPGP Internet standard as described in RFC4880.
.
This package contains the agent program gpg-agent which handles all
secret key material for OpenPGP and S/MIME use. The agent also
provides a passphrase cache, which is used by pre-2.1 versions of
GnuPG for OpenPGP operations. Without this package, trying to do
secret-key operations with any part of the modern GnuPG suite will
fail.
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gpg-wks-client
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 184
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Depends: dirmngr (= 2.2.27-3ubuntu2.1), gpg (= 2.2.27-3ubuntu2.1), gpg-agent (= 2.2.27-3ubuntu2.1), libassuan0 (>= 2.5.0), libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgpg-error0 (>= 1.42)
Recommends: gnupg (= 2.2.27-3ubuntu2.1)
Description: GNU privacy guard - Web Key Service client
GnuPG is GNU's tool for secure communication and data storage.
It can be used to encrypt data and to create digital signatures.
It includes an advanced key management facility and is compliant
with the proposed OpenPGP Internet standard as described in RFC4880.
.
This package provides the GnuPG client for the Web Key Service
protocol.
.
A Web Key Service is a service that allows users to upload keys per
mail to be verified over https as described in
https://tools.ietf.org/html/draft-koch-openpgp-webkey-service
.
For more information see: https://wiki.gnupg.org/WKS
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gpg-wks-server
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 168
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Depends: gpg (= 2.2.27-3ubuntu2.1), gpg-agent (= 2.2.27-3ubuntu2.1), libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgpg-error0 (>= 1.42)
Recommends: gnupg (= 2.2.27-3ubuntu2.1)
Description: GNU privacy guard - Web Key Service server
GnuPG is GNU's tool for secure communication and data storage.
It can be used to encrypt data and to create digital signatures.
It includes an advanced key management facility and is compliant
with the proposed OpenPGP Internet standard as described in RFC4880.
.
This package provides the GnuPG server for the Web Key Service
protocol.
.
A Web Key Service is a service that allows users to upload keys per
mail to be verified over https as described in
https://tools.ietf.org/html/draft-koch-openpgp-webkey-service
.
For more information see: https://wiki.gnupg.org/WKS
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gpgconf
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 280
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg (<< 2.1.21-4), gnupg-agent (<< 2.1.21-4)
Depends: libassuan0 (>= 2.5.0), libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgpg-error0 (>= 1.42), libreadline8 (>= 6.0)
Breaks: gnupg (<< 2.1.21-4), gnupg-agent (<< 2.1.21-4)
Description: GNU privacy guard - core configuration utilities
GnuPG is GNU's tool for secure communication and data storage.
.
This package contains core utilities used by different tools in the
suite offered by GnuPG. It can be used to programmatically edit
config files for tools in the GnuPG suite, to launch or terminate
per-user daemons (if installed), etc.
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gpgsm
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 480
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg2 (<< 2.1.10-2)
Depends: gpgconf (= 2.2.27-3ubuntu2.1), libassuan0 (>= 2.5.0), libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgpg-error0 (>= 1.42), libksba8 (>= 1.6.0), libreadline8 (>= 6.0)
Recommends: gnupg (= 2.2.27-3ubuntu2.1)
Breaks: gnupg2 (<< 2.1.10-2)
Description: GNU privacy guard - S/MIME version
GnuPG is GNU's tool for secure communication and data storage.
It can be used to encrypt data and to create digital signatures.
It includes an advanced key management facility and is compliant
with the proposed OpenPGP Internet standard as described in RFC4880.
.
This package contains the gpgsm program. gpgsm is a tool to provide
digital encryption and signing services on X.509 certificates and the
CMS protocol. gpgsm includes complete certificate management.
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: gpgv
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 324
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gnupg2
Version: 2.2.27-3ubuntu2.1
Replaces: gnupg2 (<< 2.0.21-2), gpgv2 (<< 2.1.11-7+exp1)
Depends: libbz2-1.0, libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgpg-error0 (>= 1.42), zlib1g (>= 1:1.1.4)
Suggests: gnupg
Breaks: gnupg2 (<< 2.0.21-2), gpgv2 (<< 2.1.11-7+exp1), python-debian (<< 0.1.29)
Description: GNU privacy guard - signature verification tool
GnuPG is GNU's tool for secure communication and data storage.
.
gpgv is actually a stripped-down version of gpg which is only able
to check signatures. It is somewhat smaller than the fully-blown gpg
and uses a different (and simpler) way to check that the public keys
used to make the signature are valid. There are no configuration
files and only a few options are implemented.
Homepage: https://www.gnupg.org/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: grep
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 496
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 3.7-1build1
Provides: rgrep
Depends: dpkg (>= 1.15.4) | install-info
Pre-Depends: libc6 (>= 2.34), libpcre3
Suggests: libpcre3 (>= 7.7)
Conflicts: rgrep
Description: GNU grep, egrep and fgrep
'grep' is a utility to search for text in files; it can be used from the
command line or in scripts. Even if you don't want to use it, other packages
on your system probably will.
.
The GNU family of grep utilities may be the "fastest grep in the west".
GNU grep is based on a fast lazy-state deterministic matcher (about
twice as fast as stock Unix egrep) hybridized with a Boyer-Moore-Gosper
search for a fixed string that eliminates impossible text from being
considered by the full regexp matcher without necessarily having to
look at every character. The result is typically many times faster
than Unix grep or egrep. (Regular expressions containing backreferencing
will run more slowly, however.)
Original-Maintainer: Anibal Monsalve Salazar <anibal@debian.org>
Homepage: https://www.gnu.org/software/grep/

Package: groff-base
Status: install ok installed
Priority: important
Section: text
Installed-Size: 3444
Maintainer: Colin Watson <cjwatson@debian.org>
Architecture: amd64
Multi-Arch: foreign
Source: groff
Version: 1.22.4-8build1
Depends: libc6 (>= 2.35), libgcc-s1 (>= 4.0), libstdc++6 (>= 4.1.1), libuchardet0 (>= 0.0.1)
Suggests: groff
Conffiles:
/etc/groff/man.local e6591616404c7c443f71ff21d27430d7
/etc/groff/mdoc.local 4bc6267468942826b757fa2f868c8237
Description: GNU troff text-formatting system (base system components)
This package contains the traditional UN\*X text formatting tools
troff, nroff, tbl, eqn, and pic. These utilities, together with the
man-db package, are essential for displaying the on-line manual pages.
.
groff-base is a stripped-down package containing the necessary components
to read manual pages in ASCII, Latin-1, and UTF-8, plus the PostScript
device (groff's default). Users who want a full groff installation, with
the standard set of devices, fonts, macros, and documentation, should
install the groff package.
Homepage: https://www.gnu.org/software/groff/

Package: gsettings-desktop-schemas
Status: install ok installed
Priority: optional
Section: gnome
Installed-Size: 308
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 42.0-1ubuntu1
Depends: dconf-gsettings-backend | gsettings-backend, session-migration
Breaks: gnome-control-center (<< 1:3.19.92), gnome-settings-daemon (<< 3.19.92), gnome-shell (<< 40), mutter (<< 3.31.4), nautilus (<< 3.7.92)
Description: GSettings desktop-wide schemas
gsettings-desktop-schemas contains a collection of GSettings schemas for
settings shared by various components of a desktop.
Homepage: https://www.gnome.org/
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: gtk-update-icon-cache
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 160
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gtk+3.0
Version: 3.24.33-1ubuntu2
Replaces: libgtk-3-bin (<< 3.20.6-1), libgtk2.0-bin (<< 2.24.30-2)
Depends: libc6 (>= 2.34), libgdk-pixbuf-2.0-0 (>= 2.40.0), libglib2.0-0 (>= 2.57.2)
Breaks: libgtk-3-bin (<< 3.20.6-1), libgtk2.0-bin (<< 2.24.30-2)
Description: icon theme caching utility
gtk-update-icon-cache creates mmap()able cache files for icon themes.
.
GTK can use the cache files created by gtk-update-icon-cache to avoid a lot
of system call and disk seek overhead when the application starts. Since the
format of the cache files allows them to be mmap()ed shared between multiple
applications, the overall memory consumption is reduced as well.
Homepage: https://www.gtk.org/
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: gyp
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 1165
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.1+20210831gitd6c5dd5-5
Depends: python3:any, python3-pkg-resources
Description: Cross-platform build script generator
GYP (Generate Your Projects) is a tool to generate native Visual Studio,
Xcode, SCons and make build files from a description of a project in a
simple JSON-inspired format. Its syntax is a universal cross-platform
build representation that still allows sufficient per-platform flexibility
to accommodate irreconcilable differences.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://chromium.googlesource.com/external/gyp/

Package: gzip
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 244
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.10-4ubuntu4
Depends: dpkg (>= 1.15.4) | install-info
Pre-Depends: libc6 (>= 2.34)
Suggests: less
Description: GNU compression utilities
This package provides the standard GNU file compression utilities, which
are also the default compression tools for Debian. They typically operate
on files with names ending in '.gz', but can also decompress files ending
in '.Z' created with 'compress'.
Homepage: https://www.gnu.org/software/gzip/
Original-Maintainer: Milan Kupcevic <milan@debian.org>

Package: hdparm
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 244
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 9.60+ds-1build3
Depends: libc6 (>= 2.34), lsb-base
Recommends: powermgmt-base
Conffiles:
/etc/hdparm.conf fe09abd1838cf3e012353933c5aa0dda
Description: tune hard disk parameters for high performance
Get/set device parameters for Linux SATA/IDE drives.
Provides a command line interface to various kernel interfaces supported by
the Linux SATA/PATA/SAS "libata" subsystem and the older IDE driver subsystem.
Many newer (2008 and later) USB drive enclosures now also support "SAT"
(SCSI-ATA Command Translation) and therefore may also work with hdparm.
Original-Maintainer: Alexandre Mestiashvili <mestia@debian.org>
Homepage: http://sourceforge.net/projects/hdparm/

Package: hicolor-icon-theme
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 440
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.17-2
Description: default fallback theme for FreeDesktop.org icon themes
This is the default fallback theme used by implementations of the
Freedesktop.org Icon Theme specification.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: hostname
Essential: yes
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 51
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 3.23ubuntu2
Replaces: nis (<< 3.17-30)
Pre-Depends: libc6 (>= 2.34)
Breaks: nis (<< 3.17-30)
Description: utility to set/show the host name or domain name
This package provides commands which can be used to display the system's
DNS name, and to display or set its hostname or NIS domain name.
Original-Maintainer: Michael Meskes <meskes@debian.org>

Package: htop
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 334
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 3.0.5-7build2
Depends: libc6 (>= 2.34), libncursesw6 (>= 6), libnl-3-200 (>= 3.2.7), libnl-genl-3-200 (>= 3.2.7), libtinfo6 (>= 6)
Suggests: lm-sensors, lsof, strace
Description: interactive processes viewer
Htop is an ncursed-based process viewer similar to top, but it
allows one to scroll the list vertically and horizontally to see
all processes and their full command lines.
.
Tasks related to processes (killing, renicing) can be done without
entering their PIDs.
Original-Maintainer: Daniel Lange <DLange@debian.org>
Homepage: https://htop.dev/

Package: humanity-icon-theme
Status: install ok installed
Priority: optional
Section: gnome
Installed-Size: 20660
Maintainer: Ubuntu MOTU Developers <ubuntu-motu@lists.ubuntu.com>
Architecture: all
Version: 0.6.16
Depends: adwaita-icon-theme, hicolor-icon-theme
Description: Humanity Icon theme
Humanity and Humanity Dark are nice and well polished icon themes for
the GNOME desktop.

Package: info
Status: install ok installed
Priority: important
Section: doc
Installed-Size: 849
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: texinfo
Version: 6.8-4build1
Replaces: texinfo (<< 4.7-2), texinfo-doc-nonfree
Provides: info-browser
Depends: libc6 (>= 2.34), libtinfo6 (>= 6), install-info
Breaks: texinfo-doc-nonfree
Description: Standalone GNU Info documentation browser
The Info file format is an easily-parsable representation for online
documents. This program allows you to view Info documents, like the
ones stored in /usr/share/info.
.
Much of the software in Debian comes with its online documentation in
the form of Info files, so it is most likely you will want to install it.
Original-Maintainer: Debian TeX maintainers <debian-tex-maint@lists.debian.org>
Homepage: https://www.gnu.org/software/texinfo/

Package: init
Status: install ok installed
Priority: important
Section: metapackages
Installed-Size: 22
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: init-system-helpers
Version: 1.62
Depends: init-system-helpers (>= 1.25)
Pre-Depends: systemd-sysv
Description: metapackage ensuring an init system is installed
This package is a metapackage which allows you to select from the available
init systems while ensuring that one of these is available on the system at
all times.
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>
Important: yes

Package: init-system-helpers
Essential: yes
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 133
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.62
Depends: perl-base (>= 5.20.1-3)
Conflicts: file-rc (<< 0.8.17~)
Description: helper tools for all init systems
This package contains helper tools that are necessary for switching between
the various init systems that Debian contains (e. g. sysvinit or
systemd). An example is deb-systemd-helper, a script that enables systemd unit
files without depending on a running systemd.
.
It also includes the "service", "invoke-rc.d", and "update-rc.d" scripts which
provide an abstraction for enabling, disabling, starting, and stopping
services for all supported Debian init systems as specified by the policy.
.
While this package is maintained by pkg-systemd-maintainers, it is NOT
specific to systemd at all. Maintainers of other init systems are welcome to
include their helpers in this package.
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: initramfs-tools
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 147
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.140ubuntu13
Provides: linux-initramfs-tool
Depends: initramfs-tools-core (= 0.140ubuntu13), linux-base
Suggests: bash-completion
Breaks: e2fsprogs (<< 1.42.13), initscripts (<< 2.88dsf-59.3~), netplan.io (<< 0.37), upstart
Conflicts: linux-initramfs-tool, usplash (<< 0.5.50)
Conffiles:
/etc/initramfs-tools/update-initramfs.conf e2026d4603e7161efaccca519aeb1297
/etc/kernel/postinst.d/initramfs-tools c1cb0e052a2cdeef4f3257585c83c58d
/etc/kernel/postrm.d/initramfs-tools e7471d253a5b24e2fd85b40be4e43218
Description: generic modular initramfs generator (automation)
This package builds a bootable initramfs for Linux kernel packages. The
initramfs is loaded along with the kernel and is responsible for
mounting the root filesystem and starting the main init system.
Original-Maintainer: Debian kernel team <debian-kernel@lists.debian.org>

Package: initramfs-tools-bin
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 135
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: initramfs-tools
Version: 0.140ubuntu13
Depends: libc6 (>= 2.34), libgcc-s1 (>= 3.0), libudev1 (>= 183)
Description: binaries used by initramfs-tools
This package contains binaries used inside the initramfs images generated
by initramfs-tools.
Original-Maintainer: Debian kernel team <debian-kernel@lists.debian.org>

Package: initramfs-tools-core
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 274
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: initramfs-tools
Version: 0.140ubuntu13
Replaces: initramfs-tools (<< 0.121~)
Depends: busybox-initramfs (>= 1:1.30.1-4ubuntu5~), initramfs-tools-bin (= 0.140ubuntu13), klibc-utils (>= 2.0.4-8~), cpio (>= 2.12), zstd, kmod, udev, coreutils (>= 8.24), logsave | e2fsprogs (<< 1.45.3-1~)
Suggests: bash-completion
Breaks: busybox-initramfs (<< 1:1.30.1-4ubuntu5~), initramfs-tools (<< 0.121~)
Conffiles:
/etc/initramfs-tools/initramfs.conf 928db4c3f5c9c61d79ce5ae9c2e1476a
Description: generic modular initramfs generator (core tools)
This package contains the mkinitramfs program that can be used to
create a bootable initramfs for a Linux kernel. The initramfs should
be loaded along with the kernel and is then responsible for mounting
the root filesystem and starting the main init system.
Original-Maintainer: Debian kernel team <debian-kernel@lists.debian.org>

Package: install-info
Status: install ok installed
Priority: important
Section: doc
Installed-Size: 257
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: texinfo
Version: 6.8-4build1
Replaces: texinfo (<< 4.13a.dfsg.1-2)
Depends: libc6 (>= 2.34)
Pre-Depends: dpkg (>= 1.16.1)
Breaks: texinfo (<< 4.13a.dfsg.1-2)
Description: Manage installed documentation in info format
The install-info utility creates the index of all installed documentation
in info format and makes it available to info readers.
Original-Maintainer: Debian TeX maintainers <debian-tex-maint@lists.debian.org>
Homepage: https://www.gnu.org/software/texinfo/

Package: iproute2
Status: install ok installed
Priority: important
Section: net
Installed-Size: 2880
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 5.15.0-1ubuntu2
Replaces: iproute
Provides: arpd
Depends: debconf (>= 0.5) | debconf-2.0, libbpf0 (>= 1:0.2), libbsd0 (>= 0.0), libc6 (>= 2.34), libcap2 (>= 1:2.10), libdb5.3, libelf1 (>= 0.131), libmnl0 (>= 1.0.3-4~), libselinux1 (>= 3.1~), libxtables12 (>= 1.6.0+snapshot20161117), libcap2-bin
Recommends: libatm1 (>= 2.4.1-17~)
Suggests: iproute2-doc
Conflicts: arpd, iproute (<< 20130000-1)
Conffiles:
/etc/iproute2/bpf_pinning fd070252e6e9996bd04d9d59e4ce21eb
/etc/iproute2/ematch_map 0e0f36cafc6a9cf76bc704cfd8f96ece
/etc/iproute2/group 3aea2c0e0dd75e13a5f8f48f2936915f
/etc/iproute2/nl_protos 393e42fa549d0974eb66d576675779c2
/etc/iproute2/rt_dsfield 4c80d267a84d350d89d88774efe48a0f
/etc/iproute2/rt_protos 35b7f1673d1d0486c4188fd06b46a410
/etc/iproute2/rt_protos.d/README 88e45597012c565f9a10ffef1bc14312
/etc/iproute2/rt_realms 7137bdf40e8d58c87ac7e3bba503767f
/etc/iproute2/rt_scopes 6298b8df09e9bda23ea7da49021ca457
/etc/iproute2/rt_tables a1313318d6778fe6b8c680248ef5a463
/etc/iproute2/rt_tables.d/README 18bfdabbd4d5b14eae350720ea5ff431
Description: networking and traffic control tools
The iproute2 suite is a collection of utilities for networking and
traffic control.
.
These tools communicate with the Linux kernel via the (rt)netlink
interface, providing advanced features not available through the
legacy net-tools commands 'ifconfig' and 'route'.
Homepage: https://wiki.linuxfoundation.org/networking/iproute2
Original-Maintainer: Alexander Wirt <formorer@debian.org>

Package: iptables
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 2837
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.8.7-1ubuntu5
Replaces: iptables-nftables-compat (<< 1.6.2~)
Depends: libip4tc2 (= 1.8.7-1ubuntu5), libip6tc2 (= 1.8.7-1ubuntu5), libxtables12 (= 1.8.7-1ubuntu5), netbase (>= 6.0), libc6 (>= 2.34), libmnl0 (>= 1.0.3-4~), libnetfilter-conntrack3 (>= 1.0.6), libnfnetlink0, libnftnl11 (>= 1.1.5)
Suggests: firewalld, kmod, nftables
Breaks: iptables-nftables-compat (<< 1.6.2~)
Description: administration tools for packet filtering and NAT
The iptables/xtables framework has been replaced by nftables. You should
consider migrating now.
.
iptables is the userspace command line program used to configure
the Linux packet filtering and NAT ruleset. It is targeted towards systems
and networks administrators.
.
This package contains several different utilities, the most important ones:
.
iptables-nft, iptables-nft-save, iptables-nft-restore (nft-based version)
.
iptables-legacy, iptables-legacy-save, iptables-legacy-restore (legacy version)
.
ip6tables-nft, ip6tables-nft-save, ip6tables-nft-restore (nft-based version)
.
ip6tables-legacy, ip6tables-legacy-save, ip6tables-legacy-restore (legacy version)
.
arptables-nft, arptables-nft-save, arptables-nft-restore (nft-based version)
.
ebtables-nft, ebtables-nft-save, ebtables-nft-restore (nft-based version)
Homepage: https://www.netfilter.org/
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>

Package: iputils-ping
Status: install ok installed
Priority: important
Section: net
Installed-Size: 113
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: iputils
Version: 3:20211215-1
Provides: ping
Depends: libcap2-bin, libc6 (>= 2.34), libcap2 (>= 1:2.10), libidn2-0 (>= 0.6)
Description: Tools to test the reachability of network hosts
The ping command sends ICMP ECHO_REQUEST packets to a host in order to
test if the host is reachable via the network.
.
This package includes a ping6 utility which supports IPv6 network
connections.
Original-Maintainer: Noah Meyerhans <noahm@debian.org>
Homepage: https://github.com/iputils/iputils/

Package: iputils-tracepath
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 52
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: iputils
Version: 3:20211215-1
Depends: libc6 (>= 2.34)
Suggests: traceroute
Description: Tools to trace the network path to a remote host
The tracepath utility is similar to the traceroute utility, but also
attempts to discover the MTU of the path. Supports IPv4 and IPv6.
Original-Maintainer: Noah Meyerhans <noahm@debian.org>
Homepage: https://github.com/iputils/iputils/

Package: irqbalance
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 148
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.8.0-1build1
Depends: libc6 (>= 2.34), libcap-ng0 (>= 0.7.9), libglib2.0-0 (>= 2.35.8), libncursesw6 (>= 6), libnuma1 (>= 2.0.11), libsystemd0, libtinfo6 (>= 6)
Pre-Depends: init-system-helpers (>= 1.54~)
Conffiles:
/etc/default/irqbalance 36e64b919c5778f81128d01a0cf29014
/etc/init.d/irqbalance fcb4a4d3f2770082bcbf0f3dc899b70c
Description: Daemon to balance interrupts for SMP systems
Daemon to balance interrupts across multiple CPUs, which can lead to better
performance and IO balance on SMP systems. This package is especially useful
on systems with multi-core processors, as interrupts will typically only be
serviced by the first core.
.
Note: irqbalance is not useful if you don't have more than one CPU core.
Homepage: https://github.com/Irqbalance/irqbalance
Original-Maintainer: Paride Legovini <paride@debian.org>

Package: isc-dhcp-client
Status: install ok installed
Priority: important
Section: net
Installed-Size: 672
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: isc-dhcp
Version: 4.4.1-2.3ubuntu2.2
Provides: dhcp-client
Depends: libc6 (>= 2.34), libdns-export1110, libisc-export1105, debianutils (>= 2.8.2), iproute2
Recommends: isc-dhcp-common
Suggests: resolvconf, avahi-autoipd, isc-dhcp-client-ddns
Conffiles:
/etc/apparmor.d/sbin.dhclient 4b18441217660d94d1edd6341e0775d1
/etc/dhcp/debug 521717b5f9e08db15893d3d062c59aeb
/etc/dhcp/dhclient-enter-hooks.d/resolved-enter 4ecfd14e38e7362cd6aeb3e438c2ec43
/etc/dhcp/dhclient-exit-hooks.d/resolved 12e194a7c3bdde03d4a444c05061b69e
/etc/dhcp/dhclient-exit-hooks.d/rfc3442-classless-routes 95e21c32fa7f603db75f1dc33db53cf5
/etc/dhcp/dhclient.conf c3b6c3271031ab8e250a192f4eb18695
Description: DHCP client for automatically obtaining an IP address
This is the Internet Software Consortium's DHCP client.
.
Dynamic Host Configuration Protocol (DHCP) is a protocol like BOOTP
(actually dhcpd includes much of the functionality of bootpd). It
gives client machines "leases" for IP addresses and can
automatically set their network configuration. If your machine
depends on DHCP (especially likely if it's a workstation on a large
network, or a laptop, or attached to a cable modem), keep this or
another DHCP client installed.
.
Extra documentation can be found in the package isc-dhcp-common.
Homepage: http://www.isc.org
Original-Maintainer: Debian ISC DHCP Maintainers <isc-dhcp@packages.debian.org>

Package: isc-dhcp-common
Status: install ok installed
Priority: important
Section: net
Installed-Size: 164
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: isc-dhcp
Version: 4.4.1-2.3ubuntu2.2
Depends: debianutils (>= 2.8.2)
Description: common manpages relevant to all of the isc-dhcp packages
This package includes manpages that are relevant to the various ISC DHCP
packages.
.
The dhcp-options manpage describes available options for dhcpd and dhclient.
The dhcp-eval manpage describes evaluation of conditional expressions.
Homepage: http://www.isc.org
Original-Maintainer: Debian ISC DHCP Maintainers <isc-dhcp@packages.debian.org>

Package: iso-codes
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 19769
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.9.0-1
Suggests: isoquery
Description: ISO language, territory, currency, script codes and their translations
This package provides the ISO 639, ISO 639-3, and ISO 639-5 language
code lists, the ISO 4217 currency code list, the ISO 3166 territory
code list, the ISO 3166-2 sub-territory list, and the ISO 15924
script code list as JSON files.
.
More importantly, it also provides their translations to be used by
other programs.
Original-Maintainer: Dr. Tobias Quathamer <toddy@debian.org>
Homepage: https://salsa.debian.org/iso-codes-team/iso-codes

Package: javascript-common
Status: install ok installed
Priority: optional
Section: web
Installed-Size: 33
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 11+nmu1
Suggests: apache2 (>= 2.4.6~) | lighttpd | httpd
Conffiles:
/etc/apache2/conf-available/javascript-common.conf 133aafb01e900b05e75042fd47dec067
/etc/lighttpd/conf-available/90-javascript-alias.conf 568434a47d89bb89ecf81c8f9c4e1669
Description: Base support for JavaScript library packages
Web applications that use JavaScript need to distribute it through HTTP. Using
a common path for every script avoids the need to enable this path in the HTTP
server for every package.
.
This is a helper package that creates /usr/share/javascript and enables it in
the Apache and Lighttpd webserver.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>

Package: kbd
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 1328
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2.3.0-3ubuntu4
Provides: console-utilities
Depends: libc6 (>= 2.34), console-setup | console-setup-mini
Conflicts: console-utilities
Description: Linux console font and keytable utilities
This package allows you to set up the Linux console, change the font,
resize text mode virtual consoles and remap the keyboard.
.
You will probably want to install a set of data files, such as the one
in the “console-setup” package.
Homepage: http://www.kbd-project.org/
Original-Maintainer: Console utilities maintainers <pkg-kbd-devel@lists.alioth.debian.org>

Package: keyboard-configuration
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 842
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: console-setup
Version: 1.205ubuntu3
Replaces: console-setup (<< 1.47), console-setup-mini (<< 1.47)
Depends: liblocale-gettext-perl
Pre-Depends: debconf (>= 1.5.34)
Breaks: console-setup (<< 1.71), console-setup-mini (<< 1.47)
Description: system-wide keyboard preferences
This package maintains the keyboard preferences in
/etc/default/keyboard. Other packages can use the information
provided by this package in order to configure the keyboard on the
console or in X Window.
Original-Maintainer: Debian Install System Team <debian-boot@lists.debian.org>

Package: klibc-utils
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 547
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: klibc
Version: 2.0.10-4
Depends: libklibc (= 2.0.10-4)
Breaks: initramfs-tools (<< 0.123~)
Description: small utilities built with klibc for early boot
This package contains a collection of programs that are linked
against klibc. These duplicate some of the functionality of a
regular Linux toolset, but are typically much smaller than their
full-function counterparts. They are intended for inclusion in
initramfs images and embedded systems.
Original-Maintainer: Debian Kernel Team <debian-kernel@lists.debian.org>
Homepage: https://git.kernel.org/cgit/libs/klibc/klibc.git

Package: kmod
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 251
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 29-1ubuntu1
Depends: libc6 (>= 2.34), liblzma5 (>= 5.1.1alpha+20120614), libssl3 (>= 3.0.0~~alpha1), libzstd1 (>= 1.4.0), libkmod2 (= 29-1ubuntu1), lsb-base
Conffiles:
/etc/depmod.d/ubuntu.conf 7c8439ef36b12e5f226b5dbfa20b8c2d
/etc/init.d/kmod 82698019c962069b438bd2a82d9fa1e7
/etc/modprobe.d/blacklist-ath_pci.conf d1da9bb08c2b0f56f3be93fd0e37946b
/etc/modprobe.d/blacklist-firewire.conf 9cc07a17e8e64f9cd35ff59c29debe69
/etc/modprobe.d/blacklist-framebuffer.conf 097e2142ae3e4dd2911eda7844ce0c18
/etc/modprobe.d/blacklist-rare-network.conf 8fb4b96124e461f53adceba9ca91f09a
/etc/modprobe.d/blacklist.conf 75f90164fe53985db48e7aa168bd5e7c
/etc/modprobe.d/iwlwifi.conf f27bc645e93e20c8e532325d190ac8ee
Description: tools for managing Linux kernel modules
This package contains a set of programs for loading, inserting, and
removing kernel modules for Linux.
It replaces module-init-tools.
Original-Maintainer: Marco d'Itri <md@linux.it>

Package: kpartx
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 95
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: multipath-tools
Version: 0.8.8-1ubuntu1
Depends: libc6 (>= 2.34), libdevmapper1.02.1 (>= 2:1.02.97), udev, dmsetup
Description: create device mappings for partitions
Kpartx can be used to set up device mappings for the partitions of any
partitioned block device.
.
It is part of the Linux multipath-tools, but is useful on any
device-mapper using system.
Homepage: http://christophe.varoqui.free.fr/
Original-Maintainer: Debian DM Multipath Team <team+linux-blocks@tracker.debian.org>

Package: landscape-common
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 402
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: landscape-client
Version: 19.12-0ubuntu13
Depends: python3:any, debconf (>= 0.5) | debconf-2.0, python3-twisted, python3-configobj, python3-apt, ca-certificates, python3-gdbm, python3-netifaces, lsb-release, lsb-base, adduser, bc, lshw, libpam-modules
Description: Landscape administration system client - Common files
Landscape is a web-based tool for managing Ubuntu systems. This
package is necessary if you want your machine to be managed in a
Landscape account.
.
This package provides the core libraries, as well as the landscape-sysinfo
command. It also sets up the landscape user, landscape directories, and the
hook that runs landscape-sysinfo on startup.
Homepage: https://github.com/CanonicalLtd/landscape-client
Original-Maintainer: Landscape Team <landscape-team@canonical.com>

Package: language-pack-en
Status: install ok installed
Priority: optional
Section: translations
Installed-Size: 9
Maintainer: Language pack maintainers <language-packs@ubuntu.com>
Architecture: all
Version: 1:22.04+20220721
Replaces: language-pack-en (<< 1:22.04+20220721), language-pack-en-base, language-pack-gnome-en (<< 1:22.04+20220721), language-pack-gnome-en-base (<< 1:22.04+20220721), language-pack-kde-en (<< 1:22.04+20220721), language-pack-kde-en-base (<< 1:22.04+20220721)
Depends: language-pack-en-base (>= 1:22.04+20220721)
Pre-Depends: dpkg (>= 1.16.1)
Description: translation updates for language English
Translation data updates for all supported packages for:
English
.
language-pack-en-base provides the bulk of translation data
and is updated only seldom. This package provides frequent translation
updates.

Package: language-pack-en-base
Status: install ok installed
Priority: optional
Section: translations
Installed-Size: 3749
Maintainer: Language pack maintainers <language-packs@ubuntu.com>
Architecture: all
Version: 1:22.04+20220721
Replaces: language-pack-en (<< 1:22.04+20220721), language-pack-en-base (<< 1:22.04+20220721), language-pack-gnome-en (<< 1:22.04+20220721), language-pack-gnome-en-base (<< 1:22.04+20220721), language-pack-kde-en (<< 1:22.04+20220721), language-pack-kde-en-base (<< 1:22.04+20220721)
Depends: locales (>= 2.3.6), language-pack-en (>= 1:22.04+20220721)
Pre-Depends: dpkg (>= 1.16.1)
Conflicts: language-pack-en (<< 1:22.04+20220721)
Description: translations for language English
Translation data for all supported packages for:
English
.
This package provides the bulk of translation data and is updated
only seldom. language-pack-en provides frequent
translation updates, so you should install this as well.

Package: less
Status: install ok installed
Priority: important
Section: text
Installed-Size: 321
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 590-1build1
Depends: libc6 (>= 2.34), libtinfo6 (>= 6)
Description: pager program similar to more
This package provides "less", a file pager (that is, a memory-efficient
utility for displaying text one screenful at a time). Less has many
more features than the basic pager "more". As part of the GNU project,
it is widely regarded as the standard pager on UNIX-derived systems.
.
Also provided are "lessecho", a simple utility for ensuring arguments
with spaces are correctly quoted; "lesskey", a tool for modifying the
standard (vi-like) keybindings; and "lesspipe", a filter for specific
types of input, such as .doc or .txt.gz files.
Homepage: http://www.greenwoodsoftware.com/less/
Original-Maintainer: Milan Kupcevic <milan@debian.org>

Package: libacl1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 67
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: acl
Version: 2.3.1-1
Depends: libc6 (>= 2.33)
Description: access control list - shared library
This package contains the shared library containing the POSIX 1003.1e
draft standard 17 functions for manipulating access control lists.
Original-Maintainer: Guillem Jover <guillem@debian.org>
Homepage: https://savannah.nongnu.org/projects/acl/

Package: libaio1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 37
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libaio
Version: 0.3.112-13build1
Depends: libc6 (>= 2.4)
Description: Linux kernel AIO access library - shared library
This library enables userspace to use Linux kernel asynchronous I/O
system calls, important for the performance of databases and other
advanced applications.
.
This package contains the shared library.
Homepage: https://pagure.io/libaio
Original-Maintainer: Guillem Jover <guillem@debian.org>

Package: libalgorithm-diff-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 127
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.201-1
Depends: perl:any
Recommends: libalgorithm-diff-xs-perl
Description: module to find differences between files
Algorithm::Diff is a Perl module that allows users to analyze text based on a
Longest Common Subsequence (LCS) algorithm. It can compare two files and find
the differences between them, which can produce the same information as the
common Unix tool 'diff'.
.
There is an XS-optimized implementation of the core loop, which accelerates
some types of diff output (see libalgorithm-diff-xs-perl).
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Algorithm-Diff

Package: libalgorithm-diff-xs-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 50
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.04-6build3
Depends: perl, perlapi-5.34.0, libc6 (>= 2.34), libalgorithm-diff-perl
Description: module to find differences between files (XS accelerated)
Algorithm::Diff::XS is a Perl diff utility module based on Joe Schaefer's
excellent but not very well-known Algorithm::LCS module, with a drop-in
interface identical to Algorithm::Diff.
.
Note that only the LCSidx function is optimized in XS at the moment, which
means only compact_diff will get significantly faster for large data sets,
while diff and sdiff will run in identical speed as Algorithm::Diff.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Algorithm-Diff-XS

Package: libalgorithm-merge-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 42
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.08-3
Depends: perl, libalgorithm-diff-perl
Description: Perl module for three-way merge of textual data
Algorithm::Merge provides three-way merge and diff functions, complementing
the functionality offered by Algorithm::Diff (libalgorithm-diff-perl). Given
three sets of items, known as the original, left and right, this module can
take a three-way difference or merge them. Taking a difference provides an
array reference that is very similar to the behaviour of Algorithm::Diff. One
can also implement custom conflict resolution using the CONFLICT callback.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Algorithm-Merge

Package: libapparmor1
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 170
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: apparmor
Version: 3.0.4-2ubuntu2.1
Replaces: libapparmor-perl (<< 3.0.3-3)
Depends: libc6 (>= 2.34)
Breaks: libapparmor-perl (<< 3.0.3-3)
Description: changehat AppArmor library
libapparmor1 provides a shared library one can compile programs
against in order to use various AppArmor functionality,
such as transitioning to a different AppArmor profile or hat.
Homepage: https://apparmor.net/
Original-Maintainer: Debian AppArmor Team <pkg-apparmor-team@lists.alioth.debian.org>

Package: libappstream4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 576
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: appstream
Version: 0.15.2-2
Depends: libc6 (>= 2.33), libcurl3-gnutls (>= 7.63.0), libglib2.0-0 (>= 2.67.3+git20210214), libstemmer0d (>= 0+svn527), libxml2 (>= 2.9.0), libxmlb2 (>= 0.3.4), libyaml-0-2
Description: Library to access AppStream services
AppStream is a metadata specification which permits software components to
provide information about themselves to automated systems and end-users
before the software is actually installed.
This permits informative displays of new applications to users in software
centers, as well as allowing a system to make decisions on which new software
a user might want to install (e.g. missing firmware or media handlers).
.
This package contains a GObject-based library to access AppStream
services, like the software component metadata pool.
It also contains functions for reading, writing and transforming AppStream
metadata.
Original-Maintainer: Matthias Klumpp <mak@debian.org>
Homepage: https://www.freedesktop.org/wiki/Distributions/AppStream/

Package: libapt-pkg6.0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 3177
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: apt
Version: 2.4.7
Provides: libapt-pkg (= 2.4.7)
Depends: libbz2-1.0, libc6 (>= 2.34), libgcc-s1 (>= 3.3.1), libgcrypt20 (>= 1.9.0), liblz4-1 (>= 0.0~r127), liblzma5 (>= 5.1.1alpha+20120614), libstdc++6 (>= 11), libsystemd0 (>= 221), libudev1 (>= 183), libxxhash0 (>= 0.7.1), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.2.2.3)
Recommends: apt (>= 2.4.7)
Breaks: appstream (<< 0.9.0-3~), apt (<< 1.6~), aptitude (<< 0.8.9), dpkg (<< 1.20.8), libapt-inst1.5 (<< 0.9.9~)
Description: package management runtime library
This library provides the common functionality for searching and
managing packages as well as information about packages.
Higher-level package managers can depend upon this library.
.
This includes:

- retrieval of information about packages from multiple sources
- retrieval of packages and all dependent packages
  needed to satisfy a request either through an internal
  solver or by interfacing with an external one
- authenticating the sources and validating the retrieved data
- installation and removal of packages in the system
- providing different transports to retrieve data over cdrom, ftp,
  http(s), rsh as well as an interface to add more transports like
  tor+http(s) (apt-transport-tor).
  Original-Maintainer: APT Development Team <deity@lists.debian.org>

Package: libarchive13
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 876
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libarchive
Version: 3.6.0-1ubuntu1
Depends: libacl1 (>= 2.2.23), libbz2-1.0, libc6 (>= 2.33), liblz4-1 (>= 0.0~r130), liblzma5 (>= 5.2.2), libnettle8, libxml2 (>= 2.7.4), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Suggests: lrzip
Description: Multi-format archive and compression library (shared library)
The libarchive library provides a flexible interface for reading and writing
archives in various formats such as tar and cpio. libarchive also supports
reading and writing archives compressed using various compression filters such
as gzip and bzip2. The library is inherently stream-oriented; readers serially
iterate through the archive, writers serially add things to the archive.
.
Archive formats supported are:
.
_ tar (read and write, including GNU extensions)
_ pax (read and write, including GNU and star extensions)
_ cpio (read and write, including odc and newc variants)
_ iso9660 (read and write, including Joliet and Rockridge extensions, with
some limitations)
_ zip (read only, with some limitations, uses zlib)
_ mtree (read and write)
_ shar (write only)
_ ar (read and write, including BSD and GNU/SysV variants)
_ empty (read only; in particular, note that no other format will accept an
empty file)
_ raw (read only)
_ xar (read only)
_ rar (read only, with some limitations)
_ 7zip (read and write, with some limitations)
.
Filters supported are:
.
_ gzip (read and write, uses zlib)
_ bzip2 (read and write, uses bzlib)
_ compress (read and write, uses an internal implementation)
_ uudecode (read only)
_ separate command-line compressors with fixed-signature auto-detection
_ xz and lzma (read and write using liblzma)
_ zstandard (read and write using libzstd)
.
This package provides the libarchive shared library.
Homepage: https://www.libarchive.org/
Original-Maintainer: Peter Pentchev <roam@debian.org>

Package: libargon2-1
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 56
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: argon2
Version: 0~20171227-0.3
Depends: libc6 (>= 2.34)
Description: memory-hard hashing function - runtime library
Argon2 is a password-hashing function that can be used to hash passwords
for credential storage, key derivation, or other applications.
.
There are two main versions of Argon2: Argon2i and Argon2d.
Argon2i is the safest against side-channel attacks, while Argon2d provides
the highest resistance against GPU cracking attacks.
.
Argon2i and Argon2d are parametrized by:

- A time cost, which defines the amount of computation realized and
  therefore the execution time, given in number of iterations
- A memory cost, which defines the memory usage, given in kibibytes
- A parallelism degree, which defines the number of parallel threads
  .
  This package includes the dynamic library against which programs are linked.
  Original-Maintainer: Luca Bruno <lucab@debian.org>
  Homepage: https://github.com/P-H-C/phc-winner-argon2

Package: libasan6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 7517
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-11
Version: 11.2.0-19ubuntu1
Depends: gcc-11-base (= 11.2.0-19ubuntu1), libc6 (>= 2.34), libgcc-s1
Description: AddressSanitizer -- a fast memory error detector
AddressSanitizer (ASan) is a fast memory error detector. It finds
use-after-free and {heap,stack,global}-buffer overflow bugs in C/C++ programs.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libassuan0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 110
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libassuan
Version: 2.5.5-1build1
Depends: libc6 (>= 2.33), libgpg-error0 (>= 1.33)
Description: IPC library for the GnuPG components
Libassuan is a small library implementing the so-called "Assuan
protocol". This protocol is used for IPC between most newer GnuPG
components. Both server and client side functions are provided.
Homepage: https://www.gnupg.org/related_software/libassuan/index.html
Original-Maintainer: Debian GnuPG-Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: libatasmart4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 82
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libatasmart
Version: 0.19-5build2
Depends: libc6 (>= 2.33), libudev1 (>= 183)
Description: ATA S.M.A.R.T. reading and parsing library
A small and lightweight parser library for ATA S.M.A.R.T. hard disk
health monitoring.
.
This package contains the shared library.
Homepage: http://0pointer.de/blog/projects/being-smart.html
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: libatk-bridge2.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 250
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: at-spi2-atk
Version: 2.38.0-3
Depends: libatk1.0-0 (>= 2.36.0~), libatspi2.0-0 (>= 2.9.90), libc6 (>= 2.7), libdbus-1-3 (>= 1.9.14), libglib2.0-0 (>= 2.41.1)
Description: AT-SPI 2 toolkit bridge - shared library
This package contains the ATK bridge shared library.
Original-Maintainer: Debian Accessibility Team <pkg-a11y-devel@alioth-lists.debian.net>
Homepage: https://wiki.gnome.org/Accessibility

Package: libatk1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 199
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: atk1.0
Version: 2.36.0-3build1
Depends: libc6 (>= 2.4), libglib2.0-0 (>= 2.55.2), libatk1.0-data (>= 2.36.0-3build1)
Description: ATK accessibility toolkit
ATK is a toolkit providing accessibility interfaces for applications or
other toolkits. By implementing these interfaces, those other toolkits or
applications can be used with tools such as screen readers, magnifiers, and
other alternative input devices.
.
This is the runtime part of ATK, needed to run applications built with it.
Original-Maintainer: Debian Accessibility Team <pkg-a11y-devel@alioth-lists.debian.net>
Homepage: https://wiki.gnome.org/Accessibility

Package: libatk1.0-data
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 44
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: atk1.0
Version: 2.36.0-3build1
Description: Common files for the ATK accessibility toolkit
ATK is a toolkit providing accessibility interfaces for applications or
other toolkits. By implementing these interfaces, those other toolkits or
applications can be used with tools such as screen readers, magnifiers, and
other alternative input devices.
.
This contains the common files which the runtime libraries need.
Original-Maintainer: Debian Accessibility Team <pkg-a11y-devel@alioth-lists.debian.net>
Homepage: https://wiki.gnome.org/Accessibility

Package: libatm1
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 110
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: linux-atm
Version: 1:2.5.1-4build2
Depends: libc6 (>= 2.34)
Description: shared library for ATM (Asynchronous Transfer Mode)
Shared libraries needed by ATM (Asynchronous Transfer Mode) related programs
Homepage: http://linux-atm.sourceforge.net/
Original-Maintainer: Debian QA Group <packages@qa.debian.org>

Package: libatomic1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 45
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.14)
Description: support library providing **atomic built-in functions
library providing **atomic built-in functions. When an atomic call cannot
be turned into lock-free instructions, GCC will make calls into this library.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libatspi2.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 255
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: at-spi2-core
Version: 2.44.0-3
Depends: libc6 (>= 2.7), libdbus-1-3 (>= 1.9.14), libglib2.0-0 (>= 2.62), libx11-6 (>= 2:1.2.99.901), libxi6 (>= 2:1.2.99.4)
Recommends: at-spi2-core (= 2.44.0-3)
Description: Assistive Technology Service Provider Interface - shared library
This package contains the shared library for applications that wish to use
the at-spi interface.
Original-Maintainer: Debian Accessibility Team <pkg-a11y-devel@alioth-lists.debian.net>
Homepage: https://wiki.gnome.org/Accessibility

Package: libattr1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 57
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: attr
Version: 1:2.5.1-1build1
Depends: libc6 (>= 2.4)
Conffiles:
/etc/xattr.conf 743ca3f83ea263f1f56ad1f63f907bdb
Description: extended attribute handling - shared library
Contains the runtime environment required by programs that make use
of extended attributes.
Original-Maintainer: Guillem Jover <guillem@debian.org>
Homepage: https://savannah.nongnu.org/projects/attr/

Package: libaudit-common
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 23
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: audit
Version: 1:3.0.7-1build1
Conffiles:
/etc/libaudit.conf cdc703f9d27f0d980271a9e95d0f18b2
Description: Dynamic library for security auditing - common files
The audit-libs package contains the dynamic libraries needed for
applications to use the audit framework. It is used to monitor systems for
security related events.
.
This package contains the libaudit.conf configuration file and the associated
manpage.
Original-Maintainer: Laurent Bigonville <bigon@debian.org>
Homepage: https://people.redhat.com/sgrubb/audit/

Package: libaudit1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 156
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: audit
Version: 1:3.0.7-1build1
Depends: libaudit-common (>= 1:3.0.7-1build1), libc6 (>= 2.33), libcap-ng0 (>= 0.7.9)
Description: Dynamic library for security auditing
The audit-libs package contains the dynamic libraries needed for
applications to use the audit framework. It is used to monitor systems for
security related events.
Original-Maintainer: Laurent Bigonville <bigon@debian.org>
Homepage: https://people.redhat.com/sgrubb/audit/

Package: libauthen-sasl-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 119
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.1600-1.1
Depends: perl:any
Suggests: libdigest-hmac-perl, libgssapi-perl
Description: Authen::SASL - SASL Authentication framework
SASL is a generic mechanism for authentication used by several network
protocols. Authen::SASL provides an implementation framework that all
protocols should be able to share.
.
The framework allows different implementations of the connection class
to be plugged in. At the time of writing there were two such plugins:

- Authen::SASL::Perl
  This module implements several mechanisms and is implemented
  entirely in Perl.
- Authen::SASL::Cyrus
  This module uses the Cyrus SASL C-library (both version 1 and 2 are
  supported).
  Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
  Homepage: https://metacpan.org/release/Authen-SASL

Package: libavahi-client3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 137
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: avahi
Version: 0.8-5ubuntu5
Depends: libavahi-common3 (= 0.8-5ubuntu5), libc6 (>= 2.34), libdbus-1-3 (>= 1.9.14)
Description: Avahi client library
Avahi is a fully LGPL framework for Multicast DNS Service Discovery.
It allows programs to publish and discover services and hosts
running on a local network with no specific configuration. For
example you can plug into a network and instantly find printers to
print to, files to look at and people to talk to.
.
This package contains the library for Avahi's C API which allows you
to integrate mDNS/DNS-SD functionality into your application.
Homepage: http://avahi.org/
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: libavahi-common-data
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 116
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: avahi
Version: 0.8-5ubuntu5
Description: Avahi common data files
Avahi is a fully LGPL framework for Multicast DNS Service Discovery.
It allows programs to publish and discover services and hosts
running on a local network with no specific configuration. For
example you can plug into a network and instantly find printers to
print to, files to look at and people to talk to.
.
This package contains common data files for avahi.
Homepage: http://avahi.org/
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: libavahi-common3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 114
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: avahi
Version: 0.8-5ubuntu5
Depends: libc6 (>= 2.34), libavahi-common-data (= 0.8-5ubuntu5)
Description: Avahi common library
Avahi is a fully LGPL framework for Multicast DNS Service Discovery.
It allows programs to publish and discover services and hosts
running on a local network with no specific configuration. For
example you can plug into a network and instantly find printers to
print to, files to look at and people to talk to.
.
This package contains the Avahi common library, which is a set of common
functions used by many of Avahis components and client applications.
Homepage: http://avahi.org/
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: libbinutils
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 2776
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: binutils
Version: 2.38-3ubuntu1
Replaces: binutils (<< 2.29-6)
Depends: libc6 (>= 2.34), zlib1g (>= 1:1.2.0), binutils-common (= 2.38-3ubuntu1)
Breaks: binutils (<< 2.29-6)
Description: GNU binary utilities (private shared library)
This package includes the private shared libraries libbfd and libopcodes.
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://www.gnu.org/software/binutils/

Package: libblkid1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 323
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: util-linux
Version: 2.37.2-4ubuntu3
Depends: libc6 (>= 2.33)
Description: block device ID library
The blkid library allows system programs such as fsck and mount to
quickly and easily find block devices by filesystem UUID or label.
This allows system administrators to avoid specifying filesystems by
hard-coded device names and use a logical naming system instead.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: libblockdev-crypto2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 71
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libblockdev
Version: 2.26-1
Depends: libblkid1 (>= 2.23.0), libblockdev-utils2 (>= 2.20), libc6 (>= 2.25), libcryptsetup12 (>= 2:2.0.3), libglib2.0-0 (>= 2.42.2), libnss3 (>= 2:3.13.4-2~), libvolume-key1 (>= 0.3.9)
Description: Crypto plugin for libblockdev
The libblockdev library plugin (and at the same time a standalone library)
providing the functionality related to encrypted devices (LUKS).
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://github.com/storaged-project/libblockdev

Package: libblockdev-fs2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 81
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libblockdev
Version: 2.26-1
Depends: libblkid1 (>= 2.24.2), libblockdev-part-err2 (>= 2.14), libblockdev-utils2 (>= 2.16), libc6 (>= 2.7), libglib2.0-0 (>= 2.42.2), libmount1 (>= 2.30.2), libparted-fs-resize0 (>= 3.1), libparted2 (>= 3.1), e2fsprogs
Description: file system plugin for libblockdev
The libblockdev library plugin (and at the same time a standalone library)
providing the functionality related to operations with file systems.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://github.com/storaged-project/libblockdev

Package: libblockdev-loop2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 34
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libblockdev
Version: 2.26-1
Depends: libblockdev-utils2 (>= 2.14), libc6 (>= 2.27), libglib2.0-0 (>= 2.42.2)
Description: Loop device plugin for libblockdev
The libblockdev library plugin (and at the same time a standalone library)
providing the functionality related to loop devices.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://github.com/storaged-project/libblockdev

Package: libblockdev-part-err2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 35
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libblockdev
Version: 2.26-1
Depends: libc6 (>= 2.3), libglib2.0-0 (>= 2.42.2)
Description: Partition error utility functions for libblockdev
libblockdev-part-err is a library providing utility functions used by the
libblockdev library and its plugins.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://github.com/storaged-project/libblockdev

Package: libblockdev-part2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 64
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libblockdev
Version: 2.26-1
Depends: libblockdev-part-err2 (>= 2.14), libblockdev-utils2 (>= 2.14), libc6 (>= 2.29), libglib2.0-0 (>= 2.42.2), libparted2 (>= 3.1), gdisk (>= 0.8.6), fdisk | util-linux (<< 2.29.2-3~)
Description: Partitioning plugin for libblockdev
The libblockdev library plugin (and at the same time a standalone library)
providing the functionality related to partitioning devices.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://github.com/storaged-project/libblockdev

Package: libblockdev-swap2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 43
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libblockdev
Version: 2.26-1
Depends: libblkid1 (>= 2.23.0), libblockdev-utils2 (>= 2.14), libc6 (>= 2.4), libglib2.0-0 (>= 2.42.2)
Description: Swap plugin for libblockdev
The libblockdev library plugin (and at the same time a standalone library)
providing the functionality related to swap devices.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://github.com/storaged-project/libblockdev

Package: libblockdev-utils2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 60
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libblockdev
Version: 2.26-1
Depends: libc6 (>= 2.7), libglib2.0-0 (>= 2.42.2), libkmod2 (>= 5~), libudev1 (>= 216)
Description: Utility functions for libblockdev
The libblockdev-utils is a library providing utility functions used by the
libblockdev library and its plugins.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://github.com/storaged-project/libblockdev

Package: libblockdev2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 224
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libblockdev
Version: 2.26-1
Depends: libblockdev-utils2 (>= 2.14), libc6 (>= 2.34), libglib2.0-0 (>= 2.42.2)
Conffiles:
/etc/libblockdev/conf.d/00-default.cfg 7a51eb0d581c2472e8738775147375a1
Description: Library for manipulating block devices
libblockdev is a C library with GObject introspection support that can be used
for doing low-level operations with block devices like setting up LVM, BTRFS,
LUKS or MD RAID.
.
The library uses plugins (LVM, BTRFS,...) and serves as a thin wrapper around
its plugins' functionality. All the plugins, however, can be used as
standalone libraries. One of the core principles of libblockdev is that it is
stateless from the storage configuration's perspective (e.g. it has no
information about VGs when creating an LV).
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://github.com/storaged-project/libblockdev

Package: libbpf0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 344
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libbpf (0.5.0-1)
Version: 1:0.5.0-1
Depends: libc6 (>= 2.22), libelf1 (>= 0.142), zlib1g (>= 1:1.2.3.3)
Description: eBPF helper library (shared library)
libbpf is a library for loading eBPF programs and reading and
manipulating eBPF objects from user-space.
.
This package contains the shared library.
Original-Maintainer: Sudip Mukherjee <sudipm.mukherjee@gmail.com>

Package: libbrotli1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 784
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: brotli
Version: 1.0.9-2build6
Depends: libc6 (>= 2.29)
Description: library implementing brotli encoder and decoder (shared libraries)
Brotli is a generic-purpose lossless compression algorithm
that compresses data using a combination of a modern variant
of the LZ77 algorithm, Huffman coding and 2nd order context modeling,
with a compression ratio comparable to the best currently available
general-purpose compression methods. It is similar in speed with
deflate but offers more dense compression.
.
This package installs shared libraries.
Original-Maintainer: Tomasz Buchert <tomasz@debian.org>
Homepage: https://github.com/google/brotli

Package: libbsd0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 136
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libbsd
Version: 0.11.5-1
Depends: libc6 (>= 2.33), libmd0 (>= 1.0.3-2)
Description: utility functions from BSD systems - shared library
This library provides some C functions such as strlcpy() that are commonly
available on BSD systems but not on others like GNU systems.
.
For a detailed list of the provided functions, please see the libbsd-dev
package description.
Original-Maintainer: Guillem Jover <guillem@debian.org>
Homepage: https://libbsd.freedesktop.org/

Package: libbz2-1.0
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 100
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: bzip2
Version: 1.0.8-5build1
Depends: libc6 (>= 2.4)
Description: high-quality block-sorting file compressor library - runtime
This package contains libbzip2 which is used by the bzip2 compressor.
.
bzip2 is a freely available, patent free, data compressor.
.
bzip2 compresses files using the Burrows-Wheeler block-sorting text
compression algorithm, and Huffman coding. Compression is generally
considerably better than that achieved by more conventional
LZ77/LZ78-based compressors, and approaches the performance of the PPM
family of statistical compressors.
.
The archive file format of bzip2 (.bz2) is incompatible with that of its
predecessor, bzip (.bz).
Original-Maintainer: Anibal Monsalve Salazar <anibal@debian.org>
Homepage: https://sourceware.org/bzip2/

Package: libc-ares2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 112
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: c-ares
Version: 1.18.1-1build1
Replaces: libc-ares1
Depends: libc6 (>= 2.17)
Conflicts: libcares2
Description: asynchronous name resolver
c-ares is a C library that performs DNS requests and name resolution
asynchronously.
.
It is a fork of the library named "ares", with additional features:

- IPv6 support;
- extended cross-platform portability;
- 64-bit clean sources.
  .
  This package provides the shared libraries.
  Original-Maintainer: Gregor Jasny <gjasny@googlemail.com>
  Homepage: https://c-ares.org/

Package: libc-bin
Essential: yes
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 2537
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: glibc
Version: 2.35-0ubuntu3.1
Depends: libc6 (>> 2.35), libc6 (<< 2.36)
Suggests: manpages
Conffiles:
/etc/bindresvport.blacklist 4c09213317e4e3dd3c71d74404e503c5
/etc/gai.conf 28fa76ff5a9e0566eaa1e11f1ce51f09
/etc/ld.so.conf 4317c6de8564b68d628c21efa96b37e4
/etc/ld.so.conf.d/libc.conf d4d833fd095fb7b90e1bb4a547f16de6
Description: GNU C Library: Binaries
This package contains utility programs related to the GNU C Library.
.

- getconf: query system configuration variables
- getent: get entries from administrative databases
- iconv, iconvconfig: convert between character encodings
- ldd, ldconfig: print/configure shared library dependencies
- locale, localedef: show/generate locale definitions
- tzselect, zdump, zic: select/dump/compile time zones
  Homepage: https://www.gnu.org/software/libc/libc.html
  Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
  Original-Vcs-Browser: https://salsa.debian.org/glibc-team/glibc
  Original-Vcs-Git: https://salsa.debian.org/glibc-team/glibc.git

Package: libc-dev-bin
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 298
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: glibc
Version: 2.35-0ubuntu3.1
Depends: libc6 (>> 2.35), libc6 (<< 2.36)
Recommends: manpages, manpages-dev, libc-devtools (>> 2.35)
Description: GNU C Library: Development binaries
This package contains utility programs related to the GNU C Library
development package.
.

- gencat: generate message catalogs
- rpcgen: compile RPC protocols to C
  Homepage: https://www.gnu.org/software/libc/libc.html
  Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
  Original-Vcs-Browser: https://salsa.debian.org/glibc-team/glibc
  Original-Vcs-Git: https://salsa.debian.org/glibc-team/glibc.git

Package: libc-devtools
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 350
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: glibc
Version: 2.35-0ubuntu3.1
Replaces: libc-dev-bin (<< 2.31-8)
Depends: libc6 (>= 2.34), libgd3 (>= 2.1.0~alpha~)
Recommends: manpages, manpages-dev
Breaks: libc-dev-bin (<< 2.31-8)
Description: GNU C Library: Development tools
This package contains development tools shipped by the GNU C
Library.
.

- memusage, memusagestat: profile a program's memory usage
- mtrace: interpret the malloc trace log
- sotruss: trace shared library calls
- sprof: display shared object profiling data
  Homepage: https://www.gnu.org/software/libc/libc.html
  Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
  Original-Vcs-Browser: https://salsa.debian.org/glibc-team/glibc
  Original-Vcs-Git: https://salsa.debian.org/glibc-team/glibc.git

Package: libc6
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 13592
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.35-0ubuntu3.1
Replaces: libc6-amd64
Depends: libgcc-s1, libcrypt1 (>= 1:4.4.10-10ubuntu4)
Recommends: libidn2-0 (>= 2.0.5~), libnss-nis, libnss-nisplus
Suggests: glibc-doc, debconf | debconf-2.0, locales
Breaks: busybox (<< 1.30.1-6), fakeroot (<< 1.25.3-1.1ubuntu2~), hurd (<< 1:0.9.git20170910-1), ioquake3 (<< 1.36+u20200211.f2c61c1~dfsg-2~), iraf-fitsutil (<< 2018.07.06-4), libgegl-0.4-0 (<< 0.4.18), libtirpc1 (<< 0.2.3), locales (<< 2.35), locales-all (<< 2.35), macs (<< 2.2.7.1-3~), nocache (<< 1.1-1~), nscd (<< 2.35), openarena (<< 0.8.8+dfsg-4~), openssh-server (<< 1:8.2p1-4), r-cran-later (<< 0.7.5+dfsg-2), wcc (<< 0.0.2+dfsg-3)
Conffiles:
/etc/ld.so.conf.d/x86_64-linux-gnu.conf d4e7a7b88a71b5ffd9e2644e71a0cfab
Description: GNU C Library: Shared libraries
Contains the standard libraries that are used by nearly all programs on
the system. This package includes shared versions of the standard C library
and the standard math library, as well as many others.
Homepage: https://www.gnu.org/software/libc/libc.html
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Original-Vcs-Browser: https://salsa.debian.org/glibc-team/glibc
Original-Vcs-Git: https://salsa.debian.org/glibc-team/glibc.git

Package: libc6-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 13037
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: glibc
Version: 2.35-0ubuntu3.1
Provides: libc-dev
Depends: libc6 (= 2.35-0ubuntu3.1), libc-dev-bin (= 2.35-0ubuntu3.1), linux-libc-dev, libcrypt-dev, rpcsvc-proto, libtirpc-dev, libnsl-dev
Suggests: glibc-doc, manpages-dev
Breaks: libc6-dev-amd64-cross (<< 2.35~), libgcc-10-dev (<< 10-20200321-1~), libgcc-7-dev (<< 7.5.0-6~), libgcc-8-dev (<< 8.4.0-2~), libgcc-9-dev (<< 9.3.0-5~), libperl5.26 (<< 5.26.1-3), python3.7 (<< 3.7.7-1+b1), python3.8 (<< 3.8.2-1+b1)
Conflicts: libc0.1-dev, libc0.3-dev, libc6.1-dev
Description: GNU C Library: Development Libraries and Header Files
Contains the symlinks, headers, and object files needed to compile
and link programs which use the standard C library.
Homepage: https://www.gnu.org/software/libc/libc.html
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Original-Vcs-Browser: https://salsa.debian.org/glibc-team/glibc
Original-Vcs-Git: https://salsa.debian.org/glibc-team/glibc.git

Package: libcairo-gobject2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 102
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: cairo
Version: 1.16.0-5ubuntu2
Depends: libcairo2 (= 1.16.0-5ubuntu2), libglib2.0-0 (>= 2.14.0)
Description: Cairo 2D vector graphics library (GObject library)
Cairo is a multi-platform library providing anti-aliased
vector-based rendering for multiple target backends.
.
This package contains the GObject library, providing wrapper GObject types
for all cairo types.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://cairographics.org/

Package: libcairo2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 1351
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: cairo
Version: 1.16.0-5ubuntu2
Depends: libc6 (>= 2.34), libfontconfig1 (>= 2.12.6), libfreetype6 (>= 2.9.1), libpixman-1-0 (>= 0.30.0), libpng16-16 (>= 1.6.2-1), libx11-6, libxcb-render0, libxcb-shm0, libxcb1 (>= 1.6), libxext6, libxrender1, zlib1g (>= 1:1.1.4)
Breaks: libwebkit2gtk-3.0-25 (<< 2.4.5-2~), libwebkitgtk-1.0-0 (<< 2.4.5-2~), libwebkitgtk-3.0-0 (<< 2.4.5-2~), weston (<< 1.5.0-3~)
Description: Cairo 2D vector graphics library
Cairo is a multi-platform library providing anti-aliased
vector-based rendering for multiple target backends. Paths consist
of line segments and cubic splines and can be rendered at any width
with various join and cap styles. All colors may be specified with
optional translucence (opacity/alpha) and combined using the
extended Porter/Duff compositing algebra as found in the X Render
Extension.
.
Cairo exports a stateful rendering API similar in spirit to the path
construction, text, and painting operators of PostScript, (with the
significant addition of translucence in the imaging model). When
complete, the API is intended to support the complete imaging model of
PDF 1.4.
.
This package contains the shared libraries.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://cairographics.org/

Package: libcap-ng0
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libcap-ng
Version: 0.7.9-2.2build3
Depends: libc6 (>= 2.33)
Description: An alternate POSIX capabilities library
This library implements the user-space interfaces to the POSIX
1003.1e capabilities available in Linux kernels. These capabilities are
a partitioning of the all powerful root privilege into a set of distinct
privileges.
.
The libcap-ng library is intended to make programming with POSIX
capabilities much easier than the traditional libcap library.
.
This package contains header files and libraries for libcap-ng.
Original-Maintainer: Pierre Chifflier <pollux@debian.org>
Homepage: http://people.redhat.com/sgrubb/libcap-ng

Package: libcap2
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 65
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 1:2.44-1build3
Depends: libc6 (>= 2.33)
Description: POSIX 1003.1e capabilities (library)
Libcap implements the user-space interfaces to the POSIX 1003.1e capabilities
available in Linux kernels. These capabilities are a partitioning of the all
powerful root privilege into a set of distinct privileges.
.
This package contains the shared library.
Homepage: https://sites.google.com/site/fullycapable/
Original-Maintainer: Christian Kastner <ckk@debian.org>

Package: libcap2-bin
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 115
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: libcap2
Version: 1:2.44-1build3
Replaces: libcap-bin
Depends: libc6 (>= 2.34), libcap2 (>= 1:2.33)
Recommends: libpam-cap
Breaks: libcap-bin
Description: POSIX 1003.1e capabilities (utilities)
Libcap implements the user-space interfaces to the POSIX 1003.1e capabilities
available in Linux kernels. These capabilities are a partitioning of the all
powerful root privilege into a set of distinct privileges.
.
This package contains additional utilities.
Homepage: https://sites.google.com/site/fullycapable/
Original-Maintainer: Christian Kastner <ckk@debian.org>

Package: libcbor0.8
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 83
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libcbor
Version: 0.8.0-2ubuntu1
Depends: libc6 (>= 2.14)
Description: library for parsing and generating CBOR (RFC 7049)
CBOR is a general-purpose schema-less binary data format, defined in
RFC 7049. This package provides a C library for parsing and generating
CBOR. The main features are:
.

- Complete RFC conformance
- Robust C99 implementation
- Layered architecture offers both control and convenience
- Flexible memory management
- No shared global state - threading friendly
- Proper handling of UTF-8
- Full support for streams & incremental processing
- Extensive documentation and test suite
- No runtime dependencies, small footprint
  .
  This package contains the runtime library.
  Homepage: https://github.com/PJK/libcbor
  Original-Maintainer: Vincent Bernat <bernat@debian.org>

Package: libcc1-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 144
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.15), libgcc-s1 (>= 3.0), libstdc++6 (>= 5.2)
Description: GCC cc1 plugin for GDB
libcc1 is a plugin for GDB.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libclone-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 43
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.45-1build3
Depends: perl, perlapi-5.34.0, libc6 (>= 2.34)
Description: module for recursively copying Perl datatypes
The Clone module provides a clone() method which makes recursive copies of
nested hash, array, scalar and reference types, including tied variables and
objects.
.
It is faster (although less flexible) than Storable's dclone. Its
functionality is _not_ serializing in-memory objects (i.e. as
Data::Dumper or YAML::Dump do), but deep-copying them over to new
in-memory structures.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Clone

Package: libcolord2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 616
Maintainer: Christopher James Halse Rogers <raof@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: colord
Version: 1.4.6-1
Depends: libc6 (>= 2.29), libglib2.0-0 (>= 2.58), liblcms2-2 (>= 2.6), libudev1 (>= 196)
Suggests: colord
Description: system service to manage device colour profiles -- runtime
colord is a system service that makes it easy to manage, install and generate
colour profiles to accurately colour manage input and output devices.
.
It provides a D-Bus API for system frameworks to query, a persistent data
store, and a mechanism for session applications to set system policy.
.
This package contains a gobject-based convenience library for programs to
interact with the colord system daemon.
Homepage: http://www.freedesktop.org/software/colord/

Package: libcom-err2
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 101
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: e2fsprogs
Version: 1.46.5-2ubuntu1.1
Replaces: libcomerr2 (<< 1.43.9-1~)
Provides: libcomerr2 (= 1.46.5-2ubuntu1.1)
Depends: libc6 (>= 2.17)
Breaks: libcomerr2 (<< 1.43.9-1~)
Description: common error description library
libcomerr is an attempt to present a common error-handling mechanism to
manipulate the most common form of error code in a fashion that does not
have the problems identified with mechanisms commonly in use.
Homepage: http://e2fsprogs.sourceforge.net
Original-Maintainer: Theodore Y. Ts'o <tytso@mit.edu>

Package: libcrypt-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 320
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcrypt
Version: 1:4.4.27-1
Replaces: libc6-dev (<< 2.29-4), libcrypt1-dev, libcrypt2-dev, manpages-dev (<< 5.01-1)
Provides: libcrypt1-dev
Depends: libcrypt1 (= 1:4.4.27-1)
Breaks: libc6-dev (<< 2.29-4), manpages-dev (<< 5.01-1)
Conflicts: libcrypt1-dev, libcrypt2-dev
Description: libcrypt development files
This package contains the files needed for developing applications that
use libcrypt.
Original-Maintainer: Marco d'Itri <md@linux.it>

Package: libcrypt1
Protected: yes
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 225
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcrypt
Version: 1:4.4.27-1
Replaces: libc6 (<< 2.29-4)
Depends: libc6 (>= 2.25)
Conflicts: libpam0g (<< 1.4.0-10)
Description: libcrypt shared library
libxcrypt is a modern library for one-way hashing of passwords.
It supports DES, MD5, NTHASH, SUNMD5, SHA-2-256, SHA-2-512, and
bcrypt-based password hashes
It provides the traditional Unix 'crypt' and 'crypt_r' interfaces,
as well as a set of extended interfaces like 'crypt_gensalt'.
Original-Maintainer: Marco d'Itri <md@linux.it>
Important: yes

Package: libcryptsetup12
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 572
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: cryptsetup
Version: 2:2.4.3-1ubuntu1.1
Depends: libargon2-1 (>= 0~20171227), libblkid1 (>= 2.17.2), libc6 (>= 2.34), libdevmapper1.02.1 (>= 2:1.02.97), libjson-c5 (>= 0.15), libssl3 (>= 3.0.0~~alpha1), libuuid1 (>= 2.16)
Description: disk encryption support - shared library
Cryptsetup provides an interface for configuring encryption on block
devices (such as /home or swap partitions), using the Linux kernel
device mapper target dm-crypt. It features integrated Linux Unified Key
Setup (LUKS) support.
.
This package provides the libcryptsetup shared library.
Homepage: https://gitlab.com/cryptsetup/cryptsetup
Original-Maintainer: Debian Cryptsetup Team <pkg-cryptsetup-devel@alioth-lists.debian.net>

Package: libctf-nobfd0
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 311
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: binutils
Version: 2.38-3ubuntu1
Replaces: libbinutils (<< 2.33.50.20191128-1~)
Depends: libc6 (>= 2.14), zlib1g (>= 1:1.2.0)
Breaks: libbinutils (<< 2.33.50.20191128-1~)
Description: Compact C Type Format library (runtime, no BFD dependency)
This package includes the libctf-nobfd shared library. The Compact C Type
Format (CTF) is a way of representing information about a binary program
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://www.gnu.org/software/binutils/

Package: libctf0
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 239
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: binutils
Version: 2.38-3ubuntu1
Depends: libbinutils (= 2.38-3ubuntu1), libc6 (>= 2.33), zlib1g (>= 1:1.2.0)
Description: Compact C Type Format library (runtime, BFD dependency)
This package includes the libctf-nobfd shared library. The Compact C Type
Format (CTF) is a way of representing information about a binary program
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://www.gnu.org/software/binutils/

Package: libcups2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 783
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: cups
Version: 2.4.1op1-1ubuntu4.1
Depends: libavahi-client3 (>= 0.6.16), libavahi-common3 (>= 0.6.16), libc6 (>= 2.34), libgnutls30 (>= 3.7.2), libgssapi-krb5-2 (>= 1.17), zlib1g (>= 1:1.2.0)
Suggests: cups-common
Description: Common UNIX Printing System(tm) - Core library
The Common UNIX Printing System (or CUPS(tm)) is a printing system and
general replacement for lpd and the like. It supports the Internet
Printing Protocol (IPP), and has its own filtering driver model for
handling various document types.
.
This package provides the base shared libraries for CUPS.
Homepage: https://github.com/OpenPrinting/cups/
Original-Maintainer: Debian Printing Team <debian-printing@lists.debian.org>

Package: libcurl3-gnutls
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 766
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: curl
Version: 7.81.0-1ubuntu1.4
Depends: libbrotli1 (>= 0.6.0), libc6 (>= 2.34), libgnutls30 (>= 3.7.2), libgssapi-krb5-2 (>= 1.17), libidn2-0 (>= 0.6), libldap-2.5-0 (>= 2.5.4), libnettle8, libnghttp2-14 (>= 1.12.0), libpsl5 (>= 0.16.0), librtmp1 (>= 2.4+20131018.git79459a2-3~), libssh-4 (>= 0.9.0), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Recommends: ca-certificates
Description: easy-to-use client-side URL transfer library (GnuTLS flavour)
libcurl is an easy-to-use client-side URL transfer library, supporting DICT,
FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S,
RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
.
libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP
form based upload, proxies, cookies, user+password authentication (Basic,
Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling
and more!
.
libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported,
fast, thoroughly documented and is already used by many known, big and
successful companies and numerous applications.
.
SSL support is provided by GnuTLS.
Homepage: https://curl.haxx.se
Original-Maintainer: Alessandro Ghedini <ghedo@debian.org>

Package: libcurl4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 782
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: curl
Version: 7.81.0-1ubuntu1.4
Replaces: libcurl3
Depends: libbrotli1 (>= 0.6.0), libc6 (>= 2.34), libgssapi-krb5-2 (>= 1.17), libidn2-0 (>= 0.6), libldap-2.5-0 (>= 2.5.4), libnghttp2-14 (>= 1.12.0), libpsl5 (>= 0.16.0), librtmp1 (>= 2.4+20131018.git79459a2-3~), libssh-4 (>= 0.9.0), libssl3 (>= 3.0.0~~alpha1), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Recommends: ca-certificates
Conflicts: libcurl3
Description: easy-to-use client-side URL transfer library (OpenSSL flavour)
libcurl is an easy-to-use client-side URL transfer library, supporting DICT,
FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S,
RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
.
libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP
form based upload, proxies, cookies, user+password authentication (Basic,
Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling
and more!
.
libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported,
fast, thoroughly documented and is already used by many known, big and
successful companies and numerous applications.
.
SSL support is provided by OpenSSL.
Homepage: https://curl.haxx.se
Original-Maintainer: Alessandro Ghedini <ghedo@debian.org>

Package: libdata-dump-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 64
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.25-1
Depends: perl:any
Description: Perl module to help dump data structures
Data::Dump provides a single function called dump that takes a list of values
as its argument and produces a string as its result. The string contains Perl
code that, when evaled, produces a deep copy of the original arguments. The
string is formatted for easy reading.
.
If called in void context, the dump is printed on standard error instead of
being returned. If you don't like importing a function that overrides Perl's
not-so-useful builtin, then you can also import the same function as "pp"
(the mnemonic for "pretty-print").
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Data-Dump

Package: libdatrie1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 63
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libdatrie
Version: 0.2.13-2
Depends: libc6 (>= 2.14)
Description: Double-array trie library
This package provides shared libraries needed to run programs that use the
datrie library. It is usually automatically installed.
Original-Maintainer: Theppitak Karoonboonyanan <thep@debian.org>
Homepage: https://linux.thai.net/projects/libthai

Package: libdb5.3
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 1750
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: db5.3
Version: 5.3.28+dfsg1-0.8ubuntu3
Depends: libc6 (>= 2.34)
Description: Berkeley v5.3 Database Libraries [runtime]
This is the runtime package for programs that use the v5.3 Berkeley
database library.
Homepage: http://www.oracle.com/technetwork/database/database-technologies/berkeleydb/overview/index.html
Original-Maintainer: Debian Berkeley DB Team <team+bdb@tracker.debian.org>

Package: libdbus-1-3
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 457
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: dbus
Version: 1.12.20-2ubuntu4
Depends: libc6 (>= 2.34), libsystemd0
Recommends: dbus
Breaks: dbus (<< 1.9.16-1~)
Description: simple interprocess messaging system (library)
D-Bus is a message bus, used for sending messages between applications.
Conceptually, it fits somewhere in between raw sockets and CORBA in
terms of complexity.
.
D-Bus supports broadcast messages, asynchronous messages (thus
decreasing latency), authentication, and more. It is designed to be
low-overhead; messages are sent using a binary protocol, not using
XML. D-Bus also supports a method call mapping for its messages, but
it is not required; this makes using the system quite simple.
.
It comes with several bindings, including GLib, Python, Qt and Java.
.
The daemon can be found in the dbus package.
Homepage: https://dbus.freedesktop.org/
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: libdconf1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 107
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: dconf
Version: 0.40.0-3
Depends: libc6 (>= 2.14), libglib2.0-0 (>= 2.55.2)
Description: simple configuration storage system - runtime library
DConf is a low-level key/value database designed for storing desktop
environment settings.
.
This package contains the runtime library.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Projects/dconf

Package: libdebconfclient0
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 79
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: cdebconf
Version: 0.261ubuntu1
Depends: libc6 (>= 2.4)
Description: Debian Configuration Management System (C-implementation library)
Debconf is a configuration management system for Debian packages. It is
used by some packages to prompt you for information before they are
installed. cdebconf is a reimplementation of the original debconf in C.
.
This library allows C programs to interface with cdebconf.
Original-Maintainer: Debian Install System Team <debian-boot@lists.debian.org>

Package: libdeflate0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 154
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libdeflate
Version: 1.10-2
Depends: libc6 (>= 2.14)
Description: fast, whole-buffer DEFLATE-based compression and decompression
The supported formats are:

- DEFLATE (raw)
- zlib (a.k.a. DEFLATE with a zlib wrapper)
- gzip (a.k.a. DEFLATE with a gzip wrapper)
  .
  libdeflate is heavily optimized. It is significantly faster than the zlib
  library, both for compression and decompression, and especially on x86
  processors. In addition, libdeflate provides optional high compression modes
  that provide a better compression ratio than the zlib's "level 9".
  Original-Maintainer: Debian Med Packaging Team <debian-med-packaging@lists.alioth.debian.org>
  Homepage: https://github.com/ebiggers/libdeflate

Package: libdevmapper-event1.02.1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 76
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: lvm2 (2.03.11-2.1ubuntu4)
Version: 2:1.02.175-2.1ubuntu4
Depends: libc6 (>= 2.33), libdevmapper1.02.1 (>= 2:1.02.97)
Description: Linux Kernel Device Mapper event support library
The Linux Kernel Device Mapper is the LVM (Linux Logical Volume Management)
Team's implementation of a minimalistic kernel-space driver that handles
volume management, while keeping knowledge of the underlying device layout
in user-space. This makes it useful for not only LVM, but software raid,
and other drivers that create "virtual" block devices.
.
This package contains the userspace library to help with event monitoring
for devmapper devices, in conjunction with the dmevent daemon.
Homepage: https://sourceware.org/lvm2/
Original-Maintainer: Debian LVM Team <team+lvm@tracker.debian.org>

Package: libdevmapper1.02.1
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 492
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: lvm2 (2.03.11-2.1ubuntu4)
Version: 2:1.02.175-2.1ubuntu4
Depends: libc6 (>= 2.33), libselinux1 (>= 3.1~), libudev1 (>= 183)
Recommends: dmsetup (>= 2:1.02.175-2.1ubuntu4~)
Description: Linux Kernel Device Mapper userspace library
The Linux Kernel Device Mapper is the LVM (Linux Logical Volume Management)
Team's implementation of a minimalistic kernel-space driver that handles
volume management, while keeping knowledge of the underlying device layout
in user-space. This makes it useful for not only LVM, but software raid,
and other drivers that create "virtual" block devices.
.
This package contains the (user-space) shared library for accessing the
device-mapper; it allows usage of the device-mapper through a clean,
consistent interface (as opposed to through kernel ioctls).
Homepage: https://sourceware.org/lvm2/
Original-Maintainer: Debian LVM Team <team+lvm@tracker.debian.org>

Package: libdns-export1110
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 2262
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: bind9-libs
Version: 1:9.11.19+dfsg-2.1ubuntu3
Depends: libc6 (>= 2.34), libisc-export1105, libssl3 (>= 3.0.0~~alpha1)
Description: Exported DNS Shared Library
The Berkeley Internet Name Domain (BIND) implements an Internet domain
name server. BIND is the most widely-used name server software on the
Internet, and is supported by the Internet Software Consortium, www.isc.org.
.
This package delivers the exported libdns shared library.
Homepage: https://www.isc.org/downloads/bind/
Original-Maintainer: Debian DNS Team <team+dns@tracker.debian.org>

Package: libdpkg-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 2340
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: dpkg
Version: 1.21.1ubuntu2.1
Depends: perl:any, dpkg (>= 1.18.11)
Recommends: libfile-fcntllock-perl, liblocale-gettext-perl, bzip2, xz-utils
Suggests: debian-keyring, gnupg, gpgv, gcc | c-compiler, binutils, patch, sensible-utils, git, bzr
Breaks: dgit (<< 3.13~), pkg-kde-tools (<< 0.15.28~)
Description: Dpkg perl modules
This package provides the perl modules used by the scripts
in dpkg-dev. They cover a wide range of functionality. Among them
there are the following public modules:
.

- Dpkg: core variables
- Dpkg::Arch: architecture handling functions
- Dpkg::Build::Info: build information functions
- Dpkg::BuildFlags: set, modify and query compilation build flags
- Dpkg::BuildOptions: parse and manipulate DEB_BUILD_OPTIONS
- Dpkg::BuildProfiles: parse and manipulate build profiles
- Dpkg::Changelog: parse changelogs
- Dpkg::Changelog::Entry: represents a changelog entry
- Dpkg::Changelog::Parse: generic changelog parser for dpkg-parsechangelog
- Dpkg::Checksums: generate and parse checksums
- Dpkg::Compression: simple database of available compression methods
- Dpkg::Compression::FileHandle: transparently (de)compress files
- Dpkg::Compression::Process: wrapper around compression tools
- Dpkg::Conf: parse dpkg configuration files
- Dpkg::Control: parse and manipulate Debian control information
  (.dsc, .changes, Packages/Sources entries, etc.)
- Dpkg::Control::Changelog: represent fields output by dpkg-parsechangelog
- Dpkg::Control::Fields: manage (list of known) control fields
- Dpkg::Control::Hash: parse and manipulate a block of RFC822-like fields
- Dpkg::Control::Info: parse files like debian/control
- Dpkg::Control::Tests: parse files like debian/tests/control
- Dpkg::Control::Tests::Entry: represents a debian/tests/control stanza
- Dpkg::Deps: parse and manipulate dependencies
- Dpkg::Deps::Simple: represents a single dependency statement
- Dpkg::Deps::Multiple: base module to represent multiple dependencies
- Dpkg::Deps::Union: list of unrelated dependencies
- Dpkg::Deps::AND: list of AND dependencies
- Dpkg::Deps::OR: list of OR dependencies
- Dpkg::Deps::KnownFacts: list of installed and virtual packages
- Dpkg::Exit: push, pop and run exit handlers
- Dpkg::Gettext: wrapper around Locale::gettext
- Dpkg::IPC: spawn sub-processes and feed/retrieve data
- Dpkg::Index: collections of Dpkg::Control (Packages/Sources files for
  example)
- Dpkg::Interface::Storable: base object serializer
- Dpkg::Path: common path handling functions
- Dpkg::Source::Format: manipulate debian/source/format files
- Dpkg::Source::Package: extract Debian source packages
- Dpkg::Substvars: substitute variables in strings
- Dpkg::Vendor: identify current distribution vendor
- Dpkg::Version: parse and manipulate Debian package versions
  .
  All the packages listed in Suggests or Recommends are used by some of the
  modules.
  Homepage: https://wiki.debian.org/Teams/Dpkg
  Original-Maintainer: Dpkg Developers <debian-dpkg@lists.debian.org>

Package: libdrm-amdgpu1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 84
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libdrm
Version: 2.4.110-1ubuntu1
Depends: libc6 (>= 2.28), libdrm2 (>= 2.4.108)
Description: Userspace interface to amdgpu-specific kernel DRM services -- runtime
This library implements the userspace interface to the kernel DRM
services. DRM stands for "Direct Rendering Manager", which is the
kernelspace portion of the "Direct Rendering Infrastructure" (DRI).
The DRI is currently used on Linux to provide hardware-accelerated
OpenGL drivers.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://cgit.freedesktop.org/mesa/drm/

Package: libdrm-common
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: libdrm
Version: 2.4.110-1ubuntu1
Description: Userspace interface to kernel DRM services -- common files
This library implements the userspace interface to the kernel DRM
services. DRM stands for "Direct Rendering Manager", which is the
kernelspace portion of the "Direct Rendering Infrastructure" (DRI).
The DRI is currently used on Linux to provide hardware-accelerated
OpenGL drivers.
.
This package provides common files for libdrm.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://cgit.freedesktop.org/mesa/drm/

Package: libdrm-intel1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 190
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libdrm
Version: 2.4.110-1ubuntu1
Depends: libc6 (>= 2.17), libdrm2 (>= 2.4.108), libpciaccess0
Description: Userspace interface to intel-specific kernel DRM services -- runtime
This library implements the userspace interface to the kernel DRM
services. DRM stands for "Direct Rendering Manager", which is the
kernelspace portion of the "Direct Rendering Infrastructure" (DRI).
The DRI is currently used on Linux to provide hardware-accelerated
OpenGL drivers.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://cgit.freedesktop.org/mesa/drm/

Package: libdrm-nouveau2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 82
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libdrm
Version: 2.4.110-1ubuntu1
Depends: libc6 (>= 2.14), libdrm2 (>= 2.4.108)
Description: Userspace interface to nouveau-specific kernel DRM services -- runtime
This library implements the userspace interface to the kernel DRM
services. DRM stands for "Direct Rendering Manager", which is the
kernelspace portion of the "Direct Rendering Infrastructure" (DRI).
The DRI is currently used on Linux to provide hardware-accelerated
OpenGL drivers.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://cgit.freedesktop.org/mesa/drm/

Package: libdrm-radeon1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 95
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libdrm
Version: 2.4.110-1ubuntu1
Depends: libc6 (>= 2.4), libdrm2 (>= 2.4.108)
Description: Userspace interface to radeon-specific kernel DRM services -- runtime
This library implements the userspace interface to the kernel DRM
services. DRM stands for "Direct Rendering Manager", which is the
kernelspace portion of the "Direct Rendering Infrastructure" (DRI).
The DRI is currently used on Linux to provide hardware-accelerated
OpenGL drivers.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://cgit.freedesktop.org/mesa/drm/

Package: libdrm2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 128
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libdrm
Version: 2.4.110-1ubuntu1
Depends: libdrm-common (>= 2.4.110-1ubuntu1), libc6 (>= 2.33)
Description: Userspace interface to kernel DRM services -- runtime
This library implements the userspace interface to the kernel DRM
services. DRM stands for "Direct Rendering Manager", which is the
kernelspace portion of the "Direct Rendering Infrastructure" (DRI).
The DRI is currently used on Linux to provide hardware-accelerated
OpenGL drivers.
.
This package provides the runtime environment for libdrm.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://cgit.freedesktop.org/mesa/drm/

Package: libdw1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 729
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: elfutils
Version: 0.186-1build1
Depends: libbz2-1.0, libc6 (>= 2.34), libelf1 (= 0.186-1build1), liblzma5 (>= 5.1.1alpha+20120614), zlib1g (>= 1:1.2.2.3)
Description: library that provides access to the DWARF debug information
libdw1 provides a library that provides access to DWARF debug information
stored inside ELF files.
.
This library is part of elfutils.
Original-Maintainer: Debian Elfutils Maintainers <debian-gcc@lists.debian.org>
Homepage: https://sourceware.org/elfutils/

Package: libeatmydata1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 39
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libeatmydata
Version: 130-2build1
Replaces: eatmydata (<< 82-1)
Depends: libc6 (>= 2.34)
Breaks: eatmydata (<< 82-1)
Description: Library and utilities to disable fsync and friends - shared library
This package contains the actual LD_PRELOAD library (libeatmydata) supporting
the operation of the eatmydata package. Users typically want to use or depend
on the eatmydata package instead of this one, so see its description for
further information.
Homepage: https://www.flamingspork.com/projects/libeatmydata/
Original-Maintainer: Mattia Rizzolo <mattia@debian.org>

Package: libedit2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 260
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libedit
Version: 3.1-20210910-1build1
Replaces: libedit-dev (<< 3.1-20180525-2~)
Depends: libbsd0 (>= 0.1.3), libc6 (>= 2.33), libtinfo6 (>= 6)
Description: BSD editline and history libraries
Command line editor library provides generic line editing,
history, and tokenization functions.
.
It slightly resembles GNU readline.
Homepage: https://www.thrysoee.dk/editline/
Original-Maintainer: LLVM Packaging Team <pkg-llvm-team@lists.alioth.debian.org>

Package: libefiboot1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 123
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: efivar
Version: 37-6ubuntu2
Depends: libc6 (>= 2.33), libefivar1 (>= 37)
Breaks: efibootmgr (<< 0.12-2)
Description: Library to manage UEFI variables
Library to allow for the manipulation of UEFI variables related to booting.
Original-Maintainer: Debian UEFI Maintainers <debian-efi@lists.debian.org>
Homepage: https://github.com/rhinstaller/efivar

Package: libefivar1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 171
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: efivar
Version: 37-6ubuntu2
Depends: libc6 (>= 2.34)
Breaks: efibootmgr (<< 0.12-2)
Description: Library to manage UEFI variables
Library to allow for the simple manipulation of UEFI variables.
Original-Maintainer: Debian UEFI Maintainers <debian-efi@lists.debian.org>
Homepage: https://github.com/rhinstaller/efivar

Package: libelf1
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 192
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: elfutils
Version: 0.186-1build1
Depends: libc6 (>= 2.33), zlib1g (>= 1:1.1.4)
Description: library to read and write ELF files
The libelf1 package provides a shared library which allows reading and
writing ELF files on a high level. Third party programs depend on
this package to read internals of ELF files. The programs of the
elfutils package use it also to generate new ELF files.
.
This library is part of elfutils.
Original-Maintainer: Debian Elfutils Maintainers <debian-gcc@lists.debian.org>
Homepage: https://sourceware.org/elfutils/

Package: libencode-locale-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 32
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.05-1.1
Depends: perl:any
Description: utility to determine the locale encoding
In many applications it's wise to let Perl use Unicode for the strings it
processes. Most of the interfaces Perl has to the outside world are still byte
based. Programs therefore need to decode byte strings that enter the program
from the outside and encode them again on the way out.
.
The POSIX locale system is used to specify both the language conventions
requested by the user and the preferred character set to consume and output.
The Encode::Locale module looks up the charset and encoding (called a CODESET
in the locale jargon) and arranges for the Encode module to know this encoding
under the name "locale". It means bytes obtained from the environment can be
converted to Unicode strings by calling Encode::encode(locale => $bytes) and
converted back again with Encode::decode(locale => $string).
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Encode-Locale

Package: libepoxy0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 1380
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libepoxy
Version: 1.5.10-1
Depends: libc6 (>= 2.34)
Description: OpenGL function pointer management library
It hides the complexity of dlopen(), dlsym(), glXGetProcAddress(),
eglGetProcAddress(), etc. from the app developer, with very little
knowledge needed on their part. They get to read GL specs and write
code using undecorated function names like glCompileShader().
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://github.com/anholt/libepoxy

Package: liberror-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 71
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.17029-1
Depends: perl:any
Description: Perl module for error/exception handling in an OO-ish way
The Error module provides two interfaces. Firstly "Error" provides a
procedural interface to exception handling. Secondly "Error" is a base class
for errors/exceptions that can either be thrown, for subsequent catch, or can
simply be recorded.
.
Errors in the class "Error" should not be thrown directly, but the user
should throw errors from a sub-class of "Error".
.
Warning: Using the "Error" module is no longer recommended due to the
black-magical nature of its syntactic sugar, which often tends to break. Its
maintainers have stopped actively writing code that uses it, and discourage
people from doing so.
.
Recommended alternatives are Exception::Class (libexception-class-perl),
Error::Exception (not packaged), TryCatch (libtrycatch-perl), and Try::Tiny
(libtry-tiny-perl).
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Error

Package: libestr0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libestr
Version: 0.1.10-2.1build3
Depends: libc6 (>= 2.14)
Description: Helper functions for handling strings (lib)
The 'libestr' library contains some essential string manipulation
functions and more, like escaping special characters.
.
This package contains the shared library.
Homepage: http://libestr.sourceforge.net/
Original-Maintainer: Pierre Chifflier <pollux@debian.org>

Package: libevent-core-2.1-7
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 256
Maintainer: Balint Reczey <rbalint@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libevent
Version: 2.1.12-stable-1build3
Depends: libc6 (>= 2.33)
Description: Asynchronous event notification library (core)
Libevent is an asynchronous event notification library that provides a
mechanism to execute a callback function when a specific event occurs
on a file descriptor or after a timeout has been reached.
.
It is meant to replace the asynchronous event loop found in
event driven network servers. Currently, libevent supports /dev/poll,
kqueue(2), event ports, select(2), poll(2) and epoll(4).
.
The libevent_core library includes event loops, timers, buffer code,
and various small compatibility functions.
.
If you're writing software that only uses libevent's event loop, you
should link against only the libevent_core library.
Homepage: https://libevent.org/

Package: libexpat1
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 432
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: expat
Version: 2.4.7-1
Depends: libc6 (>= 2.25)
Description: XML parsing C library - runtime library
This package contains the runtime, shared library of expat, the C
library for parsing XML. Expat is a stream-oriented parser in
which an application registers handlers for things the parser
might find in the XML document (like start tags).
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>
Homepage: https://libexpat.github.io/

Package: libext2fs2
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 574
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: e2fsprogs
Version: 1.46.5-2ubuntu1.1
Replaces: e2fslibs (<< 1.43.9-1~)
Provides: e2fslibs (= 1.46.5-2ubuntu1.1)
Depends: libc6 (>= 2.34)
Breaks: e2fslibs (<< 1.43.9-1~)
Description: ext2/ext3/ext4 file system libraries
The ext2, ext3 and ext4 file systems are successors of the original ext
("extended") file system. They are the main file system types used for
hard disks on Debian and other Linux systems.
.
This package provides the ext2fs and e2p libraries, for userspace software
that directly accesses extended file systems. Programs that use libext2fs
include e2fsck, mke2fs, and tune2fs. Programs that use libe2p include
dumpe2fs, chattr, and lsattr.
Homepage: http://e2fsprogs.sourceforge.net
Original-Maintainer: Theodore Y. Ts'o <tytso@mit.edu>

Package: libfakeroot
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 172
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: fakeroot
Version: 1.28-1ubuntu1
Replaces: fakeroot (<< 1.20-2~)
Depends: libc6 (>= 2.34)
Breaks: fakeroot (<< 1.20-2~)
Conffiles:
/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf f9f2331782e9078d5472c77e1d9cd869
Description: tool for simulating superuser privileges - shared libraries
fakeroot provides a fake "root environment" by means of LD_PRELOAD and
SysV IPC (or TCP) trickery. It puts wrappers around getuid(), chown(),
stat(), and other file-manipulation functions, so that unprivileged
users can (for instance) populate .deb archives with root-owned files;
various build tools use fakeroot for this by default.
.
This package contains the LD_PRELOAD libraries.
Original-Maintainer: Clint Adams <clint@debian.org>

Package: libfastjson4
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libfastjson
Version: 0.99.9-1build2
Depends: libc6 (>= 2.14)
Description: fast json library for C
The libfastjson library is a fork from json-c with a focus on performance.
.
This package contains the shared library.
Homepage: https://github.com/rsyslog/libfastjson
Original-Maintainer: Michael Biebl <biebl@debian.org>

Package: libfdisk1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 433
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: util-linux
Version: 2.37.2-4ubuntu3
Depends: libblkid1 (>= 2.24.2), libc6 (>= 2.33), libuuid1 (>= 2.16)
Description: fdisk partitioning library
The libfdisk library is used for manipulating partition tables. It is
the core of the fdisk, cfdisk, and sfdisk tools.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: libffi8
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libffi
Version: 3.4.2-4
Replaces: libffi8ubuntu1 (<< 3.4.2-1)
Provides: libffi8ubuntu1 (= 3.4.2-4)
Depends: libc6 (>= 2.27)
Breaks: libffi8ubuntu1 (<< 3.4.2-1)
Description: Foreign Function Interface library runtime
A foreign function interface is the popular name for the interface that
allows code written in one language to call code written in another
language.
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>
Homepage: https://sourceware.org/libffi/

Package: libfido2-1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 236
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libfido2
Version: 1.10.0-1
Depends: libc6 (>= 2.33), libcbor0.8 (>= 0.5.0), libssl3 (>= 3.0.0~~alpha1), libudev1 (>= 183), zlib1g (>= 1:1.2.0)
Description: library for generating and verifying FIDO 2.0 objects
A library for communicating with a FIDO device over USB, and for verifying
attestation and assertion signatures. FIDO U2F (CTAP 1) and FIDO 2.0 (CTAP 2)
are supported.
.
This package contains the library.
Original-Maintainer: Debian Authentication Maintainers <pkg-auth-maintainers@lists.alioth.debian.org>
Homepage: https://developers.yubico.com/libfido2/

Package: libfile-basedir-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 39
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.09-1
Depends: perl:any, libipc-system-simple-perl
Description: Perl module to use the freedesktop basedir specification
The File::BaseDir module can be used to find directories and files as
specified by the XDG Base Directory Specification. It takes care of
defaults and uses File::Spec to make the output platform specific.
.
For this module the XDG basedir specification 0.6 was used.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/File-BaseDir

Package: libfile-desktopentry-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 47
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.22-2
Depends: perl:any, libfile-basedir-perl, liburi-perl
Recommends: x-terminal-emulator
Description: Perl module to handle freedesktop .desktop files
File::DesktopEntry is used to work with .desktop files. The
format of these files is specified by the freedesktop "Desktop
Entry" specification. For this module version 1.0 of the
specification was used:
.
<http://standards.freedesktop.org/desktop-entry-spec/desktop-entry-spec-1.0.html>
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/File-DesktopEntry

Package: libfile-fcntllock-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 131
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.22-3build7
Depends: perl, perlapi-5.34.0, libc6 (>= 2.34)
Suggests: gcc | c-compiler
Description: Perl module for file locking with fcntl(2)
File::FcntlLock is a Perl module to do file locking in an object oriented
fashion using the fcntl(2) system call. This allows locks on parts of a file
as well as on the whole file and overcomes some known problems with flock(2),
on which Perl's flock() function is based.
.
Furthermore due to its design it supports reliable locking over NFS.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/File-FcntlLock

Package: libfile-listing-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.14-1
Depends: perl:any, libhttp-date-perl
Description: module to parse directory listings
File::Listing exports a single function called parse_dir(), which can be used
to parse directory listings.
.
The first parameter to parse_dir() is the directory listing to parse. It can
be a scalar, a reference to an array of directory lines or a glob
representing a filehandle to read the directory listing from.
.
The second parameter is the time zone to use when parsing time stamps in the
listing. If this value is undefined, then the local time zone is assumed.
.
The third parameter is the type of listing to assume. Currently supported
formats are 'unix', 'apache' and 'dosftp'. The default value 'unix'.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/File-Listing

Package: libfile-mimeinfo-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 112
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.31-1
Depends: perl:any, libencode-locale-perl, libfile-basedir-perl, libfile-desktopentry-perl, shared-mime-info
Recommends: libio-stringy-perl
Description: Perl module to determine file types
File::MimeInfo can be used to determine the mime type of a file. It tries to
implement the freedesktop specification for a shared MIME database.
.
This package also contains two related utilities:

- mimetype: determine a file's mimetype
- mimeopen: open files according to their mimetype
  Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
  Homepage: https://metacpan.org/release/File-MimeInfo

Package: libflashrom1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 869
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: flashrom
Version: 1.2-5build1
Depends: libc6 (>= 2.33), libftdi1-2 (>= 1.2), libpci3 (>= 1:3.5.1), libusb-1.0-0 (>= 2:1.0.22)
Description: Identify, read, write, erase, and verify BIOS/ROM/flash chips - library
flashrom is a tool for identifying, reading, writing, verifying and erasing
flash chips. It's often used to flash BIOS/EFI/coreboot/firmware/optionROM
images in-system using a supported mainboard, but it also supports flashing of
network cards (NICs), SATA controller cards, and other external devices which
can program flash chips.
.
It supports a wide range of DIP32, PLCC32, DIP8, SO8/SOIC8, TSOP32/40/48,
and BGA chips, which use various protocols such as LPC, FWH, parallel
flash, or SPI.
.
The tool can be used to flash BIOS/firmware images for example -- be it
proprietary BIOS images or coreboot (previously known as LinuxBIOS) images.
.
It can also be used to read the current existing BIOS/firmware from a
flash chip.
.
This package provides flashrom library development files.
Original-Maintainer: Debian EFI <debian-efi@lists.debian.org>
Homepage: http://www.flashrom.org

Package: libfont-afm-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.20-3
Depends: perl:any
Description: Perl interface to Adobe Font Metrics files
This module implements the Font::AFM class. Objects of this class are
initialised from an AFM-file and allow you to obtain information
about the font and the metrics of the various glyphs in the font.
.
All measurements in AFM files are given in terms of units equal to
1/1000 of the scale factor of the font being used. To compute actual
sizes in a document, these amounts should be multiplied by (scale
factor of font)/1000.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Font-AFM

Package: libfontconfig1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 331
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: fontconfig
Version: 2.13.1-4.2ubuntu5
Provides: libfontconfig
Depends: libc6 (>= 2.33), libexpat1 (>= 2.0.1), libfreetype6 (>= 2.9.1), libuuid1 (>= 2.16), fontconfig-config (>= 2.13.1-4.2ubuntu5)
Breaks: xpdf (<= 3.03-11)
Description: generic font configuration library - runtime
Fontconfig is a font configuration and customization library, which
does not depend on the X Window System. It is designed to locate
fonts within the system and select them according to requirements
specified by applications.
.
This package contains the runtime library needed to launch applications
using fontconfig.
Homepage: https://www.freedesktop.org/wiki/Software/fontconfig/
Original-Maintainer: Debian freedesktop.org maintainers <pkg-freedesktop-maintainers@lists.alioth.debian.org>

Package: libfontenc1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 50
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libfontenc
Version: 1:1.1.4-1build3
Depends: libc6 (>= 2.14), zlib1g (>= 1:1.1.4)
Description: X11 font encoding library
libfontenc is a library which helps font libraries portably determine
and deal with different encodings of fonts.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libfontenc
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libfreetype6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 870
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: freetype
Version: 2.11.1+dfsg-1ubuntu0.1
Depends: libbrotli1 (>= 0.6.0), libc6 (>= 2.33), libpng16-16 (>= 1.6.2-1), zlib1g (>= 1:1.1.4)
Description: FreeType 2 font engine, shared library files
The FreeType project is a team of volunteers who develop free,
portable and high-quality software solutions for digital typography.
They specifically target embedded systems and focus on providing small,
efficient and ubiquitous products.
.
The FreeType 2 library is their new software font engine. It has been
designed to provide the following important features:

- A universal and simple API to manage font files
- Support for several font formats through loadable modules
- High-quality anti-aliasing
- High portability & performance
  .
  Supported font formats include:
- TrueType files (.ttf) and collections (.ttc)
- Type 1 font files both in ASCII (.pfa) or binary (.pfb) format
- Type 1 Multiple Master fonts. The FreeType 2 API also provides
  routines to manage design instances easily
- Type 1 CID-keyed fonts
- OpenType/CFF (.otf) fonts
- CFF/Type 2 fonts
- Adobe CEF fonts (.cef), used to embed fonts in SVG documents with
  the Adobe SVG viewer plugin.
- Windows FNT/FON bitmap fonts
  .
  This package contains the files needed to run programs that use the
  FreeType 2 library.
  Homepage: https://www.freetype.org
  Original-Maintainer: Hugh McMaster <hugh.mcmaster@outlook.com>

Package: libfribidi0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 136
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: fribidi
Version: 1.0.8-2ubuntu3.1
Depends: libc6 (>= 2.4)
Description: Free Implementation of the Unicode BiDi algorithm
FriBiDi is a BiDi algorithm implementation for Hebrew and/or Arabic
languages.
This package contains the shared libraries.
Homepage: http://www.fribidi.org/
Original-Maintainer: Debian Hebrew Packaging Team <team+hebrew@tracker.debian.org>

Package: libftdi1-2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 81
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libftdi1
Version: 1.5-5build3
Depends: libc6 (>= 2.14), libusb-1.0-0 (>= 2:1.0.16)
Description: C Library to control and program the FTDI USB controllers
This library could talk to FTDI's FT232BM, FT245BM, FT2232C, FT2232D, FT245R,
FT232H and FT230X type USB chips from userspace. It uses libusb 1.0 to
communicate with the chips.
.
Functionalities include the possibility to use the chips in standard
mode, in bitbang mode, and to read or write the serial EEPROM.
.
This is the C version of the library.
Original-Maintainer: Aurelien Jarno <aurel32@debian.org>
Homepage: https://www.intra2net.com/en/developer/libftdi/

Package: libfuse3-3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 282
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: fuse3
Version: 3.10.5-1build1
Depends: libc6 (>= 2.34)
Suggests: fuse3
Description: Filesystem in Userspace (library) (3.x version)
Filesystem in Userspace (FUSE) is a simple interface for userspace programs to
export a virtual filesystem to the Linux kernel. It also aims to provide a
secure method for non privileged users to create and mount their own filesystem
implementations.
.
This package contains the shared library.
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>
Homepage: https://github.com/libfuse/libfuse/wiki

Package: libfwupd2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 389
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: fwupd
Version: 1.7.5-3
Depends: libc6 (>= 2.27), libcurl3-gnutls (>= 7.63.0), libglib2.0-0 (>= 2.53.2), libjcat1 (>= 0.1.0), libjson-glib-1.0-0 (>= 1.5.2)
Description: Firmware update daemon library
fwupd is a daemon to allow session software to update device firmware.
You can either use a GUI software manager like GNOME Software to view and
apply updates, the command-line tool or the system D-Bus interface directly.
Firmware updates are supported for a variety of technologies.
See <https://github.com/fwupd/fwupd> for details
.
This package provides the library used by the daemon.
Original-Maintainer: Debian EFI <debian-efi@lists.debian.org>
Homepage: https://github.com/fwupd/fwupd

Package: libfwupdplugin5
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 588
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: fwupd
Version: 1.7.5-3
Depends: libfwupd2 (= 1.7.5-3), libarchive13 (>= 3.0.4), libc6 (>= 2.14), libgcab-1.0-0 (>= 1.0), libglib2.0-0 (>= 2.67.3), libgudev-1.0-0 (>= 212), libgusb2 (>= 0.3.5), libjcat1 (>= 0.1.0), libxmlb2 (>= 0.3.2)
Description: Firmware update daemon plugin library
fwupd is a daemon to allow session software to update device firmware.
You can either use a GUI software manager like GNOME Software to view and
apply updates, the command-line tool or the system D-Bus interface directly.
Firmware updates are supported for a variety of technologies.
See <https://github.com/fwupd/fwupd> for details
.
This package provides the library for the interface between daemon and plugins.
Original-Maintainer: Debian EFI <debian-efi@lists.debian.org>
Homepage: https://github.com/fwupd/fwupd

Package: libgcab-1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 90
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcab
Version: 1.4-3build2
Depends: libc6 (>= 2.14), libglib2.0-0 (>= 2.61.2), zlib1g (>= 1:1.1.4)
Description: Microsoft Cabinet file manipulation library
libgcab provides functions to manipulate cabinet (.cab) files,
both for reading and writing their contents.
.
This package contains the shared library.
Original-Maintainer: Stephen Kitt <skitt@debian.org>
Homepage: https://wiki.gnome.org/msitools

Package: libgcc-11-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 13878
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-11
Version: 11.2.0-19ubuntu1
Replaces: libtsan0 (<< 11.2.0-11)
Depends: gcc-11-base (= 11.2.0-19ubuntu1), libgcc-s1 (>= 11.2.0-19ubuntu1), libgomp1 (>= 11.2.0-19ubuntu1), libitm1 (>= 11.2.0-19ubuntu1), libatomic1 (>= 11.2.0-19ubuntu1), libasan6 (>= 11.2.0-19ubuntu1), liblsan0 (>= 11.2.0-19ubuntu1), libtsan0 (>= 11.2.0-19ubuntu1), libubsan1 (>= 11.2.0-19ubuntu1), libquadmath0 (>= 11.2.0-19ubuntu1)
Recommends: libc6-dev (>= 2.13-0ubuntu6)
Breaks: libtsan0 (<< 11.2.0-11)
Description: GCC support library (development files)
This package contains the headers and static library files necessary for
building C programs which use libgcc, libgomp, libquadmath, libssp or libitm.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libgcc-s1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 140
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Replaces: libgcc1 (<< 1:10)
Provides: libgcc1 (= 1:12-20220319-1ubuntu1)
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.35)
Description: GCC support library
Shared version of the support library, a library of internal subroutines
that GCC uses to overcome shortcomings of particular machines, or
special needs for some languages.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libgcrypt20
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 1354
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 1.9.4-3ubuntu3
Depends: libc6 (>= 2.33), libgpg-error0 (>= 1.27)
Suggests: rng-tools
Description: LGPL Crypto library - runtime library
libgcrypt contains cryptographic functions. Many important free
ciphers, hash algorithms and public key signing algorithms have been
implemented:
.
Arcfour, Blowfish, CAST5, DES, AES, Twofish, Serpent, rfc2268 (rc2), SEED,
Poly1305, Camellia, ChaCha20, IDEA, Salsa, SM4, Blake-2, CRC, MD2, MD4, MD5,
RIPE-MD160, SM3, SHA-1, SHA-256, SHA-512, SHA3-224, SHA3-256, SHA3-384,
SHA3-512, SHAKE128, SHAKE256, Tiger, Whirlpool, DSA, DSA2, ElGamal, RSA, ECC
(Curve25519, sec256k1, GOST R 34.10-2001 and GOST R 34.10-2012, etc.)
Homepage: https://directory.fsf.org/project/libgcrypt/
Original-Maintainer: Debian GnuTLS Maintainers <pkg-gnutls-maint@lists.alioth.debian.org>

Package: libgd3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 452
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libgd2
Version: 2.3.0-2ubuntu2
Depends: libc6 (>= 2.29), libfontconfig1 (>= 2.12.6), libfreetype6 (>= 2.2.1), libjpeg8 (>= 8c), libpng16-16 (>= 1.6.2-1), libtiff5 (>= 4.0.3), libwebp7, libxpm4, zlib1g (>= 1:1.1.4)
Suggests: libgd-tools
Description: GD Graphics Library
GD is a graphics library. It allows your code to quickly draw images
complete with lines, arcs, text, multiple colours, cut and paste from
other images, flood fills, and write out the result as a PNG file.
This is particularly useful in World Wide Web applications, where PNG is
one of the formats accepted for inline images by most browsers.
.
This is the runtime package of the library.
Homepage: http://www.libgd.org/
Original-Maintainer: GD Team <team+gd@tracker.debian.org>

Package: libgdbm-compat4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gdbm
Version: 1.23-1
Depends: libc6 (>= 2.33), libgdbm6 (>= 1.16)
Description: GNU dbm database routines (legacy support runtime version)
GNU dbm ('gdbm') is a library of database functions that use extendible
hashing and works similarly to the standard UNIX 'dbm' functions.
.
The basic use of 'gdbm' is to store key/data pairs in a data file, thus
providing a persistent version of the 'dictionary' Abstract Data Type
('hash' to perl programmers).
This package includes library files, required to run old programs,
that use legacy 'dbm' interface. For new programs, please use modern
interface, provided by libgdbm6 and libgdbm-dev.
Original-Maintainer: Nicolas Mora <babelouest@debian.org>
Homepage: https://gnu.org/software/gdbm

Package: libgdbm6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 100
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gdbm
Version: 1.23-1
Depends: libc6 (>= 2.33)
Suggests: gdbm-l10n (= 1.23-1)
Description: GNU dbm database routines (runtime version)
GNU dbm ('gdbm') is a library of database functions that use extendible
hashing and works similarly to the standard UNIX 'dbm' functions.
.
The basic use of 'gdbm' is to store key/data pairs in a data file, thus
providing a persistent version of the 'dictionary' Abstract Data Type
('hash' to perl programmers).
Original-Maintainer: Nicolas Mora <babelouest@debian.org>
Homepage: https://gnu.org/software/gdbm

Package: libgdk-pixbuf-2.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 512
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gdk-pixbuf
Version: 2.42.8+dfsg-1
Replaces: libgdk-pixbuf2.0-0 (<< 2.40.0+dfsg-6~)
Depends: libgdk-pixbuf2.0-common (>= 2.42.8+dfsg-1), shared-mime-info, libc6 (>= 2.34), libglib2.0-0 (>= 2.59.0), libjpeg8 (>= 8c), libpng16-16 (>= 1.6.2-1), libtiff5 (>= 4.0.3)
Recommends: libgdk-pixbuf2.0-bin
Breaks: libgdk-pixbuf2.0-0 (<< 2.40.0+dfsg-6~)
Description: GDK Pixbuf library
The GDK Pixbuf library provides:

- Image loading and saving facilities.
- Fast scaling and compositing of pixbufs.
- Simple animation loading (ie. animated GIFs)
  Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
  Homepage: https://www.gtk.org/

Package: libgdk-pixbuf2.0-bin
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 83
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gdk-pixbuf
Version: 2.42.8+dfsg-1
Replaces: libgdk-pixbuf2.0-dev (<< 2.36.12-2~)
Depends: libc6 (>= 2.34), libgdk-pixbuf-2.0-0 (>= 2.35.4), libglib2.0-0 (>= 2.56.0)
Breaks: libgdk-pixbuf2.0-dev (<< 2.36.12-2~)
Description: GDK Pixbuf library (thumbnailer)
The GDK Pixbuf library provides:

- Image loading and saving facilities.
- Fast scaling and compositing of pixbufs.
- Simple animation loading (ie. animated GIFs)
  .
  This package contains the GDK pixdata compression utility, the thumbnailer
  and a utility for converting images into C code.
  Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
  Homepage: https://www.gtk.org/

Package: libgdk-pixbuf2.0-common
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 56
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: gdk-pixbuf
Version: 2.42.8+dfsg-1
Description: GDK Pixbuf library - data files
This package contains the common files and translations for the GDK
Pixbuf library.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://www.gtk.org/

Package: libgirepository-1.0-1
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 175
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gobject-introspection
Version: 1.72.0-1
Provides: libgirepository-1.0-1-with-libffi8 (= 1.72.0-1)
Depends: libglib2.0-0 (>= 2.70.0), libc6 (>= 2.29), libffi8 (>= 3.4)
Breaks: libcjs0 (<< 4.8.2-1+b1), libgjs0g (<< 1.68.4-1+b1), libglib-object-introspection-perl (<< 0.049-1+b2), python-gi (<< 3.42.0-1+b1), python3-gi (<< 3.42.0-1+b1), ruby-gobject-introspection (<< 3.4.3-1+b2)
Description: Library for handling GObject introspection data (runtime library)
GObject Introspection is a project for providing machine readable
introspection data of the API of C libraries. This introspection
data can be used in several different use cases, for example
automatic code generation for bindings, API verification and documentation
generation.
.
GObject Introspection contains tools to generate and handle the
introspection data.
.
This package contains a C library for handling the introspection data.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/GObjectIntrospection

Package: libgl1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 653
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libglvnd
Version: 1.4.0-1
Depends: libc6 (>= 2.14), libglvnd0 (= 1.4.0-1), libglx0 (= 1.4.0-1)
Description: Vendor neutral GL dispatch library -- legacy GL support
This is an implementation of the vendor-neutral dispatch layer for
arbitrating OpenGL API calls between multiple vendors on a per-screen basis.
.
This package contains support for old libGL for compatibility reasons.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://gitlab.freedesktop.org/glvnd/libglvnd

Package: libgl1-amber-dri
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 16805
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: mesa-amber
Version: 21.3.7-0ubuntu1
Replaces: libgl1-mesa-dri (<< 22.0.0~)
Provides: dri-drivers
Depends: libc6 (>= 2.34), libdrm-intel1 (>= 2.4.38), libdrm-nouveau2 (>= 2.4.66), libdrm-radeon1 (>= 2.4.17), libdrm2 (>= 2.4.38), libexpat1 (>= 2.0.1), libgcc-s1 (>= 3.4), libglapi-mesa (>= 21.3.5), libstdc++6 (>= 5.2), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Conflicts: libgl1-mesa-dri (<< 22.0.0~)
Description: free implementation of the OpenGL API -- DRI modules
This version of Mesa provides GLX and DRI capabilities: it is capable of
both direct and indirect rendering. For direct rendering, it can use DRI
modules from the libgl1-mesa-dri package to accelerate drawing.
.
This package does not include the OpenGL library itself, only the DRI
modules for accelerating direct rendering.
.
For a complete description of Mesa Amber, please look at the
libglx-amber0 package.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://mesa3d.org/

Package: libgl1-mesa-dri
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 24544
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: mesa
Version: 22.0.5-0ubuntu0.1
Depends: libc6 (>= 2.34), libdrm-amdgpu1 (>= 2.4.105), libdrm-nouveau2 (>= 2.4.66), libdrm-radeon1 (>= 2.4.31), libdrm2 (>= 2.4.75), libelf1 (>= 0.142), libexpat1 (>= 2.0.1), libgcc-s1 (>= 3.4), libglapi-mesa (= 22.0.5-0ubuntu0.1), libllvm13, libsensors5 (>= 1:3.5.0), libstdc++6 (>= 11), libvulkan1 (>= 1.2.131.2), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Recommends: libgl1-amber-dri
Description: free implementation of the OpenGL API -- DRI modules
This version of Mesa provides GLX and DRI capabilities: it is capable of
both direct and indirect rendering. For direct rendering, it can use DRI
modules from the libgl1-mesa-dri package to accelerate drawing.
.
This package does not include the OpenGL library itself, only the DRI
modules for accelerating direct rendering.
.
For a complete description of Mesa, please look at the
libglx-mesa0 package.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://mesa3d.org/

Package: libglapi-mesa
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 305
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: mesa
Version: 22.0.5-0ubuntu0.1
Depends: libc6 (>= 2.34)
Description: free implementation of the GL API -- shared library
The Mesa GL API module is responsible for dispatching all the gl\*
functions. It is intended to be mainly used by both the libgles1-mesa
and libgles2-mesa packages.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://mesa3d.org/

Package: libglib2.0-0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 4076
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: glib2.0
Version: 2.72.1-1
Depends: libc6 (>= 2.34), libffi8 (>= 3.4), libmount1 (>= 2.35.2-7~), libpcre3, libselinux1 (>= 3.1~), zlib1g (>= 1:1.2.2)
Recommends: libglib2.0-data, shared-mime-info, xdg-user-dirs
Breaks: gimp (<< 2.10.14-3~), glib-networking-tests (<< 2.70.0~), gnome-keyring (<< 40.0-3~), libgirepository-1.0-1 (<< 1.62.0-4~), libgladeui-2-6 (<< 3.22.2), libsoup2.4-tests (<< 2.72.0-3~)
Description: GLib library of C routines
GLib is a library containing many useful C routines for things such
as trees, hashes, lists, and strings. It is a useful general-purpose
C library used by projects such as GTK+, GIMP, and GNOME.
.
This package contains the shared libraries.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Projects/GLib

Package: libglib2.0-bin
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 341
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: glib2.0
Version: 2.72.1-1
Depends: libglib2.0-data, libc6 (>= 2.34), libelf1 (>= 0.142), libglib2.0-0 (= 2.72.1-1)
Description: Programs for the GLib library
GLib is a library containing many useful C routines for things such
as trees, hashes, lists, and strings. It is a useful general-purpose
C library used by projects such as GTK+, GIMP, and GNOME.
.
This package contains the program files which is used for the libraries
and others.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Projects/GLib

Package: libglib2.0-data
Status: install ok installed
Priority: important
Section: misc
Installed-Size: 112
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: glib2.0
Version: 2.72.1-1
Description: Common files for GLib library
GLib is a library containing many useful C routines for things such
as trees, hashes, lists, and strings. It is a useful general-purpose
C library used by projects such as GTK+, GIMP, and GNOME.
.
This package is needed for the runtime libraries to display messages in
languages other than English.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Projects/GLib

Package: libglvnd0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 725
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libglvnd
Version: 1.4.0-1
Replaces: libgldispatch0-nvidia
Depends: libc6 (>= 2.34)
Breaks: libgldispatch0-nvidia
Description: Vendor neutral GL dispatch library
This is an implementation of the vendor-neutral dispatch layer for
arbitrating OpenGL API calls between multiple vendors on a per-screen basis.
.
This package contains the GL dispatch library.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://gitlab.freedesktop.org/glvnd/libglvnd

Package: libglx-mesa0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 555
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: mesa
Version: 22.0.5-0ubuntu0.1
Provides: libglx-vendor
Depends: libc6 (>= 2.34), libdrm2 (>= 2.4.75), libexpat1 (>= 2.0.1), libglapi-mesa (= 22.0.5-0ubuntu0.1), libstdc++6 (>= 4.1.1), libx11-6 (>= 2:1.4.99.1), libx11-xcb1 (>= 2:1.7.5), libxcb-dri2-0 (>= 1.8), libxcb-dri3-0 (>= 1.13), libxcb-glx0 (>= 1.8), libxcb-present0, libxcb-shm0, libxcb-sync1, libxcb-xfixes0, libxcb1 (>= 1.9.2), libxext6, libxfixes3, libxshmfence1, libxxf86vm1, libgl1-mesa-dri
Breaks: glx-diversions (<< 0.8.4~), libopengl-perl (<< 0.6704+dfsg-2)
Description: free implementation of the OpenGL API -- GLX vendor library
Mesa is a 3-D graphics library with an API which is very similar to
that of OpenGL. To the extent that Mesa utilizes the OpenGL command
syntax or state machine, it is being used with authorization from
Silicon Graphics, Inc. However, the authors make no claim that Mesa
is in any way a compatible replacement for OpenGL or associated with
Silicon Graphics, Inc.
.
This version of Mesa provides GLX and DRI capabilities: it is capable of
both direct and indirect rendering. For direct rendering, it can use DRI
modules from the libgl1-mesa-dri package to accelerate drawing.
.
This package does not include the modules themselves: these can be found
in the libgl1-mesa-dri package.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://mesa3d.org/

Package: libglx0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 163
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libglvnd
Version: 1.4.0-1
Depends: libc6 (>= 2.34), libglvnd0 (= 1.4.0-1), libx11-6 (>= 2:1.4.99.1), libglx-mesa0
Description: Vendor neutral GL dispatch library -- GLX support
This is an implementation of the vendor-neutral dispatch layer for
arbitrating OpenGL API calls between multiple vendors on a per-screen basis.
.
This package contains support for GLX.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://gitlab.freedesktop.org/glvnd/libglvnd

Package: libgmp10
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 544
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gmp
Version: 2:6.2.1+dfsg-3ubuntu1
Depends: libc6 (>= 2.14)
Breaks: libmath-gmp-perl (<< 2.20-1), libmath-prime-util-gmp-perl (<< 0.51-2), postgresql-pgmp (<< 1.0.3-1)
Description: Multiprecision arithmetic library
GNU MP is a programmer's library for arbitrary precision
arithmetic (ie, a bignum package). It can operate on signed
integer, rational, and floating point numeric types.
.
It has a rich set of functions, and the functions have a regular
interface.
Homepage: https://gmplib.org/
Original-Maintainer: Debian Science Team <debian-science-maintainers@lists.alioth.debian.org>

Package: libgnutls30
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 2284
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gnutls28
Version: 3.7.3-4ubuntu1.1
Depends: libc6 (>= 2.34), libgmp10 (>= 2:6.2.1+dfsg), libhogweed6 (>= 3.6), libidn2-0 (>= 2.0.0), libnettle8 (>= 3.7~), libp11-kit0 (>= 0.23.18.1), libtasn1-6 (>= 4.14), libunistring2 (>= 0.9.7)
Suggests: gnutls-bin
Description: GNU TLS library - main runtime library
GnuTLS is a portable library which implements the Transport Layer
Security (TLS 1.0, 1.1, 1.2, 1.3) and Datagram
Transport Layer Security (DTLS 1.0, 1.2) protocols.
.
GnuTLS features support for:

- certificate path validation, as well as DANE and trust on first use.
- the Online Certificate Status Protocol (OCSP).
- public key methods, including RSA and Elliptic curves, as well as password
  and key authentication methods such as SRP and PSK protocols.
- all the strong encryption algorithms, including AES and Camellia.
- CPU-assisted cryptography with VIA padlock and AES-NI instruction sets.
- HSMs and cryptographic tokens, via PKCS #11.
  .
  This package contains the main runtime library.
  Homepage: https://www.gnutls.org/
  Original-Maintainer: Debian GnuTLS Maintainers <pkg-gnutls-maint@lists.alioth.debian.org>

Package: libgomp1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 320
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.34)
Breaks: gcc-4.3 (<< 4.3.6-1), gcc-4.4 (<< 4.4.6-4), gcc-4.5 (<< 4.5.3-2)
Description: GCC OpenMP (GOMP) support library
GOMP is an implementation of OpenMP for the C, C++, and Fortran compilers
in the GNU Compiler Collection.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libgpg-error0
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 189
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libgpg-error
Version: 1.43-3
Depends: libc6 (>= 2.34)
Recommends: libgpg-error-l10n
Description: GnuPG development runtime library
Library that defines common error values, messages, and common
runtime functionality for all GnuPG components. Among these are GPG,
GPGSM, GPGME, GPG-Agent, libgcrypt, pinentry, SmartCard Daemon and
possibly more in the future.
.
It will likely be renamed "gpgrt" in the future.
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>
Homepage: https://www.gnupg.org/related_software/libgpg-error/

Package: libgpgme11
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 372
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gpgme1.0
Version: 1.16.0-1.2ubuntu4
Depends: gnupg (>= 2.1.21-4) | gpg, libassuan0 (>= 2.4.2), libc6 (>= 2.34), libgpg-error0 (>= 1.36)
Recommends: dirmngr, gpg-agent, gpg-wks-client, gpgsm
Description: GPGME - GnuPG Made Easy (library)
GPGME is a wrapper library which provides a C API to access some of the
GnuPG functions, such as encrypt, decrypt, sign, verify, ...
.
This package contains the library.
Homepage: https://www.gnupg.org/related_software/gpgme/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: libgpm2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 65
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gpm
Version: 1.20.7-10build1
Depends: libc6 (>= 2.33)
Suggests: gpm
Description: General Purpose Mouse - shared library
This package provides a library that handles mouse requests
and delivers them to applications. See the description for the 'gpm'
package for more information.
Original-Maintainer: Axel Beckert <abe@debian.org>
Homepage: https://nico.schottelius.org/software/gpm/

Package: libgraphite2-3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 179
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: graphite2
Version: 1.3.14-1build2
Replaces: libgraphite2-2.0.0
Provides: libgraphite2-2.0.0
Depends: libc6 (>= 2.14)
Breaks: libgraphite2-2.0.0 (<< 1.2.0)
Description: Font rendering engine for Complex Scripts -- library
Graphite is a system that can be used to create and use "smart fonts" capable
of displaying writing systems with various complex behaviors, such as:
contextual shaping, ligatures, reordering, split glyphs, bidirectionality,
stacking diacritics and complex positioning.
.
This library was designed and developed by the NRSI (Non-Roman Script
Initiative) within SIL International (www.sil.org) to act as a complement to
other smart font rendering technologies with limited practical local
extensibility. Its purpose is to help meet the needs of a very large number
of "minority language" communities for local extensibility of complex script
behaviors.
.
The behavior of the rendering engine for a given writing system is specified
through extra tables added to a TrueType font. These tables are generated by
compiling a GDL (Graphite Description Language) source file into a font using
grcompiler.
.
This package contains the shared library.
Original-Maintainer: Debian LibreOffice Maintainers <debian-openoffice@lists.debian.org>
Homepage: http://graphite.sil.org/

Package: libgssapi-krb5-2
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 455
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: krb5
Version: 1.19.2-2
Depends: libc6 (>= 2.33), libcom-err2 (>= 1.43.9), libk5crypto3 (>= 1.16), libkrb5-3 (= 1.19.2-2), libkrb5support0 (>= 1.15~beta1)
Suggests: krb5-doc, krb5-user
Breaks: moonshot-gss-eap (<= 1.0)
Description: MIT Kerberos runtime libraries - krb5 GSS-API Mechanism
Kerberos is a system for authenticating users and services on a network.
Kerberos is a trusted third-party service. That means that there is a
third party (the Kerberos server) that is trusted by all the entities on
the network (users and services, usually called "principals").
.
This is the MIT reference implementation of Kerberos V5.
.
This package contains the runtime library for the MIT Kerberos
implementation of GSS-API used by applications and Kerberos clients.
Original-Maintainer: Sam Hartman <hartmans@debian.org>
Homepage: http://web.mit.edu/kerberos/

Package: libgstreamer1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 2984
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gstreamer1.0
Version: 1.20.3-0ubuntu1
Depends: libc6 (>= 2.34), libcap2 (>= 1:2.10), libdw1 (>= 0.126), libglib2.0-0 (>= 2.70.0), libunwind8, libcap2-bin
Suggests: gstreamer1.0-tools
Breaks: gstreamer1.0-plugins-bad (<< 1.11.1), gstreamer1.0-plugins-base (<< 1.8.0), libgstreamer-plugins-bad1.0-0 (<< 1.13.1)
Description: Core GStreamer libraries and elements
GStreamer is a streaming media framework, based on graphs of filters
which operate on media data. Applications using this library can do
anything from real-time sound processing to playing videos, and just
about anything else media-related. Its plugin-based architecture means
that new data types or processing capabilities can be added simply by
installing new plug-ins.
.
This package contains the core library and elements.
Homepage: https://gstreamer.freedesktop.org
Original-Maintainer: Maintainers of GStreamer packages <gstreamer1.0@packages.debian.org>

Package: libgtk-3-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 10280
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gtk+3.0
Version: 3.24.33-1ubuntu2
Provides: gtk3-binver-3.0.0
Depends: adwaita-icon-theme, hicolor-icon-theme, shared-mime-info, libatk-bridge2.0-0 (>= 2.5.3), libatk1.0-0 (>= 2.35.1), libc6 (>= 2.34), libcairo-gobject2 (>= 1.14.0), libcairo2 (>= 1.14.0), libcolord2 (>= 0.1.10), libcups2 (>= 2.3~b6), libepoxy0 (>= 1.4.3), libfontconfig1 (>= 2.12.6), libfribidi0 (>= 0.19.7), libgdk-pixbuf-2.0-0 (>= 2.40.0), libglib2.0-0 (>= 2.59.0), libharfbuzz0b (>= 2.2.0), libpango-1.0-0 (>= 1.45.5), libpangocairo-1.0-0 (>= 1.44.0), libpangoft2-1.0-0 (>= 1.44.0), libwayland-client0 (>= 1.20.0), libwayland-cursor0 (>= 1.14.91), libwayland-egl1 (>= 1.15.0), libx11-6 (>= 2:1.4.99.1), libxcomposite1 (>= 1:0.4.5), libxcursor1 (>> 1.1.2), libxdamage1 (>= 1:1.1), libxext6, libxfixes3, libxi6 (>= 2:1.2.99.4), libxinerama1 (>= 2:1.1.4), libxkbcommon0 (>= 0.5.0), libxrandr2 (>= 2:1.5.0), libgtk-3-common (>= 3.24.33-1ubuntu2)
Recommends: libgtk-3-bin, librsvg2-common
Suggests: gvfs
Conffiles:
/etc/gtk-3.0/settings.ini 17193df36387c79f30763b729b8a49a9
Description: GTK graphical user interface library
GTK is a multi-platform toolkit for creating graphical user
interfaces. Offering a complete set of widgets, GTK is suitable
for projects ranging from small one-off tools to complete application
suites.
.
This package contains the shared libraries.
Homepage: https://www.gtk.org/
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libgtk-3-bin
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 337
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: gtk+3.0
Version: 3.24.33-1ubuntu2
Replaces: gtk-3-examples (<< 3.24.13)
Depends: gtk-update-icon-cache, libc6 (>= 2.34), libcairo2 (>= 1.14.0), libgdk-pixbuf-2.0-0 (>= 2.40.0), libglib2.0-0 (>= 2.57.2), libgtk-3-0 (>= 3.24.33-1ubuntu2), libgtk-3-common (>= 3.24.33-1ubuntu2)
Breaks: gtk-3-examples (<< 3.24.13)
Description: programs for the GTK graphical user interface library
GTK is a multi-platform toolkit for creating graphical user
interfaces. Offering a complete set of widgets, GTK is suitable
for projects ranging from small one-off tools to complete application
suites.
.
This package contains the utilities which are used by the libraries
and other packages.
Homepage: https://www.gtk.org/
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libgtk-3-common
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 432
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: gtk+3.0
Version: 3.24.33-1ubuntu2
Replaces: libgtk-3-dev (<< 3.24.30-3~)
Depends: dconf-gsettings-backend | gsettings-backend
Recommends: libgtk-3-0
Breaks: libgtk-3-dev (<< 3.24.30-3~)
Conffiles:
/etc/gtk-3.0/im-multipress.conf c358838e1789c1d4e6da7f525fc922cf
Description: common files for the GTK graphical user interface library
GTK is a multi-platform toolkit for creating graphical user
interfaces. Offering a complete set of widgets, GTK is suitable
for projects ranging from small one-off tools to complete application
suites.
.
This package contains the common files which the libraries need.
Homepage: https://www.gtk.org/
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libgtkd-3-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 12749
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gtk-d
Version: 3.10.0-1ubuntu1
Depends: libcairo-gobject2, libgtk-3-0, librsvg2-2, libc6 (>= 2.34), libgcc-s1 (>= 3.0), libphobos2-ldc-shared98 (>= 1:1.28.0)
Description: GTK+ graphical user interface library - D bindings
GTK+ is a multi-platform toolkit for creating graphical user interfaces.
Offering a complete set of widgets, GTK+ is suitable for projects ranging
from small one-off tools to complete application suites.
.
This package contains runtime files needed for applications written in D.
Homepage: https://gtkd.org/
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libgudev-1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libgudev (237-2build1)
Version: 1:237-2build1
Depends: libc6 (>= 2.33), libglib2.0-0 (>= 2.38.0), libudev1 (>= 199)
Description: GObject-based wrapper library for libudev
This library makes it much simpler to use libudev from programs already using
GObject. It also makes it possible to easily use libudev from other
programming languages, such as Javascript, because of GObject introspection
support.
Homepage: https://wiki.gnome.org/Projects/libgudev
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libgusb2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 97
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libgusb
Version: 0.3.10-1
Depends: libc6 (>= 2.14), libglib2.0-0 (>= 2.44.0), libusb-1.0-0 (>= 2:1.0.22)
Recommends: usb.ids
Description: GLib wrapper around libusb1
GUsb is a GObject wrapper for libusb1 that makes it easy to do
asynchronous control, bulk and interrupt transfers with proper
cancellation and integration into a mainloop.
.
This package contains the GUsb shared library.
Original-Maintainer: Debian UEFI Maintainers <debian-efi@lists.debian.org>
Homepage: http://www.hughski.com/downloads.html

Package: libharfbuzz0b
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 860
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: harfbuzz
Version: 2.7.4-1ubuntu3.1
Replaces: libharfbuzz0, libharfbuzz0a
Depends: libc6 (>= 2.33), libfreetype6 (>= 2.9.1), libglib2.0-0 (>= 2.31.8), libgraphite2-3 (>= 1.2.2)
Conflicts: libharfbuzz0, libharfbuzz0a
Description: OpenType text shaping engine (shared library)
HarfBuzz is an implementation of the OpenType Layout engine (aka layout
engine) and the script-specific logic (aka shaping engine).
.
This package contains the shared libraries.
Homepage: https://www.freedesktop.org/wiki/Software/HarfBuzz
Original-Maintainer: أحمد المحمودي (Ahmed El-Mahmoudy) <aelmahmoudy@users.sourceforge.net>

Package: libhogweed6
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 336
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: nettle
Version: 3.7.3-1build2
Depends: libc6 (>= 2.14), libgmp10 (>= 2:6.2.1+dfsg), libnettle8
Description: low level cryptographic library (public-key cryptos)
Nettle is a cryptographic library that is designed to fit easily in more or
less any context: In crypto toolkits for object-oriented languages (C++,
Python, Pike, ...), in applications like LSH or GNUPG, or even in kernel
space.
.
It tries to solve a problem of providing a common set of cryptographic
algorithms for higher-level applications by implementing a
context-independent set of cryptographic algorithms. In that light, Nettle
doesn't do any memory allocation or I/O, it simply provides the
cryptographic algorithms for the application to use in any environment and
in any way it needs.
.
This package contains the asymmetric cryptographic algorithms, which,
require the GNU multiple precision arithmetic library (libgmp) for
their large integer computations.
Homepage: http://www.lysator.liu.se/~nisse/nettle/
Original-Maintainer: Magnus Holmgren <holmgren@debian.org>

Package: libhtml-form-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 62
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.07-1
Depends: perl:any, libhtml-parser-perl, libhttp-message-perl, liburi-perl
Description: module that represents an HTML form element
Objects of the HTML::Form class represents a single HTML <form> ... </form>
instance. A form consists of a sequence of inputs that usually have names,
and which can take on various values. The state of a form can be tweaked and
it can then be asked to provide HTTP::Request objects that can be passed to
the request() method of LWP::UserAgent.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/HTML-Form

Package: libhtml-format-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 126
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.12-1.1
Depends: perl:any, libfont-afm-perl, libhtml-tree-perl
Description: module for transforming HTML into various formats
HTML::Formatter is a base class for various formatters, which are modules
that traverse an HTML syntax tree and produce various output file formats.
There are currently three formatter classes included:
.

- HTML::FormatText for converting to plain human-readable text
- HTML::FormatPS for converting to PostScript
- HTML::FormatRTF for converting to Microsoft's Rich Text Format (RTF)
  Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
  Homepage: https://metacpan.org/release/HTML-Format

Package: libhtml-parser-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 222
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 3.76-1build2
Depends: perl, perlapi-5.34.0, libc6 (>= 2.34), libhtml-tagset-perl, liburi-perl
Recommends: libhttp-message-perl
Suggests: libdata-dump-perl
Enhances: libwww-perl
Description: collection of modules that parse HTML text documents
HTML::Parser is a collection of modules useful for handling HTML documents.
These modules used to be part of the libwww-perl distribution, but are now
unbundled in order to facilitate a separate development track.
.
Objects of the HTML::Parser class will recognize markup and separate it from
content data. As different kinds of markup are recognized, the corresponding
event handler is invoked. The document to be parsed may also be supplied in
arbitrary chunks, making on-the-fly parsing of network documents possible.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/HTML-Parser

Package: libhtml-tagset-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.20-4
Depends: perl
Description: data tables pertaining to HTML
HTML::Tagset contains data tables useful in dealing with HTML. For instance,
it provides %HTML::Tagset::emptyElement, which lists all of the HTML elements
which cannot have content. It provides no functions or methods.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/HTML-Tagset

Package: libhtml-tree-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 481
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 5.07-2
Depends: perl, libhtml-parser-perl, libhtml-tagset-perl
Recommends: libhtml-format-perl, libwww-perl
Description: Perl module to represent and create HTML syntax trees
HTML::Tree is a collection of modules that represent, create and extract
information from HTML syntax trees. These modules used to be part of
the libwww-perl distribution, but are now unbundled in order to
facilitate a separate development track.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/HTML-Tree

Package: libhttp-cookies-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 50
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.10-1
Depends: perl:any, libhttp-date-perl, libhttp-message-perl
Description: HTTP cookie jars
This class is for objects that represent a "cookie jar" -- that is, a
database of all the HTTP cookies that a given LWP::UserAgent object knows
about.
.
Cookies are a general mechanism which server side connections can use to both
store and retrieve information on the client side of the connection. For more
information about cookies refer to
<URL:http://curl.haxx.se/rfc/cookie_spec.html> and
<URL:http://www.cookiecentral.com/>. HTTP::Cookies also implements the new
style cookies described in RFC 2965. The two variants of cookies are supposed
to be able to coexist happily.
.
Instances of the class HTTP::Cookies are able to store a collection of
Set-Cookie2: and Set-Cookie: headers and are able to use this information to
initialize Cookie-headers in HTTP::Request objects. The state of a
HTTP::Cookies object can be saved in and restored from files.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/HTTP-Cookies

Package: libhttp-daemon-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 56
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.13-1ubuntu0.1
Depends: perl:any, libhttp-date-perl, libhttp-message-perl, libio-socket-ip-perl, liblwp-mediatypes-perl, libsocket-perl
Description: simple http server class
Instances of the HTTP::Daemon class are HTTP/1.1 servers that listen on a
socket for incoming requests. The HTTP::Daemon is a subclass of
IO::Socket::IP, so you can perform socket operations directly on it too.
.
The accept() method will return when a connection from a client is available.
The returned value will be an HTTP::Daemon::ClientConn object which is
another IO::Socket::IP subclass. Calling the get_request() method on this
object will read data from the client and return an HTTP::Request object. The
ClientConn object also provide methods to send back various responses.
.
This HTTP daemon does not fork(2) for you. Your application, i.e. the user of
the HTTP::Daemon is responsible for forking if that is desirable. Also note
that the user is responsible for generating responses that conform to the
HTTP/1.1 protocol.
Homepage: https://metacpan.org/release/HTTP-Daemon
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>

Package: libhttp-date-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 29
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.05-1
Depends: perl, libtimedate-perl, libtime-local-perl (>= 1.28)
Description: module of date conversion routines
HTTP::Date provides functions that deal the date formats used by the HTTP
protocol (and then some more). Only the first two functions, time2str() and
str2time(), are exported by default.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/HTTP-Date

Package: libhttp-message-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 191
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.36-1
Depends: perl:any, libencode-locale-perl, libencode-perl (>= 3.01), libhttp-date-perl, libio-html-perl, liblwp-mediatypes-perl, liburi-perl
Recommends: libclone-perl
Description: perl interface to HTTP style messages
The HTTP::Message distribution contains classes useful for representing the
messages passed in HTTP style communication. These are classes representing
requests, responses and the headers contained within them.
.
The HTTP::Headers class encapsulates HTTP-style message headers. The headers
consist of attribute-value pairs also called fields, which may be repeated,
and which are printed in a particular order. The field names are cases
insensitive.
.
Instances of this class are usually created as member variables of the
HTTP::Request and HTTP::Response classes, internal to the library.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/HTTP-Message

Package: libhttp-negotiate-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 34
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.01-1
Replaces: libwww-perl (<< 6.00)
Depends: perl, libhttp-message-perl
Breaks: libwww-perl (<< 6.00)
Description: implementation of content negotiation
HTTP::Negotiate provides a complete implementation of the HTTP content
negotiation algorithm. Content negotiation allows for the selection of a
preferred content representation based upon attributes of the negotiable
variants and the value of the various Accept\* header fields in the request.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/HTTP-Negotiate

Package: libice6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 116
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libice
Version: 2:1.0.10-1build2
Depends: libbsd0 (>= 0.2.0), libc6 (>= 2.33), x11-common
Description: X11 Inter-Client Exchange library
This package provides the main interface to the X11 Inter-Client Exchange
library, which allows for communication of data between X clients.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libICE
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libicu70
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 34444
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: icu
Version: 70.1-2
Replaces: libiculx63 (<< 63.1-5)
Depends: libc6 (>= 2.34), libgcc-s1 (>= 3.3.1), libstdc++6 (>= 5.2)
Breaks: libiculx63 (<< 63.1-5), openttd (<< 1.8.0-2~)
Description: International Components for Unicode
ICU is a C++ and C library that provides robust and full-featured
Unicode and locale support. This package contains the runtime
libraries for ICU.
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>
Homepage: https://icu.unicode.org/

Package: libidn2-0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 220
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libidn2
Version: 2.3.2-2build1
Depends: libc6 (>= 2.14), libunistring2 (>= 0.9.7)
Description: Internationalized domain names (IDNA2008/TR46) library
Libidn2 implements the revised algorithm for internationalized domain
names called IDNA2008/TR46.
.
This package contains runtime libraries.
Homepage: https://www.gnu.org/software/libidn/#libidn2
Original-Maintainer: Debian Libidn team <help-libidn@gnu.org>

Package: libinih1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 30
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libinih
Version: 53-1ubuntu3
Depends: libc6 (>= 2.4)
Description: simple .INI file parser
inih (INI Not Invented Here) is a simple .INI file parser written in C.
It's only a couple of pages of code, and it was designed to be small and
simple, so it's good for embedded systems. It's also more or less
compatible with Python's ConfigParser style of .INI files, including
RFC 822-style multi-line syntax and name: value entries.
Homepage: https://github.com/benhoyt/inih
Original-Maintainer: Yangfl <mmyangfl@gmail.com>

Package: libintl-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 4321
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.26-3build2
Depends: perl:any
Recommends: libintl-xs-perl
Description: Uniforum message translations system compatible i18n library
libintl-perl is an internationalization library for Perl that aims to be
compatible with the Uniforum message translations system as implemented for
example in GNU gettext.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/libintl-perl

Package: libintl-xs-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 53
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: libintl-perl
Version: 1.26-3build2
Depends: libintl-perl (= 1.26-3build2), perl, perlapi-5.34.0, libc6 (>= 2.34)
Description: XS Uniforum message translations system compatible i18n library
libintl-perl is an internationalization library for Perl that aims to be
compatible with the Uniforum message translations system as implemented for
example in GNU gettext.
.
This package contains the XS Implementation of Uniforum Message Translation,
which is, thanks to the use of C code and libraries, a little bit faster than
the pure Perl implementation.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/libintl-perl

Package: libio-html-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 40
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.004-2
Depends: perl:any
Description: open an HTML file with automatic charset detection
IO::HTML provides an easy way to open a file containing HTML while
automatically determining its encoding. It uses the HTML5 encoding
sniffing algorithm specified in section 8.2.2.1 of the draft standard.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/IO-HTML

Package: libio-socket-ssl-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 561
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.074-2
Depends: perl:any, libnet-ssleay-perl, netbase
Recommends: libio-socket-ip-perl | libio-socket-inet6-perl, libsocket-perl | libsocket6-perl, liburi-perl | libnet-libidn-perl | libnet-idn-encode-perl
Suggests: ca-certificates
Description: Perl module implementing object oriented interface to SSL sockets
This module is a true drop-in replacement for IO::Socket::INET that
uses SSL to encrypt data before it is transferred to a remote server
or client. IO::Socket::SSL supports all the extra features that one
needs to write a full-featured SSL client or server application:
multiple SSL contexts, cipher selection, certificate verification, and
SSL version selection. As an extra bonus, it works perfectly with
mod_perl.
.
IO::Socket::SSL uses IPv6 if libio-socket-ip-perl (>= 0.20) or
libio-socket-inet6-perl is installed.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/IO-Socket-SSL

Package: libio-stringy-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 134
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: io-stringy
Version: 2.111-3
Depends: perl
Description: modules for I/O on in-core objects (strings/arrays)
IO::stringy primarily provides modules for performing both traditional and
object-oriented I/O on things _other_ than normal filehandles; in particular,
IO::Scalar, IO::ScalarArray, and IO::Lines.
.
The libio-stringy-perl package provides the following modules:
.

- IO::AtomicFile - write a file which is updated atomically
- IO::InnerFile - define a file inside another file
- IO::Lines - IO:: interface for reading/writing an array of lines
- IO::Scalar - IO:: interface for reading/writing a scalar
- IO::ScalarArray - IO:: interface for reading/writing an array of scalars
- IO::Stringy - I/O on in-core objects like strings and arrays
- IO::Wrap - wrap raw filehandles in IO::Handle interface
- IO::WrapTie - wrap tieable objects in IO::Handle interface
  Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
  Homepage: https://metacpan.org/release/IO-stringy

Package: libip4tc2
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 83
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: iptables
Version: 1.8.7-1ubuntu5
Depends: libc6 (>= 2.28)
Description: netfilter libip4tc library
The iptables/xtables framework has been replaced by nftables. You should
consider migrating now.
.
This package contains the user-space iptables (IPv4) C library from the
Netfilter xtables framework.
.
iptables IPv4 ruleset ADT and kernel interface.
.
This library has been considered private for years (and still is), in the
sense of changing symbols and backward compatibility not guaranteed.
Homepage: https://www.netfilter.org/
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>

Package: libip6tc2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 83
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: iptables
Version: 1.8.7-1ubuntu5
Depends: libc6 (>= 2.28)
Description: netfilter libip6tc library
The iptables/xtables framework has been replaced by nftables. You should
consider migrating now.
.
This package contains the user-space iptables (IPv6) C library from the
Netfilter xtables framework.
.
iptables IPv6 ruleset ADT and kernel interface.
.
This library has been considered private for years (and still is), in the
sense of changing symbols and backward compatibility not guaranteed.
Homepage: https://www.netfilter.org/
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>

Package: libipc-system-simple-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 61
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.30-1
Depends: perl:any
Description: Perl module to run commands simply, with detailed diagnostics
IPC::System::Simple takes the hard work out of calling external commands; it
provides replacements for system() and the backtick operator that will either
succeed, or die with rich diagnostic messages on errors.
.
The module also includes the ability to specify acceptable exit values, trap
errors, or process diagnostics.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/IPC-System-Simple

Package: libisc-export1105
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 510
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: bind9-libs
Version: 1:9.11.19+dfsg-2.1ubuntu3
Depends: libc6 (>= 2.34), libssl3 (>= 3.0.0~~alpha1)
Description: Exported ISC Shared Library
The Berkeley Internet Name Domain (BIND) implements an Internet domain
name server. BIND is the most widely-used name server software on the
Internet, and is supported by the Internet Software Consortium, www.isc.org.
.
This package delivers the exported libisc shared library.
Homepage: https://www.isc.org/downloads/bind/
Original-Maintainer: Debian DNS Team <team+dns@tracker.debian.org>

Package: libisl23
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 2159
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: isl
Version: 0.24-2build1
Replaces: libisl-dbg (<< 0.19)
Depends: libc6 (>= 2.14), libgmp10 (>= 2:6.2.1+dfsg)
Breaks: libisl-dbg (<< 0.19)
Description: manipulating sets and relations of integer points bounded by linear constraints
isl is a library for manipulating sets and relations of integer points
bounded by linear constraints. Supported operations on sets include
intersection, union, set difference, emptiness check, convex hull,
(integer) affine hull, integer projection, and computing the lexicographic
minimum using parametric integer programming. It also includes an ILP solver
based on generalized basis reduction.
.
This package contains the runtime library.
Homepage: http://isl.gforge.inria.fr/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libisns0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 492
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: open-isns
Version: 0.101-0ubuntu2
Depends: libc6 (>= 2.33), libssl3 (>= 3.0.0~~alpha1)
Recommends: netbase
Description: Internet Storage Name Service - shared libraries
Open-iSNS is an implementation of the Internet Storage Name Service
(iSNS), according to RFC 4171, which facilitates automated discovery,
management, and configuration of iSCSI and Fibre Channel devices on a
TCP/IP network.
.
This package provides the libisns shared library for use in client
applications.
Homepage: https://github.com/open-iscsi/open-isns
Original-Maintainer: Debian iSCSI Maintainers <open-isns@packages.debian.org>

Package: libitm1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 115
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.34)
Description: GNU Transactional Memory Library
GNU Transactional Memory Library (libitm) provides transaction support for
accesses to the memory of a process, enabling easy-to-use synchronization of
accesses to shared memory by several threads.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libjansson4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 91
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: jansson
Version: 2.13.1-1.1build3
Depends: libc6 (>= 2.14)
Description: C library for encoding, decoding and manipulating JSON data
Jansson is a C library for encoding, decoding and manipulating JSON data.
.
It features:

- Simple and intuitive API and data model
- Comprehensive documentation
- No dependencies on other libraries
- Full Unicode support (UTF-8)
- Extensive test suite
  Homepage: http://www.digip.org/jansson/
  Original-Maintainer: Alessandro Ghedini <ghedo@debian.org>

Package: libjbig0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 82
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: jbigkit
Version: 2.1-3.1build3
Depends: libc6 (>= 2.4)
Description: JBIGkit libraries
JBIG-KIT provides a portable library of compression and decompression functions
with a documented interface that you can include very easily into your image or
document processing software.
.
This package contains the dynamically linked library.
Homepage: http://www.cl.cam.ac.uk/~mgk25/jbigkit/
Original-Maintainer: Michael van der Kolff <mvanderkolff@gmail.com>

Package: libjcat1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 96
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libjcat
Version: 0.1.9-1
Depends: libc6 (>= 2.4), libglib2.0-0 (>= 2.61.2), libgnutls30 (>= 3.7.0), libgpg-error0 (>= 1.14), libgpgme11 (>= 1.2.0), libjson-glib-1.0-0 (>= 1.5.2)
Description: JSON catalog library
The libjcat library assembles checksum and metadata into a JSON based catalog.
.
This is used by other software to validate metadata.
Original-Maintainer: Debian EFI team <debian-efi@lists.debian.org>
Homepage: https://github.com/hughsie/libjcat

Package: libjpeg-turbo8
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 543
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libjpeg-turbo
Version: 2.1.2-0ubuntu1
Replaces: libjpeg8 (<< 8c-2ubuntu5)
Depends: libc6 (>= 2.14)
Breaks: libjpeg8 (<< 8c-2ubuntu5)
Description: IJG JPEG compliant runtime library.
Runtime library supporting the Independent JPEG Group's standard
for JPEG files.
.
This package contains the shared library which is a drop in
replacement for libjpeg8, which has better performance than
standard libjpeg by use of SIMD and other optimizations.
Homepage: http://libjpeg-turbo.virtualgl.org/

Package: libjpeg8
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 9
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libjpeg8-empty
Version: 8c-2ubuntu10
Depends: libjpeg-turbo8 (>= 1.1.90+svn722-1ubuntu6)
Description: Independent JPEG Group's JPEG runtime library (dependency package)
libjpeg8 dependency package, depending on libjpeg-turbo8.

Package: libjs-events
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 43
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: node-events
Version: 3.3.0+~3.0.0-2
Recommends: javascript-common
Description: Node.js events module for browsers
Implements the Node.js events module in browsers.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/Gozala/events

Package: libjs-highlight.js
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 2111
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: highlight.js
Version: 9.18.5+dfsg1-1
Provides: libjs-highlight
Recommends: javascript-common
Description: JavaScript library for syntax highlighting
Highlight.js is a JavaScript library which automatically detects the
language of code blocks in a web page, and provides syntax highlighting
for them. The library supports more than fifty languages and is bundled
with more than twenty style themes.
.
This package contains the library highlight.js usable in a web browser.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://highlightjs.org/

Package: libjs-inherits
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 12
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: node-inherits
Version: 2.0.4-4
Description: Browser library that exposes inherits function from Node.js environment
node-inherits exposes standard inherits implementation of Node.js util
module, and allows bundlers such as browserify to not include full util
package in client code.
.
It is recommended to use this module for all code that requires only
the inherits function and that has a chance to run in a browser too.
.
This is the browser module.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/inherits

Package: libjs-is-typedarray
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 14
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: node-is-typedarray
Version: 1.0.0-4
Recommends: javascript-common
Description: JavaScript library checking if object is TypedArray
Detect whether or not an object is a Typed Array.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/hughsk/is-typedarray

Package: libjs-psl
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 309
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: psl.js
Version: 1.8.0+ds-6
Recommends: javascript-common
Description: Domain name parser based on the Public Suffix List
psl is a JavaScript domain name parser based on the Public Suffix List
(https://publicsuffix.org/). This implementation is tested against the test
data hosted by Mozilla and kindly provided by Comodo.
.
The Public Suffix List is a cross-vendor initiative to provide an accurate
list of domain name suffixes. A "public suffix" is one under which Internet
users can directly register names. Some examples of public suffixes are
".com", ".co.uk" and "pvt.k12.wy.us". The Public Suffix List is a list of all
known public suffixes.
.
This package provides the library for browsers.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/lupomontero/psl#readme

Package: libjs-source-map
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 563
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: node-source-map
Version: 0.7.0++dfsg2+really.0.6.1-9
Recommends: javascript-common
Description: Mozilla source map generator and consumer - JavaScript library
Mozilla implementation of source map generator and consumer, for source
maps written in the Asynchronous Module Definition format.
.
Source maps provide a language-agnostic way to compile back production
code to the original source code.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/mozilla/source-map

Package: libjs-sprintf-js
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: node-sprintf-js
Version: 1.1.2+ds1+~1.1.2-1
Recommends: javascript-common
Suggests: libjs-angularjs
Description: JavaScript sprintf implementation
This package is a javascript implementation of C sprintf (3).
This function composes a string with the same text that would be printed if
format was used on printf, but instead of being printed, the content is
stored as a string in the buffer pointed by a str argument.
.
This package include the minified javascript files that could be used in
browser context.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/alexei/sprintf.js

Package: libjs-typedarray-to-buffer
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: node-typedarray-to-buffer
Version: 4.0.0-2
Recommends: javascript-common
Description: Nodejs utility converting TypedArray to buffer without copy
Convert a typed array to a Buffer without a copy.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/feross/typedarray-to-buffer

Package: libjson-c5
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 97
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: json-c
Version: 0.15-3~ubuntu1.22.04.1
Depends: libc6 (>= 2.33)
Description: JSON manipulation library - shared library
This library allows you to easily construct JSON objects in C,
output them as JSON formatted strings and parse JSON formatted
strings back into the C representation of JSON objects.
Original-Maintainer: Nicolas Mora <babelouest@debian.org>
Homepage: https://github.com/json-c/json-c/wiki

Package: libjson-glib-1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 210
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: json-glib
Version: 1.6.6-1build1
Depends: libjson-glib-1.0-common (>= 1.6.6-1build1), libc6 (>= 2.4), libglib2.0-0 (>= 2.55.2)
Description: GLib JSON manipulation library
JSON-GLib is a library for parsing, generating and manipulating JavaScript
Object Notation (JSON) data streams using the GLib type system. It allows
manipulating JSON data types with a Document Object Model API. It also
allows serializing and deserializing simple or complex GObjects to and
from JSON data types.
Homepage: https://wiki.gnome.org/Projects/JsonGlib
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libjson-glib-1.0-common
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 44
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: json-glib
Version: 1.6.6-1build1
Description: GLib JSON manipulation library (common files)
JSON-GLib is a library for parsing, generating and manipulating JavaScript
Object Notation (JSON) data streams using the GLib type system. It allows
manipulating JSON data types with a Document Object Model API. It also
allows serializing and deserializing simple or complex GObjects to and
from JSON data types.
.
This package contains the translations files.
Homepage: https://wiki.gnome.org/Projects/JsonGlib
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libk5crypto3
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 292
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: krb5
Version: 1.19.2-2
Depends: libc6 (>= 2.33), libkrb5support0 (>= 1.16)
Suggests: krb5-doc, krb5-user
Breaks: libgssapi-krb5-2 (<= 1.18~), libkrb5-3 (<= 1.18~)
Description: MIT Kerberos runtime libraries - Crypto Library
Kerberos is a system for authenticating users and services on a network.
Kerberos is a trusted third-party service. That means that there is a
third party (the Kerberos server) that is trusted by all the entities on
the network (users and services, usually called "principals").
.
This is the MIT reference implementation of Kerberos V5.
.
This package contains the runtime cryptography libraries used by
applications and Kerberos clients.
Original-Maintainer: Sam Hartman <hartmans@debian.org>
Homepage: http://web.mit.edu/kerberos/

Package: libkeyutils1
Status: install ok installed
Priority: required
Section: misc
Installed-Size: 47
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: keyutils
Version: 1.6.1-2ubuntu3
Depends: libc6 (>= 2.14)
Description: Linux Key Management Utilities (library)
Keyutils is a set of utilities for managing the key retention facility in the
kernel, which can be used by filesystems, block devices and more to gain and
retain the authorization and encryption keys required to perform secure
operations.
.
This package provides a wrapper library for the key management facility system
calls.
Homepage: https://people.redhat.com/~dhowells/keyutils/
Original-Maintainer: Christian Kastner <ckk@debian.org>

Package: libklibc
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 114
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: klibc
Version: 2.0.10-4
Description: minimal libc subset for use with initramfs
klibc is intended to be a minimalistic libc subset for use with
initramfs. It is deliberately written for small size, minimal
entanglement, and portability, not speed. It is definitely a work in
progress, and a lot of things are still missing.
Original-Maintainer: Debian Kernel Team <debian-kernel@lists.debian.org>
Homepage: https://git.kernel.org/cgit/libs/klibc/klibc.git

Package: libkmod2
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 139
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: kmod
Version: 29-1ubuntu1
Depends: libc6 (>= 2.33), liblzma5 (>= 5.1.1alpha+20120614), libssl3 (>= 3.0.0~~alpha1), libzstd1 (>= 1.4.0)
Description: libkmod shared library
This library provides an API for insertion, removal, configuration and
listing of kernel modules.
Original-Maintainer: Marco d'Itri <md@linux.it>

Package: libkrb5-3
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 1052
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: krb5
Version: 1.19.2-2
Depends: libc6 (>= 2.34), libcom-err2 (>= 1.43.9), libk5crypto3 (>= 1.15~beta1), libkeyutils1 (>= 1.5.9), libkrb5support0 (= 1.19.2-2), libssl3 (>= 3.0.0~~alpha1)
Recommends: krb5-locales
Suggests: krb5-doc, krb5-user
Breaks: libapache2-mod-auth-kerb (<= 5.4-2.4), libsmbclient (<= 2:3.6.1-2), sssd (<= 1.2.1-4.3)
Description: MIT Kerberos runtime libraries
Kerberos is a system for authenticating users and services on a network.
Kerberos is a trusted third-party service. That means that there is a
third party (the Kerberos server) that is trusted by all the entities on
the network (users and services, usually called "principals").
.
This is the MIT reference implementation of Kerberos V5.
.
This package contains the runtime library for the main Kerberos v5 API
used by applications and Kerberos clients.
Original-Maintainer: Sam Hartman <hartmans@debian.org>
Homepage: http://web.mit.edu/kerberos/

Package: libkrb5support0
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 164
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: krb5
Version: 1.19.2-2
Depends: libc6 (>= 2.34)
Breaks: libgssapi-krb5-2 (<< 1.13~alpha1-1), libk5crypto3 (<< 1.16), libkadm5clnt-mit9 (<< 1.13~alpha1-1), libkadm5srv-mit9 (<< 1.13~alpha1-1), libkdb5-8 (<< 1.16)
Description: MIT Kerberos runtime libraries - Support library
Kerberos is a system for authenticating users and services on a network.
Kerberos is a trusted third-party service. That means that there is a
third party (the Kerberos server) that is trusted by all the entities on
the network (users and services, usually called "principals").
.
This is the MIT reference implementation of Kerberos V5.
.
This package contains an internal runtime support library used by other
Kerberos libraries.
Original-Maintainer: Sam Hartman <hartmans@debian.org>
Homepage: http://web.mit.edu/kerberos/

Package: libksba8
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 302
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libksba
Version: 1.6.0-2build1
Depends: libc6 (>= 2.14), libgpg-error0 (>= 1.14)
Description: X.509 and CMS support library
KSBA (pronounced Kasbah) is a library to make X.509 certificates as
well as the CMS easily accessible by other applications. Both
specifications are building blocks of S/MIME and TLS.
.
KSBA provides these subsystems: ASN.1 Parser, BER Decoder, BER
Encoder, Certificate Handling and CMS Handling.
.
This package contains the runtime library files.
Homepage: https://www.gnupg.org/related_software/libksba/
Original-Maintainer: Debian GnuTLS Maintainers <pkg-gnutls-maint@lists.alioth.debian.org>

Package: liblcms2-2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 414
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: lcms2
Version: 2.12~rc1-2build2
Depends: libc6 (>= 2.29)
Suggests: liblcms2-utils
Description: Little CMS 2 color management library
LittleCMS 2 intends to be a small-footprint color management engine, with
special focus on accuracy and performance. It uses the International Color
Consortium standard (ICC) of color management. LittleCMS 2 is a full
implementation of ICC specification 4.2 plus all addendums. It fully supports
all V2 and V4 profiles, including abstract, devicelink and named color
profiles.
.
This package contains the shared library of liblcms2.
Homepage: http://www.littlecms.com/
Original-Maintainer: Thomas Weber <tweber@debian.org>

Package: libldap-2.5-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 565
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: openldap
Version: 2.5.13+dfsg-0ubuntu0.22.04.1
Replaces: libldap-2.3-0, libldap2
Depends: libc6 (>= 2.34), libgnutls30 (>= 3.7.2), libsasl2-2 (>= 2.1.27+dfsg2)
Recommends: libldap-common
Conflicts: ldap-utils (<= 2.1.23-1)
Description: OpenLDAP libraries
These are the run-time libraries for the OpenLDAP (Lightweight Directory
Access Protocol) servers and clients.
Homepage: https://www.openldap.org/
Original-Maintainer: Debian OpenLDAP Maintainers <pkg-openldap-devel@lists.alioth.debian.org>

Package: libldap-common
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 109
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: openldap
Version: 2.5.13+dfsg-0ubuntu0.22.04.1
Replaces: libldap-2.4-2 (<< 2.4.44+dfsg-1)
Conffiles:
/etc/ldap/ldap.conf 4f02c6860a58b7402a4b5c5ec24aa7b2
Description: OpenLDAP common files for libraries
These are common files for the run-time libraries for the OpenLDAP
(Lightweight Directory Access Protocol) servers and clients.
Homepage: https://www.openldap.org/
Original-Maintainer: Debian OpenLDAP Maintainers <pkg-openldap-devel@lists.alioth.debian.org>

Package: libllvm11
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 81609
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: llvm-toolchain-11
Version: 1:11.1.0-6
Depends: libc6 (>= 2.34), libedit2 (>= 2.11-20080614-0), libffi8 (>= 3.4), libgcc-s1 (>= 3.3), libstdc++6 (>= 11), libtinfo6 (>= 6), libxml2 (>= 2.7.4), zlib1g (>= 1:1.2.0)
Description: Modular compiler and toolchain technologies, runtime library
LLVM is a collection of libraries and tools that make it easy to build
compilers, optimizers, just-in-time code generators, and many other
compiler-related programs.
.
This package contains the LLVM runtime library.
Original-Maintainer: LLVM Packaging Team <pkg-llvm-team@lists.alioth.debian.org>
Homepage: https://www.llvm.org/

Package: libllvm13
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 97545
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: llvm-toolchain-13
Version: 1:13.0.1-2ubuntu2.1
Depends: libc6 (>= 2.34), libedit2 (>= 2.11-20080614-0), libffi8 (>= 3.4), libgcc-s1 (>= 3.3), libstdc++6 (>= 12), libtinfo6 (>= 6), libxml2 (>= 2.7.4), zlib1g (>= 1:1.2.0)
Description: Modular compiler and toolchain technologies, runtime library
LLVM is a collection of libraries and tools that make it easy to build
compilers, optimizers, just-in-time code generators, and many other
compiler-related programs.
.
This package contains the LLVM runtime library.
Homepage: https://www.llvm.org/
Original-Maintainer: LLVM Packaging Team <pkg-llvm-team@lists.alioth.debian.org>

Package: liblmdb0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 109
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: lmdb
Version: 0.9.24-1build2
Depends: libc6 (>= 2.34)
Description: Lightning Memory-Mapped Database shared library
This package contains the LMDB shared library.
.
Lighting Memory-Mapped Database (LMDB) is an ultra-fast, ultra-compact
key-value embedded data store developed for the OpenLDAP Project. It uses
memory-mapped files, so it has the read performance of a pure in-memory
database while still offering the persistence of standard disk-based
databases, and is only limited to the size of the virtual address space, (it
is not limited to the size of physical RAM).
Homepage: http://symas.com/mdb/
Original-Maintainer: LMDB <lmdb@packages.debian.org>

Package: liblocale-gettext-perl
Status: install ok installed
Priority: important
Section: perl
Installed-Size: 59
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.07-4build3
Depends: libc6 (>= 2.34)
Pre-Depends: perl-base, perlapi-5.34.0
Description: module using libc functions for internationalization in Perl
The Locale::gettext module permits access from perl to the gettext() family of
functions for retrieving message strings from databases constructed
to internationalize software.
.
It provides gettext(), dgettext(), dcgettext(), textdomain(),
bindtextdomain(), bind_textdomain_codeset(), ngettext(), dcngettext()
and dngettext().
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/gettext

Package: liblsan0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 2961
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.34), libgcc-s1 (>= 3.3)
Description: LeakSanitizer -- a memory leak detector (runtime)
LeakSanitizer (Lsan) is a memory leak detector which is integrated
into AddressSanitizer.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: liblvm2cmd2.03
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 2938
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: lvm2
Version: 2.03.11-2.1ubuntu4
Depends: libaio1 (>= 0.3.93), libblkid1 (>= 2.24.2), libc6 (>= 2.33), libselinux1 (>= 3.1~), libsystemd0 (>= 222), libudev1 (>= 183), dmeventd
Description: LVM2 command library
This package contains the lvm2cmd shared library.
Homepage: https://sourceware.org/lvm2/
Original-Maintainer: Debian LVM Team <team+lvm@tracker.debian.org>

Package: liblwp-mediatypes-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 72
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.04-1
Depends: perl
Description: module to guess media type for a file or a URL
LWP::MediaTypes provides functions for handling media (also known as MIME)
types and encodings. The mapping from file extensions to media types is
defined by the media.types file. If the ~/.media.types file exists it is used
instead. For backwards compatibility it will also look for ~/.mime.types.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/LWP-MediaTypes

Package: liblwp-protocol-https-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 27
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.10-1
Depends: perl:any, ca-certificates, libio-socket-ssl-perl, libnet-http-perl, libwww-perl
Suggests: libcrypt-ssleay-perl
Description: HTTPS driver for LWP::UserAgent
The LWP::Protocol::https module provides support for using HTTPS schemed URLs
with LWP. LWP::Protocol::https is a plug-in to the LWP protocol handling, so
you don't use it directly. Once the module is installed LWP is able to access
sites using HTTP over SSL/TLS.
.
If hostname verification is requested by LWP::UserAgent's ssl_opts, and
neither SSL_ca_file nor SSL_ca_path is set, then SSL_ca_file is implied to be
the one provided by ca-certificates.
.
This module used to be bundled with libwww-perl, but it was unbundled in
v6.02 in order to be able to declare its dependencies properly for the CPAN
tool-chain. Applications that need HTTPS support can just declare their
dependency on LWP::Protocol::https and will no longer need to know what
underlying modules to install.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/LWP-Protocol-https

Package: liblz4-1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 145
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: lz4
Version: 1.9.3-2build2
Replaces: liblz4-1a
Depends: libc6 (>= 2.14)
Breaks: liblz4-1a
Description: Fast LZ compression algorithm library - runtime
LZ4 is a very fast lossless compression algorithm, providing compression speed
at 400 MB/s per core, scalable with multi-cores CPU. It also features an
extremely fast decoder, with speed in multiple GB/s per core, typically
reaching RAM speed limits on multi-core systems.
.
This package includes the shared library.
Homepage: https://github.com/Cyan4973/lz4
Original-Maintainer: Nobuhiro Iwamatsu <iwamatsu@debian.org>

Package: liblzma5
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 290
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: xz-utils
Version: 5.2.5-2ubuntu1
Depends: libc6 (>= 2.34)
Breaks: liblzma2 (<< 5.1.1alpha+20110809-3~)
Description: XZ-format compression library
XZ is the successor to the Lempel-Ziv/Markov-chain Algorithm
compression format, which provides memory-hungry but powerful
compression (often better than bzip2) and fast, easy decompression.
.
The native format of liblzma is XZ; it also supports raw (headerless)
streams and the older LZMA format used by lzma. (For 7-Zip's related
format, use the p7zip package instead.)
Homepage: https://tukaani.org/xz/
Original-Maintainer: Jonathan Nieder <jrnieder@gmail.com>

Package: liblzo2-2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 159
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: lzo2
Version: 2.10-2build3
Depends: libc6 (>= 2.14)
Description: data compression library
LZO is a portable, lossless data compression library.
It offers pretty fast compression and very fast decompression.
Decompression requires no memory. In addition there are slower
compression levels achieving a quite competitive compression ratio
while still decompressing at this very high speed.
Homepage: https://www.oberhumer.com/opensource/lzo/
Original-Maintainer: Stephen Kitt <skitt@debian.org>

Package: libmagic-mgc
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 7127
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: file
Version: 1:5.41-3
Replaces: libmagic1 (<< 1:5.28-4~)
Breaks: libmagic1 (<< 1:5.28-4~)
Description: File type determination library using "magic" numbers (compiled magic file)
This package provides the compiled magic file "magic.mgc". It has
been separated from libmagic1 in order to meet the multiarch
requirements without breaking applications that expect this file
at its absolute path.
Original-Maintainer: Christoph Biedl <debian.axhn@manchmal.in-ulm.de>
Homepage: https://www.darwinsys.com/file/

Package: libmagic1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 228
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: file
Version: 1:5.41-3
Depends: libbz2-1.0, libc6 (>= 2.33), liblzma5 (>= 5.1.1alpha+20120614), zlib1g (>= 1:1.1.4), libmagic-mgc (= 1:5.41-3)
Suggests: file
Conffiles:
/etc/magic 272913026300e7ae9b5e2d51f138e674
/etc/magic.mime 272913026300e7ae9b5e2d51f138e674
Description: Recognize the type of data in a file using "magic" numbers - library
This library can be used to classify files according to magic number
tests. It implements the core functionality of the file command.
Original-Maintainer: Christoph Biedl <debian.axhn@manchmal.in-ulm.de>
Homepage: https://www.darwinsys.com/file/

Package: libmailtools-perl
Status: install ok installed
Priority: optional
Section: mail
Installed-Size: 223
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.21-1
Depends: perl, libnet-perl, libnet-smtp-ssl-perl, libtest-simple-perl, libtimedate-perl
Description: modules to manipulate email in perl programs
MailTools is a set of perl modules which provide an easy interface to
manipulating email in an object-oriented fashion.
.
Mail::Address - Parse mail addresses
Mail::Cap - Parse mailcap files
Mail::Field - Base class for manipulation of mail header fields
Mail::Field::AddrList - object representation of e-mail address lists
Mail::Field::Date - a date header field
Mail::Field::Generic - implementation for inspecific fields
Mail::Filter - Filter mail through multiple subroutines
Mail::Header - manipulate MIME headers
Mail::Internet - manipulate email messages
Mail::Mailer - Simple interface to electronic mailing mechanisms
Mail::Send - Simple electronic mail interface
Mail::Util - mail utility functions
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/MailTools

Package: libmaxminddb0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 76
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libmaxminddb
Version: 1.5.2-1build2
Depends: libc6 (>= 2.33)
Suggests: mmdb-bin
Description: IP geolocation database library
The libmaxminddb library provides a C library for reading MaxMind DB files,
including the GeoIP2 databases from MaxMind. This is a custom binary format
designed to facilitate fast lookups of IP addresses while allowing for great
flexibility in the type of data associated with an address.
.
The MaxMind DB format is an open format. The spec is available at
http://maxmind.github.io/MaxMind-DB/. This spec is licensed under the Creative
Commons Attribution-ShareAlike 3.0 Unported License.
Homepage: https://maxmind.github.io/libmaxminddb/
Original-Maintainer: Faidon Liambotis <paravoid@debian.org>

Package: libmbim-glib4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 492
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libmbim
Version: 1.26.2-1build1
Depends: libc6 (>= 2.14), libglib2.0-0 (>= 2.56)
Description: Support library to use the MBIM protocol
libmbim is a glib-based library for talking to WWAN modems and devices
which speak the Mobile Interface Broadband Model (MBIM) protocol.
Homepage: https://www.freedesktop.org/wiki/Software/libmbim/
Original-Maintainer: DebianOnMobile Maintainers <debian-on-mobile-maintainers@alioth-lists.debian.net>

Package: libmbim-proxy
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 33
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: libmbim
Version: 1.26.2-1build1
Depends: libc6 (>= 2.34), libglib2.0-0 (>= 2.56), libmbim-glib4 (= 1.26.2-1build1)
Description: Proxy to communicate with MBIM ports
libmbim is a glib-based library for talking to WWAN modems and devices
which speak the Mobile Interface Broadband Model (MBIM) protocol.
.
This package contains the binary mbim-proxy used by libmbim to allow multiple
clients to use the same MBIM port simultaneously.
Homepage: https://www.freedesktop.org/wiki/Software/libmbim/
Original-Maintainer: DebianOnMobile Maintainers <debian-on-mobile-maintainers@alioth-lists.debian.net>

Package: libmd0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 71
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libmd
Version: 1.0.4-1build1
Depends: libc6 (>= 2.33)
Description: message digest functions from BSD systems - shared library
The libmd library provides various message digest ("hash") functions,
as found on various BSDs on a library with the same name and with a
compatible API.
Homepage: https://www.hadrons.org/software/libmd/
Original-Maintainer: Guillem Jover <guillem@debian.org>

Package: libmm-glib0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 1122
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: modemmanager
Version: 1.18.6-1
Depends: libc6 (>= 2.14), libglib2.0-0 (>= 2.56.0)
Recommends: modemmanager (>= 1.18.6-1)
Description: D-Bus service for managing modems - shared libraries
ModemManager is a DBus-activated daemon which controls mobile broadband
(2G/3G/4G/5G) devices and connections. Whether built-in devices, USB dongles,
Bluetooth-paired telephones or professional RS232/USB devices with external
power supplies, ModemManager is able to prepare and configure the modems and
setup connections with them.
.
This package contains shared libraries for applications interfacing with
ModemManager.
Original-Maintainer: DebianOnMobile Maintainers <debian-on-mobile-maintainers@alioth-lists.debian.net>
Homepage: https://www.freedesktop.org/wiki/Software/ModemManager/

Package: libmnl0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 47
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libmnl
Version: 1.0.4-3build2
Depends: libc6 (>= 2.14)
Description: minimalistic Netlink communication library
libmnl is a minimalistic user-space library oriented to Netlink developers.
There are a lot of common tasks in parsing, validating, constructing of
both the Netlink header and TLVs that are repetitive and easy to get wrong.
This library aims to provide simple helpers that allows you to re-use code
and to avoid re-inventing the wheel.
.
The main features of this library are:
.
Small: the shared library requires around 30KB for an x86-based computer.
.
Simple: this library avoids complexity and elaborated abstractions that
tend to hide Netlink details.
.
Easy to use: the library simplifies the work for Netlink-wise developers.
It provides functions to make socket handling, message building,
validating, parsing and sequence tracking, easier.
.
Easy to re-use: you can use the library to build your own abstraction
layer on top of this library.
.
Decoupling: the interdependency of the main bricks that compose the
library is reduced, i.e. the library provides many helpers, but the
programmer is not forced to use them.
.
This package contains the shared libraries needed to run programs that use
the minimalistic Netlink communication library.
Homepage: https://netfilter.org/projects/libmnl/
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>

Package: libmodule-find-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 29
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.15-1
Depends: perl
Description: module to find and use installed Perl modules
Module::Find is a Perl module that allows developers to find and use modules
in categories. This is useful for auto-detecting driver or plugin modules.
You can differentiate between looking in the category itself or in all
subcategories.
.
If you want Module::Find to search in a certain directory (like the plugins
directory of your software installation), make sure you modify @INC before
you call the Module::Find functions.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Module-List

Package: libmodule-scandeps-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 95
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.31-1
Depends: perl:any
Description: module to recursively scan Perl code for dependencies
Module::ScanDeps is a Perl module that scans potential modules used by perl
programs to determine information about modules they depend on. It performs
static analysis as well as more aggressive scanning (by running files in
compile-only or normal mode).
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Module-ScanDeps

Package: libmount1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 382
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: util-linux
Version: 2.37.2-4ubuntu3
Depends: libblkid1 (>= 2.17.2), libc6 (>= 2.34), libselinux1 (>= 3.1~)
Suggests: cryptsetup-bin
Description: device mounting library
This device mounting library is used by mount and umount helpers.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: libmpc3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 125
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: mpclib3
Version: 1.2.1-2build1
Depends: libc6 (>= 2.4), libgmp10 (>= 2:6.2.1+dfsg), libmpfr6 (>= 4.0.0)
Description: multiple precision complex floating-point library
MPC is a portable library written in C for arbitrary precision
arithmetic on complex numbers providing correct rounding. For the time
being, it contains all arithmetic operations over complex numbers, the
exponential and the logarithm functions, the trigonometric and
hyperbolic functions.
.
Ultimately, it should implement a multiprecision equivalent of the ISO
C99 standard.
.
It builds upon the GNU MP and the MPFR libraries.
Homepage: http://www.multiprecision.org/mpc/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libmpdec3
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 250
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: mpdecimal
Version: 2.5.1-2build2
Depends: libc6 (>= 2.32), libgcc-s1 (>= 3.3.1), libstdc++6 (>= 5.2)
Breaks: libpython3.8-stdlib (<< 2.8.5-2)
Description: library for decimal floating point arithmetic (runtime library)
mpdecimal is a package for correctly-rounded arbitrary precision decimal
floating point arithmetic.
Homepage: https://www.bytereef.org/mpdecimal/index.html
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: libmpfr6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 3405
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: mpfr4
Version: 4.1.0-3build3
Depends: libc6 (>= 2.14), libgmp10 (>= 2:6.2.1+dfsg)
Breaks: libgmp3 (<< 4.1.4-3), libmpc3 (<< 1.1.0-1~)
Description: multiple precision floating-point computation
MPFR provides a library for multiple-precision floating-point computation
with correct rounding. The computation is both efficient and has a
well-defined semantics. It copies the good ideas from the
ANSI/IEEE-754 standard for double-precision floating-point arithmetic
(53-bit mantissa).
Homepage: https://www.mpfr.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libmspack0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 96
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libmspack
Version: 0.10.1-2build2
Depends: libc6 (>= 2.14)
Description: library for Microsoft compression formats (shared library)
The purpose of libmspack is to provide both compression and decompression of
some loosely related file formats used by Microsoft. The intention is to
support all of the following formats: COMPRESS.EXE [SZDD],
Microsoft Help (.HLP), COMPRESS.EXE [KWAJ], Microsoft Cabinet (.CAB),
HTML Help (.CHM), Microsoft eBook (.LIT), Windows Imaging Format (.WIM),
Exchange Offline Address Book (.LZX).
Homepage: https://www.cabextract.org.uk/libmspack/
Original-Maintainer: Marc Dequènes (Duck) <Duck@DuckCorp.org>

Package: libncurses6
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 329
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: ncurses
Version: 6.3-2
Depends: libtinfo6 (= 6.3-2), libc6 (>= 2.34)
Recommends: libgpm2
Breaks: cowdancer (<< 0.89~)
Description: shared libraries for terminal handling
The ncurses library routines are a terminal-independent method of
updating character screens with reasonable optimization.
.
This package contains the shared libraries necessary to run programs
compiled with ncurses.
Original-Maintainer: Craig Small <csmall@debian.org>
Homepage: https://invisible-island.net/ncurses/

Package: libncursesw6
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 422
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: ncurses
Version: 6.3-2
Depends: libtinfo6 (= 6.3-2), libc6 (>= 2.34)
Recommends: libgpm2
Description: shared libraries for terminal handling (wide character support)
The ncurses library routines are a terminal-independent method of
updating character screens with reasonable optimization.
.
This package contains the shared libraries necessary to run programs
compiled with ncursesw, which includes support for wide characters.
Original-Maintainer: Craig Small <csmall@debian.org>
Homepage: https://invisible-island.net/ncurses/

Package: libnet-dbus-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 622
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.2.0-1build3
Depends: perl, perlapi-5.34.0, libc6 (>= 2.34), libdbus-1-3 (>= 1.9.14), libxml-twig-perl
Description: Perl extension for the DBus bindings
Net::DBus provides a Perl API for the DBus message system. The DBus Perl
interface is currently operating against the 0.32 development version of
DBus, but should work with later versions too, providing the API changes have
not been too drastic.
.
Users of this package are either typically, service providers in which case
the Net::DBus::Service and Net::DBus::Object modules are of most relevance,
or are client consumers, in which case Net::DBus::RemoteService and
Net::DBus::RemoteObject are of most relevance.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Net-DBus

Package: libnet-http-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 61
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.22-1
Depends: perl:any, libio-socket-ip-perl, liburi-perl
Recommends: libio-socket-ssl-perl
Description: module providing low-level HTTP connection client
The Net::HTTP class is a low-level HTTP client. An instance of the
Net::HTTP class represents a connection to an HTTP server. The
HTTP protocol is described in RFC 2616. The Net::HTTP class
supports HTTP/1.0 and HTTP/1.1. Net::HTTP is a sub-class of IO::Socket::INET.
You can mix its methods with reading and writing from the socket directly.
This is not necessarily a good idea, unless you know what you are doing.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Net-HTTP

Package: libnet-smtp-ssl-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.04-1
Depends: libio-socket-ssl-perl, perl
Recommends: libauthen-sasl-perl
Description: Perl module providing SSL support to Net::SMTP
Net::SMTP::SSL implements the same API as Net::SMTP, but uses IO::Socket::SSL
for its network operations. Due to the nature of Net::SMTP's new method, it is
not overridden to make use of a default port for the SMTPS service. Perhaps
future versions will be smart like that. Port 465 is usually what you want,
and it's not a pain to specify that.
.
This package is deprecated. Net::SMTP (in perl core) has support for SMTP
over SSL, and also for STARTTLS, since version 1.28 (included in Perl 5.22).
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Net-SMTP-SSL

Package: libnet-ssleay-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 1345
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 1.92-1build2
Depends: perl, perl-openssl-abi-3, perlapi-5.34.0, libc6 (>= 2.34), libssl3 (>= 3.0.0~~alpha1)
Description: Perl module for Secure Sockets Layer (SSL)
Net::SSLeay is a perl module that allows you to call Secure Sockets Layer
(SSL) functions of the SSLeay library directly from your perl scripts. It
is useful if you want to program robots that access secure web servers or
if you want to build your own applications over SSL encrypted tunnels. If
you just want to view web pages on https servers, you do not need this -
your web browser already knows to do that.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Net-SSLeay

Package: libnetfilter-conntrack3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 141
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libnetfilter-conntrack
Version: 1.0.9-1
Depends: libc6 (>= 2.14), libmnl0 (>= 1.0.3-4~), libnfnetlink0
Description: Netfilter netlink-conntrack library
libnetfilter_conntrack is a userspace library providing a programming
interface (API) to the in-kernel connection tracking state table.
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>
Homepage: https://www.netfilter.org/projects/libnetfilter_conntrack/

Package: libnetplan0
Status: install ok installed
Priority: important
Section: net
Installed-Size: 280
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: netplan.io
Version: 0.104-0ubuntu2.1
Depends: libc6 (>= 2.27), libglib2.0-0 (>= 2.70.0), libuuid1 (>= 2.16), libyaml-0-2
Description: YAML network configuration abstraction runtime library
netplan reads YAML network configuration files which are written
by administrators, installers, cloud image instantiations, or other OS
deployments. During early boot it then generates backend specific
configuration files in /run to hand off control of devices to a particular
networking daemon.
.
Currently supported backends are networkd and NetworkManager.
.
This package contains the necessary runtime library files.
Homepage: https://netplan.io/
Original-Maintainer: Debian netplan Maintainers <team+netplan@tracker.debian.org>

Package: libnettle8
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 356
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: nettle
Version: 3.7.3-1build2
Depends: libc6 (>= 2.17)
Description: low level cryptographic library (symmetric and one-way cryptos)
Nettle is a cryptographic library that is designed to fit easily in more or
less any context: In crypto toolkits for object-oriented languages (C++,
Python, Pike, ...), in applications like LSH or GNUPG, or even in kernel
space.
.
It tries to solve a problem of providing a common set of cryptographic
algorithms for higher-level applications by implementing a
context-independent set of cryptographic algorithms. In that light, Nettle
doesn't do any memory allocation or I/O, it simply provides the
cryptographic algorithms for the application to use in any environment and
in any way it needs.
.
This package contains the symmetric and one-way cryptographic
algorithms. To avoid having this package depend on libgmp, the
asymmetric cryptos reside in a separate library, libhogweed.
Homepage: http://www.lysator.liu.se/~nisse/nettle/
Original-Maintainer: Magnus Holmgren <holmgren@debian.org>

Package: libnewt0.52
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 200
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: newt
Version: 0.52.21-5ubuntu2
Depends: libc6 (>= 2.34), libslang2 (>= 2.2.4)
Recommends: libfribidi0
Conffiles:
/etc/newt/palette.original d41d8cd98f00b204e9800998ecf8427e
/etc/newt/palette.ubuntu ac72ec93d29d94ad06bb3180f16cefb1
Description: Not Erik's Windowing Toolkit - text mode windowing with slang
Newt is a windowing toolkit for text mode built from the slang library.
It allows color text mode applications to easily use stackable windows,
push buttons, check boxes, radio buttons, lists, entry fields, labels,
and displayable text. Scrollbars are supported, and forms may be nested
to provide extra functionality. This package contains the shared library
for programs that have been built with newt.
Homepage: https://pagure.io/newt
Original-Maintainer: Alastair McKinstry <mckinstry@debian.org>

Package: libnfnetlink0
Status: install ok installed
Priority: extra
Section: libs
Installed-Size: 48
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libnfnetlink
Version: 1.0.1-3build3
Depends: libc6 (>= 2.14)
Description: Netfilter netlink library
libnfnetlink is the low-level library for netfilter related
kernel/userspace communication. It provides a generic messaging
infrastructure for in-kernel netfilter subsystems (such as
nfnetlink_log, nfnetlink_queue, nfnetlink_conntrack) and their
respective users and/or management tools in userspace.
Original-Maintainer: Alexander Wirt <formorer@debian.org>

Package: libnftables1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 913
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: nftables
Version: 1.0.2-1ubuntu3
Depends: libc6 (>= 2.33), libgmp10 (>= 2:6.2.1+dfsg), libjansson4 (>= 2.3), libmnl0 (>= 1.0.3-4~), libnftnl11 (>= 1.2.1), libxtables12 (>= 1.6.0+snapshot20161117)
Description: Netfilter nftables high level userspace API library
This library provides high level semantics to interact with the nftables
framework by Netfilter project.
.
nftables replaces the old popular iptables, ip6tables, arptables and ebtables.
.
Netfilter software and nftables in particular are used in applications such
as Internet connection sharing, firewalls, IP accounting, transparent
proxying, advanced routing and traffic control.
.
A Linux kernel >= 3.13 is required. However, >= 4.14 is recommended.
.
This package contains the libnftables library.
Homepage: https://www.netfilter.org/
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>

Package: libnftnl11
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 227
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libnftnl
Version: 1.2.1-1build1
Depends: libc6 (>= 2.14), libmnl0 (>= 1.0.3-4~)
Description: Netfilter nftables userspace API library
libnftnl is the low-level library for Netfilter 4th generation
framework nftables.
.
Is the user-space library for low-level interaction with
nftables Netlink's API over libmnl.
Homepage: https://git.netfilter.org/libnftnl
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>

Package: libnghttp2-14
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 203
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: nghttp2
Version: 1.43.0-1build3
Depends: libc6 (>= 2.14)
Description: library implementing HTTP/2 protocol (shared library)
This is an implementation of the Hypertext Transfer Protocol version
2 in C. The framing layer of HTTP/2 is implemented as a reusable C
library.
.
This package installs a shared library.
Homepage: https://nghttp2.org/
Original-Maintainer: Tomasz Buchert <tomasz@debian.org>

Package: libnl-3-200
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 180
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libnl3
Version: 3.5.0-0.1
Depends: libc6 (>= 2.34)
Conffiles:
/etc/libnl-3/classid 3e07259e58674631830b152e983ca995
/etc/libnl-3/pktloc 7613dbc41b2dc3258195b6b6abd0f179
Description: library for dealing with netlink sockets
This is a library for applications dealing with netlink sockets.
The library provides an interface for raw netlink messaging and various
netlink family specific interfaces.
Original-Maintainer: Heiko Stuebner <mmind@debian.org>
Homepage: http://www.infradead.org/~tgr/libnl/

Package: libnl-genl-3-200
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 61
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libnl3
Version: 3.5.0-0.1
Depends: libnl-3-200 (= 3.5.0-0.1), libc6 (>= 2.4)
Description: library for dealing with netlink sockets - generic netlink
This is a library for applications dealing with netlink sockets.
The library provides an interface for raw netlink messaging and various
netlink family specific interfaces.
.
API to the generic netlink protocol, an extended version of the netlink
protocol.
Original-Maintainer: Heiko Stuebner <mmind@debian.org>
Homepage: http://www.infradead.org/~tgr/libnl/

Package: libnode-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 6001
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: nodejs
Version: 12.22.9~dfsg-1ubuntu3
Replaces: nodejs-dev (<< 10.0.0~dfsg1-3)
Provides: libv8-dev
Depends: libssl-dev, libuv1-dev (>= 1.33.0~), libnode72 (= 12.22.9~dfsg-1ubuntu3)
Breaks: nodejs-dev (<< 10.0.0~dfsg1-3)
Description: evented I/O for V8 javascript (development files)
Node.js is a platform built on Chrome's JavaScript runtime for easily
building fast, scalable network applications. Node.js uses an
event-driven, non-blocking I/O model that makes it lightweight and
efficient, perfect for data-intensive real-time applications that run
across distributed devices.
.
This package provides development headers for libnode72
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@alioth-lists.debian.net>
Homepage: https://nodejs.org/

Package: libnode72
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 40236
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: nodejs
Version: 12.22.9~dfsg-1ubuntu3
Depends: libbrotli1 (>= 1.0.0), libc-ares2 (>= 1.11.0~rc1), libc6 (>= 2.34), libgcc-s1 (>= 3.4), libicu70 (>= 70.1-1~), libnghttp2-14 (>= 1.41.0), libstdc++6 (>= 11), libuv1 (>= 1.39.0), zlib1g (>= 1:1.1.4)
Breaks: libnode64
Description: evented I/O for V8 javascript - runtime library
Node.js is a platform built on Chrome's JavaScript runtime for easily
building fast, scalable network applications. Node.js uses an
event-driven, non-blocking I/O model that makes it lightweight and
efficient, perfect for data-intensive real-time applications that run
across distributed devices.
.
Node.js is bundled with several useful libraries to handle server
tasks:
.
System, Events, Standard I/O, Modules, Timers, Child Processes, POSIX,
HTTP, Multipart Parsing, TCP, DNS, Assert, Path, URL, Query Strings.
.
This package provides the dynamic library for Node.js.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@alioth-lists.debian.net>
Homepage: https://nodejs.org/

Package: libnotify-bin
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 39
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: libnotify
Version: 0.7.9-3ubuntu5.22.04.1
Depends: libc6 (>= 2.34), libglib2.0-0 (>= 2.26), libnotify4 (>= 0.7.3)
Description: sends desktop notifications to a notification daemon (Utilities)
A library that sends desktop notifications to a notification daemon, as
defined in the Desktop Notifications spec. These notifications can be
used to inform the user about an event or display some form of
information without getting in the user's way.
.
This package contains the binary which sends the notification.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libnotify4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 66
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libnotify
Version: 0.7.9-3ubuntu5.22.04.1
Depends: libc6 (>= 2.7), libgdk-pixbuf-2.0-0 (>= 2.22.0), libglib2.0-0 (>= 2.37.3)
Suggests: gnome-shell | notification-daemon
Description: sends desktop notifications to a notification daemon
A library that sends desktop notifications to a notification daemon, as
defined in the Desktop Notifications spec. These notifications can be
used to inform the user about an event or display some form of
information without getting in the user's way.
.
This package contains the shared library. To actually display the
notifications, you need to install the package notification-daemon.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libnpth0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 40
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: npth
Version: 1.6-3build2
Depends: libc6 (>= 2.34)
Description: replacement for GNU Pth using system threads
nPth is a non-preemptive threads implementation using an API very
similar to the one known from GNU Pth. It has been designed as a
replacement of GNU Pth for non-ancient operating systems. In
contrast to GNU Pth it is based on the system's standard threads
implementation. Thus nPth allows the use of libraries which are not
compatible to GNU Pth.
Homepage: https://www.gnupg.org/
Original-Maintainer: Eric Dorland <eric@debian.org>

Package: libnsl-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 347
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libnsl
Version: 1.3.0-2build2
Replaces: libc6-dev (<< 2.31-4)
Depends: libnsl2 (= 1.3.0-2build2), libtirpc-dev
Breaks: libc6-dev (<< 2.31-4)
Description: libnsl development files
This package contains the files needed for developing applications that
use libnsl.
Homepage: https://github.com/thkukuk/libnsl
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>

Package: libnsl2
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 123
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libnsl
Version: 1.3.0-2build2
Depends: libc6 (>= 2.33), libtirpc3 (>= 1.0.2)
Description: Public client interface for NIS(YP) and NIS+
This package contains the libnsl library, which contains the public client
interface for NIS(YP) and NIS+. This code was formerly part of glibc, but is
now standalone to be able to link against TI-RPC for IPv6 support.
Homepage: https://github.com/thkukuk/libnsl
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>

Package: libnspr4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 314
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: nspr
Version: 2:4.32-3build1
Depends: libc6 (>= 2.34)
Description: NetScape Portable Runtime Library
This library provides platform independent non-GUI operating system
facilities including:

- threads,
- thread synchronisation,
- normal file I/O and network I/O,
- interval timing and calendar time,
- basic memory management (malloc and free),
- shared library linking.
  Homepage: http://www.mozilla.org/projects/nspr/
  Original-Maintainer: Maintainers of Mozilla-related packages <team+pkg-mozilla@tracker.debian.org>

Package: libnss-systemd
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 488
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: systemd
Version: 249.11-0ubuntu3.4
Depends: libc6 (>= 2.34), systemd (= 249.11-0ubuntu3.4)
Description: nss module providing dynamic user and group name resolution
nss-systemd is a plug-in module for the GNU Name Service Switch (NSS)
functionality of the GNU C Library (glibc), providing UNIX user and group name
resolution for dynamic users and groups allocated through the DynamicUser=
option in systemd unit files. See systemd.exec(5) for details on this
option.
.
Installing this package automatically adds the module to /etc/nsswitch.conf.
Homepage: https://www.freedesktop.org/wiki/Software/systemd
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: libnss3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 3804
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: nss
Version: 2:3.68.2-0ubuntu1.1
Depends: libc6 (>= 2.34), libnspr4 (>= 2:4.24), libsqlite3-0 (>= 3.5.9)
Conflicts: libnss3-1d (<< 2:3.13.4-2)
Description: Network Security Service libraries
This is a set of libraries designed to support cross-platform development
of security-enabled client and server applications. It can support SSLv2
and v4, TLS, PKCS #5, #7, #11, #12, S/MIME, X.509 v3 certificates and
other security standards.
Homepage: http://www.mozilla.org/projects/security/pki/nss/
Original-Maintainer: Maintainers of Mozilla-related packages <team+pkg-mozilla@tracker.debian.org>

Package: libntfs-3g89
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 371
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: ntfs-3g
Version: 1:2021.8.22-3ubuntu1.1
Depends: libc6 (>= 2.33)
Description: read/write NTFS driver for FUSE (runtime library)
NTFS-3G uses FUSE (Filesystem in Userspace) to provide support for the NTFS
filesystem used by Microsoft Windows.
.
This package contains the actual library.
Homepage: https://github.com/tuxera/ntfs-3g/wiki
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>

Package: libnuma1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 71
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: numactl
Version: 2.0.14-3ubuntu2
Depends: libc6 (>= 2.33)
Description: Libraries for controlling NUMA policy
Library to control specific NUMA (Non-Uniform Memory Architecture)
scheduling or memory placement policies.
Homepage: https://github.com/numactl/numactl
Original-Maintainer: Ian Wienand <ianw@debian.org>

Package: libopeniscsiusr
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 198
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: open-iscsi
Version: 2.1.5-1ubuntu1
Replaces: libopeniscsiusr0.2.0 (<< 2.1.4-0ubuntu1~)
Depends: libc6 (>= 2.33), libkmod2 (>= 5~)
Breaks: libopeniscsiusr0.2.0 (<< 2.1.4-0ubuntu1~)
Enhances: open-iscsi
Description: iSCSI userspace library
The Open-iSCSI project is a high-performance, transport independent,
multi-platform implementation of RFC3720 iSCSI.
.
Open-iSCSI is partitioned into user and kernel parts.
.
The kernel portion of Open-iSCSI is a from-scratch code
licensed under GPL. The kernel part implements iSCSI data path
(that is, iSCSI Read and iSCSI Write), and consists of three
loadable modules: scsi_transport_iscsi.ko, libiscsi.ko and iscsi_tcp.ko.
.
User space contains the entire control plane: configuration
manager, iSCSI Discovery, Login and Logout processing,
connection-level error processing, Nop-In and Nop-Out handling,
and (in the future:) Text processing, iSNS, SLP, Radius, etc.
.
The user space Open-iSCSI consists of a daemon process called
iscsid, and a management utility iscsiadm.
.
This package contains the iSCSI userspace library.
Homepage: https://www.open-iscsi.com/
Original-Maintainer: Debian iSCSI Maintainers <open-iscsi@packages.debian.org>

Package: libp11-kit0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 1292
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: p11-kit
Version: 0.24.0-6build1
Depends: libc6 (>= 2.34), libffi8 (>= 3.4)
Breaks: opencryptoki (<= 3.6.1+dfsg-1)
Description: library for loading and coordinating access to PKCS#11 modules - runtime
The p11-kit library provides a way to load and enumerate Public-Key
Cryptography Standard #11 modules, along with a standard configuration
setup for installing PKCS#11 modules so that they're discoverable. It
also solves problems with coordinating the use of PKCS#11 by different
components or libraries living in the same process.
.
This package contains the shared library required for applications loading
and accessing PKCS#11 modules.
Homepage: https://p11-glue.github.io/p11-glue/p11-kit.html
Original-Maintainer: Debian GnuTLS Maintainers <pkg-gnutls-maint@lists.alioth.debian.org>

Package: libpackagekit-glib2-18
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 463
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: packagekit
Version: 1.2.5-2ubuntu2
Depends: libc6 (>= 2.7), libglib2.0-0 (>= 2.54)
Recommends: packagekit (= 1.2.5-2ubuntu2)
Description: Library for accessing PackageKit using GLib
PackageKit allows performing simple software management tasks over a DBus
interface e.g. refreshing the cache, updating, installing and removing
software packages or searching for multimedia codecs and file handlers.
.
This package provides an advanced library to access PackageKit using GLib.
It makes use of only async D-Bus calls and provides high level tasks which
peform the "transaction dance".
Homepage: https://www.freedesktop.org/software/PackageKit/
Original-Maintainer: Matthias Klumpp <mak@debian.org>

Package: libpam-cap
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libcap2
Version: 1:2.44-1build3
Replaces: libcap2-bin (<< 1:2.22-1.1)
Depends: libc6 (>= 2.4), libcap2 (>= 1:2.33), libpam0g (>= 0.99.7.1), libpam-runtime (>= 1.1.3-2~)
Breaks: libcap2-bin (<< 1:2.22-1.1)
Conffiles:
/etc/security/capability.conf fa5804a90b16addeec23008102b4746d
Description: POSIX 1003.1e capabilities (PAM module)
Libcap implements the user-space interfaces to the POSIX 1003.1e capabilities
available in Linux kernels. These capabilities are a partitioning of the all
powerful root privilege into a set of distinct privileges.
.
This package contains the PAM module for enforcing capabilities on users and
groups at PAM session start time.
Homepage: https://sites.google.com/site/fullycapable/
Original-Maintainer: Christian Kastner <ckk@debian.org>

Package: libpam-modules
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 1138
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pam
Version: 1.4.0-11ubuntu2
Replaces: libpam-umask, libpam0g-util
Provides: libpam-mkhomedir, libpam-motd, libpam-umask
Pre-Depends: libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), libcrypt1 (>= 1:4.3.0), libdb5.3, libnsl2 (>= 1.0), libpam0g (>= 1.3.2), libselinux1 (>= 3.1~), libtirpc3 (>= 1.0.2), debconf (>= 0.5) | debconf-2.0, libpam-modules-bin (= 1.4.0-11ubuntu2)
Conflicts: libpam-mkhomedir, libpam-motd, libpam-umask
Conffiles:
/etc/security/access.conf dc21d0fd769d655b311d785670e5c6ae
/etc/security/faillock.conf 164da8ffb87f3074179bc60b71d0b99f
/etc/security/group.conf f1e26e8db6f7abd2d697d7dad3422c36
/etc/security/limits.conf 38dce56af34daf316b901d465769a137
/etc/security/namespace.conf 6b3796403421d66db7defc46517711bc
/etc/security/namespace.init d9e6a7c85e966427ef23a04ec6c7000f
/etc/security/pam_env.conf 89cc8702173d5cd51abc152ae9f8d6bc
/etc/security/sepermit.conf d41c74654734a5c069a37bfc02f0a6d4
/etc/security/time.conf 06e05c6079e839c8833ac7c3abfde192
Description: Pluggable Authentication Modules for PAM
This package completes the set of modules for PAM. It includes the
pam_unix.so module as well as some specialty modules.
Homepage: http://www.linux-pam.org/
Original-Maintainer: Steve Langasek <vorlon@debian.org>

Package: libpam-modules-bin
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 248
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: pam
Version: 1.4.0-11ubuntu2
Replaces: libpam-modules (<< 1.1.3-8)
Depends: libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), libcrypt1 (>= 1:4.3.0), libpam0g (>= 0.99.7.1), libselinux1 (>= 3.1~)
Description: Pluggable Authentication Modules for PAM - helper binaries
This package contains helper binaries used by the standard set of PAM
modules in the libpam-modules package.
Homepage: http://www.linux-pam.org/
Original-Maintainer: Steve Langasek <vorlon@debian.org>

Package: libpam-runtime
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 312
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: pam
Version: 1.4.0-11ubuntu2
Replaces: libpam0g-dev, libpam0g-util
Depends: debconf (>= 0.5) | debconf-2.0, debconf (>= 1.5.19) | cdebconf, libpam-modules (>= 1.0.1-6)
Conflicts: libpam0g-util
Conffiles:
/etc/pam.conf 87fc76f18e98ee7d3848f6b81b3391e5
/etc/pam.d/other 31aa7f2181889ffb00b87df4126d1701
Description: Runtime support for the PAM library
Contains configuration files and directories required for
authentication to work on Debian systems. This package is required
on almost all installations.
Homepage: http://www.linux-pam.org/
Original-Maintainer: Steve Langasek <vorlon@debian.org>

Package: libpam-systemd
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 646
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: systemd
Version: 249.11-0ubuntu3.4
Provides: default-logind (= 249.11-0ubuntu3.4), logind (= 249.11-0ubuntu3.4)
Depends: libc6 (>= 2.34), libcap2 (>= 1:2.24-9~), libpam0g (>= 0.99.7.1), systemd (= 249.11-0ubuntu3.4), libpam-runtime (>= 1.0.1-6), default-dbus-system-bus | dbus-system-bus, systemd-sysv
Description: system and service manager - PAM module
This package contains the PAM module which registers user sessions in
the systemd control group hierarchy for logind.
.
If in doubt, do install this package.
.
Packages that depend on logind functionality need to depend on libpam-systemd.
Homepage: https://www.freedesktop.org/wiki/Software/systemd
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: libpam0g
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 235
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pam
Version: 1.4.0-11ubuntu2
Replaces: libpam0g-util
Depends: libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), debconf (>= 0.5) | debconf-2.0
Suggests: libpam-doc
Description: Pluggable Authentication Modules library
Contains the shared library for Linux-PAM, a library that enables the
local system administrator to choose how applications authenticate users.
In other words, without rewriting or recompiling a PAM-aware application,
it is possible to switch between the authentication mechanism(s) it uses.
One may entirely upgrade the local authentication system without touching
the applications themselves.
Homepage: http://www.linux-pam.org/
Original-Maintainer: Steve Langasek <vorlon@debian.org>

Package: libpango-1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 563
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pango1.0
Version: 1.50.6+ds-2
Depends: fontconfig (>= 2.13.0), libc6 (>= 2.14), libfribidi0 (>= 1.0.6), libglib2.0-0 (>= 2.67.3), libharfbuzz0b (>= 2.6.0), libthai0 (>= 0.1.25)
Breaks: libpangocairo-1.0-0 (<< 1.44.7), libpangoft2-1.0-0 (<< 1.44.7), libpangoxft-1.0-0 (<< 1.44.7)
Description: Layout and rendering of internationalized text
Pango is a library for layout and rendering of text, with an emphasis
on internationalization. Pango can be used anywhere that text layout is
needed. however, most of the work on Pango-1.0 was done using the GTK+
widget toolkit as a test platform. Pango forms the core of text and
font handling for GTK+-2.0.
.
Pango is designed to be modular; the core Pango layout can be used with
four different font backends:

- Core X windowing system fonts
- Client-side fonts on X using the Xft library
- Direct rendering of scalable fonts using the FreeType library
- Native fonts on Microsoft backends
  .
  This package contains the shared libraries.
  Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
  Homepage: https://www.pango.org/

Package: libpangocairo-1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 159
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pango1.0
Version: 1.50.6+ds-2
Depends: libc6 (>= 2.4), libcairo2 (>= 1.12.10), libfontconfig1 (>= 2.13.0), libglib2.0-0 (>= 2.62.0), libharfbuzz0b (>= 2.6.0), libpango-1.0-0 (= 1.50.6+ds-2), libpangoft2-1.0-0 (= 1.50.6+ds-2)
Description: Layout and rendering of internationalized text
Pango is a library for layout and rendering of text, with an emphasis
on internationalization. Pango can be used anywhere that text layout is
needed. however, most of the work on Pango-1.0 was done using the GTK+
widget toolkit as a test platform. Pango forms the core of text and
font handling for GTK+-2.0.
.
Pango is designed to be modular; the core Pango layout can be used with
four different font backends:

- Core X windowing system fonts
- Client-side fonts on X using the Xft library
- Direct rendering of scalable fonts using the FreeType library
- Native fonts on Microsoft backends
  .
  This package contains the shared libraries.
  Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
  Homepage: https://www.pango.org/

Package: libpangoft2-1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 197
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pango1.0
Version: 1.50.6+ds-2
Depends: libc6 (>= 2.14), libfontconfig1 (>= 2.13.0), libfreetype6 (>= 2.2.1), libglib2.0-0 (>= 2.67.3), libharfbuzz0b (>= 2.6.0), libpango-1.0-0 (= 1.50.6+ds-2)
Description: Layout and rendering of internationalized text
Pango is a library for layout and rendering of text, with an emphasis
on internationalization. Pango can be used anywhere that text layout is
needed. however, most of the work on Pango-1.0 was done using the GTK+
widget toolkit as a test platform. Pango forms the core of text and
font handling for GTK+-2.0.
.
Pango is designed to be modular; the core Pango layout can be used with
four different font backends:

- Core X windowing system fonts
- Client-side fonts on X using the Xft library
- Direct rendering of scalable fonts using the FreeType library
- Native fonts on Microsoft backends
  .
  This package contains the shared libraries.
  Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
  Homepage: https://www.pango.org/

Package: libparted-fs-resize0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 148
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: parted
Version: 3.4-2build1
Depends: libc6 (>= 2.14), libparted2 (= 3.4-2build1)
Suggests: libparted-dev
Description: disk partition manipulator - shared FS resizing library
GNU Parted is a program that allows you to create, destroy, resize,
move, and copy disk partitions. This is useful for creating space
for new operating systems, reorganizing disk usage, and copying data
to new hard disks.
.
This package contains the libparted-fs-resize shared library for
resizing HFS+ and FAT file systems.
Homepage: https://www.gnu.org/software/parted
Original-Maintainer: Parted Maintainer Team <parted-maintainers@alioth-lists.debian.net>

Package: libparted2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 458
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: parted
Version: 3.4-2build1
Provides: libparted
Depends: libblkid1 (>= 2.17.2), libc6 (>= 2.34), libdevmapper1.02.1 (>= 2:1.02.97), libuuid1 (>= 2.16), dmidecode
Suggests: parted, libparted-dev, libparted-i18n (= 3.4-2build1)
Description: disk partition manipulator - shared library
GNU Parted is a program that allows you to create, destroy, resize,
move, and copy disk partitions. This is useful for creating space
for new operating systems, reorganizing disk usage, and copying data
to new hard disks.
.
This package contains the shared library.
Homepage: https://www.gnu.org/software/parted
Original-Maintainer: Parted Maintainer Team <parted-maintainers@alioth-lists.debian.net>

Package: libpcap0.8
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 357
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libpcap
Version: 1.10.1-4build1
Replaces: libpcap0.8-dev (<< 1.0.0-2)
Depends: libc6 (>= 2.33), libdbus-1-3 (>= 1.9.14)
Description: system interface for user-level packet capture
libpcap (Packet CAPture) provides a portable framework for low-level
network monitoring. Applications include network statistics collection,
security monitoring, network debugging, etc.
.
Since almost every system vendor provides a different interface for
packet capture, and since there are several tools that require this
functionality, the libpcap authors created this system-independent API
to ease in porting and to alleviate the need for several
system-dependent packet capture modules in each application.
Homepage: https://www.tcpdump.org/
Original-Maintainer: Romain Francoise <rfrancoise@debian.org>

Package: libpci3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 90
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pciutils
Version: 1:3.7.0-6
Depends: libc6 (>= 2.34), libudev1 (>= 196), zlib1g (>= 1:1.1.4), pci.ids (>= 0.0~2019.11.10-2)
Description: PCI utilities (shared library)
This package contains the libpci shared library files.
.
The libpci library provides portable access to configuration
registers of devices connected to the PCI bus.
Original-Maintainer: Guillem Jover <guillem@debian.org>
Homepage: https://mj.ucw.cz/sw/pciutils/

Package: libpciaccess0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 61
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libpciaccess
Version: 0.16-3
Depends: libc6 (>= 2.33), zlib1g (>= 1:1.1.4)
Suggests: pciutils
Description: Generic PCI access library for X
Provides functionality for X to access the PCI bus and devices
in a platform-independent way.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libpcre2-8-0
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 621
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pcre2
Version: 10.39-3build1
Depends: libc6 (>= 2.14)
Description: New Perl Compatible Regular Expression Library- 8 bit runtime files
This is PCRE2, the new implementation of PCRE, a library of functions
to support regular expressions whose syntax and semantics are as
close as possible to those of the Perl 5 language. New projects
should use this library in preference to the older library,
confusingly called pcre3 in Debian.
.
This package contains the 8 bit runtime library, which operates on
ASCII and UTF-8 input.
Homepage: https://pcre.org/
Original-Maintainer: Matthew Vernon <matthew@debian.org>

Package: libpcre3
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 683
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pcre3
Version: 2:8.39-13ubuntu0.22.04.1
Depends: libc6 (>= 2.14)
Breaks: approx (<< 4.4-1~), cduce (<< 0.5.3-2~), cmigrep (<< 1.5-7~), galax (<< 1.1-7~), libpcre-ocaml (<< 6.0.1~), liquidsoap (<< 0.9.2-3~), ocsigen (<< 1.3.3-1~)
Conflicts: libpcre3-dev (<= 4.3-3)
Description: Old Perl 5 Compatible Regular Expression Library - runtime files
This is a library of functions to support regular expressions whose syntax
and semantics are as close as possible to those of the Perl 5 language.
.
New packages should use the newer pcre2 packages, and existing
packages should migrate to pcre2.
.
This package contains the runtime libraries.
Original-Maintainer: Matthew Vernon <matthew@debian.org>

Package: libperl5.34
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 28629
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: perl
Version: 5.34.0-3ubuntu1
Replaces: libarchive-tar-perl (<= 1.38-2), libcompress-raw-bzip2-perl (<< 2.101), libcompress-raw-zlib-perl (<< 2.101), libcompress-zlib-perl (<< 2.102), libdigest-md5-perl (<< 2.58), libdigest-sha-perl (<< 6.02), libencode-perl (<< 3.08), libio-compress-base-perl (<< 2.102), libio-compress-bzip2-perl (<< 2.102), libio-compress-perl (<< 2.102), libio-compress-zlib-perl (<< 2.102), libmime-base64-perl (<< 3.16), libmodule-corelist-perl (<< 2.14-2), libstorable-perl (<< 3.23), libsys-syslog-perl (<< 0.36), libthreads-perl (<< 2.26), libthreads-shared-perl (<< 1.62), libtime-hires-perl (<< 1.9767), libtime-piece-perl (<< 1.3401), perl (<< 5.22.0~), perl-base (<< 5.22.0~)
Depends: libbz2-1.0, libc6 (>= 2.35), libcrypt1 (>= 1:4.1.0), libdb5.3, libgdbm-compat4 (>= 1.18-3), libgdbm6 (>= 1.18-3), zlib1g (>= 1:1.2.2.3), perl-modules-5.34 (>= 5.34.0-3ubuntu1)
Suggests: sensible-utils
Breaks: libcompress-raw-bzip2-perl (<< 2.101), libcompress-raw-zlib-perl (<< 2.101), libcompress-zlib-perl (<< 2.102), libdigest-md5-perl (<< 2.58), libdigest-sha-perl (<< 6.02), libencode-perl (<< 3.08), libfilter-perl (<< 1.60), libio-compress-base-perl (<< 2.102), libio-compress-bzip2-perl (<< 2.102), libio-compress-perl (<< 2.102), libio-compress-zlib-perl (<< 2.102), libmime-base64-perl (<< 3.16), libstorable-perl (<< 3.23), libsys-syslog-perl (<< 0.36), libthreads-perl (<< 2.26), libthreads-shared-perl (<< 1.62), libtime-hires-perl (<< 1.9767), libtime-piece-perl (<< 1.3401)
Description: shared Perl library
This package contains the shared Perl library, used by applications
which embed a Perl interpreter.
.
It also contains the architecture-dependent parts of the standard
library (and depends on perl-modules-5.34 which contains the
architecture-independent parts).
Homepage: http://dev.perl.org/perl5/
Original-Maintainer: Niko Tyni <ntyni@debian.org>

Package: libphobos2-ldc-shared98
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 6241
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: ldc
Version: 1:1.28.0-1ubuntu1
Depends: libc6 (>= 2.34), libgcc-s1 (>= 4.2), libllvm11 (>= 1:9~svn298832-1~), libstdc++6 (>= 11), zlib1g (>= 1:1.2.0)
Conflicts: libphobos2-ldc-shared94
Description: LLVM D Compiler - Standard and runtime libraries
LDC is a portable compiler for the D programming language with modern
optimization and code generation capabilities.
It is based on the latest DMD frontend and uses LLVM as backend.
.
This package contains the Phobos D standard library, D runtime library
and LDC JIT library.
Homepage: https://github.com/ldc-developers/ldc
Original-Maintainer: Debian D Language Group <team+d-team@tracker.debian.org>

Package: libpipeline1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 68
Maintainer: Colin Watson <cjwatson@debian.org>
Architecture: amd64
Multi-Arch: same
Source: libpipeline
Version: 1.5.5-1
Depends: libc6 (>= 2.26)
Description: Unix process pipeline manipulation library
This is a C library for setting up and running pipelines of processes,
without needing to involve shell command-line parsing which is often
error-prone and insecure.
Homepage: https://nongnu.org/libpipeline/

Package: libpixman-1-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 708
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pixman
Version: 0.40.0-1build4
Depends: libc6 (>= 2.29)
Description: pixel-manipulation library for X and cairo
A library for manipulating pixel regions -- a set of Y-X banded
rectangles, image compositing using the Porter/Duff model
and implicit mask generation for geometric primitives including
trapezoids, triangles, and rectangles.
Homepage: http://pixman.org/
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libplymouth5
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 419
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: plymouth
Version: 0.9.5+git20211018-1ubuntu3
Replaces: plymouth (<< 0.9.2-1~)
Depends: libc6 (>= 2.34), libpng16-16 (>= 1.6.2-1), libudev1 (>= 183)
Breaks: plymouth (<< 0.9.2-1~)
Description: graphical boot animation and logger - shared libraries
Plymouth is an application that runs very early in the boot process
(even before the root filesystem is mounted!) that provides a graphical
boot animation while the boot process happens in the background.
.
This package contains the shared libraries.
Homepage: http://www.freedesktop.org/wiki/Software/Plymouth
Original-Maintainer: Laurent Bigonville <bigon@debian.org>

Package: libpng16-16
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 353
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libpng1.6
Version: 1.6.37-3build5
Depends: libc6 (>= 2.29), zlib1g (>= 1:1.2.11)
Description: PNG library - runtime (version 1.6)
libpng is a library implementing an interface for reading and writing
PNG (Portable Network Graphics) format files.
.
This package contains the runtime library files needed to run software
using libpng.
Homepage: http://libpng.org/pub/png/libpng.html
Original-Maintainer: Maintainers of libpng1.6 packages <libpng1.6@packages.debian.org>

Package: libpolkit-agent-1-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 80
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: policykit-1
Version: 0.105-33
Depends: libc6 (>= 2.4), libglib2.0-0 (>= 2.37.3), libpolkit-gobject-1-0 (= 0.105-33)
Description: PolicyKit Authentication Agent API
PolicyKit is a toolkit for defining and handling the policy that
allows unprivileged processes to speak to privileged processes.
.
This package contains a library for accessing the authentication agent.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://www.freedesktop.org/wiki/Software/polkit/

Package: libpolkit-gobject-1-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 158
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: policykit-1
Version: 0.105-33
Depends: libc6 (>= 2.7), libglib2.0-0 (>= 2.37.3), libsystemd0 (>= 213)
Description: PolicyKit Authorization API
PolicyKit is a toolkit for defining and handling the policy that
allows unprivileged processes to speak to privileged processes.
.
This package contains a library for accessing PolicyKit.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://www.freedesktop.org/wiki/Software/polkit/

Package: libpopt0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 120
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: popt
Version: 1.18-3build1
Depends: libc6 (>= 2.33)
Description: lib for parsing cmdline parameters
Popt was heavily influenced by the getopt() and getopt_long() functions,
but it allows more powerful argument expansion. It can parse arbitrary
argv[] style arrays and automatically set variables based on command
line arguments. It also allows command line arguments to be aliased via
configuration files and includes utility functions for parsing arbitrary
strings into argv[] arrays using shell-like rules.
.
This package contains the runtime library and locale data.
Homepage: https://github.com/rpm-software-management/popt
Original-Maintainer: Michael Jeanson <mjeanson@debian.org>

Package: libproc-processtable-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 111
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 0.634-1build1
Depends: perl, perlapi-5.34.0, libc6 (>= 2.34)
Description: Perl library for accessing process table information
Proc::ProcessTable attempts to unify the interfaces to Unix process table
information, without having to run a ps subprocess from within a perl or
shell script and parse the output.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Proc-ProcessTable

Package: libprocps8
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 131
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: procps
Version: 2:3.3.17-6ubuntu2
Replaces: procps (<< 1:3.3.2-1)
Depends: libc6 (>= 2.34), libsystemd0 (>= 209)
Description: library for accessing process information from /proc
The libprocps library is a way of accessing information out of the /proc
filesystem.
.
This package contains the shared libraries necessary to run programs
compiled with libprocps.
Homepage: https://gitlab.com/procps-ng/procps
Original-Maintainer: Craig Small <csmall@debian.org>

Package: libpsl5
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 95
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libpsl
Version: 0.21.0-1.2build2
Depends: libidn2-0 (>= 0.16), libc6 (>= 2.33), libunistring2 (>= 0.9.7)
Recommends: publicsuffix (>= 20150507)
Description: Library for Public Suffix List (shared libraries)
Libpsl allows checking domains against the Public Suffix List.
It can be used to avoid privacy-leaking 'super-cookies',
'super domain' certificates, for domain highlighting purposes
sorting domain lists by site and more.
.
Please see https://publicsuffix.org for more detailed information.
.
This package contains runtime libraries.
Homepage: https://github.com/rockdaboot/libpsl
Original-Maintainer: Tim Rühsen <tim.ruehsen@gmx.de>

Package: libpython3-stdlib
Status: install ok installed
Priority: important
Section: python
Installed-Size: 39
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: python3-defaults
Version: 3.10.4-0ubuntu2
Depends: libpython3.10-stdlib (>= 3.10.4-1~)
Description: interactive high-level object-oriented language (default python3 version)
This package contains the majority of the standard library for the Python
language (default python3 version).
.
This package is a dependency package, which depends on Debian's default
Python 3 version's standard library (currently v3.10).
Homepage: https://www.python.org/
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: libpython3.10
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 5773
Maintainer: Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: python3.10
Version: 3.10.4-3ubuntu0.1
Depends: libpython3.10-stdlib (= 3.10.4-3ubuntu0.1), libc6 (>= 2.35), libexpat1 (>= 2.1~beta3), zlib1g (>= 1:1.2.0)
Description: Shared Python runtime library (version 3.10)
Python is a high-level, interactive, object-oriented language. Its 3.10 version
includes an extensive class library with lots of goodies for
network programming, system administration, sounds and graphics.
.
This package contains the shared runtime library, normally not needed
for programs using the statically linked interpreter.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: libpython3.10-minimal
Status: install ok installed
Priority: important
Section: python
Installed-Size: 5086
Maintainer: Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: python3.10
Version: 3.10.4-3ubuntu0.1
Depends: libc6 (>= 2.14), libssl3 (>= 3.0.0~~alpha1)
Recommends: libpython3.10-stdlib
Conflicts: binfmt-support (<< 1.1.2)
Conffiles:
/etc/python3.10/sitecustomize.py d6b276695157bde06a56ba1b2bc53670
Description: Minimal subset of the Python language (version 3.10)
This package contains some essential modules. It is normally not
used on it's own, but as a dependency of python3.10-minimal.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: libpython3.10-stdlib
Status: install ok installed
Priority: important
Section: python
Installed-Size: 8031
Maintainer: Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: python3.10
Version: 3.10.4-3ubuntu0.1
Replaces: python3-gdbm (<< 3.9.9-1~)
Depends: libpython3.10-minimal (= 3.10.4-3ubuntu0.1), media-types | mime-support, libbz2-1.0, libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libdb5.3, libffi8 (>= 3.4), liblzma5 (>= 5.1.1alpha+20120614), libmpdec3, libncursesw6 (>= 6.1), libnsl2 (>= 1.0), libreadline8 (>= 7.0~beta), libsqlite3-0 (>= 3.14.0), libtinfo6 (>= 6), libtirpc3 (>= 1.0.2), libuuid1 (>= 2.20.1)
Breaks: python3-gdbm (<< 3.9.9-1~)
Description: Interactive high-level object-oriented language (standard library, version 3.10)
Python is a high-level, interactive, object-oriented language. Its 3.10 version
includes an extensive class library with lots of goodies for
network programming, system administration, sounds and graphics.
.
This package contains Python 3.10's standard library. It is normally not
used on its own, but as a dependency of python3.10.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: libqmi-glib5
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 3481
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libqmi
Version: 1.30.4-1
Depends: libc6 (>= 2.14), libglib2.0-0 (>= 2.56), libmbim-glib4 (>= 1.18.0), libmbim-proxy
Description: Support library to use the Qualcomm MSM Interface (QMI) protocol
Libraries for adding QMI support to applications that use glib.
Original-Maintainer: DebianOnMobile Maintainers <debian-on-mobile-maintainers@alioth-lists.debian.net>
Homepage: https://www.freedesktop.org/wiki/Software/libqmi

Package: libqmi-proxy
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: libqmi
Version: 1.30.4-1
Depends: libqmi-glib5 (= 1.30.4-1), libc6 (>= 2.34), libglib2.0-0 (>= 2.56)
Description: Proxy to communicate with QMI ports
This package contains the binary qmi-proxy used by libqmi to allow multiple
clients to use the same QMI port simultaneously.
Original-Maintainer: DebianOnMobile Maintainers <debian-on-mobile-maintainers@alioth-lists.debian.net>
Homepage: https://www.freedesktop.org/wiki/Software/libqmi

Package: libquadmath0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 296
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.23)
Description: GCC Quad-Precision Math Library
A library, which provides quad-precision mathematical functions on targets
supporting the \_\_float128 datatype. The library is used to provide on such
targets the REAL(16) type in the GNU Fortran compiler.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libreadline8
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 461
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: readline
Version: 8.1.2-1
Depends: readline-common, libc6 (>= 2.33), libtinfo6 (>= 6)
Description: GNU readline and history libraries, run-time libraries
The GNU readline library aids in the consistency of user interface
across discrete programs that need to provide a command line
interface.
.
The GNU history library provides a consistent user interface for
recalling lines of previously typed input.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: librsvg2-2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 11084
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: librsvg
Version: 2.52.5+dfsg-3
Depends: libc6 (>= 2.34), libcairo-gobject2 (>= 1.10.0), libcairo2 (>= 1.15.12), libgcc-s1 (>= 4.2), libgdk-pixbuf-2.0-0 (>= 2.31.1), libglib2.0-0 (>= 2.50.0), libpango-1.0-0 (>= 1.45.5), libpangocairo-1.0-0 (>= 1.44.0), libxml2 (>= 2.9.0)
Recommends: librsvg2-common
Suggests: librsvg2-bin
Description: SAX-based renderer library for SVG files (runtime)
The rsvg library is an efficient renderer for Scalable Vector Graphics
(SVG) pictures.
.
This package contains the runtime library, necessary to run
applications using librsvg.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Projects/LibRsvg

Package: librsvg2-common
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 89
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: librsvg
Version: 2.52.5+dfsg-3
Depends: librsvg2-2 (= 2.52.5+dfsg-3), libgdk-pixbuf-2.0-0 (>= 2.23.5-2), libglib2.0-0 (>= 2.50.0)
Description: SAX-based renderer library for SVG files (extra runtime)
The rsvg library is an efficient renderer for Scalable Vector Graphics
(SVG) pictures.
.
This package includes the gdk-pixbuf loader allowing
to load SVG images transparently inside GTK+ applications.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Projects/LibRsvg

Package: librtmp1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 141
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: rtmpdump
Version: 2.4+20151223.gitfa8646d.1-2build4
Depends: libc6 (>= 2.14), libgmp10 (>= 2:6.2.1+dfsg), libgnutls30 (>= 3.7.2), libhogweed6, libnettle8, zlib1g (>= 1:1.1.4)
Description: toolkit for RTMP streams (shared library)
A small dumper for media content streamed over the RTMP protocol (like BBC's
iPlayer high quality streams). Supplying an RTMP URL will result in a dumped
flv file, which can be played/transcoded with standard tools.
.
This package contains the shared libraries, header files needed by
programs that want to use librtmp.
Homepage: http://rtmpdump.mplayerhq.hu/
Original-Maintainer: Debian Multimedia Maintainers <debian-multimedia@lists.debian.org>

Package: libsasl2-2
Status: install ok installed
Priority: standard
Section: libs
Installed-Size: 170
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: cyrus-sasl2
Version: 2.1.27+dfsg2-3ubuntu1
Replaces: libsasl2
Depends: libsasl2-modules-db (>= 2.1.27+dfsg2-3ubuntu1), libc6 (>= 2.34)
Recommends: libsasl2-modules (>= 2.1.27+dfsg2-3ubuntu1)
Breaks: postfix (<= 2.8.3-1), slapd (<= 2.4.25-3)
Description: Cyrus SASL - authentication abstraction library
This is the Cyrus SASL API implementation, version 2.1.
.
SASL is the Simple Authentication and Security Layer, a method for
adding authentication support to connection-based protocols. To use
SASL, a protocol includes a command for identifying and
authenticating a user to a server and for optionally negotiating
protection of subsequent protocol interactions. If its use is
negotiated, a security layer is inserted between the protocol and the
connection. See RFC 2222 for more information.
.
Any of: ANONYMOUS, CRAM-MD5, DIGEST-MD5, GSSAPI (MIT or Heimdal
Kerberos 5), NTLM, OTP, PLAIN, or LOGIN can be used.
Homepage: https://www.cyrusimap.org/sasl/
Original-Maintainer: Debian Cyrus Team <team+cyrus@tracker.debian.org>

Package: libsasl2-modules
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 267
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: cyrus-sasl2
Version: 2.1.27+dfsg2-3ubuntu1
Depends: libc6 (>= 2.14), libssl3 (>= 3.0.0~~alpha1)
Suggests: libsasl2-modules-gssapi-mit | libsasl2-modules-gssapi-heimdal, libsasl2-modules-ldap, libsasl2-modules-otp, libsasl2-modules-sql
Breaks: logcheck-database (<= 1.3.16~)
Conffiles:
/etc/logcheck/ignore.d.server/libsasl2-modules bef6e87d49dab9587a357eb525524bda
Description: Cyrus SASL - pluggable authentication modules
This is the Cyrus SASL API implementation, version 2.1. See package
libsasl2-2 and RFC 2222 for more information.
.
This package provides the following SASL modules: LOGIN, PLAIN, ANONYMOUS,
NTLM, CRAM-MD5, and DIGEST-MD5 (with DES support).
Homepage: https://www.cyrusimap.org/sasl/
Original-Maintainer: Debian Cyrus Team <team+cyrus@tracker.debian.org>

Package: libsasl2-modules-db
Status: install ok installed
Priority: standard
Section: libs
Installed-Size: 97
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: cyrus-sasl2
Version: 2.1.27+dfsg2-3ubuntu1
Depends: libc6 (>= 2.14), libdb5.3
Description: Cyrus SASL - pluggable authentication modules (DB)
This is the Cyrus SASL API implementation, version 2.1. See package
libsasl2-2 and RFC 2222 for more information.
.
This package provides the DB plugin, which supports Berkeley DB lookups.
Homepage: https://www.cyrusimap.org/sasl/
Original-Maintainer: Debian Cyrus Team <team+cyrus@tracker.debian.org>

Package: libseccomp2
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 145
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libseccomp
Version: 2.5.3-2ubuntu2
Depends: libc6 (>= 2.4)
Description: high level interface to Linux seccomp filter
This library provides a high level interface to constructing, analyzing
and installing seccomp filters via a BPF passed to the Linux Kernel's
prctl() syscall.
Homepage: https://github.com/seccomp/libseccomp
Original-Maintainer: Kees Cook <kees@debian.org>

Package: libselinux1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 207
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libselinux
Version: 3.3-1build2
Depends: libc6 (>= 2.34), libpcre2-8-0 (>= 10.22)
Description: SELinux runtime shared libraries
This package provides the shared libraries for Security-enhanced
Linux that provides interfaces (e.g. library functions for the
SELinux kernel APIs like getcon(), other support functions like
getseuserbyname()) to SELinux-aware applications. Security-enhanced
Linux is a patch of the Linux kernel and a number of utilities with
enhanced security functionality designed to add mandatory access
controls to Linux. The Security-enhanced Linux kernel contains new
architectural components originally developed to improve the security
of the Flask operating system. These architectural components provide
general support for the enforcement of many kinds of mandatory access
control policies, including those based on the concepts of Type
Enforcement, Role-based Access Control, and Multi-level Security.
.
libselinux1 provides an API for SELinux applications to get and set
process and file security contexts and to obtain security policy
decisions. Required for any applications that use the SELinux
API. libselinux may use the shared libsepol to manipulate the binary
policy if necessary (e.g. to downgrade the policy format to an older
version supported by the kernel) when loading policy.
Original-Maintainer: Debian SELinux maintainers <selinux-devel@lists.alioth.debian.org>
Homepage: https://selinuxproject.org

Package: libsemanage-common
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 37
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: libsemanage
Version: 3.3-1build2
Conffiles:
/etc/selinux/semanage.conf f6f9b97af233c90ca127f406fb6f0932
Description: Common files for SELinux policy management libraries
This package provides the common files used by the shared libraries
for SELinux policy management.
.
Security-enhanced Linux is a patch of the Linux kernel and a
number of utilities with enhanced security functionality designed to
add mandatory access controls to Linux. The Security-enhanced Linux
kernel contains new architectural components originally developed to
improve the security of the Flask operating system. These
architectural components provide general support for the enforcement
of many kinds of mandatory access control policies, including those
based on the concepts of Type Enforcement, Role-based Access
Control, and Multi-level Security.
Original-Maintainer: Debian SELinux maintainers <selinux-devel@lists.alioth.debian.org>
Homepage: https://selinuxproject.org

Package: libsemanage2
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 300
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libsemanage
Version: 3.3-1build2
Depends: libsemanage-common (>= 3.3-1build2), libaudit1 (>= 1:2.2.1), libbz2-1.0, libc6 (>= 2.33), libselinux1 (>= 3.3), libsepol2 (>= 3.3)
Breaks: policycoreutils (<< 3.0)
Description: SELinux policy management library
This package provides the shared libraries for SELinux policy management.
It uses libsepol for binary policy manipulation and libselinux for
interacting with the SELinux system. It also exec's helper programs
for loading policy and for checking whether the file_contexts
configuration is valid (load_policy and setfiles from
policycoreutils) presently, although this may change at least for the
bootstrapping case
.
Security-enhanced Linux is a patch of the Linux kernel and a
number of utilities with enhanced security functionality designed to
add mandatory access controls to Linux. The Security-enhanced Linux
kernel contains new architectural components originally developed to
improve the security of the Flask operating system. These
architectural components provide general support for the enforcement
of many kinds of mandatory access control policies, including those
based on the concepts of Type Enforcement, Role-based Access
Control, and Multi-level Security.
Original-Maintainer: Debian SELinux maintainers <selinux-devel@lists.alioth.debian.org>
Homepage: https://selinuxproject.org

Package: libsensors-config
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 42
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: lm-sensors
Version: 1:3.6.0-7ubuntu1
Replaces: libsensors4
Suggests: lm-sensors
Breaks: libsensors4
Conffiles:
/etc/sensors.d/.placeholder d41d8cd98f00b204e9800998ecf8427e
/etc/sensors3.conf 41bd2b70a6ce64a21c2d1f70b9eed091
Description: lm-sensors configuration files
Lm-sensors is a hardware health monitoring package for Linux. It allows you
to access information from temperature, voltage, and fan speed sensors. It
works with most newer systems.
.
This library is only functional with a Linux kernel, it is provided on
non-Linux systems for portability reasons only.
.
This package contains the configuration files.
Homepage: https://hwmon.wiki.kernel.org/lm_sensors
Original-Maintainer: Aurelien Jarno <aurel32@debian.org>

Package: libsensors5
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 96
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: lm-sensors
Version: 1:3.6.0-7ubuntu1
Depends: libsensors-config, libc6 (>= 2.33)
Suggests: lm-sensors
Description: library to read temperature/voltage/fan sensors
Lm-sensors is a hardware health monitoring package for Linux. It allows you
to access information from temperature, voltage, and fan speed sensors. It
works with most newer systems.
.
This library is only functional with a Linux kernel, it is provided on
non-Linux systems for portability reasons only.
.
This package contains a shared library for querying lm-sensors.
Homepage: https://hwmon.wiki.kernel.org/lm_sensors
Original-Maintainer: Aurelien Jarno <aurel32@debian.org>

Package: libsepol2
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 735
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libsepol
Version: 3.3-1build1
Depends: libc6 (>= 2.33)
Description: SELinux library for manipulating binary security policies
Security-enhanced Linux is a patch of the Linux kernel and a number
of utilities with enhanced security functionality designed to add
mandatory access controls to Linux. The Security-enhanced Linux
kernel contains new architectural components originally developed to
improve the security of the Flask operating system. These
architectural components provide general support for the enforcement
of many kinds of mandatory access control policies, including those
based on the concepts of Type Enforcement®, Role-based Access
Control, and Multi-level Security.
.
libsepol provides an API for the manipulation of SELinux binary policies.
It is used by checkpolicy (the policy compiler) and similar tools, as well
as by programs like load_policy that need to perform specific transformations
on binary policies such as customizing policy boolean settings.
Homepage: https://selinuxproject.org
Original-Maintainer: Debian SELinux maintainers <selinux-devel@lists.alioth.debian.org>

Package: libsgutils2-2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 294
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: sg3-utils
Version: 1.46-1build1
Replaces: libsgutils2
Depends: libc6 (>= 2.33)
Suggests: sg3-utils
Conflicts: libsgutils2
Description: utilities for devices using the SCSI command set (shared libraries)
Most OSes have SCSI pass-through interfaces that enable user space programs
to send SCSI commands to a device and fetch the response. With SCSI to ATA
Translation (SAT) many ATA disks now can process SCSI commands. Typically
each utility in this package implements one SCSI command. See the draft
standards at www.t10.org for SCSI command definitions plus SAT. ATA
commands are defined in the draft standards at www.t13.org . For a mapping
between supported SCSI and ATA commands and utility names in this package
see the COVERAGE file
.
Shared library used by the utilities in the sg3-utils package.
Homepage: http://sg.danny.cz/sg/
Original-Maintainer: Ritesh Raj Sarraf <rrs@debian.org>

Package: libsigsegv2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 49
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libsigsegv
Version: 2.13-1ubuntu3
Depends: libc6 (>= 2.4)
Description: Library for handling page faults in a portable way
GNU libsigsegv is a library that allows handling page faults in a
portable way. It is used e.g. for generational garbage collectors
and stack overflow handlers.
.
This package contains the shared library.
Homepage: https://www.gnu.org/software/libsigsegv/
Original-Maintainer: Debian Common Lisp Team <debian-common-lisp@lists.debian.org>

Package: libslang2
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 1628
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: slang2
Version: 2.3.2-5build4
Depends: libc6 (>= 2.35)
Description: S-Lang programming library - runtime version
S-Lang is a C programmer's library that includes routines for the rapid
development of sophisticated, user friendly, multi-platform applications.
.
This package contains only the shared library libslang.so.\* and copyright
information. It is only necessary for programs that use this library (such
as jed and slrn). If you plan on doing development with S-Lang, you will
need the companion -dev package as well.
Original-Maintainer: Alastair McKinstry <mckinstry@debian.org>
Built-Using: unicode-data (= 14.0.0-1.1)
Homepage: http://www.jedsoft.org/slang/

Package: libsm6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 55
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libsm
Version: 2:1.2.3-1build2
Depends: libc6 (>= 2.14), libice6 (>= 1:1.0.0), libuuid1 (>= 2.16)
Description: X11 Session Management library
This package provides the main interface to the X11 Session Management
library, which allows for applications to both manage sessions, and make use
of session managers to save and restore their state for later use.
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libSM
Homepage: https://www.x.org
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libsmartcols1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 209
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: util-linux
Version: 2.37.2-4ubuntu3
Depends: libc6 (>= 2.14)
Description: smart column output alignment library
This smart column output alignment library is used by fdisk utilities.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: libsmbios-c2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 304
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: libsmbios
Version: 2.4.3-1build1
Replaces: libsmbios2, libsmbios2v5
Provides: libsmbios2 (= 2.3.1-1), libsmbios2v5 (= 2.3.1-0ubuntu2)
Depends: libc6 (>= 2.33)
Suggests: libsmbios-doc
Conflicts: libsmbios2, libsmbios2v5
Description: Provide access to (SM)BIOS information -- dynamic library
libsmbios aims towards providing access to as much BIOS information as
possible. It does this by providing a library of functions that can be used
as well as sample binaries.
.
It incorporates extensible access to SMBIOS information capabilities and
ability to perform unit tests across multiple systems without using physical
hardware. Moreover, centralized, data-driven exception handling for broken
BIOS tables is provided. Currently, full access to the SMBIOS table and its
items is implemented. Additionally, access and manipulation of Dell Indexed
IO Token (type 0xD4) is implemented. This token is a vendor-extention
SMBIOS structure which allows uniform access to manipulate the system CMOS
to enable, disable, or otherwise manipulate normal BIOS functions or features.
Original-Maintainer: Debian UEFI Maintainers <debian-efi@lists.debian.org>
Homepage: https://github.com/dell/libsmbios/

Package: libsodium23
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 402
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libsodium
Version: 1.0.18-1build2
Depends: libc6 (>= 2.33)
Description: Network communication, cryptography and signaturing library
NaCl (pronounced "salt") is a new easy-to-use high-speed software library for
network communication, encryption, decryption, signatures, etc.
.
NaCl's goal is to provide all of the core operations needed to build
higher-level cryptographic tools.
.
Sodium is a portable, cross-compilable, installable, packageable fork of NaCl,
with a compatible API.
Homepage: https://www.libsodium.org/
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>

Package: libsort-naturally-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 40
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.03-2
Depends: perl
Description: Sort naturally - sort lexically except for numerical parts
Sort::Naturally exports two functions, nsort and ncmp; they are used
in implementing the idea of "natural sorting" algorithm. With that natural
sorting, numeric substrings are compared numerically, and other
word-characters are compared lexically.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Sort-Naturally

Package: libsqlite3-0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 1602
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: sqlite3
Version: 3.37.2-2
Depends: libc6 (>= 2.34)
Breaks: python-migrate (<< 0.11.0-4~), python3-migrate (<< 0.11.0-4~)
Description: SQLite 3 shared library
SQLite is a C library that implements an SQL database engine.
Programs that link with the SQLite library can have SQL database
access without running a separate RDBMS process.
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>
Homepage: https://www.sqlite.org/

Package: libss2
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 113
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: e2fsprogs
Version: 1.46.5-2ubuntu1.1
Replaces: e2fsprogs (<< 1.34-1)
Depends: libcom-err2, libc6 (>= 2.34)
Description: command-line interface parsing library
libss provides a simple command-line interface parser which will
accept input from the user, parse the command into an argv argument
vector, and then dispatch it to a handler function.
.
It was originally inspired by the Multics SubSystem library.
Homepage: http://e2fsprogs.sourceforge.net
Original-Maintainer: Theodore Y. Ts'o <tytso@mit.edu>

Package: libssh-4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 486
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libssh
Version: 0.9.6-2build1
Depends: libc6 (>= 2.33), libgssapi-krb5-2 (>= 1.17), libssl3 (>= 3.0.0~~alpha1), zlib1g (>= 1:1.1.4)
Breaks: remmina (<< 1.2.31.2+dfsg-1+), remmina-plugin-nx (<< 1.2.31.2+dfsg-1+), x2goclient (<< 4.1.2.1-1+)
Description: tiny C SSH library (OpenSSL flavor)
The ssh library was designed to be used by programmers needing a working SSH
implementation by the mean of a library. The complete control of the client
is made by the programmer. With libssh, you can remotely execute programs,
transfer files, use a secure and transparent tunnel for your remote programs.
With its SFTP implementation, you can play with remote files easily.
.
This package contains shared libraries linked against OpenSSL.
Homepage: https://www.libssh.org/
Original-Maintainer: Laurent Bigonville <bigon@debian.org>

Package: libssl-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 12082
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.2-0ubuntu1.6
Depends: libssl3 (= 3.0.2-0ubuntu1.6)
Suggests: libssl-doc
Conflicts: libssl1.0-dev
Description: Secure Sockets Layer toolkit - development files
This package is part of the OpenSSL project's implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
.
It contains development libraries, header files, and manpages for libssl
and libcrypto.
Homepage: https://www.openssl.org/
Original-Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>

Package: libssl3
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 5822
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.2-0ubuntu1.6
Depends: libc6 (>= 2.34), debconf (>= 0.5) | debconf-2.0
Description: Secure Sockets Layer toolkit - shared libraries
This package is part of the OpenSSL project's implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
.
It provides the libssl and libcrypto shared libraries.
Homepage: https://www.openssl.org/
Original-Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>

Package: libstdc++-11-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 18710
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-11
Version: 11.2.0-19ubuntu1
Provides: libstdc++-dev
Depends: gcc-11-base (= 11.2.0-19ubuntu1), libgcc-11-dev (= 11.2.0-19ubuntu1), libstdc++6 (>= 11.2.0-19ubuntu1), libc6-dev (>= 2.13-0ubuntu6)
Suggests: libstdc++-11-doc
Description: GNU Standard C++ Library v3 (development files)
This package contains the headers and static library files necessary for
building C++ programs which use libstdc++.
.
libstdc++-v3 is a complete rewrite from the previous libstdc++-v2, which
was included up to g++-2.95. The first version of libstdc++-v3 appeared
in g++-3.0.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libstdc++6
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 2750
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Replaces: libstdc++6-12-dbg (<< 4.9.0-3)
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.34), libgcc-s1 (>= 4.2)
Breaks: gcc-4.3 (<< 4.3.6-1), gcc-4.4 (<< 4.4.6-4), gcc-4.5 (<< 4.5.3-2)
Conflicts: scim (<< 1.4.2-1)
Description: GNU Standard C++ Library v3
This package contains an additional runtime library for C++ programs
built with the GNU compiler.
.
libstdc++-v3 is a complete rewrite from the previous libstdc++-v2, which
was included up to g++-2.95. The first version of libstdc++-v3 appeared
in g++-3.0.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libstemmer0d
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 839
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: snowball
Version: 2.2.0-1build1
Depends: libc6 (>= 2.4)
Description: Snowball stemming algorithms for use in Information Retrieval
Snowball provides access to efficient algorithms for calculating a
"stemmed" form of a word. This is a form with most of the common
morphological endings removed; hopefully representing a common
linguistic base form. This is most useful in building search engines
and information retrieval software; for example, a search with stemming
enabled should be able to find a document containing "cycling" given the
query "cycles".
.
Snowball provides algorithms for several (mainly European) languages.
It also provides access to the classic Porter stemming algorithm for
English: although this has been superseded by an improved algorithm, the
original algorithm may be of interest to information retrieval
researchers wishing to reproduce results of earlier experiments.
Homepage: https://snowballstem.org/
Original-Maintainer: Stefano Rivera <stefanor@debian.org>

Package: libsystemd0
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 993
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: systemd
Version: 249.11-0ubuntu3.4
Pre-Depends: libc6 (>= 2.34), libcap2 (>= 1:2.24-9~), libgcrypt20 (>= 1.9.0), liblz4-1 (>= 0.0~r122), liblzma5 (>= 5.1.1alpha+20120614), libzstd1 (>= 1.4.0)
Description: systemd utility library
The libsystemd0 library provides interfaces to various systemd components.
Homepage: https://www.freedesktop.org/wiki/Software/systemd
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: libtasn1-6
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 133
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 4.18.0-4build1
Depends: libc6 (>= 2.14)
Description: Manage ASN.1 structures (runtime)
Manage ASN1 (Abstract Syntax Notation One) structures.
The main features of this library are:

- on-line ASN1 structure management that doesn't require any C code
  file generation.
- off-line ASN1 structure management with C code file generation
  containing an array.
- DER (Distinguish Encoding Rules) encoding
- no limits for INTEGER and ENUMERATED values
  .
  This package contains runtime libraries.
  Homepage: https://www.gnu.org/software/libtasn1/
  Original-Maintainer: Debian GnuTLS Maintainers <pkg-gnutls-maint@lists.alioth.debian.org>

Package: libtcl8.6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 4091
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tcl8.6
Version: 8.6.12+dfsg-1build1
Replaces: tcl8.6 (<< 8.6.0-2)
Provides: libtcl
Depends: tzdata, libc6 (>= 2.35), zlib1g (>= 1:1.2.2)
Suggests: tcl8.6
Breaks: nsf (<< 2.2.0)
Conflicts: tcl74 (<= 7.4p3-2), tcl8.6 (<< 8.6.0-2)
Description: Tcl (the Tool Command Language) v8.6 - run-time library files
Tcl is a powerful, easy to use, embeddable, cross-platform interpreted
scripting language. This package contains the Tcl library and auxiliary
code which allows one to run Tcl-enabled applications. This version
includes thread support.
Homepage: http://www.tcl.tk/
Original-Maintainer: Debian Tcl/Tk Packagers <pkg-tcltk-devel@lists.alioth.debian.org>

Package: libterm-readkey-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 72
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2.38-1build4
Depends: perl, perlapi-5.34.0, libc6 (>= 2.28)
Description: perl module for simple terminal control
Term::ReadKey is a compiled perl module dedicated to providing simple
control over terminal driver modes (cbreak, raw, cooked, etc.) support for
non-blocking reads, if the architecture allows, and some generalized handy
functions for working with terminals. One of the main goals is to have the
functions as portable as possible, so you can just plug in "use
Term::ReadKey" on any architecture and have a good likelihood of it working.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/TermReadKey

Package: libtext-charwidth-perl
Status: install ok installed
Priority: important
Section: perl
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.04-10build3
Depends: libc6 (>= 2.34), perl-base, perlapi-5.34.0
Description: get display widths of characters on the terminal
Text::CharWidth permits one to get the display widths of characters
and strings on the terminal, using wcwidth() and wcswidth() from libc.
.
It provides mbwidth(), mbswidth(), and mblen().
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Text-CharWidth

Package: libtext-iconv-perl
Status: install ok installed
Priority: important
Section: perl
Installed-Size: 52
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.7-7build3
Depends: libc6 (>= 2.34), perl-base, perlapi-5.34.0
Description: module to convert between character sets in Perl
The iconv() family of functions from XPG4 defines an API for converting
between character sets (e.g. UTF-8 to Latin1, EBCDIC to ASCII). They
are provided by libc6.
.
This package allows access to them from Perl via the Text::Iconv
package.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Text-Iconv

Package: libtext-wrapi18n-perl
Status: install ok installed
Priority: important
Section: perl
Installed-Size: 25
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.06-9
Depends: libtext-charwidth-perl
Description: internationalized substitute of Text::Wrap
The Text::WrapI18N module is a substitution for Text::Wrap, supporting
multibyte characters such as UTF-8, EUC-JP, and GB2312, fullwidth characters
such as east Asian characters, combining characters such as diacritical marks
and Thai, and languages which don't use whitespaces between words such as
Chinese and Japanese.
.
It provides wrap().
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Text-WrapI18N

Package: libthai-data
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 595
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: libthai
Version: 0.1.29-1build1
Breaks: libthai0 (<< 0.1.10)
Description: Data files for Thai language support library
LibThai is a set of Thai language support routines aimed to ease
developers' tasks to incorporate Thai language support in their applications.
It includes important Thai-specific functions e.g. word breaking, input and
output methods as well as basic character and string supports.
.
This package contains data files needed by the LibThai library.
Homepage: https://linux.thai.net/projects/libthai
Original-Maintainer: Theppitak Karoonboonyanan <thep@debian.org>

Package: libthai0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 99
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libthai
Version: 0.1.29-1build1
Depends: libthai-data (>= 0.1.10), libc6 (>= 2.14), libdatrie1 (>= 0.2.0)
Enhances: libqtcore4, libqtgui4
Description: Thai language support library
LibThai is a set of Thai language support routines aimed to ease
developers' tasks to incorporate Thai language support in their applications.
It includes important Thai-specific functions e.g. word breaking, input and
output methods as well as basic character and string supports.
.
This package contains the shared libraries needed to run programs that use
the LibThai library.
Homepage: https://linux.thai.net/projects/libthai
Original-Maintainer: Theppitak Karoonboonyanan <thep@debian.org>

Package: libtie-ixhash-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 33
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.23-2.1
Depends: perl:any
Description: Perl module to order associative arrays
Tie::IxHash implements Perl hashes that preserve the order in which the
hash elements were added. The order is not affected when values
corresponding to existing keys in the IxHash are changed. The elements can
also be set to any arbitrary supplied order. The familiar perl array
operations can also be performed on the IxHash.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Tie-IxHash

Package: libtiff5
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 570
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tiff
Version: 4.3.0-6
Depends: libc6 (>= 2.33), libdeflate0 (>= 1.0), libjbig0 (>= 2.0), libjpeg8 (>= 8c), liblzma5 (>= 5.1.1alpha+20120614), libwebp7, libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Description: Tag Image File Format (TIFF) library
libtiff is a library providing support for the Tag Image File Format
(TIFF), a widely used format for storing image data. This package
includes the shared library.
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>
Homepage: https://libtiff.gitlab.io/libtiff/

Package: libtimedate-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 123
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.3300-2
Depends: perl:any
Description: collection of modules to manipulate date/time information
TimeDate is a collection of Perl modules useful for manipulating date and
time information. Date::Parse can parse absolute date specifications in a
wide variety of input formats and many languages (via Date::Language).
.
This package also includes Date::Format, which can format dates into strings,
as well as Time::Zone, which contains miscellaneous time zone functions.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/TimeDate

Package: libtinfo6
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 558
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: ncurses
Version: 6.3-2
Depends: libc6 (>= 2.33)
Description: shared low-level terminfo library for terminal handling
The ncurses library routines are a terminal-independent method of
updating character screens with reasonable optimization.
.
This package contains the shared low-level terminfo library.
Original-Maintainer: Craig Small <csmall@debian.org>
Homepage: https://invisible-island.net/ncurses/

Package: libtirpc-common
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 32
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: libtirpc
Version: 1.3.2-2ubuntu0.1
Replaces: libtirpc1, libtirpc3 (<< 1.1.4-0.1~)
Breaks: libtirpc1, libtirpc3 (<< 1.1.4-0.1~)
Conffiles:
/etc/netconfig ca8db53e3af4d735335c2607d21c7195
Description: transport-independent RPC library - common files
This package contains a port of Sun's transport-independent RPC library to
Linux. The library is intended as a replacement for the RPC code in the GNU C
library, providing among others support for RPC (and in turn, NFS) over IPv6.
.
This package contains the netconfig configuration file as well as the
associated manpage.
Homepage: http://sourceforge.net/projects/libtirpc
Original-Maintainer: Josue Ortega <josue@debian.org>

Package: libtirpc-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 720
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libtirpc
Version: 1.3.2-2ubuntu0.1
Depends: libtirpc3 (= 1.3.2-2ubuntu0.1)
Description: transport-independent RPC library - development files
This package contains a port of Sun's transport-independent RPC library to
Linux. The library is intended as a replacement for the RPC code in the GNU C
library, providing among others support for RPC (and in turn, NFS) over IPv6.
.
This package contains the files needed for development against libtirpc.
Homepage: http://sourceforge.net/projects/libtirpc
Original-Maintainer: Josue Ortega <josue@debian.org>

Package: libtirpc3
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 219
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libtirpc
Version: 1.3.2-2ubuntu0.1
Depends: libc6 (>= 2.34), libgssapi-krb5-2 (>= 1.17), libtirpc-common (>= 1.3.2-2ubuntu0.1)
Breaks: nfs-common (<< 1:1.2.8-7), nfs-kernel-server (<< 1:1.2.8-7)
Description: transport-independent RPC library
This package contains a port of Sun's transport-independent RPC library to
Linux. The library is intended as a replacement for the RPC code in the GNU C
library, providing among others support for RPC (and in turn, NFS) over IPv6.
Homepage: http://sourceforge.net/projects/libtirpc
Original-Maintainer: Josue Ortega <josue@debian.org>

Package: libtry-tiny-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 48
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.31-1
Depends: perl:any
Suggests: libsub-name-perl
Description: module providing minimalistic try/catch
Try::Tiny is a Perl module that provides bare bones try/catch statements. It
is designed to eliminate common mistakes with eval blocks, and NOTHING else.
.
The main focus of this module is to provide simple and reliable error
handling for those having a hard time installing TryCatch, but who still want
to write correct eval blocks without 5 lines of boilerplate each time.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/Try-Tiny

Package: libtsan0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 7254
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-11
Version: 11.2.0-19ubuntu1
Depends: gcc-11-base (= 11.2.0-19ubuntu1), libc6 (>= 2.34), libgcc-s1
Description: ThreadSanitizer -- a Valgrind-based detector of data races (runtime)
ThreadSanitizer (Tsan) is a data race detector for C/C++ programs.
The Linux and Mac versions are based on Valgrind.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libtss2-esys-3.0.2-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 623
Maintainer: Mathieu Trudel-Lapierre <cyphermox@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tpm2-tss
Version: 3.2.0-1ubuntu1
Replaces: libtss2-esys0 (<< 3.0.2-1)
Depends: libtss2-tcti-cmd0, libtss2-tcti-device0, libtss2-tcti-mssim0, libtss2-tcti-swtpm0, tpm-udev, libc6 (>= 2.34), libssl3 (>= 3.0.0~~alpha1), libtss2-mu0 (>= 3.0.1), libtss2-sys1 (>= 3.1.0)
Breaks: libtss2-esys0 (<< 3.0.2-1)
Description: TPM2 Software stack library - TSS and TCTI libraries
TPM2.0 TSS (Software Stack) consists of API layers provided to support
TPM 2.0 chips. It is made out of three layers:
.

- Enhanced System API (ESAPI)
- System API (SAPI), which implements the system layer API;
- Marshaling/Unmarshaling (MU)
- TPM Command Transmission Interface (TCTI), which is used by SAPI to
  allow communication with the TAB/RM layer;
  .
  This package contains the TSS esys libraries that client applications
  will link against when they require accessing the TPM.
  Homepage: https://github.com/tpm2-software/tpm2-tss

Package: libtss2-mu0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 344
Maintainer: Mathieu Trudel-Lapierre <cyphermox@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tpm2-tss
Version: 3.2.0-1ubuntu1
Replaces: libtss2-esys0 (<< 3.0.1-2)
Depends: tpm-udev, libc6 (>= 2.14)
Breaks: libtss2-esys0 (<< 3.0.1-2)
Description: TPM2 Software stack library - TSS and TCTI libraries
TPM2.0 TSS (Software Stack) consists of API layers provided to support
TPM 2.0 chips. It is made out of three layers:
.

- Enhanced System API (ESAPI)
- System API (SAPI), which implements the system layer API;
- Marshaling/Unmarshaling (MU)
- TPM Command Transmission Interface (TCTI), which is used by SAPI to
  allow communication with the TAB/RM layer;
  .
  This package contains the TSS mu libraries that client applications
  will link against when they require accessing the TPM.
  Homepage: https://github.com/tpm2-software/tpm2-tss

Package: libtss2-sys1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 170
Maintainer: Mathieu Trudel-Lapierre <cyphermox@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tpm2-tss
Version: 3.2.0-1ubuntu1
Replaces: libtss2-esys0 (<< 3.0.1-2)
Depends: tpm-udev, libc6 (>= 2.4), libtss2-mu0 (>= 3.0.1)
Breaks: libtss2-esys0 (<< 3.0.1-2)
Description: TPM2 Software stack library - TSS and TCTI libraries
TPM2.0 TSS (Software Stack) consists of API layers provided to support
TPM 2.0 chips. It is made out of three layers:
.

- Enhanced System API (ESAPI)
- System API (SAPI), which implements the system layer API;
- Marshaling/Unmarshaling (MU)
- TPM Command Transmission Interface (TCTI), which is used by SAPI to
  allow communication with the TAB/RM layer;
  .
  This package contains the TSS sys libraries that client applications
  will link against when they require accessing the TPM.
  Homepage: https://github.com/tpm2-software/tpm2-tss

Package: libtss2-tcti-cmd0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 57
Maintainer: Mathieu Trudel-Lapierre <cyphermox@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tpm2-tss
Version: 3.2.0-1ubuntu1
Replaces: libtss2-esys0 (<< 3.0.1-2)
Depends: tpm-udev, libc6 (>= 2.7), libtss2-mu0 (>= 3.0.1)
Breaks: libtss2-esys0 (<< 3.0.1-2)
Description: TPM2 Software stack library - TSS and TCTI libraries
TPM2.0 TSS (Software Stack) consists of API layers provided to support
TPM 2.0 chips. It is made out of three layers:
.

- Enhanced System API (ESAPI)
- System API (SAPI), which implements the system layer API;
- Marshaling/Unmarshaling (MU)
- TPM Command Transmission Interface (TCTI), which is used by SAPI to
  allow communication with the TAB/RM layer;
  .
  This package contains the TCTI cmd libraries that client applications
  will link against when they require accessing the TPM.
  Homepage: https://github.com/tpm2-software/tpm2-tss

Package: libtss2-tcti-device0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 52
Maintainer: Mathieu Trudel-Lapierre <cyphermox@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tpm2-tss
Version: 3.2.0-1ubuntu1
Replaces: libtss2-esys0 (<< 3.0.1-2)
Depends: tpm-udev, libc6 (>= 2.4), libtss2-mu0 (>= 3.0.1)
Breaks: libtss2-esys0 (<< 3.0.1-2)
Description: TPM2 Software stack library - TSS and TCTI libraries
TPM2.0 TSS (Software Stack) consists of API layers provided to support
TPM 2.0 chips. It is made out of three layers:
.

- Enhanced System API (ESAPI)
- System API (SAPI), which implements the system layer API;
- Marshaling/Unmarshaling (MU)
- TPM Command Transmission Interface (TCTI), which is used by SAPI to
  allow communication with the TAB/RM layer;
  .
  This package contains the TCTI device libraries that client applications
  will link against when they require accessing the TPM.
  Homepage: https://github.com/tpm2-software/tpm2-tss

Package: libtss2-tcti-mssim0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 56
Maintainer: Mathieu Trudel-Lapierre <cyphermox@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tpm2-tss
Version: 3.2.0-1ubuntu1
Replaces: libtss2-esys0 (<< 3.0.1-2)
Depends: tpm-udev, libc6 (>= 2.7), libtss2-mu0 (>= 3.0.1)
Breaks: libtss2-esys0 (<< 3.0.1-2)
Description: TPM2 Software stack library - TSS and TCTI libraries
TPM2.0 TSS (Software Stack) consists of API layers provided to support
TPM 2.0 chips. It is made out of three layers:
.

- Enhanced System API (ESAPI)
- System API (SAPI), which implements the system layer API;
- Marshaling/Unmarshaling (MU)
- TPM Command Transmission Interface (TCTI), which is used by SAPI to
  allow communication with the TAB/RM layer;
  .
  This package contains the TCTI mssim libraries that client applications
  will link against when they require accessing the TPM.
  Homepage: https://github.com/tpm2-software/tpm2-tss

Package: libtss2-tcti-swtpm0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 56
Maintainer: Mathieu Trudel-Lapierre <cyphermox@ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tpm2-tss
Version: 3.2.0-1ubuntu1
Replaces: libtss2-esys0 (<< 3.0.1-2)
Depends: tpm-udev, libc6 (>= 2.14), libtss2-mu0 (>= 3.0.1)
Breaks: libtss2-esys0 (<< 3.0.1-2)
Description: TPM2 Software stack library - TSS and TCTI libraries
TPM2.0 TSS (Software Stack) consists of API layers provided to support
TPM 2.0 chips. It is made out of three layers:
.

- Enhanced System API (ESAPI)
- System API (SAPI), which implements the system layer API;
- Marshaling/Unmarshaling (MU)
- TPM Command Transmission Interface (TCTI), which is used by SAPI to
  allow communication with the TAB/RM layer;
  .
  This package contains the TCTI swtpm libraries that client applications
  will link against when they require accessing the TPM.
  Homepage: https://github.com/tpm2-software/tpm2-tss

Package: libubsan1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 2675
Maintainer: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gcc-12
Version: 12-20220319-1ubuntu1
Depends: gcc-12-base (= 12-20220319-1ubuntu1), libc6 (>= 2.34), libgcc-s1 (>= 3.3), libstdc++6 (>= 4.1.1)
Description: UBSan -- undefined behaviour sanitizer (runtime)
UndefinedBehaviorSanitizer can be enabled via -fsanitize=undefined.
Various computations will be instrumented to detect undefined behavior
at runtime. Available for C and C++.
Homepage: http://gcc.gnu.org/
Original-Maintainer: Debian GCC Maintainers <debian-gcc@lists.debian.org>

Package: libuchardet0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 208
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: uchardet
Version: 0.0.7-1build2
Depends: libc6 (>= 2.14), libgcc-s1 (>= 3.3.1), libstdc++6 (>= 4.1.1)
Description: universal charset detection library - shared library
uchardet is a C language binding of the original C++ implementation
of the universal charset detection library by Mozilla.
.
uchardet is a encoding detector library, which takes a sequence of
bytes in an unknown character encoding without any additional
information, and attempts to determine the encoding of the text.
.
This package contains the shared library.
Homepage: https://www.freedesktop.org/wiki/Software/uchardet/
Original-Maintainer: James Cowgill <jcowgill@debian.org>

Package: libudev1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 345
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: systemd
Version: 249.11-0ubuntu3.4
Depends: libc6 (>= 2.34)
Description: libudev shared library
This library provides access to udev device information.
Homepage: https://www.freedesktop.org/wiki/Software/systemd
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: libudisks2-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 835
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: udisks2
Version: 2.9.4-1ubuntu2
Depends: libc6 (>= 2.4), libglib2.0-0 (>= 2.50)
Description: GObject based library to access udisks2
The udisks daemon serves as an interface to system block devices,
implemented via D-Bus. It handles operations such as querying, mounting,
unmounting, formatting, or detaching storage devices such as hard disks
or USB thumb drives.
.
This provides a convenience library for communicating with udisks2 from
GObject based programs.
Homepage: https://www.freedesktop.org/wiki/Software/udisks
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: libunistring2
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 1746
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libunistring
Version: 1.0-1
Depends: libc6 (>= 2.34)
Description: Unicode string library for C
The 'libunistring' library implements Unicode strings (in the UTF-8,
UTF-16, and UTF-32 encodings), together with functions for Unicode
characters (character names, classifications, properties) and
functions for string processing (formatted output, width, word
breaks, line breaks, normalization, case folding, regular
expressions).
.
This package contains the shared library.
Original-Maintainer: Jörg Frings-Fürst <debian@jff.email>
Homepage: https://www.gnu.org/software/libunistring/

Package: libunwind8
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 196
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libunwind
Version: 1.3.2-2build2
Replaces: libgcc1 (<< 1:4.0.0-2)
Depends: libc6 (>= 2.34), liblzma5 (>= 5.1.1alpha+20110809)
Conflicts: libunwind1-dev
Description: library to determine the call-chain of a program - runtime
The primary goal of this project is to define a portable and efficient C
programming interface (API) to determine the call-chain of a program.
The API additionally provides the means to manipulate the preserved
(callee-saved) state of each call-frame and to resume execution at any
point in the call-chain (non-local goto). The API supports both local
(same-process) and remote (across-process) operation. As such, the API
is useful in a number of applications.
.
This package includes the shared libraries
Homepage: http://www.nongnu.org/libunwind
Original-Maintainer: Adrian Bunk <bunk@debian.org>

Package: liburcu8
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 331
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: liburcu
Version: 0.13.1-1
Depends: libc6 (>= 2.34)
Description: userspace RCU (read-copy-update) library
This data synchronization library provides read-side access which scales
linearly with the number of cores. It does so by allowing multiples copies of
a given data structure to live at the same time, and by monitoring the data
structure accesses to detect grace periods after which memory reclamation is
possible.
Original-Maintainer: Jon Bernard <jbernard@debian.org>
Homepage: https://liburcu.org/

Package: liburi-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 222
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 5.10-1
Depends: perl:any
Suggests: libbusiness-isbn-perl (>= 3.005), libwww-perl
Description: module to manipulate and access URI strings
URI is a collection of Perl modules that represent and manipulate Uniform
Resource Identifier (URI) references as specified in RFC 2396.
.
URI objects can be used to access and manipulate the various components
that make up these strings. There are also methods to combine URIs in
various ways.
.
The URI class replaces the URI::URL class that used to be distributed with
libwww-perl. This package also includes an emulation of the old URI::URL
interface, which implements both the old and the new interface.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/URI

Package: libusb-1.0-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 144
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libusb-1.0
Version: 2:1.0.25-1ubuntu2
Depends: libc6 (>= 2.34), libudev1 (>= 183)
Description: userspace USB programming library
Library for programming USB applications without the knowledge
of Linux kernel internals.
.
This package contains what you need to run programs that use this
library.
Homepage: http://www.libusb.info
Original-Maintainer: Aurelien Jarno <aurel32@debian.org>

Package: libutempter0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 51
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libutempter
Version: 1.2.1-2build2
Depends: libc6 (>= 2.34)
Description: privileged helper for utmp/wtmp updates (runtime)
The libutempter library provides interface for terminal emulators such as
screen and xterm to record user sessions to utmp and wtmp files.
.
The utempter is a privileged helper used by libutempter library to manipulate
utmp and wtmp files.
Homepage: http://git.altlinux.org/people/ldv/packages/?p=libutempter.git
Original-Maintainer: Christian Göttsche <cgzones@googlemail.com>

Package: libuuid1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 134
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: util-linux
Version: 2.37.2-4ubuntu3
Depends: libc6 (>= 2.25)
Recommends: uuid-runtime
Description: Universally Unique ID library
The libuuid library generates and parses 128-bit Universally Unique
IDs (UUIDs). A UUID is an identifier that is unique within the space
of all such identifiers across both space and time. It can be used for
multiple purposes, from tagging objects with an extremely short lifetime
to reliably identifying very persistent objects across a network.
.
See RFC 4122 for more information.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: libuv1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 252
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 1.43.0-1
Depends: libc6 (>= 2.34)
Description: asynchronous event notification library - runtime library
Libuv is the asynchronous library behind Node.js. Very similar to libevent or
libev, it provides the main elements for event driven systems: watching and
waiting for availability in a set of sockets, and some other events like timers
or asynchronous messages. However, libuv also comes with some other extras
like:

- files watchers and asynchronous operations
- a portable TCP and UDP API, as well as asynchronous DNS resolution
- processes and threads management, and a portable inter-process
  communications mechanism, with pipes and work queues
- a plugins mechanism for loading libraries dynamically
- interface with external libraries that also need to access the I/O.
  .
  This package includes the dynamic library against which you can link
  your program.
  Original-Maintainer: Dominique Dumont <dod@debian.org>
  Homepage: https://github.com/libuv/libuv

Package: libuv1-dev
Status: install ok installed
Priority: optional
Section: libdevel
Installed-Size: 631
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libuv1
Version: 1.43.0-1
Replaces: libuv-dev
Depends: libuv1 (= 1.43.0-1)
Conflicts: libuv-dev
Description: asynchronous event notification library - development files
Libuv is the asynchronous library behind Node.js. Very similar to libevent or
libev, it provides the main elements for event driven systems: watching and
waiting for availability in a set of sockets, and some other events like timers
or asynchronous messages. However, libuv also comes with some other extras
like:

- files watchers and asynchronous operations
- a portable TCP and UDP API, as well as asynchronous DNS resolution
- processes and threads management, and a portable inter-process
  communications mechanism, with pipes and work queues
- a plugins mechanism for loading libraries dynamically
- interface with external libraries that also need to access the I/O.
  .
  Install this package if you wish to develop your own programs using the
  libuv engine.
  Original-Maintainer: Dominique Dumont <dod@debian.org>
  Homepage: https://github.com/libuv/libuv

Package: libvolume-key1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 180
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: volume-key
Version: 0.3.12-3.1build3
Depends: libblkid1 (>= 2.16), libc6 (>= 2.14), libcryptsetup12 (>= 2:1.4), libglib2.0-0 (>= 2.18.0), libgpgme11 (>= 1.4.1), libnspr4 (>= 2:4.9-2~), libnss3 (>= 2:3.13.4-2~), gnupg
Description: Library for manipulating storage encryption keys and passphrases
This package provides libvolume_key, a library for manipulating storage volume
encryption keys and storing them separately from volumes.
.
The main goal of the software is to allow restoring access to an encrypted
hard drive if the primary user forgets the passphrase. The encryption key
back up can also be useful for extracting data after a hardware or software
failure that corrupts the header of the encrypted volume, or to access the
company data after an employee leaves abruptly.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://pagure.io/volume_key

Package: libvte-2.91-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 569
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: vte2.91
Version: 0.68.0-1
Depends: libvte-2.91-common (= 0.68.0-1), libatk1.0-0 (>= 1.12.4), libc6 (>= 2.34), libcairo2 (>= 1.10.0), libfribidi0 (>= 1.0.0), libgcc-s1 (>= 3.3.1), libglib2.0-0 (>= 2.52.0), libgnutls30 (>= 3.7.2), libgtk-3-0 (>= 3.24.22), libicu70 (>= 70.1-1~), libpango-1.0-0 (>= 1.44.3), libpangocairo-1.0-0 (>= 1.22.0), libpcre2-8-0 (>= 10.22), libstdc++6 (>= 11), libsystemd0 (>= 220), zlib1g (>= 1:1.2.0)
Description: Terminal emulator widget for GTK+ 3.0 - runtime files
The VTE library provides a terminal emulator widget VteTerminal for
applications using the GTK+ toolkit. It also provides the VtePTY object
containing functions for starting a new process on a new
pseudo-terminal and for manipulating pseudo-terminals.
.
This package contains the runtime library, needed by programs using the
VTE widget with GTK+ 3.0.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Apps/Terminal/VTE

Package: libvte-2.91-common
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 152
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: vte2.91
Version: 0.68.0-1
Depends: libc6 (>= 2.34)
Conffiles:
/etc/profile.d/vte-2.91.sh a1f60728d39e70bdfb1039b296dd52ca
/etc/profile.d/vte.csh 1f922824a6d29c466178d0834d17321c
Description: Terminal emulator widget for GTK+ 3.0 - common files
The VTE library provides a terminal emulator widget VteTerminal for
applications using the GTK+ toolkit. It also provides the VtePTY object
containing functions for starting a new process on a new
pseudo-terminal and for manipulating pseudo-terminals.
.
This package contains internationalization files for the VTE library
and common files for the GTK+ 3.x version.
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>
Homepage: https://wiki.gnome.org/Apps/Terminal/VTE

Package: libvted-3-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 235
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: gtk-d
Version: 3.10.0-1ubuntu1
Depends: libvte-2.91-0, libc6 (>= 2.14), libgcc-s1 (>= 3.0), libphobos2-ldc-shared98 (>= 1:1.28.0)
Description: Terminal emulator widget for GTK+ - D bindings
The VTE library provides a terminal emulator widget VteTerminal for
applications using the GTK+ toolkit.
It also provides the VtePTY object containing functions for starting a
new process on a new pseudo-terminal and for manipulating pseudo-terminals.
.
This package contains the D language bindings for VTE.
Homepage: https://gtkd.org/
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: libvulkan1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 494
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: vulkan-loader
Version: 1.3.204.1-2
Replaces: libvulkan-dev (<< 1.1.70+dfsg1-2), vulkan-loader
Depends: libc6 (>= 2.34)
Recommends: mesa-vulkan-drivers | vulkan-icd
Breaks: libvulkan-dev (<< 1.1.70+dfsg1-2), vulkan-loader
Description: Vulkan loader library
The Loader implements the main VK library. It handles layer management and
driver management. The loader fully supports multi-gpu operation. As part of
this, it dispatches API calls to the correct driver, and to the correct
layers, based on the GPU object selected by the application.
.
This package includes the loader library.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://github.com/KhronosGroup/Vulkan-Loader

Package: libwayland-client0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 85
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: wayland
Version: 1.20.0-1
Replaces: libwayland0 (<< 1.1.0-1)
Depends: libc6 (>= 2.28), libffi8 (>= 3.4)
Conflicts: libwayland0 (<< 1.1.0-1)
Description: wayland compositor infrastructure - client library
Wayland is a protocol for a compositor to talk to its clients as well
as a C library implementation of that protocol. The compositor can be
a standalone display server running on Linux kernel modesetting and
evdev input devices, an X application, or a wayland client
itself. The clients can be traditional applications, X servers
(rootless or fullscreen) or other display servers.
.
This package ships the library that implements the client side of
the Wayland protocol.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://wayland.freedesktop.org/

Package: libwayland-cursor0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 58
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: wayland
Version: 1.20.0-1
Replaces: libwayland0 (<< 1.1.0-1)
Depends: libc6 (>= 2.28), libwayland-client0 (>= 1.20.0)
Conflicts: libwayland0 (<< 1.1.0-1)
Description: wayland compositor infrastructure - cursor library
Wayland is a protocol for a compositor to talk to its clients as well
as a C library implementation of that protocol. The compositor can be
a standalone display server running on Linux kernel modesetting and
evdev input devices, an X application, or a wayland client
itself. The clients can be traditional applications, X servers
(rootless or fullscreen) or other display servers.
.
This package ships a helper library to manage cursors.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://wayland.freedesktop.org/

Package: libwayland-egl1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 38
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: wayland
Version: 1.20.0-1
Replaces: libwayland-egl1-mesa (<< 18.0.5-0)
Provides: libwayland-egl1-mesa
Depends: libc6 (>= 2.2.5)
Breaks: libwayland-egl1-mesa (<< 18.0.5-0)
Description: wayland compositor infrastructure - EGL library
Wayland is a protocol for a compositor to talk to its clients as well
as a C library implementation of that protocol. The compositor can be
a standalone display server running on Linux kernel modesetting and
evdev input devices, an X application, or a wayland client
itself. The clients can be traditional applications, X servers
(rootless or fullscreen) or other display servers.
.
This package ships the library that implements the Wayland EGL platform
of the Wayland protocol.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://wayland.freedesktop.org/

Package: libwebp7
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 435
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libwebp
Version: 1.2.2-2
Depends: libc6 (>= 2.34)
Description: Lossy compression of digital photographic images
Image Compression format, based on the VP8 codec.
WebP uses the modern VP8 compression format to deliver efficient
compression of images for the web. More than 30% extra gain over
optimized JPEG, for same quality, is not unusual.
Original-Maintainer: Jeff Breidenbach <jab@debian.org>
Homepage: https://developers.google.com/speed/webp/

Package: libwrap0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 109
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: tcp-wrappers
Version: 7.6.q-31build2
Depends: libc6 (>= 2.33), libnsl2 (>= 1.0)
Description: Wietse Venema's TCP wrappers library
Wietse Venema's network logger, also known as TCPD or LOG_TCP.
.
These programs log the client host name of incoming telnet,
ftp, rsh, rlogin, finger etc. requests.
.
Security options are:

- access control per host, domain and/or service;
- detection of host name spoofing or host address spoofing;
- booby traps to implement an early-warning system.
  Original-Maintainer: Marco d'Itri <md@linux.it>

Package: libwww-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 380
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 6.61-1
Depends: perl:any, ca-certificates, libencode-locale-perl, libfile-listing-perl, libhtml-parser-perl, libhtml-tagset-perl, libhtml-tree-perl, libhttp-cookies-perl, libhttp-date-perl, libhttp-message-perl, libhttp-negotiate-perl, liblwp-mediatypes-perl, liblwp-protocol-https-perl, libnet-http-perl, libtry-tiny-perl, liburi-perl, libwww-robotrules-perl, netbase
Recommends: libdata-dump-perl, libhtml-form-perl, libhtml-format-perl, libhttp-daemon-perl, libmailtools-perl
Suggests: libauthen-ntlm-perl
Description: simple and consistent interface to the world-wide web
libwww-perl (also known as LWP) is a collection of Perl modules that provide
a simple and consistent programming interface (API) to the World-Wide Web.
The main focus of the library is to provide classes and functions that allow
you to write WWW clients. It also contains general purpose modules, as well
as a simple HTTP/1.1-compatible server implementation.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/libwww-perl

Package: libwww-robotrules-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 35
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.02-1
Replaces: libwww-perl (<< 6.00)
Depends: perl, liburi-perl
Breaks: libwww-perl (<< 6.00)
Description: database of robots.txt-derived permissions
WWW::RobotRules parses /robots.txt files as specified in "A Standard for
Robot Exclusion", at <http://www.robotstxt.org/wc/norobots.html>. Webmasters
can use the /robots.txt file to forbid conforming robots from accessing parts
of their web site.
.
The parsed files are kept in a WWW::RobotRules object, and this object
provides methods to check if access to a given URL is prohibited. The same
WWW::RobotRules object can be used for one or more parsed /robots.txt files
on any number of hosts.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/WWW-RobotRules

Package: libx11-6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 1386
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libx11
Version: 2:1.7.5-1
Depends: libc6 (>= 2.34), libxcb1 (>= 1.11.1), libx11-data
Breaks: libx11-xcb1 (<< 2:1.7.0-2)
Description: X11 client-side library
This package provides a client interface to the X Window System, otherwise
known as 'Xlib'. It provides a complete API for the basic functions of the
window system.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
https://gitlab.freedesktop.org/xorg/lib/libX11
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libx11-data
Status: install ok installed
Priority: optional
Section: x11
Installed-Size: 1429
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: libx11
Version: 2:1.7.5-1
Breaks: libx11-6 (<< 2:1.4.1)
Description: X11 client-side library
This package provides the locale data files for libx11.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
https://gitlab.freedesktop.org/xorg/lib/libX11
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libx11-protocol-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 366
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.56-7.1
Depends: perl:any
Recommends: perl (>= 5.19.8) | libio-socket-ip-perl
Description: Perl module for the X Window System Protocol, version 11
X11::Protocol is a client-side interface to the X11 Protocol (see X(1) for
information about X11), allowing perl programs to display windows and
graphics on X11 servers.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/X11-Protocol

Package: libx11-xcb1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 84
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libx11
Version: 2:1.7.5-1
Depends: libx11-6 (= 2:1.7.5-1)
Description: Xlib/XCB interface library
libX11-xcb provides functions needed by clients which take advantage of
Xlib/XCB to mix calls to both Xlib and XCB over the same X connection.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
More information about XCB can be found at:
<URL:https://xcb.freedesktop.org>
.
This module can be found at
https://gitlab.freedesktop.org/xorg/lib/libX11
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxau6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 35
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxau
Version: 1:1.0.9-1build5
Depends: libc6 (>= 2.33)
Description: X11 authorisation library
This package provides the main interface to the X11 authorisation handling,
which controls authorisation for X connections, both client-side and
server-side.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
https://gitlab.freedesktop.org/xorg/lib/libxau
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxaw7
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 495
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxaw
Version: 2:1.0.14-1
Depends: libc6 (>= 2.15), libx11-6, libxext6, libxmu6 (>= 2:1.1.3), libxpm4, libxt6
Description: X11 Athena Widget library
libXaw7 provides the second version of Xaw, the Athena Widgets toolkit,
which is largely used by legacy X applications. This version is the
most common version, as version 6 is considered deprecated, and version
8, which adds Xprint support, is unsupported and not widely used.
In general, use of a more modern toolkit such as GTK+ is recommended.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXaw
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-dri2-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 46
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.4), libxcb1
Description: X C Binding, dri2 extension
This package contains the library files needed to run software using
libxcb-dri2, the dri2 extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-dri3-0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 46
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.4), libxcb1 (>= 1.12)
Description: X C Binding, dri3 extension
This package contains the library files needed to run software using
libxcb-dri3, the dri3 extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-glx0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 154
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.4), libxcb1
Description: X C Binding, glx extension
This package contains the library files needed to run software using
libxcb-glx, the glx extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-present0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 36
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.4), libxcb1
Description: X C Binding, present extension
This package contains the library files needed to run software using
libxcb-present, the present extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-randr0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 106
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.4), libxcb1 (>= 1.9.2)
Description: X C Binding, randr extension
This package contains the library files needed to run software using
libxcb-randr, the randr extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-render0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 86
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.14), libxcb1 (>= 1.8)
Description: X C Binding, render extension
This package contains the library files needed to run software using
libxcb-render, the render extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-shape0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 37
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.4), libxcb1
Description: X C Binding, shape extension
This package contains the library files needed to run software using
libxcb-shape, the shape extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-shm0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 36
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.4), libxcb1 (>= 1.12)
Description: X C Binding, shm extension
This package contains the library files needed to run software using
libxcb-shm, the shm extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-sync1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 59
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.14), libxcb1
Description: X C Binding, sync extension
This package contains the library files needed to run software using
libxcb-sync, the sync extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb-xfixes0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 60
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.4), libxcb1
Description: X C Binding, xfixes extension
This package contains the library files needed to run software using
libxcb-xfixes, the xfixes extension for the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcb1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 206
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcb
Version: 1.14-3ubuntu3
Depends: libc6 (>= 2.14), libxau6 (>= 1:1.0.9), libxdmcp6
Breaks: alsa-utils (<< 1.0.24.2-5)
Description: X C Binding
This package contains the library files needed to run software using libxcb,
the X C Binding.
.
The XCB library provides an interface to the X Window System protocol,
designed to replace the Xlib interface. XCB provides several advantages over
Xlib:
.

- Size: small library and lower memory footprint
- Latency hiding: batch several requests and wait for the replies later
- Direct protocol access: one-to-one mapping between interface and protocol
- Thread support: access XCB from multiple threads, with no explicit locking
- Easy creation of new extensions: automatically generates interface from
  machine-parsable protocol descriptions
  Homepage: https://xcb.freedesktop.org
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcomposite1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 32
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcomposite
Version: 1:0.4.5-1build2
Depends: libc6 (>= 2.4), libx11-6 (>= 2:1.4.99.1)
Description: X11 Composite extension library
libXcomposite provides an X Window System client interface to the Composite
extension to the X protocol.
.
The Composite extension allows clients called compositing managers to control
the final drawing of the screen. Rendering is done into an off-screen buffer.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXcomposite
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxcursor1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 63
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxcursor
Version: 1:1.2.0-2build4
Depends: libc6 (>= 2.4), libx11-6 (>= 2:1.4.99.1), libxfixes3, libxrender1
Description: X cursor management library
Xcursor is a simple library designed to help locate and load cursors for the
X Window System. Cursors can be loaded from files or memory and can exist in
several sizes; the library automatically picks the best size. When using
images loaded from files, Xcursor prefers to use the Render extension's
CreateCursor request for rendering cursors. Where the Render extension is
not supported, Xcursor maps the cursor image to a standard X cursor and uses
the core X protocol CreateCursor request.
.
Preferred themes for cursors can be installed if desired, via
xcursor-themes or other cursor-theme or icon-theme packages,
configured with update-alternatives --config x-cursor-theme.
Homepage: https://www.x.org
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxdamage1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxdamage
Version: 1:1.1.5-2build2
Depends: libc6 (>= 2.4), libx11-6 (>= 2:1.4.99.1)
Description: X11 damaged region extension library
libXdamage provides an X Window System client interface to the DAMAGE
extension to the X protocol.
.
The Damage extension provides for notification of when on-screen regions have
been 'damaged' (altered).
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXdamage
Homepage: https://www.x.org
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxdmcp6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 43
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxdmcp
Version: 1:1.1.3-0ubuntu5
Depends: libbsd0 (>= 0.2.0), libc6 (>= 2.4)
Description: X11 Display Manager Control Protocol library
This package provides the main interface to the X11 display manager control
protocol library, which allows for remote logins to display managers.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXdmcp
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxext6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 110
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxext
Version: 2:1.3.4-1build1
Depends: libc6 (>= 2.14), libx11-6 (>= 2:1.6.0)
Description: X11 miscellaneous extension library
libXext provides an X Window System client interface to several extensions to
the X protocol.
.
The supported protocol extensions are:

- DOUBLE-BUFFER (DBE), the Double Buffer extension;
- DPMS, the VESA Display Power Management System extension;
- Extended-Visual-Information (EVI), an extension for gathering extra
  information about the X server's visuals;
- LBX, the Low Bandwidth X extension;
- MIT-SHM, the MIT X client/server shared memory extension;
- MIT-SUNDRY-NONSTANDARD, a miscellaneous extension by MIT;
- Multi-Buffering, the multi-buffering and stereo display extension;
- SECURITY, the X security extension;
- SHAPE, the non-rectangular shaped window extension;
- SYNC, the X synchronization extension;
- TOG-CUP, the Open Group's Colormap Utilization extension;
- XC-APPGROUP, the X Consortium's Application Group extension;
- XC-MISC, the X Consortium's resource ID querying extension;
- XTEST, the X test extension (this is one of two client-side
  implementations; the other is in the libXtst library, provided by the
  libxtst6 package);
  .
  libXext also provides a small set of utility functions to aid authors of
  client APIs for X protocol extensions.
  .
  More information about X.Org can be found at:
  <URL:http://www.X.org>
  .
  This module can be found at
  git://anongit.freedesktop.org/git/xorg/lib/libXext
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxfixes3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 51
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxfixes
Version: 1:6.0.0-1
Depends: libc6 (>= 2.14), libx11-6 (>= 2:1.6.0)
Description: X11 miscellaneous 'fixes' extension library
libXfixes provides an X Window System client interface to the 'XFIXES'
extension to the X protocol.
.
It provides support for Region types, and some cursor functions.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXfixes
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxft2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 118
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: xft
Version: 2.3.4-1
Depends: libc6 (>= 2.14), libfontconfig1 (>= 2.12.6), libfreetype6 (>= 2.3.5), libx11-6, libxrender1
Description: FreeType-based font drawing library for X
Xft provides a client-side font API for X applications, making the FreeType
font rasterizer available to X clients. Fontconfig is used for font
specification resolution. Where available, the RENDER extension handles
glyph drawing; otherwise, the core X protocol is used.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxi6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 100
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxi
Version: 2:1.8-1build1
Depends: libc6 (>= 2.14), libx11-6 (>= 2:1.6.0), libxext6
Description: X11 Input extension library
libXi provides an X Window System client interface to the XINPUT
extension to the X protocol.
.
The Input extension allows setup and configuration of multiple input devices,
and hotplugging of input devices (to be added and removed on the fly).
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXi
Homepage: https://www.x.org/
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxinerama1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 37
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxinerama
Version: 2:1.1.4-3
Depends: libc6 (>= 2.4), libx11-6 (>= 2:1.6.0), libxext6
Description: X11 Xinerama extension library
libXinerama provides an X Window System client interface to the XINERAMA
extension to the X protocol.
.
The Xinerama (also known as panoramiX) extension allows for multiple screens
attached to a single display to be treated as belonging together, and to give
desktop applications a better idea of the monitor layout.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXinerama
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxkbcommon0
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 302
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxkbcommon
Version: 1.4.0-1
Depends: xkb-data, libc6 (>= 2.33)
Description: library interface to the XKB compiler - shared library
This package provides a library to handle keyboard descriptions, including
loading them from disk, parsing them and handling their state. It's mainly
meant for client toolkits, window systems, and other system applications;
currently that includes Wayland, kmscon, GTK+, Clutter, and more.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
https://github.com/xkbcommon/libxkbcommon.git
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: http://www.xkbcommon.org/

Package: libxkbfile1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 178
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxkbfile
Version: 1:1.1.0-1build3
Depends: libc6 (>= 2.14), libx11-6
Description: X11 keyboard file manipulation library
libxkbfile provides an interface to read and manipulate description files for
XKB, the X11 keyboard configuration extension.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libxkbfile
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxml-parser-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 691
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 2.46-3build1
Depends: perl, perlapi-5.34.0, libc6 (>= 2.34), libexpat1 (>= 2.0.1), liburi-perl, libwww-perl
Description: Perl module for parsing XML files
The XML::Parser module provides ways to parse XML documents. It is built on
top of XML::Parser::Expat, which is a lower level interface to James Clark's
expat library. Each call to one of the parsing methods creates a new instance
of XML::Parser::Expat which is then used to parse the document. Expat options
may be provided when the XML::Parser object is created. These options are
then passed on to the Expat object on each parse call. They can also be given
as extra arguments to the parse methods, in which case they override options
given at XML::Parser creation time.
.
The behavior of the parser is controlled either by Style and/or Handlers
options, or by setHandlers method. These all provide mechanisms for
XML::Parser to set the handlers needed by XML::Parser::Expat. If neither
Style nor Handlers are specified, then parsing just checks the document for
being well-formed.
.
When underlying handlers get called, they receive as their first parameter
the Expat object, not the Parser object.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/XML-Parser

Package: libxml-twig-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 552
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1:3.52-1
Depends: perl:any, libxml-parser-perl
Recommends: libhtml-parser-perl, libtext-iconv-perl, libtie-ixhash-perl, libwww-perl, libxml-xpathengine-perl | libxml-xpath-perl
Suggests: libunicode-map8-perl, libunicode-string-perl, xml-twig-tools
Description: Perl module for processing huge XML documents in tree mode
The XML::Twig module provides a way to process XML documents. It is built on
top of XML::Parser.
.
The module offers a tree interface to the document, while allowing to
output the parts of it that have been completely processed.
.
It allows minimal resource (CPU and memory) usage by building the
tree only for the parts of the documents that need actual processing,
through the use of the twig_roots and twig_print_outside_roots
options. The finish and finish_print methods also help to increase
performance.
.
XML::Twig tries to make simple things easy so it tries its best to
takes care of a lot of the (usually) annoying (but sometimes
necessary) features that come with XML and XML::Parser.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/XML-Twig

Package: libxml-xpathengine-perl
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 127
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.14-1
Depends: perl
Description: re-usable XPath engine for DOM-like trees
XML::XPathEngine provides an XPath engine, that can be re-used by other
module/classes that implement trees.
.
In order to use the XPath engine, nodes in the user module need to mimic
DOM nodes. The degree of similarity between the user tree and a DOM dictates
how much of the XPath features can be used. A module implementing all of the
DOM should be able to use this module very easily (you might need to add
the cmp method on nodes in order to get ordered result sets).
.
This module is derived from Matt Sergeant's XML::XPath.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>
Homepage: https://metacpan.org/release/XML-XPathEngine

Package: libxml2
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 2096
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 2.9.13+dfsg-1ubuntu0.1
Depends: libc6 (>= 2.34), libicu70 (>= 70.1-1~), liblzma5 (>= 5.1.1alpha+20120614), zlib1g (>= 1:1.2.3.3)
Conflicts: w3c-dtd-xhtml
Description: GNOME XML library
XML is a metalanguage to let you design your own markup language.
A regular markup language defines a way to describe information in
a certain class of documents (eg HTML). XML lets you define your
own customized markup languages for many classes of document. It
can do this because it's written in SGML, the international standard
metalanguage for markup languages.
.
This package provides a library providing an extensive API to handle
such XML data files.
Homepage: http://xmlsoft.org
Original-Maintainer: Debian XML/SGML Group <debian-xml-sgml-pkgs@lists.alioth.debian.org>

Package: libxmlb2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 198
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxmlb
Version: 0.3.6-2build1
Depends: libc6 (>= 2.14), libglib2.0-0 (>= 2.53.2), liblzma5 (>= 5.1.1alpha+20120614)
Description: Binary XML library
The libxmlb library takes XML source, and
converts it to a structured binary representation with a deduplicated string
table -- where the strings have the NULs included.
.
This allows an application to mmap the binary XML file, do an XPath query and
return some strings without actually parsing the entire document. This is all
done using (almost) zero allocations and no actual copying of the binary data.
Homepage: https://github.com/hughsie/libxmlb
Original-Maintainer: Debian EFI team <debian-efi@lists.debian.org>

Package: libxmlsec1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 435
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: xmlsec1
Version: 1.2.33-1build2
Depends: libc6 (>= 2.14), libxml2 (>= 2.8.0), libxslt1.1 (>= 1.1.25)
Breaks: libreoffice-core (<< 1:6.0.5~rc2~)
Description: XML security library
The XML Security Library implements standards related to secure handling
of XML data.
.
This package provides dynamic libraries for use by applications.
Specifically, it provides all XML security library functionality
except for the cryptography engine.
Homepage: https://www.aleksey.com/xmlsec/
Original-Maintainer: Debian XML/SGML Group <debian-xml-sgml-pkgs@lists.alioth.debian.org>

Package: libxmlsec1-openssl
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 304
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: xmlsec1
Version: 1.2.33-1build2
Depends: libc6 (>= 2.14), libssl3 (>= 3.0.0~~alpha1), libxml2 (>= 2.8.0), libxmlsec1 (>= 1.2.33)
Description: Openssl engine for the XML security library
The XML Security Library implements standards related to secure handling
of XML data.
.
This package provides dynamic libraries for use by applications.
Specifically, it provides the openssl implementation of the XML security
library cryptography functions.
Homepage: https://www.aleksey.com/xmlsec/
Original-Maintainer: Debian XML/SGML Group <debian-xml-sgml-pkgs@lists.alioth.debian.org>

Package: libxmu6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 127
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxmu
Version: 2:1.1.3-3
Depends: libc6 (>= 2.14), libx11-6, libxext6, libxt6
Description: X11 miscellaneous utility library
libXmu provides a set of miscellaneous utility convenience functions for X
libraries to use. libXmuu is a lighter-weight version that does not depend
on libXt or libXext; for more information, see libxmuu1.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXmu
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxmuu1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 41
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxmu
Version: 2:1.1.3-3
Depends: libc6 (>= 2.4), libx11-6
Description: X11 miscellaneous micro-utility library
libXmuu provides a set of miscellaneous utility convenience functions for X
libraries to use. It is a lighter version of libXmu that does not depend
on libXt or libXext; for more information on libXmu, see libxmu6.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXmu
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxpm4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 97
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxpm
Version: 1:3.5.12-1build2
Depends: libc6 (>= 2.33), libx11-6
Description: X11 pixmap library
The X PixMap image format is an extension of the monochrome X BitMap
format specified in the X protocol, and is commonly used in traditional
X applications.
.
This package provides runtime support for XPM format.
Homepage: https://www.x.org
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxrandr2
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxrandr
Version: 2:1.5.2-1build1
Depends: libc6 (>= 2.14), libx11-6 (>= 2:1.6.0), libxext6, libxrender1
Description: X11 RandR extension library
libXrandr provides an X Window System client interface to the RandR
extension to the X protocol.
.
The RandR extension allows for run-time configuration of display attributes
such as resolution, rotation, and reflection.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXrandr
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxrender1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 68
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxrender
Version: 1:0.9.10-1build4
Depends: libc6 (>= 2.14), libx11-6 (>= 2:1.6.0)
Description: X Rendering Extension client library
The X Rendering Extension (Render) introduces digital image composition as
the foundation of a new rendering model within the X Window System.
Rendering geometric figures is accomplished by client-side tessellation into
either triangles or trapezoids. Text is drawn by loading glyphs into the
server and rendering sets of them. The Xrender library exposes this
extension to X clients.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXrender
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxshmfence1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 30
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxshmfence
Version: 1.3-1build4
Depends: libc6 (>= 2.27)
Description: X shared memory fences - shared library
This library provides an interface to shared-memory fences for
synchronization between the X server and direct-rendering clients.
.
This package contains the xshmfence shared library.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxslt1.1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 499
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxslt
Version: 1.1.34-4ubuntu0.22.04.1
Depends: libc6 (>= 2.33), libgcrypt20 (>= 1.9.0), libxml2 (>= 2.9.0)
Description: XSLT 1.0 processing library - runtime library
XSLT is an XML language for defining transformations of XML files from
XML to some other arbitrary format, such as XML, HTML, plain text, etc.
using standard XSLT stylesheets. libxslt is a C library which
implements XSLT version 1.0.
.
This package contains the libxslt library used by applications for XSLT
transformations.
Homepage: http://xmlsoft.org/xslt/
Original-Maintainer: Debian XML/SGML Group <debian-xml-sgml-pkgs@lists.alioth.debian.org>

Package: libxt6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 467
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxt
Version: 1:1.2.1-1
Depends: libc6 (>= 2.33), libice6 (>= 1:1.0.0), libsm6, libx11-6
Description: X11 toolkit intrinsics library
libXt provides the X Toolkit Intrinsics, an abstract widget library upon
which other toolkits are based. Xt is the basis for many toolkits, including
the Athena widgets (Xaw), and LessTif (a Motif implementation).
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXt
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxtables12
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 114
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: iptables
Version: 1.8.7-1ubuntu5
Replaces: iptables (<< 1.4.16.3-3), libxtables11 (>= 1.6.0+snapshot20161117-1)
Depends: libc6 (>= 2.34)
Breaks: iptables (<< 1.4.16.3-3), libxtables11 (>= 1.6.0+snapshot20161117-1)
Description: netfilter xtables library
The iptables/xtables framework has been replaced by nftables. You should
consider migrating now.
.
This package contains the user-space interface to the Netfilter xtables
kernel framework.
Homepage: https://www.netfilter.org/
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>

Package: libxtst6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 48
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxtst
Version: 2:1.2.3-1build4
Depends: libc6 (>= 2.4), libx11-6 (>= 2:1.6.0), libxext6, x11-common
Description: X11 Testing -- Record extension library
libXtst provides an X Window System client interface to the Record
extension to the X protocol.
.
The Record extension allows X clients to synthesise input events, which
is useful for automated testing.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXtst
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxv1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 40
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxv
Version: 2:1.0.11-1build2
Depends: libc6 (>= 2.14), libx11-6 (>= 2:1.6.0), libxext6
Description: X11 Video extension library
libXv provides an X Window System client interface to the XVideo
extension to the X protocol.
.
The XVideo extension allows for accelerated drawing of videos. Hardware
adaptors are exposed to clients, which may draw in a number of colourspaces,
including YUV.
.
More information about X.Org can be found at:
<URL:https://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXv
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxxf86dga1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 43
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxxf86dga
Version: 2:1.1.5-0ubuntu3
Depends: libc6 (>= 2.4), libx11-6 (>= 2:1.6.0), libxext6
Description: X11 Direct Graphics Access extension library
libXxf86dga provides the XFree86-DGA extension, which allows direct
graphics access to a framebuffer-like region, and also allows relative
mouse reporting, et al. It is mainly used by games and emulators for
games.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXxf86dga
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxxf86vm1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 39
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libxxf86vm
Version: 1:1.1.4-1build3
Depends: libc6 (>= 2.4), libx11-6 (>= 2:1.6.0), libxext6
Description: X11 XFree86 video mode extension library
libXxf86vm provides an interface to the XFree86-VidModeExtension
extension, which allows client applications to get and set video mode
timings in extensive detail. It is used by the xvidtune program in
particular.
.
More information about X.Org can be found at:
<URL:http://www.X.org>
.
This module can be found at
git://anongit.freedesktop.org/git/xorg/lib/libXxf86vm
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: libxxhash0
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 97
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: xxhash
Version: 0.8.1-1
Depends: libc6 (>= 2.14)
Description: shared library for xxhash
xxHash is an Extremely fast Hash algorithm, running at RAM speed limits.
It successfully completes the SMHasher test suite which evaluates collision,
dispersion and randomness qualities of hash functions. Code is highly portable,
and hashes are identical on all platforms (little / big endian).
.
This package contains the shared library.
Original-Maintainer: Josue Ortega <josue@debian.org>
Homepage: https://cyan4973.github.io/xxHash

Package: libyaml-0-2
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 144
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libyaml
Version: 0.2.2-1build2
Depends: libc6 (>= 2.14)
Description: Fast YAML 1.1 parser and emitter library
LibYAML is a C library for parsing and emitting data in YAML 1.1, a
human-readable data serialization format.
Homepage: https://github.com/yaml/libyaml
Original-Maintainer: Anders Kaseorg <andersk@mit.edu>

Package: libzstd1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 846
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: libzstd
Version: 1.4.8+dfsg-3build1
Depends: libc6 (>= 2.14)
Description: fast lossless compression algorithm
Zstd, short for Zstandard, is a fast lossless compression algorithm, targeting
real-time compression scenarios at zlib-level compression ratio.
.
This package contains the shared library.
Homepage: https://github.com/facebook/zstd
Original-Maintainer: Debian Med Packaging Team <debian-med-packaging@lists.alioth.debian.org>

Package: linux-base
Status: install ok installed
Priority: optional
Section: kernel
Installed-Size: 63
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.5ubuntu9
Depends: debconf (>= 0.5) | debconf-2.0
Conffiles:
/etc/kernel/postinst.d/xx-update-initrd-links b41c8cb1275704cf344e3e87c84633b2
Description: Linux image base package
This package contains files and support scripts for all Linux
images.
Original-Maintainer: Debian Kernel Team <debian-kernel@lists.debian.org>

Package: linux-libc-dev
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 6549
Maintainer: Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: linux
Version: 5.15.0-47.51
Replaces: linux-kernel-headers
Provides: aufs-dev, linux-kernel-headers
Conflicts: linux-kernel-headers
Description: Linux Kernel Headers for development
This package provides headers from the Linux kernel. These headers
are used by the installed headers for GNU glibc and other system
libraries. They are NOT meant to be used to build third-party modules for
your kernel. Use linux-headers-\* packages for that.

Package: locales
Status: install ok installed
Priority: important
Section: libs
Installed-Size: 17064
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: glibc
Version: 2.35-0ubuntu3.1
Depends: libc-bin (>> 2.35), debconf (>= 0.5) | debconf-2.0
Conffiles:
/etc/locale.alias 4a3f5ef911616822ec6fe04e31930bbf
Description: GNU C Library: National Language (locale) data [support]
Machine-readable data files, shared objects and programs used by the
C library for localization (l10n) and internationalization (i18n) support.
.
This package contains tools to generate locale definitions from source
files (included in this package). It allows you to customize which
definitions actually get generated. This is a space-saver over how this
package used to be, with all locales generated by default. This created
a package that unpacked to an excess of 30 megs.
Homepage: https://www.gnu.org/software/libc/libc.html
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Original-Vcs-Browser: https://salsa.debian.org/glibc-team/glibc
Original-Vcs-Git: https://salsa.debian.org/glibc-team/glibc.git

Package: login
Essential: yes
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 888
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: shadow
Version: 1:4.8.1-2ubuntu2
Pre-Depends: libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libpam0g (>= 0.99.7.1), libpam-runtime, libpam-modules
Breaks: util-linux (<< 2.32-0.2~)
Conflicts: python-4suite (<< 0.99cvs20060405-1)
Conffiles:
/etc/login.defs 905e8b2d452e98ee5d9ac93adfcfdc8b
/etc/pam.d/login 5afbc06eb5f71fef25170cf3c936a442
Description: system login tools
This package provides some required infrastructure for logins and for
changing effective user or group IDs, including:

- login, the program that invokes a user shell on a virtual terminal;
- nologin, a dummy shell for disabled user accounts;
- su, a basic tool for executing commands as root or another user.
  Homepage: https://github.com/shadow-maint/shadow
  Original-Maintainer: Shadow package maintainers <pkg-shadow-devel@lists.alioth.debian.org>

Package: logrotate
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 167
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 3.19.0-1ubuntu1.1
Depends: cron | anacron | cron-daemon | systemd-sysv, libacl1 (>= 2.2.23), libc6 (>= 2.34), libpopt0 (>= 1.14), libselinux1 (>= 3.1~)
Suggests: bsd-mailx | mailx
Conffiles:
/etc/cron.daily/logrotate 31da718265eaaa2fdabcfb2743bda171
/etc/logrotate.conf b0a820970ecd7412a334ade9c98de3f6
/etc/logrotate.d/btmp 55631862595faf6432786dc335eb3f44
/etc/logrotate.d/wtmp 46cd7ecb1810441bd450987a976f5540
Description: Log rotation utility
The logrotate utility is designed to simplify the administration of
log files on a system which generates a lot of log files. Logrotate
allows for the automatic rotation compression, removal and mailing of
log files. Logrotate can be set to handle a log file daily, weekly,
monthly or when the log file gets to a certain size. Normally, logrotate
runs as a daily cron job.
Homepage: https://github.com/logrotate/logrotate
Original-Maintainer: Christian Göttsche <cgzones@googlemail.com>

Package: logsave
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 97
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: e2fsprogs
Version: 1.46.5-2ubuntu1.1
Replaces: e2fsprogs (<< 1.45.3-1)
Depends: libc6 (>= 2.34)
Breaks: e2fsprogs (<< 1.45.3-1)
Description: save the output of a command in a log file
The logsave program will execute cmd_prog with the specified
argument(s), and save a copy of its output to logfile. If the
containing directory for logfile does not exist, logsave will
accumulate the output in memory until it can be written out. A copy
of the output will also be written to standard output.
Homepage: http://e2fsprogs.sourceforge.net
Original-Maintainer: Theodore Y. Ts'o <tytso@mit.edu>

Package: lsb-base
Status: install ok installed
Priority: required
Section: misc
Installed-Size: 58
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: lsb
Version: 11.1.0ubuntu4
Description: Linux Standard Base init script functionality
The Linux Standard Base (http://www.linuxbase.org/) is a standard
core system that third-party applications written for Linux can
depend upon.
.
This package only includes the init-functions shell library, which
may be used by other packages' initialization scripts for console
logging and other purposes.
Homepage: https://wiki.linuxfoundation.org/lsb/start
Original-Maintainer: Debian sysvinit maintainers <debian-init-diversity@chiark.greenend.org.uk>

Package: lsb-release
Status: install ok installed
Priority: important
Section: misc
Installed-Size: 66
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: lsb
Version: 11.1.0ubuntu4
Depends: python3:any, distro-info-data
Recommends: apt
Description: Linux Standard Base version reporting utility
The Linux Standard Base (http://www.linuxbase.org/) is a standard
core system that third-party applications written for Linux can
depend upon.
.
The lsb-release command is a simple tool to help identify the Linux
distribution being used and its compliance with the Linux Standard Base.
LSB conformance will not be reported unless the required metapackages are
installed.
.
While it is intended for use by LSB packages, this command may also
be useful for programmatically distinguishing between a pure Debian
installation and derived distributions.
Homepage: https://wiki.linuxfoundation.org/lsb/start
Original-Maintainer: Debian sysvinit maintainers <debian-init-diversity@chiark.greenend.org.uk>

Package: lshw
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 921
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 02.19.git.2021.06.19.996aaad9c7-2build1
Depends: libc6 (>= 2.34), libgcc-s1 (>= 3.0), libstdc++6 (>= 11)
Recommends: pci.ids, usb.ids
Description: information about hardware configuration
A small tool to provide detailed information on the hardware
configuration of the machine. It can report exact memory
configuration, firmware version, mainboard configuration, CPU version
and speed, cache configuration, bus speed, etc. on DMI-capable x86
systems, on some PowerPC machines (PowerMac G4 is known to work) and AMD64.
.
Information can be output in plain text, HTML or XML.
Homepage: https://github.com/lyonel/lshw
Original-Maintainer: Ghe Rivero <ghe@debian.org>

Package: lsof
Status: install ok installed
Priority: standard
Section: utils
Installed-Size: 447
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 4.93.2+dfsg-1.1build2
Depends: libc6 (>= 2.34), libselinux1 (>= 3.1~), libtirpc3 (>= 1.0.2)
Suggests: perl
Description: utility to list open files
Lsof is a Unix-specific diagnostic tool. Its name stands
for LiSt Open Files, and it does just that. It lists
information about any files that are open, by processes
currently running on the system.
Homepage: https://github.com/lsof-org/lsof
Original-Maintainer: Andres Salomon <dilinger@debian.org>

Package: lto-disabled-list
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 39
Maintainer: Matthias Klose <doko@ubuntu.com>
Architecture: all
Version: 24
Description: list of packages not to build with LTO
A list of source packages not to build with link time
optimization (LTO).
.
Entries in this list should have a bug report filed with
the (user) tag 'lto'.

Package: lvm2
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 4032
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.03.11-2.1ubuntu4
Depends: libaio1 (>= 0.3.93), libblkid1 (>= 2.24.2), libc6 (>= 2.34), libdevmapper-event1.02.1 (>= 2:1.02.74), libedit2 (>= 2.11-20080614-0), libselinux1 (>= 3.1~), libsystemd0 (>= 222), libudev1 (>= 183), lsb-base, dmsetup (>= 2:1.02.175-2.1ubuntu4~), dmeventd (>= 2:1.02.175-2.1ubuntu4~)
Pre-Depends: init-system-helpers (>= 1.54~)
Recommends: thin-provisioning-tools
Conffiles:
/etc/init.d/lvm2 70063dce3a90eca5ef673579e5fcc402
/etc/init.d/lvm2-lvmpolld 6ee7740a641d91e302d3fbfe42a14942
/etc/lvm/lvm.conf ab4fc5f2986ceaade6a005f65f23dc26
/etc/lvm/lvmlocal.conf eeccf159eb1e1af87ca0c141235822b2
/etc/lvm/profile/cache-mq.profile 9df1883c03bac9d3041e75745cb5e0ec
/etc/lvm/profile/cache-smq.profile d27b7f0947c6ac21944c05e6098b9850
/etc/lvm/profile/command_profile_template.profile 3bab119bec857c31a53725da2d0a9408
/etc/lvm/profile/lvmdbusd.profile ffa904d375ce53ebb6befe7d65cf391a
/etc/lvm/profile/metadata_profile_template.profile bccbaf503cb8f0adb5b4f841f7c1f735
/etc/lvm/profile/thin-generic.profile f57ede2b5b249024766c51a223e15ed5
/etc/lvm/profile/thin-performance.profile f4de81439550553043e04f019a48a827
/etc/lvm/profile/vdo-small.profile da26d10e71e517a6f02ff0d53395e3c9
Description: Linux Logical Volume Manager
This is LVM2, the rewrite of The Linux Logical Volume Manager. LVM
supports enterprise level volume management of disk and disk subsystems
by grouping arbitrary disks into volume groups. The total capacity of
volume groups can be allocated to logical volumes, which are accessed as
regular block devices.
Homepage: https://sourceware.org/lvm2/
Original-Maintainer: Debian LVM Team <team+lvm@tracker.debian.org>

Package: lxd-agent-loader
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 24
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.5
Description: LXD - VM agent loader
The LXD VM agent enables access to advanced LXD features such as file
transfer and command spawning inside virtual machines run by LXD.
.
This package contains init scripts that will automatically load the
agent and run it when started in a LXD VM.
Homepage: https://linuxcontainers.org/

Package: make
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 416
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: make-dfsg
Version: 4.3-4.1build1
Replaces: make-guile
Depends: libc6 (>= 2.34)
Suggests: make-doc
Conflicts: make-guile
Description: utility for directing compilation
GNU Make is a utility which controls the generation of executables
and other target files of a program from the program's source
files. It determines automatically which pieces of a large program
need to be (re)created, and issues the commands to (re)create
them. Make can be used to organize any task in which targets (files)
are to be automatically updated based on input files whenever the
corresponding input is newer --- it is not limited to building
computer programs. Indeed, Make is a general purpose dependency
solver.
Original-Maintainer: Manoj Srivastava <srivasta@debian.org>
Homepage: https://www.gnu.org/software/make/

Package: man-db
Status: install ok installed
Priority: important
Section: doc
Installed-Size: 2824
Maintainer: Colin Watson <cjwatson@debian.org>
Architecture: amd64
Multi-Arch: foreign
Version: 2.10.2-1
Replaces: man, nlsutils
Provides: man, man-browser
Depends: bsdextrautils | bsdmainutils (<< 12.1.1~), groff-base, debconf (>= 0.5) | debconf-2.0, libc6 (>= 2.34), libgdbm6 (>= 1.16), libpipeline1 (>= 1.5.0), libseccomp2 (>= 2.1.0), zlib1g (>= 1:1.1.4)
Suggests: apparmor, groff, less, www-browser
Conflicts: man
Conffiles:
/etc/apparmor.d/usr.bin.man 4f614d75041882370498f7fe2d43a44b
/etc/cron.daily/man-db 857c7372869b8f2105d316c606472d24
/etc/cron.weekly/man-db 7d3f58916b8a9840cd602991375e7781
/etc/manpath.config 77d8f48dc5c371248a79d1add5a68707
Description: tools for reading manual pages
This package provides the man command, the primary way of examining the
system help files (manual pages). Other utilities provided include the
whatis and apropos commands for searching the manual page database, the
manpath utility for determining the manual page search path, and the
maintenance utilities mandb, catman and zsoelim. man-db uses the groff
suite of programs to format and display the manual pages.
Homepage: https://nongnu.org/man-db/

Package: manpages
Status: install ok installed
Priority: standard
Section: doc
Installed-Size: 1669
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 5.10-1ubuntu1
Replaces: attr (<< 1:2.4.47-3), keyutils (<< 1.6-1), manpages-dev (<< 5.09-2)
Suggests: man-browser
Breaks: attr (<< 1:2.4.47-3), keyutils (<< 1.6-1), manpages-dev (<< 5.09-2)
Description: Manual pages about using a GNU/Linux system
This package contains GNU/Linux manual pages for these sections:
4 = Devices (e.g. hd, sd).
5 = File formats and protocols, syntaxes of several system
files (e.g. wtmp, /etc/passwd, nfs).
7 = Conventions and standards, macro packages, etc.
(e.g. nroff, ascii).
.
Sections 1, 6 and 8 are provided by the respective applications. This
package only includes the intro man page describing the section.
.
The man pages describe syntaxes of several system files.
Homepage: https://www.kernel.org/doc/man-pages/
Original-Maintainer: Dr. Tobias Quathamer <toddy@debian.org>

Package: manpages-dev
Status: install ok installed
Priority: optional
Section: doc
Installed-Size: 3942
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: manpages
Version: 5.10-1ubuntu1
Replaces: libattr1-dev (<< 1:2.4.47-3), libbsd-dev (<< 0.8.4-1)
Depends: manpages
Suggests: man-browser
Breaks: libattr1-dev (<< 1:2.4.47-3), libbsd-dev (<< 0.8.4-1), manpages (<< 5.09-2)
Description: Manual pages about using GNU/Linux for development
These man pages describe the Linux programming interface, including
these two sections:
2 = Linux system calls.
3 = Library calls (note that a more comprehensive source of information
may be found in the glibc-doc and glibc-doc-reference packages).
Homepage: https://www.kernel.org/doc/man-pages/
Original-Maintainer: Dr. Tobias Quathamer <toddy@debian.org>

Package: mawk
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 229
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.3.4.20200120-3
Provides: awk
Depends: libc6 (>= 2.34)
Description: Pattern scanning and text processing language
Mawk is an interpreter for the AWK Programming Language. The AWK
language is useful for manipulation of data files, text retrieval and
processing, and for prototyping and experimenting with algorithms. Mawk
is a new awk meaning it implements the AWK language as defined in Aho,
Kernighan and Weinberger, The AWK Programming Language, Addison-Wesley
Publishing, 1988. (Hereafter referred to as the AWK book.) Mawk conforms
to the POSIX 1003.2 (draft 11.3) definition of the AWK language
which contains a few features not described in the AWK book, and mawk
provides a small number of extensions.
.
Mawk is smaller and much faster than gawk. It has some compile-time
limits such as NF = 32767 and sprintf buffer = 1020.
Original-Maintainer: Boyuan Yang <byang@debian.org>
Homepage: https://invisible-island.net/mawk/

Package: mdadm
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 1180
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 4.2-0ubuntu1
Depends: debconf (>= 0.5) | debconf-2.0, libc6 (>= 2.34), libudev1 (>= 183), debconf, lsb-base, udev
Recommends: finalrd (>= 3~), kmod | module-init-tools
Suggests: default-mta | mail-transport-agent, dracut-core
Conffiles:
/etc/logcheck/ignore.d.server/mdadm 5eeaf5c5c7dc0291a986e43004dfd495
/etc/logcheck/violations.d/mdadm efd87cec251921ce0642171eae5f3b73
/etc/modprobe.d/mdadm.conf d3be82c0f275d6c25b04d388baf9e836
Description: Tool to administer Linux MD arrays (software RAID)
The mdadm utility can be used to create, manage, and monitor MD
(multi-disk) arrays for software RAID or multipath I/O.
.
This package automatically configures mdadm to assemble arrays during the
system startup process. If not needed, this functionality can be disabled.
Homepage: http://neil.brown.name/blog/mdadm
Original-Maintainer: Felix Lechner <felix.lechner@lease-up.com>

Package: media-types
Status: install ok installed
Priority: important
Section: net
Installed-Size: 97
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 7.0.0
Replaces: mime-support (<< 3.65)
Breaks: mime-support (<< 3.65)
Conffiles:
/etc/mime.types 2e5f0c27e65400ea230c8a94be277b86
Description: List of standard media types and their usual file extension
This package installs the configuration file /etc/mime.types, that lists
standard media types (originally known as "MIME" types) and their usual file
extension. This provides a simple way for programs to have a first guess at a
file's content. On standard Debian desktop systems, one will also find more
sophisticated tools, for instance provided by the "file" and "xdg-utils"
packages.
.
The /etc/mime.types file is compiled by hand using mostly information provided
by the Internet Assigned Numbers Authority (IANA).
Original-Maintainer: Mime-Support Packagers <team+debian-mimesupport-packagers@tracker.debian.org>

Package: mesa-vulkan-drivers
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 22513
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: mesa
Version: 22.0.5-0ubuntu0.1
Provides: vulkan-icd
Depends: libvulkan1, libc6 (>= 2.34), libdrm-amdgpu1 (>= 2.4.109), libdrm2 (>= 2.4.99), libelf1 (>= 0.142), libexpat1 (>= 2.0.1), libgcc-s1 (>= 3.4), libllvm13, libstdc++6 (>= 11), libwayland-client0 (>= 1.20.0), libx11-xcb1 (>= 2:1.7.5), libxcb-dri3-0 (>= 1.13), libxcb-present0, libxcb-randr0 (>= 1.13), libxcb-shm0, libxcb-sync1, libxcb1 (>= 1.9.2), libxshmfence1, libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Description: Mesa Vulkan graphics drivers
Vulkan is a low-overhead 3D graphics and compute API. This package
includes Vulkan drivers provided by the Mesa project.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://mesa3d.org/

Package: modemmanager
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 4340
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.18.6-1
Depends: libc6 (>= 2.34), libglib2.0-0 (>= 2.56.0), libgudev-1.0-0 (>= 232), libmbim-glib4 (>= 1.26.0), libmbim-proxy, libmm-glib0 (>= 1.18.2), libpolkit-gobject-1-0 (>= 0.99), libqmi-glib5 (>= 1.30.2), libqmi-proxy, libsystemd0 (>= 209), policykit-1
Recommends: usb-modeswitch
Conffiles:
/etc/dbus-1/system.d/org.freedesktop.ModemManager1.conf b34f558232938aad76d7b38fd94aaa61
Description: D-Bus service for managing modems
ModemManager is a DBus-activated daemon which controls mobile broadband
(2G/3G/4G/5G) devices and connections. Whether built-in devices, USB dongles,
Bluetooth-paired telephones or professional RS232/USB devices with external
power supplies, ModemManager is able to prepare and configure the modems and
setup connections with them.
Original-Maintainer: DebianOnMobile Maintainers <debian-on-mobile-maintainers@alioth-lists.debian.net>
Homepage: https://www.freedesktop.org/wiki/Software/ModemManager/

Package: motd-news-config
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 47
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: base-files
Version: 12ubuntu4.2
Replaces: base-files (<< 11ubuntu11)
Breaks: base-files (<< 11ubuntu11)
Conffiles:
/etc/default/motd-news c08a329a603b640095da5ffe4e73491c
Description: Configuration for motd-news shipped in base-files
This package contains the configuration read by the motd-news script
shipped in the base-files package.
.
Install this package if you want motd-news to be enabled.
Original-Maintainer: Santiago Vila <sanvila@debian.org>

Package: mount
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 389
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: util-linux
Version: 2.37.2-4ubuntu3
Pre-Depends: libblkid1 (>= 2.17.2), libc6 (>= 2.34), libmount1 (>= 2.37.2), libselinux1 (>= 3.1~), libsmartcols1 (>= 2.33)
Suggests: nfs-common
Description: tools for mounting and manipulating filesystems
This package provides the mount(8), umount(8), swapon(8),
swapoff(8), and losetup(8) commands.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: mtr-tiny
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 157
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: mtr
Version: 0.95-1
Replaces: mtr
Depends: libc6 (>= 2.34), libjansson4 (>= 2.0.1), libncurses6 (>= 6), libtinfo6 (>= 6)
Breaks: mtr, suidmanager (<< 0.50)
Description: Full screen ncurses traceroute tool
mtr combines the functionality of the 'traceroute' and 'ping' programs
in a single network diagnostic tool.
.
As mtr starts, it investigates the network connection between the host
mtr runs on and a user-specified destination host. After it
determines the address of each network hop between the machines,
it sends a sequence of ICMP ECHO requests to each one to determine the
quality of the link to each machine. As it does this, it prints
running statistics about each machine.
.
mtr-tiny is compiled without support for X and conserves disk space.
Original-Maintainer: Robert Woodcock <rcw@debian.org>
Homepage: https://www.bitwizard.nl/mtr/

Package: multipath-tools
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 1227
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.8.8-1ubuntu1
Depends: libaio1 (>= 0.3.93), libc6 (>= 2.34), libdevmapper1.02.1 (>= 2:1.02.110), libjson-c5 (>= 0.15), libreadline8 (>= 6.0), libsystemd0, libudev1 (>= 183), liburcu8 (>= 0.13.0), udev, kpartx (>= 0.8.8-1ubuntu1), lsb-base, sg3-utils-udev
Suggests: multipath-tools-boot
Conffiles:
/etc/init.d/multipath-tools 6ec3946b0ec5d4b8383d18803affe52a
/etc/multipath.conf a14f69c91f2ba59a279ac6018d23d28b
Description: maintain multipath block device access
These tools are in charge of maintaining the disk multipath device maps and
react to path and map events.
.
If you install this package you may have to change the way you address block
devices. See README.Debian for details.
Homepage: http://christophe.varoqui.free.fr/
Original-Maintainer: Debian DM Multipath Team <team+linux-blocks@tracker.debian.org>

Package: nano
Status: install ok installed
Priority: important
Section: editors
Installed-Size: 860
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 6.2-1
Replaces: nano-tiny (<< 2.8.6-2), pico
Depends: libc6 (>= 2.34), libncursesw6 (>= 6), libtinfo6 (>= 6)
Suggests: hunspell
Breaks: nano-tiny (<< 2.8.6-2)
Conflicts: pico
Conffiles:
/etc/nanorc b2c34817282284614d58163ef56df0d9
Description: small, friendly text editor inspired by Pico
GNU nano is an easy-to-use text editor originally designed as a replacement
for Pico, the ncurses-based editor from the non-free mailer package Pine
(itself now available under the Apache License as Alpine).
.
However, GNU nano also implements many features missing in Pico, including:

- undo/redo
- line numbering
- syntax coloring
- soft-wrapping of overlong lines
- selecting text by holding Shift
- interactive search and replace (with regular expression support)
- a go-to line (and column) command
- support for multiple file buffers
- auto-indentation
- tab completion of filenames and search terms
- toggling features while running
- and full internationalization support
  Original-Maintainer: Jordi Mallach <jordi@debian.org>
  Homepage: https://www.nano-editor.org/

Package: ncurses-base
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 393
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: ncurses
Version: 6.3-2
Provides: ncurses-runtime
Breaks: bash-static (<< 4.4.18-1.1), libmono-corlib4.5-cil (<< 4.6.2.7+dfsg-2), libslang2 (<< 2.3.1a-3), libtinfo5 (<< 6.1), libunibilium0 (<< 2), libunibilium4 (<< 2.0.0-3), neovim (<< 0.6.0), zsh-static (<< 5.4.2-4)
Conffiles:
/etc/terminfo/README 45b6df19fb5e21f55717482fa7a30171
Description: basic terminal type definitions
The ncurses library routines are a terminal-independent method of
updating character screens with reasonable optimization.
.
This package contains terminfo data files to support the most common types of
terminal, including ansi, dumb, linux, rxvt, screen, sun, vt100, vt102, vt220,
vt52, and xterm.
Original-Maintainer: Craig Small <csmall@debian.org>
Homepage: https://invisible-island.net/ncurses/

Package: ncurses-bin
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 646
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: ncurses
Version: 6.3-2
Pre-Depends: libc6 (>= 2.34), libtinfo6 (>= 6.3)
Description: terminal-related programs and man pages
The ncurses library routines are a terminal-independent method of
updating character screens with reasonable optimization.
.
This package contains the programs used for manipulating the terminfo
database and individual terminfo entries, as well as some programs for
resetting terminals and such.
Original-Maintainer: Craig Small <csmall@debian.org>
Homepage: https://invisible-island.net/ncurses/

Package: ncurses-term
Status: install ok installed
Priority: standard
Section: misc
Installed-Size: 4249
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: ncurses
Version: 6.3-2
Replaces: alacritty (<< 0.3.4~), dvtm (<< 0.15-3), jfbterm (<< 0.4.7-10), kon2 (<< 0.3.9b-21), libiterm1 (<< 0.5-9), tn5250 (<< 0.17.4-3)
Depends: ncurses-base (>= 6.1+20190713)
Breaks: bash-static (<< 4.4.18-1.1), dvtm (<< 0.15-3), libmono-corlib4.5-cil (<< 4.6.2.7+dfsg-2), libslang2 (<< 2.3.1a-3), libtinfo5 (<< 6.1), libunibilium0 (<< 2), libunibilium4 (<< 2.0.0-3), zsh-static (<< 5.4.2-4)
Description: additional terminal type definitions
The ncurses library routines are a terminal-independent method of
updating character screens with reasonable optimization.
.
This package contains all of the numerous terminal definitions not found in
the ncurses-base package.
Original-Maintainer: Craig Small <csmall@debian.org>
Homepage: https://invisible-island.net/ncurses/

Package: needrestart
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 500
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.5-5ubuntu2.1
Depends: perl:any, dpkg (>= 1.16.0), gettext-base, libintl-perl, libproc-processtable-perl, libsort-naturally-perl, libmodule-scandeps-perl, libterm-readkey-perl, libmodule-find-perl, binutils, xz-utils
Recommends: libpam-systemd | sysvinit-core
Suggests: needrestart-session | libnotify-bin, iucode-tool
Enhances: intel-microcode
Conffiles:
/etc/apt/apt.conf.d/99needrestart c04ae6629632795828b90dc04b67c6a4
/etc/dpkg/dpkg.cfg.d/needrestart 53f557552f8e6f1c8512d71eb89b7638
/etc/needrestart/conf.d/README.needrestart a1ef1575bfa695c11492ff7457e5c93e
/etc/needrestart/hook.d/10-dpkg 0350df665552fca4b2e371d8ec546101
/etc/needrestart/hook.d/20-rpm 7157aa9de873c3c7ad5bf62b5768adb9
/etc/needrestart/hook.d/90-none 3892c7ecdbc590a1a0dee8a0df6d5695
/etc/needrestart/iucode.sh 080c4c295dbcffce6d9ab3ecb85ec5b6
/etc/needrestart/needrestart.conf df6aa5484b23d1c7b6e2103c0d329baa
/etc/needrestart/notify.conf 1e3d19b4157f3d5af960b65cb368b5ba
/etc/needrestart/notify.d/200-write c20841e6085d2a10670abe1f7e6727ba
/etc/needrestart/notify.d/400-notify-send 37661707e75f680afc028d33df1c9c14
/etc/needrestart/notify.d/600-mail 350d5580971e89cb3a334d974a3f971d
/etc/needrestart/notify.d/README.needrestart ca287f2c1d0b1f4937c72564b28551b2
/etc/needrestart/restart.d/README.needrestart 5b5904ab8d65eaae3644a8d97b1584bb
/etc/needrestart/restart.d/dbus.service af6adfe475eb7fcbbb99854f59e1de76
/etc/needrestart/restart.d/systemd-manager b22b648806843de869331c587f5138c0
/etc/needrestart/restart.d/sysv-init 57d64c59621664a915f6a8e9b672c815
Description: check which daemons need to be restarted after library upgrades
needrestart checks which daemons need to be restarted after library upgrades.
It is inspired by checkrestart from the debian-goodies package.
.
Features:

- supports (but does not require) systemd
- binary blacklisting (i.e. display managers)
- tries to detect required restarts of interpreter based daemons
  (supports Java, Perl, Python, Ruby)
- tries to detect required restarts of containers (docker, LXC)
- tries to detect pending kernel upgrades
- tries to detect pending microcode upgrades for Intel CPUs
- could be used as nagios check_command
- fully integrated into apt/dpkg using hooks
  Homepage: https://github.com/liske/needrestart
  Original-Maintainer: Patrick Matthäi <pmatthaei@debian.org>

Package: netbase
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 41
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 6.3
Replaces: ebtables (<< 2.0.11-2)
Breaks: ebtables (<< 2.0.11-2)
Conffiles:
/etc/ethertypes cde059c510632569fb1869eb86cc026d
/etc/protocols bb9c019d6524e913fd72441d58b68216
/etc/rpc f0b6f6352bf886623adc04183120f83b
/etc/services 3975f0d8c4e1ecb25f035edfb1ba27ac
Description: Basic TCP/IP networking system
This package provides the necessary infrastructure for basic TCP/IP based
networking.
.
In particular, it supplies common name-to-number mappings in /etc/services,
/etc/rpc, /etc/protocols and /etc/ethertypes.
Original-Maintainer: Marco d'Itri <md@linux.it>

Package: netcat-openbsd
Status: install ok installed
Priority: important
Section: net
Installed-Size: 106
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.218-4ubuntu1
Replaces: netcat (<< 1.10-35)
Provides: netcat
Depends: libbsd0 (>= 0.2.0), libc6 (>= 2.34)
Breaks: netcat (<< 1.10-35)
Description: TCP/IP swiss army knife
A simple Unix utility which reads and writes data across network connections
using TCP or UDP protocol. It is designed to be a reliable "back-end" tool
that can be used directly or easily driven by other programs and scripts. At
the same time it is a feature-rich network debugging and exploration tool,
since it can create almost any kind of connection you would need and has
several interesting built-in capabilities.
.
This package contains the OpenBSD rewrite of netcat, including support for
IPv6, proxies, and Unix sockets.
Original-Maintainer: Guilhem Moulin <guilhem@debian.org>

Package: netplan.io
Status: install ok installed
Priority: important
Section: net
Installed-Size: 378
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 0.104-0ubuntu2.1
Replaces: nplan (<< 0.34~)
Provides: nplan
Depends: libc6 (>= 2.34), libglib2.0-0 (>= 2.70.0), libnetplan0 (= 0.104-0ubuntu2.1), libsystemd0 (>= 243), iproute2, python3, python3-yaml, python3-netifaces, systemd (>= 248~)
Suggests: network-manager | wpasupplicant, openvswitch-switch
Breaks: network-manager (<< 1.2.2-1), nplan (<< 0.34~)
Conflicts: netplan
Description: YAML network configuration abstraction for various backends
netplan reads YAML network configuration files which are written
by administrators, installers, cloud image instantiations, or other OS
deployments. During early boot it then generates backend specific
configuration files in /run to hand off control of devices to a particular
networking daemon.
.
Currently supported backends are networkd and NetworkManager.
Homepage: https://netplan.io/
Original-Maintainer: Debian netplan Maintainers <team+netplan@tracker.debian.org>

Package: networkd-dispatcher
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.1-2ubuntu0.22.04.2
Depends: dbus, gir1.2-glib-2.0, python3-dbus, python3-gi, python3:any
Suggests: iw | wireless-tools
Conffiles:
/etc/default/networkd-dispatcher 30d74108d00da7497f70395c32658a41
Description: Dispatcher service for systemd-networkd connection status changes
Networkd-dispatcher is a dispatcher daemon for systemd-networkd
connection status changes. It is similar to NetworkManager-dispatcher,
but is much more limited in the types of events it supports due to the
limited nature of systemd-networkd.
Homepage: https://github.com/craftyguy/networkd-dispatcher
Original-Maintainer: Julian Andres Klode <jak@debian.org>

Package: nftables
Status: install ok installed
Priority: important
Section: net
Installed-Size: 177
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.0.2-1ubuntu3
Depends: libnftables1 (= 1.0.2-1ubuntu3), libc6 (>= 2.34), libedit2 (>= 3.1-20130611-0)
Recommends: netbase
Suggests: firewalld
Conffiles:
/etc/nftables.conf b10493a168ed8e96d0d56408721425c4
Description: Program to control packet filtering rules by Netfilter project
This software provides an in-kernel packet classification framework that is
based on a network-specific Virtual Machine (VM) and the nft userspace
command line tool. The nftables framework reuses the existing Netfilter
subsystems such as the existing hook infrastructure, the connection tracking
system, NAT, userspace queueing and logging subsystem.
.
nftables replaces the old popular iptables, ip6tables, arptables and ebtables.
.
Netfilter software and nftables in particular are used in applications such
as Internet connection sharing, firewalls, IP accounting, transparent
proxying, advanced routing and traffic control.
.
A Linux kernel >= 3.13 is required. However, >= 4.14 is recommended.
Homepage: https://www.netfilter.org/
Original-Maintainer: Debian Netfilter Packaging Team <pkg-netfilter-team@lists.alioth.debian.org>

Package: node-abab
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 25
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.5-2
Depends: nodejs
Description: WHATWG spec-compliant implementations of window.atob and window.btoa
A module that implements window.atob and window.btoa according
to the WHATWG spec.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/jsdom/abab#readme

Package: node-abbrev
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.1.1+~1.1.2-1
Provides: node-types-abbrev (= 1.1.2)
Description: Get unique abbreviations for a set of strings - Node.js module
Given a set of strings, this module computes a list of distinct abbreviations.
This is handy for command-line scripts, or other cases where
one wants to be able to accept shorthands.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/abbrev-js

Package: node-agent-base
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 99
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.0.2+~cs5.4.2-1
Provides: node-async-listen (= 1.2.0), node-types-agent-base (= 4.2.2)
Depends: node-debug, node-semver
Description: Turn a function into an http.Agent instance
This module provides an http.Agent generator. That is, you pass it an async
callback function, and it returns a new http.Agent instance that will invoke
the given callback function when sending outbound HTTP requests.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/TooTallNate/node-agent-base#readme

Package: node-ansi-regex
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 5.0.1-1
Description: regular expression for matching ANSI escape codes
This module provides a regular expression for matching ANSI
escape codes.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/ansi-regex

Package: node-ansi-styles
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.3.0+~4.2.0-1
Provides: node-types-ansi-styles (= 4.2.0)
Depends: node-color-convert
Description: ANSI escape codes for styling strings in the terminal with Node.js
ansi-styles is a Node.js module which provides ANSI escape codes for styling
strings in the terminal.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/ansi-styles

Package: node-ansistyles
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.1.3-5
Description: prints output in different styles
Functions that surround a string with ansistyle codes so it prints in style.
.
This library is a dependency of npm, Node.js package manager.
.
In case you need colors, have a look at ansicolors.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/thlorenz/ansistyles

Package: node-aproba
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0-2
Depends: nodejs
Description: light-weight argument validator
Ridiculously light-weight argument validator with Node.js that is an
event-based server-side JavaScript engine
.
This JavaScript engine can help you to do argument validation in
easy manner. It is easier and concise to use than that of assertions.
The types are specified by a single character and there is nothing
like optional argument.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/iarna/aproba

Package: node-archy
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.0-4
Depends: nodejs
Description: Pretty-print nested hierarchies module for Node.js
Given a tree of nested objects with 'label' and 'nodes' fields,
node-archy returns a string representation of that tree with unicode
pipe characters.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/substack/node-archy

Package: node-are-we-there-yet
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 34
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.0+~1.1.0-1
Provides: node-types-are-we-there-yet (= 1.1.0)
Depends: node-delegates, node-readable-stream
Description: Keep track of the overall completion of many disparate processes
Track complex hierarchies of asynchronous task completion statuses. This is
intended to give you a way of recording and reporting the progress of the big
recursive fan-out and gather type workflows that are so common in async.
.
What you do with this completion data is up to you, but the most common use
case is to feed it to one of the many progress bar modules.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/iarna/are-we-there-yet

Package: node-argparse
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 163
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.1-2
Depends: node-sprintf-js, nodejs
Description: CLI arguments parser for node.js
Javascript port of python's
[argparse](http://docs.python.org/dev/library/argparse.html) module
(original version 3.2). That's a full port, except some very rare options.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/nodeca/argparse

Package: node-arrify
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.1-2
Description: Convert a value to an array
Convert a scalar value or a single element set to an array.
Supplying null or undefined results in an empty array.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/arrify#readme

Package: node-asap
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 43
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.6+~2.0.0-1
Provides: node-types-asap (= 2.0.0)
Description: High-priority task queue for Node.js and browsers
This module executes a task after the scheduled tasks are over
.
ASAP strives to schedule events to occur before yielding for IO, reflow, or
redrawing. ASAP provides a fast event queue that will execute tasks until it
is empty before yielding to the JavaScript engine's underlying event-loop.
When a task gets added to a previously empty event queue, ASAP schedules a
flush event, preferring for that event to occur before the JavaScript engine
has an opportunity to perform IO tasks or rendering, thus making the first
task and subsequent tasks semantically indistinguishable. ASAP uses a
variety of techniques to preserve this invariant on different versions of
browsers and Node.js
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/kriskowal/asap

Package: node-asynckit
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 41
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.4.0-4
Description: Minimal async jobs utility library, with streams support
Runs iterator over provided array sequentially. Stores output in the `result`
array on the matching positions. In unlikely event of an error from one of
the jobs, will not proceed to the rest of the items in the list
and return error along with salvaged data to the main callback function.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/alexindigo/asynckit

Package: node-balanced-match
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0-1
Description: Match balanced character pairs in Node.js
node-balanced-match allows matching balanced string pairs, like { and } or
<b> and </b> in Node.js.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/juliangruber/balanced-match

Package: node-brace-expansion
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 22
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.1-1
Depends: node-balanced-match
Description: Brace expansion as known from sh/bash for Node.js
node-brace-expansion provides brace expansion as known from sh/bash for
Node.js. It provides the expand() method to return an array of all possible
and valid expansions of the string argument. If none are found, the string
is returned as the only item in the array.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/juliangruber/brace-expansion

Package: node-builtins
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.0.0-1
Depends: node-semver
Breaks: node-validate-npm-package-name (<< 3.0.0-3~)
Description: lists nodejs builtin modules
This library provides a list of node.js builtin modules. The list of modules
is provided as a JSON file.
.
This is a dependency for npm, Node.js package manager.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/juliangruber/builtins

Package: node-cacache
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 142
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 15.0.5+~cs13.9.21-3
Provides: node-npmcli-move-file (= 1.0.1)
Depends: nodejs, node-chownr, node-glob (>= 7.1.2), node-graceful-fs, node-lru-cache (>= 4.1.1), node-mkdirp (>= 1.0.3), node-move-concurrently, node-p-map (>= 3.0.0), node-promise-inflight, node-rimraf (>= 2.6.1), node-ssri, node-unique-filename
Description: fast, fault-tolerant, disk-based, data-agnostic, content-addressable cache
This module is a Node.js library for managing local key and content address
caches. It's really fast, really good at concurrency, and it will never give
you corrupted data, even if cache files get corrupted or manipulated.
.
It was originally written to be used as npm's local cache, but can just as
easily be used on its own.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/cacache#readme

Package: node-chalk
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.1.2-1
Depends: node-ansi-styles (>= 3.1.0~), node-escape-string-regexp, node-supports-color (>= 4.0.0~), nodejs
Description: Terminal string styling for Node.js
Chalk is a Node.js module which provides string styling via ANSI escape codes
without extending String.prototype.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/chalk/chalk#readme

Package: node-chownr
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0-1
Description: like chown -R
This module takes the same arguments as fs.chown().
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/chownr#readme

Package: node-clean-yaml-object
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.1.0-5
Description: safe clean of an object prior to serialization
This module clean up (fill with zero byte) an object before sending
to serialisation, thus avoiding to serialize private data.
This module supports generalisation by allowing ones to specify
filter function, that support whitelisting.
.
Clearing data before serialization is critical from a security
point of view in order to avoid leaking information.
.
Node.js is an event-based server-side JavaScript engine
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tapjs/clean-yaml-object

Package: node-cli-table
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 116
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.3.11+~cs0.13.3-1
Provides: node-cli-table2 (= 0.2.0), node-cli-table3 (= 0.6.0), node-types-cli-table (= 0.3.0), node-types-cli-table2 (= 0.2.3)
Depends: node-colors, node-object-assign, node-string-width
Description: Pretty unicode tables for the CLI
This utility allows you to render unicode-aided tables on the command line
from your node.js scripts.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/Automattic/cli-table

Package: node-clone
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 24
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.1.2-3
Depends: nodejs
Description: deep cloning of objects and arrays
This module offers foolproof deep cloning of objects, arrays, numbers,
strings, etc. in JavaScript.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/pvorb/node-clone

Package: node-color-convert
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 37
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.1-1
Depends: node-color-name
Description: Plain color conversion functions
Color-convert is a color conversion library for JavaScript and node. It
converts all ways between rgb, hsl, hsv, hwb, cmyk, ansi, ansi16, hex strings,
and CSS keywords (will round to closest).
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/qix-/color-convert#readme

Package: node-color-name
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 26
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.1.4+~1.1.1-2
Provides: node-types-color-name (= 1.1.1)
Description: list of color names and its values
Given a color name, this package outputs its corresponding RGB value
Based on standard 'named colors' as defined by CSS working group
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/dfcreative/color-name

Package: node-colors
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 68
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: colors.js
Version: 1.4.0-3
Depends: nodejs
Description: Get color and style in your node.js console
This package contains the NodeJS module.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/marak/colors.js

Package: node-columnify
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 48
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.5.4+~1.5.1-1
Provides: node-types-columnify (= 1.5.1)
Depends: node-strip-ansi, node-wcwidth.js
Description: Render data in text columns with in-column text-wrap
Create text-based columns suitable for console output from objects or arrays
of objects.
.
Columns are automatically resized to fit the content of the largest cell.
Each cell will be padded with spaces to fill the available space and ensure
column contents are left-aligned.
.
Designed to handle sensible wrapping in npm search results.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/timoxley/columnify

Package: node-combined-stream
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 27
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.8+~1.0.3-1
Provides: node-types-combined-stream (= 1.0.3)
Depends: node-delayed-stream, nodejs
Description: Append streams one after another - module for Node.js
node-combined-stream can be used to append multiple streams one
after another.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/felixge/node-combined-stream

Package: node-commander
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 199
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 9.0.0-2
Breaks: cleancss (<< 5.2.2+~5.5.0~), uglifyjs (<< 3.9.4-2~), uglifyjs.terser (<< 4.1.2-10~), yarnpkg (<< 1.22.10+~cs22.25.14-6~)
Description: Complete solution for Node.js command-line interfaces
Commander is a light-weight, expressive, and powerful command-line framework
for Node.js.
.
Inspired by Ruby's commander, this Node.js module provides command line
option parsing, automated/customizable help texts, command line prompting
password query, and many more features.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tj/commander.js

Package: node-console-control-strings
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.1.0-2
Depends: nodejs
Description: cross-platform tested terminal/console command strings
This is a library for doing things like color and cursor positioning. This is
a subset of both ansi and vt100. All control codes included work on both
Windows & Unix-like OSes, except where noted.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/iarna/console-control-strings

Package: node-copy-concurrently
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 24
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.5-8
Depends: node-aproba, node-fs-write-stream-atomic, node-iferr, node-mkdirp (>= 1), node-rimraf, node-run-queue
Description: Copy files, directories and symlinks concurrently
Promises of copies of files, directories and symlinks, with concurrency
controls and win32 junction fallback.
.
Ownership is maintained when running as root, permissions are always
maintained. On Windows, if symlinks are unavailable then junctions will be
used.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://www.npmjs.com/package/copy-concurrently

Package: node-core-util-is
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.3-1
Description: util.is* functions introduced in Node v0.12 for older versions
node-core-util-is provides the util.is* functions from Node v0.12 core for
older Node.js versions.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/core-util-is

Package: node-coveralls
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 51
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.1.1-1
Depends: node-growl, node-js-yaml, node-lcov-parse, node-log-driver, node-minimist, node-fetch, nodejs:any
Description: input json-cov output and posts to coveralls.io
Coveralls.io is a web service to help you track your code coverage over
time, and ensure that all your new code is fully covered.
.
Coveralls automatically collects your code coverage data, uploads it
to their servers and gives you a nice interface to dig into it.
.
This tools based on node.js allows one to post coverage information
to coveralls.io
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/nickmerwin/node-coveralls

Package: node-cssom
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 75
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.4.4-3
Depends: nodejs
Description: CSS parser written in pure JavaScript - NodeJS module
CSSOM.js is a CSS parser written in pure JavaScript. It is also a partial
implementation of the CSS Object Model.
.
This package contains the NodeJS module.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/NV/CSSOM

Package: node-cssstyle
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 241
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.3.0-2
Depends: node-cssom
Description: CSSStyleDeclaration Object Model implementation
CSSStyleDeclaration is a work-a-like to the CSSStyleDeclaration
class in Nikita Vasilyev's CSSOM.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/chad3814/CSSStyleDeclaration

Package: node-debug
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 48
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.3.2+~cs4.1.7-1
Provides: node-types-debug (= 4.1.7)
Depends: node-ms, nodejs
Description: small debugging utility for Node.js
node-debug provides a small debugging utility for Node.js modules.
.
With this module you simply invoke the exported function to generate
your debug function, passing it a name which will determine if a
noop function is returned, or a decorated console.error, so all of the
console format string goodies you're used to work fine.
A unique color is selected per-function for visibility.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/visionmedia/debug

Package: node-decompress-response
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.0.0-2
Depends: node-mimic-response
Description: Decompress a HTTP response if needed
Decompresses the response from http.request if it's gzipped or deflated,
otherwise just passes it through.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/decompress-response

Package: node-defaults
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.3+~1.0.3-1
Provides: node-types-defaults (= 1.0.3)
Depends: node-clone
Description: merge single level defaults over a config object
A simple one level options merge utility. This module exports
a function that takes 2 arguments: options and defaults.
When called, it overrides all of undefined properties in
options with the clones of properties defined in defaults.
Sidecases: if called with a falsy options value, options will
be initialized to a new object before being merged onto.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tmpvar/defaults

Package: node-delayed-stream
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 20
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.0-5
Description: Buffer stream events for later handling - module for Node.js
node-delayed-stream can delay stream responses, and can be used
to combine streams one after another.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/felixge/node-delayed-stream

Package: node-delegates
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.0-3
Description: delegate methods and accessors to another property
This library is a dependency for webpack. Webpack takes code targeted at
node.js and makes it run in the browser. Node.js comes with API of its own
that is not available in the browsers. Webpack exposes this code
to programs that are unaware they are running in a browser.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/visionmedia/node-delegates

Package: node-depd
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 34
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0-2
Description: mark a function or property as deprecated - Node.js module
This module goes above and beyond with deprecation warnings by introspecting
the call stack (but only the bits that it is interested in).
.
Instead of just warning on the first invocation of a deprecated function and
never again, this module will warn on the first invocation of a deprecated
function per unique call site, making it ideal to alert users of all
deprecated uses across the code base, rather than just whatever happens to
execute first.
.
The deprecation warnings from this module also include the file and line
information for the call into the module that the deprecated function was in.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/dougwilson/nodejs-depd

Package: node-diff
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 415
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 5.0.0~dfsg+~5.0.1-3
Provides: node-types-diff (= 5.0.1)
Description: javascript text differencing implementation
Node is an event-based server-side JavaScript engine.
.
jsdiff is a javascript text differencing implementation
based on the algorithm proposed
in "An O(ND) Difference Algorithm and its Variations"
(Myers, 1986):
<http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.4.6927>.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/kpdecker/jsdiff

Package: node-encoding
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.1.13-2
Depends: node-iconv-lite
Description: Convert encodings, uses iconv by default and fallbacks to iconv-lite if needed
encoding is a simple wrapper around
node-iconv (https://github.com/bnoordhuis/node-iconv) and
iconv-lite (https://github.com/ashtuchkin/iconv-lite/) to convert strings
from one encoding to another. If node-iconv is not available for some reason,
iconv-lite will be used instead of it as a fallback.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/andris9/encoding

Package: node-end-of-stream
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.4.4+~1.4.1-1
Provides: node-types-end-of-stream (= 1.4.1)
Depends: node-once
Description: Invoke a callback when a stream has completed or failed
end-of-stream is a Node.js module which calls a callback when a readable,
writable, or duplex stream has completed or failed.
.
Pass a stream and a callback to end-of-stream. Both legacy streams and
streams2 are supported.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/mafintosh/end-of-stream

Package: node-err-code
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.3+dfsg-3
Description: Create an error with a code
Create new error instances with a code and additional properties.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/IndigoUnited/js-err-code#readme

Package: node-escape-string-regexp
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.0.0-2
Description: Escape RegExp special characters in Node.js
escape-string-regexp is a Node.js module to escape special characters in
regular expression strings.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/escape-string-regexp

Package: node-esprima
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 473
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.0.1+ds+~4.0.3-2
Provides: libjs-esprima (= 4.0.1+ds+~4.0.3-2), node-types-esprima (= 4.0.3)
Depends: nodejs:any
Suggests: javascript-common
Breaks: node-escodegen (<< 1.14.1+dfsg-2~)
Description: ECMAScript parsing infrastructure for multipurpose analysis
Esprima is a high-performance and standard-compliant parser for ECMAScript
written in ECMAScript.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://esprima.org

Package: node-events
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.3.0+~3.0.0-2
Provides: node-types-events (= 3.0.0)
Depends: libjs-events, nodejs
Description: Node.js events module to embed by web packers
"events" implements the Node.js events module for environments that do not
have it, like browsers.
.
This module is used by web packers.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/Gozala/events

Package: node-fancy-log
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 40
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.3.3+~cs1.3.1-2
Provides: node-ansi-gray (= 0.1.1), node-ansi-wrap (= 0.1.0), node-color-support (= 1.1.3), node-parse-node-version (= 1.0.1), node-types-fancy-log (= 1.3.1)
Depends: node-time-stamp
Description: Log things, prefixed with a timestamp
This module was pulled out of gulp-util for use inside the CLI.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/phated/fancy-log#readme

Package: node-fetch
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 186
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.6.7+~2.5.12-1
Provides: node-node-fetch (= 2.6.7), node-types-node-fetch (= 2.5.12)
Depends: node-whatwg-url
Description: light-weight module that brings window.fetch to node.js
Instead of implementing XMLHttpRequest in Node.js to run browser-specific
Fetch polyfill, why not go from native http to Fetch API directly? Hence
node-fetch, minimal code for a window.fetch compatible API on Node.js runtime.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/bitinn/node-fetch

Package: node-foreground-child
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.0-3
Depends: node-signal-exit
Description: helper running a child process as a foreground process
This Node.js module emulate simple control group in pure javacript.
It runs a child process as foreground process redirecting output
to stdout and exiting main process as soon as child exist.
.
This module could be used for implementating TAP test
for Node.js.
.
TAP is a simple text-based interface between testing modules
implemented in many popular languages.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tapjs/foreground-child

Package: node-form-data
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 38
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.1-1
Depends: node-asynckit, node-combined-stream, node-mime-types
Description: Create multipart/form-data streams module for Node.js
node-form-data can be used to submit forms and file uploads to other
web applications.
.
The API of this module is inspired by the w3c XMLHttpRequest
specification.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/felixge/node-form-data

Package: node-fs-write-stream-atomic
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 20
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.10-5
Depends: node-graceful-fs, node-iferr, node-imurmurhash
Description: Like fs.createWriteStream(...), but atomic
Writes to a tmp file and does an atomic `fs.rename` to move it into place when
it's done.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/fs-write-stream-atomic

Package: node-fs.realpath
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 25
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.0-2
Description: Use node's fs.realpath
Use node's fs.realpath, but fall back to the JS implementation if the native
one fails
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/fs.realpath

Package: node-function-bind
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 28
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.1.1+repacked+~1.0.3-1
Provides: node-has (= 1.0.3)
Description: Implementation of Function.prototype.bind
Function-bind can be used for unit tests, and is useful for webframeworks
that do not have the function-bind.
.
This package includes also the node-has (has) package,
Object.prototype.hasOwnProperty.call shortcut.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/Raynos/function-bind

Package: node-gauge
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 55
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.0.2-1
Depends: node-ansi-regex, node-aproba, node-console-control-strings, node-color-support, node-has-unicode, node-signal-exit, node-string-width, node-strip-ansi, node-wide-align
Description: terminal based horizontal progress bar
A nearly stateless terminal based horizontal gauge / progress bar. This
library is a dependency for npmlog, a logger with custom levels and colored
output for Node.js
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/gauge

Package: node-get-stream
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.0.1-1
Depends: node-pump
Description: Get a stream as a string, buffer, or array
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/get-stream

Package: node-glob
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 219
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 7.2.1+~cs7.6.15-1
Provides: node-globalyzer (= 0.1.4), node-globrex (= 0.1.2), node-tiny-glob (= 0.2.9), node-types-glob (= 7.2.0)
Depends: node-fs.realpath, node-inflight, node-inherits, node-minimatch (>= 3.1.1~), node-once, node-path-is-absolute
Breaks: node-typescript-types (<< 20201105-1~)
Description: glob functionality for Node.js
node-glob is a glob implementation for Node.js
.
It features brace expansion, extended glob matching, globstar matching,
and can be invoked synchronously as well as asynchronously.
It uses minimatch for pattern matching.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/node-glob

Package: node-got
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 541
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 11.8.3+~cs58.7.37-1
Provides: node-cacheable-lookup (= 6.0.4), node-cacheable-request (= 7.0.2), node-clone-response (= 1.0.2), node-defer-to-connect (= 2.0.1), node-http-cache-semantics (= 4.1.0), node-http2-wrapper (= 2.1.9), node-keyv (= 4.0.4), node-normalize-url (= 7.0.2), node-resolve-alpn (= 1.2.1), node-responselike (= 2.0.0), node-sindresorhus-is (= 4.2.0), node-szmarczak-http-timer (= 4.0.6), node-types-cacheable-request (= 6.0.2), node-types-http-cache-semantics (= 4.0.1), node-types-keyv (= 3.1.3), node-types-responselike (= 1.0.0)
Depends: node-decompress-response, node-get-stream, node-lowercase-keys, node-json-buffer, node-mimic-response, node-p-cancelable (>= 2.0.0~), node-quick-lru
Description: Simplified HTTP requests
This module provides a nicer interface to the built-in http module.
.
This module was created because request is bloated _(several megabytes!)_.
.
Highlights:

- Promise & stream API
- Request cancellation
- Follows redirects
- Retries on network failure
- Handles gzip/deflate
- Timeout handling
- Errors with metadata
- JSON mode
- WHATWG URL support
- Electron support
  .
  Node.js is an event-based server-side JavaScript engine.
  Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
  Homepage: https://github.com/sindresorhus/got

Package: node-graceful-fs
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.2.4+repack-1
Provides: node-types-graceful-fs (= 4.1.4)
Depends: nodejs
Description: drop-in replacement improving the Node.js fs module
node-graceful-fs module normalizes behavior across different platforms
and environments, and makes filesystem access more resilient to errors:

- queues up open and readdir calls, and retries them once something
  closes if there is an EMFILE error from too many file descriptors.
- fixes lchmod for Node versions prior to 0.6.2
- implements fs.lutimes if possible. Otherwise it becomes a noop.
- ignores EINVAL and EPERM errors in chown, fchown or lchown if the
  user isn't root.
- makes lchmod and lchown become noops, if not available.
- retries reading a file if read results in EAGAIN error.
  .
  Node.js is an event-based server-side javascript engine.
  Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
  Homepage: https://github.com/isaacs/node-graceful-fs

Package: node-growl
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 26
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.10.5-4
Depends: libnotify-bin
Description: unobtrusive notification system for nodejs
Growl support for Nodejs. Essentially a port of the Ruby Growl Library from
the same author.
.
Growl is a cross platform notification system.
.
Applications can use Growl to display small notifications
about events which may be important to the user.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tj/node-growl

Package: node-gyp
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 130
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 8.4.1-1
Provides: node-node-gyp (= 8.4.1-1)
Depends: gyp (>= 0.1+20200513gitcaa6002), libnode-dev, node-glob, node-graceful-fs, node-mkdirp, node-whatwg-fetch, node-nopt, node-npmlog, node-osenv, node-rimraf, node-semver (>= 7), node-tar, node-which, nodejs:any
Recommends: build-essential
Description: Native addon build tool for Node.js
node-gyp is a cross-platform command-line tool written in Node.js
for compiling native addon modules for Node.js.
.
It features :

- Easy to use, consistent interface
- Same commands to build a module on every platform
- Support of multiple target versions of Node.js
  .
  Node.js is an event-based server-side javascript engine.
  Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
  Homepage: https://github.com/nodejs/node-gyp

Package: node-has-flag
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.0.0-2
Description: check if argv has a specific flag
This module checks if argv has a specific flag and correctly stops
looking after an -- argument terminator.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/has-flag

Package: node-has-unicode
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.1-4
Description: Try to guess if your terminal supports unicode
What we actually detect is UTF-8 support, as that's what Node itself supports.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/iarna/has-unicode

Package: node-hosted-git-info
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 33
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.0.2-1
Depends: node-lru-cache
Description: Provides metadata from Github, Bitbucket and Gitlab
Provides metadata and conversions from repository urls for Github, Bitbucket
and Gitlab
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/hosted-git-info

Package: node-https-proxy-agent
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 91
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 5.0.0+~cs8.0.0-3
Provides: node-http-proxy-agent (= 5.0.0), node-tootallnate-once (= 3.0.0)
Depends: node-agent-base, node-debug (>= 4), node-events
Description: HTTP(s) proxy http.Agent implementation for HTTPS
This module provides an http.Agent implementation that connects to a specified
HTTP or HTTPS proxy server, and can be used with the built-in 'https' module.
.
Specifically, this 'Agent' implementation connects to an intermediary "proxy"
server and issues the CONNECT, which tells the proxy to open a direct TCP
connection to the destination server.
.
Since this agent implements the CONNECT HTTP method, it also works with other
protocols that use this method when connecting over proxies (i.e. WebSockets).
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/TooTallNate/node-https-proxy-agent#readme

Package: node-iconv-lite
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 356
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.6.3-2
Depends: node-safe-buffer (>= 5.2.1+~cs2.1.2)
Description: Pure JS character encoding conversion
Convert character encodings in pure javascript.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/ashtuchkin/iconv-lite

Package: node-iferr
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.2+~1.0.2-1
Provides: node-types-iferr (= 1.0.2)
Description: Higher-order functions for easier error handling
This library allows one to delegate to a function in case of error,
thus easing the error handling of the Node.js application.
.
This library is a dependency of npm, Node.js package manager.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/shesek/iferr

Package: node-imurmurhash
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 28
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.1.4+dfsg+~0.1.1-1
Provides: node-types-imurmurhash (= 0.1.1)
Description: incremental implementation of MurmurHash3 hashing algorithm
This module is an incremental implementation of the MurmurHash3 (32-bit)
hashing algorithm for JavaScript based on Gary Court's implementation with
kazuyukitanimura's modifications.
.
This version works significantly faster than the non-incremental version if
you need to hash many small strings into a single hash, since string
concatenation (to build the single string to pass the non-incremental version)
is fairly costly. In one case tested, using the incremental version was about
50% faster than concatenating 5-10 strings and then hashing.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/jensyt/imurmurhash-js

Package: node-indent-string
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.0.0-2
Description: Indent each line in a string
A node.js module that provides API for to indent lines in a string.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/indent-string

Package: node-inflight
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.6-2
Depends: node-once, node-wrappy
Description: add callbacks to requests in flight to avoid async duplication
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/inflight

Package: node-inherits
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.4-4
Depends: libjs-inherits (= 2.0.4-4)
Description: Node.js module that exposes inherits function
node-inherits exposes standard inherits implementation of Node.js util
module, and allows bundlers such as browserify to not include full util
package in client code.
.
It is recommended to use this module for all code that requires only
the inherits function and that has a chance to run in a browser too.
.
This is the Node.js module. Node.js is an event-based server-side
javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/inherits

Package: node-ini
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 22
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.1-1
Description: ini format parser and serializer for Node.js
Read, manipulate and write ini files.
Sections are treated as nested objects.
Items before the first heading are saved on the object directly.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/ini

Package: node-ip
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 34
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.1.5+~1.1.0-1
Provides: node-types-ip (= 1.1.0)
Description: IP address utilities for node.js
IP utility in node.js helps one with IP related queries. This module
helps in quickly accessing ip address.
.
Ip utility helps fetch results on ip address, comapre ip address,
validate ip address, range checking, subnet information etc.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/indutny/node-ip

Package: node-ip-regex
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 22
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.3.0+~4.1.1-1
Provides: node-types-ip-regex (= 4.1.1)
Description: Regular expression for matching IP addresses
Returns a regex for matching both IPv4 and IPv6.
.
Only match an exact string. Useful with RegExp
to check if a string is an IP address.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/ip-regex

Package: node-is-buffer
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.5-2
Description: Determine if an object is a Buffer
This module lets you check if an object is a Buffer without using
Buffer.isBuffer (which includes the whole buffer module in browserify).
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/feross/is-buffer

Package: node-is-plain-obj
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.0.0-2
Description: Check if a value is a plain object
An object is plain if it's created by either `{}`, `new Object()` or
`Object.create(null)`.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/is-plain-obj

Package: node-is-typedarray
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 13
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.0-4
Depends: libjs-is-typedarray
Description: Nodejs library checking if object is TypedArray
Detect whether or not an object is a Typed Array.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/hughsk/is-typedarray

Package: node-isarray
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.5-3
Description: JavaScript Array#isArray for older browsers
isarray provides Arrray#isArray for older browsers.
.
This package contains the isarray module for Node.js.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/juliangruber/isarray

Package: node-isexe
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 24
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0+~2.0.1-4
Provides: node-types-isexe (= 2.0.1)
Description: minimal module to check if a file is executable
This Node.js module allows ones to check if a given file is executable,
using promise is available and checking PATHEXT environment
variable on windows.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/isexe

Package: node-js-yaml
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 443
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.1.0+dfsg+~4.0.5-6
Provides: node-types-js-yaml (= 4.0.5)
Depends: node-argparse, node-esprima, nodejs:any
Breaks: eslint (<< 5.16.0~dfsg+~4.16.8-8~), grunt (<< 1.3.0-2~), node-gulp-concat (<< 2.6.1+~0.0.15+git20190329.179bb8c+~1.0.3-4~), node-istanbul (<< 0.4.5+repack09+~cs74.23.58-2~), node-tap (<< 12.0.1+ds-4~), node-tap-parser (<< 7.0.0+ds1-6~), yarnpkg (<< 1.22.10+~cs22.25.14-5~)
Description: YAML 1.2 parser and serializer
This is an implementation of YAML, a human-friendly data serialization
language. Started as PyYAML port, it was completely rewritten from scratch.
Now it's very fast, and supports the 1.2 spec.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/nodeca/js-yaml

Package: node-jsdom
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 4361
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 19.0.0+~cs90.11.27-1
Provides: node-browser-process-hrtime (= 1.0.0), node-data-urls (= 3.0.1), node-decimal.js (= 10.3.1), node-domexception (= 4.0.0), node-html-encoding-sniffer (= 3.0.0), node-is-potential-custom-element-name (= 1.0.1), node-nwsapi (= 2.2.0), node-parse5 (= 6.0.1), node-parse5-build-scripts, node-saxes (= 6.0.0), node-symbol-tree (= 3.2.4), node-tr46 (= 3.0.0), node-types-jsdom (= 16.2.14), node-types-parse5 (= 6.0.3), node-w3c-hr-time (= 1.0.2), node-w3c-xmlserializer (= 3.0.0), node-whatwg-encoding (= 2.0.0), node-whatwg-mimetype (= 3.0.0), node-whatwg-url (= 11.0.0), node-xml-name-validator (= 4.0.0), node-xmlchars (= 2.2.0)
Depends: node-abab, node-cssom, node-cssstyle, node-form-data, node-https-proxy-agent (>= 5.0.0+~cs8.0.0-2~), node-iconv-lite, node-lodash-packages, node-stealthy-require, node-tough-cookie, node-webidl-conversions, node-ws
Breaks: node-typescript-types (<< 20201122~)
Description: javascript implementation of the W3C DOM
node-jsdom is a CommonJS implementation of the DOM, intended to be platform
independent and as minimal/light as possible, while completely adhering to
the w3c DOM specifications.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tmpvar/jsdom

Package: node-json-buffer
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.1-1
Depends: nodejs
Description: JSON functions that can convert buffers.
json buffer converts to base64 instead, and deconverts
base64 to a buffer.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/dominictarr/json-buffer

Package: node-json-parse-better-errors
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 28
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.2+~cs3.3.1-1
Provides: node-json-parse-even-better-errors (= 2.3.1), node-types-json-parse-better-errors (= 1.0.0)
Description: JSON.parse() with context information on error
This is a Node.js library for getting nicer errors out of JSON.parse(),
including context and position of parse errors.
.
It servers similar purpose as the JSON.parse method but returns more useful
errors when exceptions happen.
.
It's really fast, really good at concurrency, and it will never give you
corrupted data, even if cache files get corrupted or manipulated.
.
It was originally written to be used as npm's local cache, but
can just as easily be used on its own
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/zkat/json-parse-better-errors

Package: node-jsonparse
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 42
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.3.1-10
Description: Pure javascript JSON streaming parser for node.js
This a simple nodejs module that parses a given JSON file and
returning object form suitable for grammar analysis.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/creationix/jsonparse

Package: node-kind-of
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 6.0.3+dfsg-2
Depends: node-is-buffer
Description: Get the native type of a value
Get the type of a value, fast.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/jonschlinkert/kind-of

Package: node-lcov-parse
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 22
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.0+20170612git80d039574ed9-5
Depends: nodejs
Description: Parse lcov results files and return JSON
This modules allows ones to parse lcov files and to return json reprensentation
of these files.
.
lcov is a graphical front-end for GCC's coverage testing tool gcov.
It collects gcov data for multiple source files and creates HTML pages
containing the source code annotated with coverage information. It
also adds overview pages for easy navigation within the file
structure.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/davglass/lcov-parse#readme

Package: node-lodash-packages
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 9903
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: node-lodash
Version: 4.17.21+dfsg+~cs8.31.198.20210220-5
Provides: node-lodash-cli (= 4.17.21), node-lodash.-reinterpolate (= 4.17.21), node-lodash.add (= 4.17.21), node-lodash.after (= 4.17.21), node-lodash.ary (= 4.17.21), node-lodash.assign (= 4.17.21), node-lodash.assignin (= 4.17.21), node-lodash.assigninwith (= 4.17.21), node-lodash.assignwith (= 4.17.21), node-lodash.at (= 4.17.21), node-lodash.attempt (= 4.17.21), node-lodash.before (= 4.17.21), node-lodash.bind (= 4.17.21), node-lodash.bindall (= 4.17.21), node-lodash.bindkey (= 4.17.21), node-lodash.camelcase (= 4.17.21), node-lodash.capitalize (= 4.17.21), node-lodash.castarray (= 4.17.21), node-lodash.ceil (= 4.17.21), node-lodash.chunk (= 4.17.21), node-lodash.clamp (= 4.17.21), node-lodash.clone (= 4.17.21), node-lodash.clonedeep (= 4.17.21), node-lodash.clonedeepwith (= 4.17.21), node-lodash.clonewith (= 4.17.21), node-lodash.compact (= 4.17.21), node-lodash.concat (= 4.17.21), node-lodash.cond (= 4.17.21), node-lodash.conforms (= 4.17.21), node-lodash.conformsto (= 4.17.21), node-lodash.constant (= 4.17.21), node-lodash.countby (= 4.17.21), node-lodash.create (= 4.17.21), node-lodash.curry (= 4.17.21), node-lodash.curryright (= 4.17.21), node-lodash.debounce (= 4.17.21), node-lodash.deburr (= 4.17.21), node-lodash.defaults (= 4.17.21), node-lodash.defaultsdeep (= 4.17.21), node-lodash.defaultto (= 4.17.21), node-lodash.defer (= 4.17.21), node-lodash.delay (= 4.17.21), node-lodash.difference (= 4.17.21), node-lodash.differenceby (= 4.17.21), node-lodash.differencewith (= 4.17.21), node-lodash.divide (= 4.17.21), node-lodash.drop (= 4.17.21), node-lodash.dropright (= 4.17.21), node-lodash.droprightwhile (= 4.17.21), node-lodash.dropwhile (= 4.17.21), node-lodash.endswith (= 4.17.21), node-lodash.eq (= 4.17.21), node-lodash.escape (= 4.17.21), node-lodash.escaperegexp (= 4.17.21), node-lodash.every (= 4.17.21), node-lodash.fill (= 4.17.21), node-lodash.filter (= 4.17.21), node-lodash.find (= 4.17.21), node-lodash.findindex (= 4.17.21), node-lodash.findkey (= 4.17.21), node-lodash.findlast (= 4.17.21), node-lodash.findlastindex (= 4.17.21), node-lodash.findlastkey (= 4.17.21), node-lodash.flatmap (= 4.17.21), node-lodash.flatmapdeep (= 4.17.21), node-lodash.flatmapdepth (= 4.17.21), node-lodash.flatten (= 4.17.21), node-lodash.flattendeep (= 4.17.21), node-lodash.flattendepth (= 4.17.21), node-lodash.flip (= 4.17.21), node-lodash.floor (= 4.17.21), node-lodash.flow (= 4.17.21), node-lodash.flowright (= 4.17.21), node-lodash.foreach (= 4.17.21), node-lodash.foreachright (= 4.17.21), node-lodash.forin (= 4.17.21), node-lodash.forinright (= 4.17.21), node-lodash.forown (= 4.17.21), node-lodash.forownright (= 4.17.21), node-lodash.frompairs (= 4.17.21), node-lodash.functions (= 4.17.21), node-lodash.functionsin (= 4.17.21), node-lodash.get (= 4.17.21), node-lodash.groupby (= 4.17.21), node-lodash.gt (= 4.17.21), node-lodash.gte (= 4.17.21), node-lodash.has (= 4.17.21), node-lodash.hasin (= 4.17.21), node-lodash.head (= 4.17.21), node-lodash.identity (= 4.17.21), node-lodash.includes (= 4.17.21), node-lodash.indexof (= 4.17.21), node-lodash.initial (= 4.17.21), node-lodash.inrange (= 4.17.21), node-lodash.intersection (= 4.17.21), node-lodash.intersectionby (= 4.17.21), node-lodash.intersectionwith (= 4.17.21), node-lodash.invert (= 4.17.21), node-lodash.invertby (= 4.17.21), node-lodash.invoke (= 4.17.21), node-lodash.invokemap (= 4.17.21), node-lodash.isarguments (= 4.17.21), node-lodash.isarray (= 4.17.21), node-lodash.isarraybuffer (= 4.17.21), node-lodash.isarraylike (= 4.17.21), node-lodash.isarraylikeobject (= 4.17.21), node-lodash.isboolean (= 4.17.21), node-lodash.isbuffer (= 4.17.21), node-lodash.isdate (= 4.17.21), node-lodash.iselement (= 4.17.21), node-lodash.isempty (= 4.17.21), node-lodash.isequal (= 4.17.21), node-lodash.isequalwith (= 4.17.21), node-lodash.iserror (= 4.17.21), node-lodash.isfinite (= 4.17.21), node-lodash.isfunction (= 4.17.21), node-lodash.isinteger (= 4.17.21), node-lodash.islength (= 4.17.21), node-lodash.ismap (= 4.17.21), node-lodash.ismatch (= 4.17.21), node-lodash.ismatchwith (= 4.17.21), node-lodash.isnan (= 4.17.21), node-lodash.isnative (= 4.17.21), node-lodash.isnil (= 4.17.21), node-lodash.isnull (= 4.17.21), node-lodash.isnumber (= 4.17.21), node-lodash.isobject (= 4.17.21), node-lodash.isobjectlike (= 4.17.21), node-lodash.isplainobject (= 4.17.21), node-lodash.isregexp (= 4.17.21), node-lodash.issafeinteger (= 4.17.21), node-lodash.isset (= 4.17.21), node-lodash.isstring (= 4.17.21), node-lodash.issymbol (= 4.17.21), node-lodash.istypedarray (= 4.17.21), node-lodash.isundefined (= 4.17.21), node-lodash.isweakmap (= 4.17.21), node-lodash.isweakset (= 4.17.21), node-lodash.iteratee (= 4.17.21), node-lodash.join (= 4.17.21), node-lodash.kebabcase (= 4.17.21), node-lodash.keyby (= 4.17.21), node-lodash.keys (= 4.17.21), node-lodash.keysin (= 4.17.21), node-lodash.last (= 4.17.21), node-lodash.lastindexof (= 4.17.21), node-lodash.lowercase (= 4.17.21), node-lodash.lowerfirst (= 4.17.21), node-lodash.lt (= 4.17.21), node-lodash.lte (= 4.17.21), node-lodash.map (= 4.17.21), node-lodash.mapkeys (= 4.17.21), node-lodash.mapvalues (= 4.17.21), node-lodash.matches (= 4.17.21), node-lodash.matchesproperty (= 4.17.21), node-lodash.max (= 4.17.21), node-lodash.maxby (= 4.17.21), node-lodash.mean (= 4.17.21), node-lodash.meanby (= 4.17.21), node-lodash.memoize (= 4.17.21), node-lodash.merge (= 4.17.21), node-lodash.mergewith (= 4.17.21), node-lodash.method (= 4.17.21), node-lodash.methodof (= 4.17.21), node-lodash.min (= 4.17.21), node-lodash.minby (= 4.17.21), node-lodash.mixin (= 4.17.21), node-lodash.multiply (= 4.17.21), node-lodash.negate (= 4.17.21), node-lodash.noop (= 4.17.21), node-lodash.now (= 4.17.21), node-lodash.nth (= 4.17.21), node-lodash.ntharg (= 4.17.21), node-lodash.omit (= 4.17.21), node-lodash.omitby (= 4.17.21), node-lodash.once (= 4.17.21), node-lodash.orderby (= 4.17.21), node-lodash.over (= 4.17.21), node-lodash.overargs (= 4.17.21), node-lodash.overevery (= 4.17.21), node-lodash.oversome (= 4.17.21), node-lodash.pad (= 4.17.21), node-lodash.padend (= 4.17.21), node-lodash.padstart (= 4.17.21), node-lodash.parseint (= 4.17.21), node-lodash.partial (= 4.17.21), node-lodash.partialright (= 4.17.21), node-lodash.partition (= 4.17.21), node-lodash.pick (= 4.17.21), node-lodash.pickby (= 4.17.21), node-lodash.property (= 4.17.21), node-lodash.propertyof (= 4.17.21), node-lodash.pull (= 4.17.21), node-lodash.pullall (= 4.17.21), node-lodash.pullallby (= 4.17.21), node-lodash.pullallwith (= 4.17.21), node-lodash.pullat (= 4.17.21), node-lodash.random (= 4.17.21), node-lodash.range (= 4.17.21), node-lodash.rangeright (= 4.17.21), node-lodash.rearg (= 4.17.21), node-lodash.reduce (= 4.17.21), node-lodash.reduceright (= 4.17.21), node-lodash.reject (= 4.17.21), node-lodash.remove (= 4.17.21), node-lodash.repeat (= 4.17.21), node-lodash.replace (= 4.17.21), node-lodash.rest (= 4.17.21), node-lodash.result (= 4.17.21), node-lodash.reverse (= 4.17.21), node-lodash.round (= 4.17.21), node-lodash.sample (= 4.17.21), node-lodash.samplesize (= 4.17.21), node-lodash.set (= 4.17.21), node-lodash.setwith (= 4.17.21), node-lodash.shuffle (= 4.17.21), node-lodash.size (= 4.17.21), node-lodash.slice (= 4.17.21), node-lodash.snakecase (= 4.17.21), node-lodash.some (= 4.17.21), node-lodash.sortby (= 4.17.21), node-lodash.sortedindex (= 4.17.21), node-lodash.sortedindexby (= 4.17.21), node-lodash.sortedindexof (= 4.17.21), node-lodash.sortedlastindex (= 4.17.21), node-lodash.sortedlastindexby (= 4.17.21), node-lodash.sortedlastindexof (= 4.17.21), node-lodash.sorteduniq (= 4.17.21), node-lodash.sorteduniqby (= 4.17.21), node-lodash.split (= 4.17.21), node-lodash.spread (= 4.17.21), node-lodash.startcase (= 4.17.21), node-lodash.startswith (= 4.17.21), node-lodash.stubarray (= 4.17.21), node-lodash.stubfalse (= 4.17.21), node-lodash.stubobject (= 4.17.21), node-lodash.stubstring (= 4.17.21), node-lodash.stubtrue (= 4.17.21), node-lodash.subtract (= 4.17.21), node-lodash.sum (= 4.17.21), node-lodash.sumby (= 4.17.21), node-lodash.tail (= 4.17.21), node-lodash.take (= 4.17.21), node-lodash.takeright (= 4.17.21), node-lodash.takerightwhile (= 4.17.21), node-lodash.takewhile (= 4.17.21), node-lodash.template (= 4.17.21), node-lodash.templatesettings (= 4.17.21), node-lodash.throttle (= 4.17.21), node-lodash.times (= 4.17.21), node-lodash.toarray (= 4.17.21), node-lodash.tofinite (= 4.17.21), node-lodash.tointeger (= 4.17.21), node-lodash.tolength (= 4.17.21), node-lodash.tolower (= 4.17.21), node-lodash.tonumber (= 4.17.21), node-lodash.topairs (= 4.17.21), node-lodash.topairsin (= 4.17.21), node-lodash.topath (= 4.17.21), node-lodash.toplainobject (= 4.17.21), node-lodash.tosafeinteger (= 4.17.21), node-lodash.tostring (= 4.17.21), node-lodash.toupper (= 4.17.21), node-lodash.transform (= 4.17.21), node-lodash.trim (= 4.17.21), node-lodash.trimend (= 4.17.21), node-lodash.trimstart (= 4.17.21), node-lodash.truncate (= 4.17.21), node-lodash.unary (= 4.17.21), node-lodash.unescape (= 4.17.21), node-lodash.union (= 4.17.21), node-lodash.unionby (= 4.17.21), node-lodash.unionwith (= 4.17.21), node-lodash.uniq (= 4.17.21), node-lodash.uniqby (= 4.17.21), node-lodash.uniqueid (= 4.17.21), node-lodash.uniqwith (= 4.17.21), node-lodash.unset (= 4.17.21), node-lodash.unzip (= 4.17.21), node-lodash.unzipwith (= 4.17.21), node-lodash.update (= 4.17.21), node-lodash.updatewith (= 4.17.21), node-lodash.uppercase (= 4.17.21), node-lodash.upperfirst (= 4.17.21), node-lodash.values (= 4.17.21), node-lodash.valuesin (= 4.17.21), node-lodash.without (= 4.17.21), node-lodash.words (= 4.17.21), node-lodash.wrap (= 4.17.21), node-lodash.xor (= 4.17.21), node-lodash.xorby (= 4.17.21), node-lodash.xorwith (= 4.17.21), node-lodash.zip (= 4.17.21), node-lodash.zipobject (= 4.17.21), node-lodash.zipobjectdeep (= 4.17.21), node-lodash.zipwith (= 4.17.21), node-types-lodash (= 4.14.177), node-types-lodash.add (= 3.7.6), node-types-lodash.after (= 4.0.6), node-types-lodash.ary (= 4.1.6), node-types-lodash.assign (= 4.2.6), node-types-lodash.assignin (= 4.2.6), node-types-lodash.assigninwith (= 4.2.6), node-types-lodash.assignwith (= 4.2.6), node-types-lodash.at (= 4.6.6), node-types-lodash.attempt (= 4.2.6), node-types-lodash.before (= 4.0.6), node-types-lodash.bind (= 4.2.6), node-types-lodash.bindall (= 4.4.6), node-types-lodash.bindkey (= 4.2.6), node-types-lodash.camelcase (= 4.3.6), node-types-lodash.capitalize (= 4.2.6), node-types-lodash.castarray (= 4.4.6), node-types-lodash.ceil (= 4.0.6), node-types-lodash.chunk (= 4.2.6), node-types-lodash.clamp (= 4.0.6), node-types-lodash.clone (= 4.5.6), node-types-lodash.clonedeep (= 4.5.6), node-types-lodash.clonedeepwith (= 4.5.6), node-types-lodash.clonewith (= 4.5.6), node-types-lodash.compact (= 3.0.6), node-types-lodash.concat (= 4.5.6), node-types-lodash.cond (= 4.5.3), node-types-lodash.constant (= 3.0.6), node-types-lodash.countby (= 4.6.6), node-types-lodash.create (= 4.2.6), node-types-lodash.curry (= 4.1.6), node-types-lodash.curryright (= 4.1.6), node-types-lodash.debounce (= 4.0.6), node-types-lodash.deburr (= 4.1.6), node-types-lodash.defaults (= 4.2.6), node-types-lodash.defaultsdeep (= 4.6.6), node-types-lodash.defer (= 4.1.6), node-types-lodash.delay (= 4.1.6), node-types-lodash.difference (= 4.5.6), node-types-lodash.differenceby (= 4.8.6), node-types-lodash.differencewith (= 4.5.6), node-types-lodash.divide (= 4.9.3), node-types-lodash.drop (= 4.1.6), node-types-lodash.dropright (= 4.1.6), node-types-lodash.droprightwhile (= 4.6.6), node-types-lodash.dropwhile (= 4.6.6), node-types-lodash.endswith (= 4.2.6), node-types-lodash.eq (= 4.0.6), node-types-lodash.escape (= 4.0.6), node-types-lodash.escaperegexp (= 4.1.6), node-types-lodash.every (= 4.6.6), node-types-lodash.fill (= 3.4.6), node-types-lodash.filter (= 4.6.6), node-types-lodash.find (= 4.6.6), node-types-lodash.findindex (= 4.6.6), node-types-lodash.findkey (= 4.6.6), node-types-lodash.findlast (= 4.6.6), node-types-lodash.findlastindex (= 4.6.6), node-types-lodash.findlastkey (= 4.7.6), node-types-lodash.flatmap (= 4.5.6), node-types-lodash.flatmapdeep (= 4.10.3), node-types-lodash.flatmapdepth (= 4.10.3), node-types-lodash.flatten (= 4.4.6), node-types-lodash.flattendeep (= 4.4.6), node-types-lodash.flattendepth (= 4.7.6), node-types-lodash.flip (= 4.2.6), node-types-lodash.floor (= 4.0.6), node-types-lodash.flow (= 3.5.6), node-types-lodash.flowright (= 3.5.6), node-types-lodash.foreach (= 4.5.6), node-types-lodash.foreachright (= 4.4.6), node-types-lodash.forin (= 4.4.6), node-types-lodash.forinright (= 4.5.6), node-types-lodash.forown (= 4.4.6), node-types-lodash.forownright (= 4.5.6), node-types-lodash.frompairs (= 4.0.6), node-types-lodash.functions (= 4.3.6), node-types-lodash.functionsin (= 4.3.6), node-types-lodash.get (= 4.4.6), node-types-lodash.groupby (= 4.6.6), node-types-lodash.gt (= 3.9.6), node-types-lodash.gte (= 3.9.6), node-types-lodash.has (= 4.5.6), node-types-lodash.hasin (= 4.5.6), node-types-lodash.head (= 4.0.6), node-types-lodash.identity (= 3.0.6), node-types-lodash.includes (= 4.3.6), node-types-lodash.indexof (= 4.0.6), node-types-lodash.initial (= 4.1.6), node-types-lodash.inrange (= 3.3.6), node-types-lodash.intersection (= 4.4.6), node-types-lodash.intersectionby (= 4.7.6), node-types-lodash.intersectionwith (= 4.4.6), node-types-lodash.invert (= 4.3.6), node-types-lodash.invertby (= 4.7.6), node-types-lodash.invoke (= 4.5.6), node-types-lodash.invokemap (= 4.6.6), node-types-lodash.isarguments (= 3.1.6), node-types-lodash.isarray (= 4.0.6), node-types-lodash.isarraybuffer (= 4.4.6), node-types-lodash.isarraylike (= 4.2.6), node-types-lodash.isarraylikeobject (= 4.2.6), node-types-lodash.isboolean (= 3.0.6), node-types-lodash.isbuffer (= 4.3.6), node-types-lodash.isdate (= 4.0.6), node-types-lodash.iselement (= 4.1.6), node-types-lodash.isempty (= 4.4.6), node-types-lodash.isequal (= 4.5.5), node-types-lodash.isequalwith (= 4.4.6), node-types-lodash.iserror (= 3.1.6), node-types-lodash.isfinite (= 3.3.6), node-types-lodash.isfunction (= 3.0.6), node-types-lodash.isinteger (= 4.0.6), node-types-lodash.islength (= 4.0.6), node-types-lodash.ismap (= 4.4.6), node-types-lodash.ismatch (= 4.4.6), node-types-lodash.ismatchwith (= 4.4.6), node-types-lodash.isnan (= 3.0.6), node-types-lodash.isnative (= 4.0.6), node-types-lodash.isnil (= 4.0.6), node-types-lodash.isnull (= 3.0.6), node-types-lodash.isnumber (= 3.0.6), node-types-lodash.isobject (= 3.0.6), node-types-lodash.isobjectlike (= 4.0.6), node-types-lodash.isplainobject (= 4.0.6), node-types-lodash.isregexp (= 4.0.6), node-types-lodash.issafeinteger (= 4.0.6), node-types-lodash.isset (= 4.4.6), node-types-lodash.isstring (= 4.0.6), node-types-lodash.issymbol (= 4.0.6), node-types-lodash.istypedarray (= 4.0.6), node-types-lodash.isundefined (= 3.0.6), node-types-lodash.isweakmap (= 4.4.6), node-types-lodash.isweakset (= 4.3.6), node-types-lodash.iteratee (= 4.7.6), node-types-lodash.join (= 4.0.6), node-types-lodash.kebabcase (= 4.1.6), node-types-lodash.keyby (= 4.6.6), node-types-lodash.keys (= 4.2.6), node-types-lodash.keysin (= 4.2.6), node-types-lodash.last (= 3.0.6), node-types-lodash.lastindexof (= 4.0.6), node-types-lodash.lowercase (= 4.3.6), node-types-lodash.lowerfirst (= 4.3.6), node-types-lodash.lt (= 3.9.6), node-types-lodash.lte (= 3.9.6), node-types-lodash.map (= 4.6.13), node-types-lodash.mapkeys (= 4.6.6), node-types-lodash.mapvalues (= 4.6.6), node-types-lodash.matches (= 4.6.6), node-types-lodash.matchesproperty (= 4.7.6), node-types-lodash.max (= 4.0.6), node-types-lodash.maxby (= 4.6.6), node-types-lodash.mean (= 4.1.6), node-types-lodash.meanby (= 4.10.5), node-types-lodash.memoize (= 4.1.6), node-types-lodash.merge (= 4.6.6), node-types-lodash.mergewith (= 4.6.6), node-types-lodash.method (= 4.5.6), node-types-lodash.methodof (= 4.5.6), node-types-lodash.min (= 4.0.6), node-types-lodash.minby (= 4.6.6), node-types-lodash.mixin (= 4.3.6), node-types-lodash.multiply (= 4.9.1), node-types-lodash.negate (= 3.0.6), node-types-lodash.noop (= 3.0.6), node-types-lodash.now (= 4.0.6), node-types-lodash.nth (= 4.11.3), node-types-lodash.ntharg (= 4.2.6), node-types-lodash.omit (= 4.5.6), node-types-lodash.omitby (= 4.6.6), node-types-lodash.once (= 4.1.6), node-types-lodash.orderby (= 4.6.6), node-types-lodash.over (= 4.7.6), node-types-lodash.overargs (= 4.7.6), node-types-lodash.overevery (= 4.7.6), node-types-lodash.oversome (= 4.7.6), node-types-lodash.pad (= 4.5.6), node-types-lodash.padend (= 4.6.6), node-types-lodash.padstart (= 4.6.6), node-types-lodash.parseint (= 4.0.6), node-types-lodash.partial (= 4.2.6), node-types-lodash.partialright (= 4.2.6), node-types-lodash.partition (= 4.6.6), node-types-lodash.pick (= 4.4.6), node-types-lodash.pickby (= 4.6.6), node-types-lodash.property (= 4.4.6), node-types-lodash.propertyof (= 4.4.6), node-types-lodash.pull (= 4.1.6), node-types-lodash.pullall (= 4.2.6), node-types-lodash.pullallby (= 4.7.6), node-types-lodash.pullallwith (= 4.7.3), node-types-lodash.pullat (= 4.6.6), node-types-lodash.random (= 3.2.6), node-types-lodash.range (= 3.2.6), node-types-lodash.rangeright (= 4.2.6), node-types-lodash.rearg (= 4.4.6), node-types-lodash.reduce (= 4.6.6), node-types-lodash.reduceright (= 4.6.6), node-types-lodash.reject (= 4.6.6), node-types-lodash.remove (= 4.7.6), node-types-lodash.repeat (= 4.1.6), node-types-lodash.replace (= 4.1.6), node-types-lodash.rest (= 4.0.6), node-types-lodash.result (= 4.5.6), node-types-lodash.reverse (= 4.0.6), node-types-lodash.round (= 4.0.6), node-types-lodash.sample (= 4.2.6), node-types-lodash.samplesize (= 4.2.6), node-types-lodash.set (= 4.3.6), node-types-lodash.setwith (= 4.3.6), node-types-lodash.shuffle (= 4.2.6), node-types-lodash.size (= 4.2.6), node-types-lodash.slice (= 4.2.6), node-types-lodash.snakecase (= 4.1.6), node-types-lodash.some (= 4.6.6), node-types-lodash.sortby (= 4.7.6), node-types-lodash.sortedindex (= 4.1.6), node-types-lodash.sortedindexby (= 4.6.6), node-types-lodash.sortedindexof (= 4.1.6), node-types-lodash.sortedlastindex (= 4.1.6), node-types-lodash.sortedlastindexby (= 4.6.6), node-types-lodash.sortedlastindexof (= 4.1.6), node-types-lodash.sorteduniq (= 4.2.6), node-types-lodash.sorteduniqby (= 4.7.6), node-types-lodash.split (= 4.4.6), node-types-lodash.spread (= 4.2.6), node-types-lodash.startcase (= 4.4.6), node-types-lodash.startswith (= 4.2.6), node-types-lodash.stubfalse (= 4.13.0), node-types-lodash.stubtrue (= 4.13.0), node-types-lodash.subtract (= 4.2.6), node-types-lodash.sum (= 4.0.6), node-types-lodash.sumby (= 4.6.6), node-types-lodash.tail (= 4.1.6), node-types-lodash.take (= 4.1.6), node-types-lodash.takeright (= 4.1.6), node-types-lodash.takerightwhile (= 4.6.6), node-types-lodash.takewhile (= 4.6.6), node-types-lodash.template (= 4.5.0), node-types-lodash.throttle (= 4.1.6), node-types-lodash.times (= 4.3.6), node-types-lodash.toarray (= 4.4.6), node-types-lodash.tofinite (= 4.12.3), node-types-lodash.tointeger (= 4.0.6), node-types-lodash.tolength (= 4.0.6), node-types-lodash.tolower (= 4.1.6), node-types-lodash.tonumber (= 4.0.6), node-types-lodash.topairs (= 4.3.6), node-types-lodash.topairsin (= 4.3.6), node-types-lodash.topath (= 4.5.6), node-types-lodash.toplainobject (= 4.2.6), node-types-lodash.tosafeinteger (= 4.0.6), node-types-lodash.tostring (= 4.1.6), node-types-lodash.toupper (= 4.1.6), node-types-lodash.transform (= 4.6.6), node-types-lodash.trim (= 4.5.6), node-types-lodash.trimend (= 4.5.6), node-types-lodash.trimstart (= 4.5.6), node-types-lodash.truncate (= 4.4.6), node-types-lodash.unary (= 4.2.6), node-types-lodash.unescape (= 4.0.6), node-types-lodash.union (= 4.6.6), node-types-lodash.unionby (= 4.8.6), node-types-lodash.unionwith (= 4.6.6), node-types-lodash.uniq (= 4.5.6), node-types-lodash.uniqby (= 4.7.6), node-types-lodash.uniqueid (= 4.0.6), node-types-lodash.uniqwith (= 4.5.6), node-types-lodash.unset (= 4.5.6), node-types-lodash.unzip (= 3.4.6), node-types-lodash.unzipwith (= 4.3.6), node-types-lodash.update (= 4.10.6), node-types-lodash.updatewith (= 4.10.3), node-types-lodash.uppercase (= 4.3.6), node-types-lodash.upperfirst (= 4.3.6), node-types-lodash.values (= 4.3.6), node-types-lodash.valuesin (= 4.3.6), node-types-lodash.without (= 4.4.6), node-types-lodash.words (= 4.2.6), node-types-lodash.wrap (= 4.1.6), node-types-lodash.xor (= 4.5.6), node-types-lodash.xorby (= 4.7.6), node-types-lodash.xorwith (= 4.5.6), node-types-lodash.zip (= 4.2.6), node-types-lodash.zipobject (= 4.1.6), node-types-lodash.zipobjectdeep (= 4.4.3), node-types-lodash.zipwith (= 4.2.6)
Description: Lo-dash is a Node.js utility library (per method packages)
Lodash makes JavaScript easier by taking the hassle out of working with arrays
, numbers, objects, strings, etc. Lodash’s modular methods are great for:

- Iterating arrays, objects, & strings
- Manipulating & testing values
- Creating composite functions
  .
  This package provides lodash methods exported as separate modules.
  .
  Node.js is an event-based server-side JavaScript engine.
  Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
  Homepage: https://lodash.com/

Package: node-log-driver
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.2.7+git+20180219+bba1761737-7
Depends: nodejs (>= 10)
Description: simple logging framework in pure javascript
This module implement logging to stdout and concatenate before
every message the log level severity (configurable)
date, time and local time zone. This modules allows ones
to easily trace log event even.
.
In all the cases logs are redirected to stdout in order to allows one
to pipe output to irc or logger program
.
This modules is needed by tools like coveralls, a coverage tools
for javascript program.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/cainus/logdriver

Package: node-lowercase-keys
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0-2
Description: Lowercase the keys of an object
It lowercases the keys and returns a new object.
If you pass the keys of an object which are not in lowercase or if you
want to ensure that all the keys are in lowercase then you can pass the
object as an argument and it returns a new object with all the keys in
lowercase.
This package is a dependency for ava.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/lowercase-keys

Package: node-lru-cache
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 35
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.0.0+~5.1.1-1
Provides: node-types-lru-cache (= 5.1.1)
Depends: node-yallist
Description: least-recently-used cache object for Node.js
A cache object that deletes the least-recently-used items.
This is the Node.js module.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/node-lru-cache

Package: node-mime
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 264
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.0.0+dfsg+~cs3.96.1-1
Provides: node-mime-db (= 1.51.0), node-mime-score (= 1.2.0), node-types-mime-db (= 1.43.1)
Depends: nodejs:any
Description: library for mime-type mapping for Node.js
mime is a Node.js library for mime-type mapping.
.
A comprehensive, compact MIME type module.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/broofa/node-mime

Package: node-mime-types
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 29
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.1.33-1
Provides: node-types-mime-types (= 2.1.1)
Depends: node-mime (>= 2.4.4)
Description: ultimate JavaScript content-type utility - Node.js module
This package provides a library for mime-type mapping similar to mime
module with some differences, such as it always returns a value, even
false if mime type is not found, and supports additional mime types.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/jshttp/mime-types

Package: node-mimic-response
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 20
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.1.0-7
Description: Mimic a Node.js HTTP response stream
Make a function mimic another one.
.
Useful when you wrap a function and like to preserve the original name and
other properties.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/mimic-response

Package: node-minimatch
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 52
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.1.1+~3.0.5-1
Provides: node-types-minimatch (= 3.0.5)
Depends: node-brace-expansion
Breaks: node-typescript-types (<< 20201105-1~)
Description: Convert glob expressions into RegExp objects for Node.js
A pure javascript, not strictly compatible, implementation of fnmatch/glob.
Supports negation, comment, double-star, brace expansion.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/minimatch

Package: node-minimist
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 40
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.2.5+~cs5.3.2-1
Provides: node-minimist-options (= 4.1.0), node-types-minimist (= 1.2.2)
Depends: node-arrify, node-is-plain-obj, node-kind-of
Breaks: node-typescript-types (<< 20201111~)
Description: Argument options parsing for Node.js
Minimist is the guts of optimist's argument parser without all the
fanciful decoration.
.
Optimist is a light-weight node.js library for option parsing.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/substack/minimist

Package: node-minipass
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 124
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.1.6+~cs8.7.18-1
Provides: node-minipass-collect (= 1.0.2), node-minipass-fetch (= 1.4.1), node-minipass-flush (= 1.0.5), node-minipass-json-stream (= 1.0.1), node-minipass-pipeline (= 1.2.4), node-minipass-sized (= 1.0.3), node-minizlib (= 2.1.2)
Depends: node-encoding, node-jsonparse, node-yallist (>= 4.0.0)
Description: Minimal implementation of a PassThrough for Node.js
minipass supports pipe/multi-pipe buffering data until either a "data"
event handler or "pipe()" is added (so firsk chunk not loose).
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/minipass#readme

Package: node-mkdirp
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 36
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.4+~1.0.2-1
Provides: node-types-mkdirp (= 1.0.2)
Depends: nodejs:any
Breaks: node-bluebird (<< 3.7.2+dfsg1-3~), node-cacache (<< 15.0.0~), node-chownr (<< 1.1.3-4~), node-copy-concurrently (<< 1.0.5-6~), node-cpr (<< 3.0.1-2~), node-fs-vacuum (<< 1.2.10-4~), node-fstream (<< 1.0.12-3~), node-klaw (<< 3.0.0-3~), node-millstone (<< 0.6.19~), node-multiparty (<< 4.2.2-1~), node-tar (<< 6.0.5~), node-zipfile (<< 0.5.12+ds-5~), npm (<< 7.0.3+repack+ds~), webpack (<< 4.43.0-2~), yarnpkg (<< 1.22.4-3~)
Description: Recursively create directories - Node.js module
mkdirp is a Node.js module to recursively create directories,
emulating mkdir -p shell command.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/node-mkdirp

Package: node-move-concurrently
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.1-4
Depends: node-aproba, node-copy-concurrently, node-fs-write-stream-atomic, node-mkdirp, node-rimraf, node-run-queue
Description: Move files and directories concurrently
Promises of moves of files or directories with rename, falling back to
recursive rename/copy on EXDEV errors, with configurable concurrency and win32
junction support.
.
If you `move` across devices or on filesystems that don't support renaming
large directories. That is, situations that result in `rename` returning
the `EXDEV` error, then `move` will fallback to copy + delete.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://www.npmjs.com/package/move-concurrently

Package: node-ms
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.1.3+~cs0.7.31-2
Provides: node-types-ms (= 0.7.31)
Depends: nodejs
Description: milliseconds conversion utility - Node.js module
This module provides a tiny milliseconds conversion utility able to
transform a string with a valid time unit to the equivalent number
of milliseconds and vice versa.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/vercel/ms

Package: node-mute-stream
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 25
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.0.8+~0.0.1-1
Provides: node-types-mute-stream (= 0.0.1)
Description: Pass-through stream that can be muted module for Node.js
node-mute-stream is a basic pass-through stream, but when muted,
the bytes are silently dropped, rather than being passed through.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/mute-stream

Package: node-negotiator
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 52
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.6.2+~0.6.1-1
Provides: node-types-negotiator (= 0.6.1)
Description: HTTP content negotiator for Node.js
node-negotiator parses HTTP Accept headers to return preferred
media types, languages, charsets, encodings from lists of
available choices.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/federomero/negotiator

Package: node-nopt
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 36
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 5.0.0-2
Depends: node-abbrev, nodejs:any
Description: Command-line option parser for Node.js
Full featured option parser, with support for :

- types (String, path, url, Number, Date, Boolean, NaN, Stream, Array)
- error handling
- abbreviations
- shorthands
  .
  Node.js is an event-based server-side javascript engine.
  Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
  Homepage: https://github.com/isaacs/nopt

Package: node-normalize-package-data
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 45
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.3+~2.4.1-1
Provides: node-types-normalize-package-data (= 2.4.1)
Depends: node-hosted-git-info (>= 3), node-resolve (>= 1.10.0~), node-semver, node-validate-npm-package-license, nodejs
Description: Normalizes package metadata - Node.js module
This module is used by node-read-package-json to normalize data it
reads from a package.json file typically found in Node.js modules,
but in principle it could come from any source.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/meryn/normalize-package-data

Package: node-npm-bundled
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 26
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.1.2-1
Description: Parses info on bundled dependencies
Npm-bundled gives info regarding bundled dependencies or transitive
dependencies of bundled dependencies.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/npm-bundled

Package: node-npm-package-arg
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 28
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 8.1.5-1
Depends: node-hosted-git-info (>= 4.0.2~), node-osenv, node-semver, node-validate-npm-package-name
Description: Parse the things that can be arguments to npm install
Parses package name and specifier passed to commands like npm install or
npm cache add, or as found in package.json dependency sections.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/npm-package-arg

Package: node-npmlog
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 33
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.0.1+~4.1.4-1
Provides: node-types-npmlog (= 4.1.4)
Depends: node-are-we-there-yet, node-console-control-strings, node-gauge (>= 4), node-set-blocking
Description: Logger with custom levels and colored output for Node.js
node-npmlog is a basic logger module used by npm.
.
npm is the package manager bundled with Node.js.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/npmlog

Package: node-object-assign
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.1.1-6
Provides: node-object.assign (= 4.1.1-6)
Depends: nodejs
Description: ES2015 Object.assign() ponyfill
Assigns enumerable own properties of source objects to the target object and
returns the target object. Additional source objects will overwrite previous
ones.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/object-assign#readme

Package: node-once
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.4.0-4
Depends: node-wrappy
Description: Run a function only once with this module for Node.js
node-once is useful to make sure a listener for multiple events is
only run once.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/once

Package: node-opener
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 27
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.5.2+~1.4.0-1
Provides: node-types-opener (= 1.4.0)
Depends: nodejs:any, xdg-utils
Description: Opens stuff, like webpages and files and executables
That is, in your desktop environment. This will make _actual windows pop up_,
with stuff in them:
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/domenic/opener

Package: node-osenv
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 22
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.1.5+~0.1.0-1
Provides: node-types-osenv (= 0.1.0)
Description: Environment settings lookup module for Node.js
node-osenv looks for hostname, user, prompt, tmpdir, home, path,
editor, shell in environment variables, utilities like hostname or
whoami, with appropriate default values.
It supports the same platforms as Node.js does.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/osenv

Package: node-p-cancelable
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 22
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.1.1-1
Breaks: node-got (<< 11.8.0)
Description: Create a promise that can be canceled
Useful for animation, loading resources, long-running async computations,
async iteration, etc.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/p-cancelable

Package: node-p-map
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.0.0+~3.1.0+~3.0.1-1
Provides: node-aggregate-error (= 3.1.0), node-clean-stack (= 3.0.1)
Depends: node-escape-string-regexp, node-indent-string
Description: Map over promises concurrently
Useful when you need to run promise-returning & async functions multiple times
with different inputs concurrently.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/p-map#readme

Package: node-path-is-absolute
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0-2
Description: Node.js 0.12 path.isAbsolute() ponyfill
Path-is-absolute is a Node.js module that gives developers the ability to
determine whether a path written in programming language is an absolute path.
An absolute path will always resolve to the same location, regardless of the
working directory. Path-is-absolute is a ponyfill, meaning that it does not
overwrite the native method in a JavaScript environment.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/path-is-absolute

Package: node-process-nextick-args
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.1-2
Description: process.nextTick but always with args
With node-process-nextick-args you will always be able to pass arguments
to process.nextTick, no matter which platform you use.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/calvinmetcalf/process-nextick-args

Package: node-promise-inflight
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.1+~1.0.0-1
Provides: node-types-promise-inflight (= 1.0.0)
Description: one promise for multiple requests in flight to avoid async duplication
Multiple requests called with the same result (only one underlying promise)
Based on the callback based function 'inflight'.
.
Usage: return inflight(key, () => {/_fetch url_/ return Promise.delay(100)}
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/iarna/promise-inflight

Package: node-promise-retry
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.1-2
Depends: node-err-code (>= 2.0.0), node-retry (>= 0.10.0)
Description: Retries a function that returns a promise
Leverage the power of the retry module to the promises world.
.
Calls fn until the returned promise ends up fulfilled or rejected with an
error different than a retry error.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/IndigoUnited/node-promise-retry#readme

Package: node-promzard
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 20
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.3.0-2
Depends: node-read
Description: Promzard provides a prompting json wizard
A prompting wizard for building files from specialized PromZard modules.
Used by npm init.
.
A reimplementation of SubStack's prompter, which does not use AST traversal.
.
From another point of view, it's a reimplementation of Marak's wizard
which doesn't use schemas.
.
The goal is a nice drop-in enhancement for npm init.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/promzard

Package: node-psl
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 151
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: psl.js
Version: 1.8.0+ds-6
Depends: libjs-psl, node-punycode, nodejs
Description: Node.js domain name parser based on the Public Suffix List
psl is a JavaScript domain name parser based on the Public Suffix List
(https://publicsuffix.org/). This implementation is tested against the test
data hosted by Mozilla and kindly provided by Comodo.
.
The Public Suffix List is a cross-vendor initiative to provide an accurate
list of domain name suffixes. A "public suffix" is one under which Internet
users can directly register names. Some examples of public suffixes are
".com", ".co.uk" and "pvt.k12.wy.us". The Public Suffix List is a list of all
known public suffixes.
.
This package provides the node.js module.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/lupomontero/psl#readme

Package: node-pump
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.0-5
Depends: node-end-of-stream, node-once
Description: small node module that pipes streams together
When using standard source.pipe(dest) source will not be destroyed if dest
emits close or an error. You are also not able to provide a callback to tell
when then pipe has finished. pump does these two things for you.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/mafintosh/pump

Package: node-punycode
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 41
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.1.1-5
Depends: nodejs
Description: Nodejs robust Punycode converter fully RFC compliant
node-punycode is a punycode converter conforming to RFC 3492 and RFC 5891,
and works on nearly all JavaScript platforms.
.
Punycode is a way to represent Unicode with the limited character subset
of ASCII supported by the Domain Name System.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://mths.be/punycode

Package: node-quick-lru
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 5.1.1-1
Description: Simple "Least Recently Used" (LRU) cache
Useful when you need to cache something and limit memory usage.
Inspired by the hashlru algorithm, but instead uses Map to support
keys of any type, not just strings, and values can be undefined.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/quick-lru

Package: node-read
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 20
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.7-3
Depends: node-mute-stream
Description: Read user input from stdin module for Node.js
node-read extends Node.js readline.question builtin method with options
like silent input, replaced input, timeout or default value.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/read

Package: node-read-package-json
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 35
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.1.1-1
Depends: node-glob, node-json-parse-better-errors, node-normalize-package-data (>= 3.0.3~), node-slash, nodejs
Recommends: node-graceful-fs
Description: Read package.json for npm module for Node.js
This module reads package.json files with semantics, defaults, and
validation for npm consumption.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/read-package-json

Package: node-readable-stream
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 149
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.6.0+~cs3.0.0-1
Provides: node-bufferstreams (= 3.0.0)
Depends: node-inherits, node-core-util-is, node-string-decoder, node-safe-buffer, node-process-nextick-args, node-util-deprecate, node-isarray
Breaks: node-libs-browser (<< 2.2.1-3)
Description: stream compatibility library for Node.js and browser
node-readable-stream package is a port to browser context of the well
known stream API of Node.js, usable both under Node.js or inside a browser.
.
A stream is an abstract interface for working with streaming data in Node.js.
There are many stream objects provided by Node.js. For instance, a request
to an HTTP server and process.stdout are both stream instances.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/nodejs/readable-stream#readme

Package: node-resolve
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 121
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.20.0+~cs5.27.9-1
Provides: node-is-core-module (= 2.6.0), node-object-keys (= 1.1.1), node-path-parse (= 1.0.7), node-types-resolve (= 1.20.1)
Depends: node-has
Breaks: node-browser-resolve (<< 2.0.0~)
Description: Synchronous/Asynchronous require.resolve() algorithm
This module implements the node require.resolve() algorithm such
that you can require.resolve() on behalf of a file asynchronously
and synchronously
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/substack/node-resolve#readme

Package: node-retry
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 39
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.13.1+~0.12.1-1
Provides: node-types-retry (= 0.12.1)
Description: Retry strategies for failed operations module for Node.js
node-retry abstracts exponential and custom retry strategies for failed
operations. Its parameters are the number of retries, exponential
factor, minimum and maximum (randomized) timeouts.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tim-kos/node-retry

Package: node-rimraf
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 40
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.2-1
Provides: node-types-rimraf (= 3.0.0)
Depends: node-glob, nodejs
Recommends: node-graceful-fs
Description: Deep deletion (like rm -rf) module for Node.js
node-rimraf is a Node.js module that provides asynchronous deep-deletion
of files and directories.
.
The `rimraf` executable is a faster alternative to the `rm -rf` shell
command.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/rimraf

Package: node-run-queue
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.0-2
Depends: node-aproba
Description: promise based dynamic priority queue runner
A promise based, dynamic priority queue runner, with concurrency limiting.
.
The concurrency means that processes don't finish in order, because some take
longer than others. Each priority level must finish entirely before the
next priority level is run. Priorities essentially represent distinct job
queues. All jobs in a queue must complete before the next highest priority job
queue is executed. Lowest is executed first.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://npmjs.com/package/run-queue

Package: node-safe-buffer
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 53
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 5.2.1+~cs2.1.2-2
Provides: node-safer-buffer (= 2.1.2)
Description: Safer Node.js Buffer API
The goal of this package is to provide a safe replacement for the node.js
`Buffer`. It's a drop-in replacement for `Buffer`. You can use it by adding
one `require` line to the top of your node.js modules; for example
var Buffer = require('safe-buffer').Buffer
Existing buffer code will continue to work without issues.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/feross/safe-buffer

Package: node-semver
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 187
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 7.3.5+~7.3.8-1
Provides: node-types-semver (= 7.3.8)
Depends: node-lru-cache, nodejs (>= 10)
Breaks: node-gyp (<< 6.0.1-1), node-typescript-types (<< 20201117~)
Description: Semantic Versioning for Node.js
Test if version(s) satisfy the supplied range(s), and sort them.
Multiple versions or ranges may be supplied.
Program exits successfully if any valid version satisfies
all supplied ranges, and prints all satisfying versions.
.
This package provides the `semver` executable and the Node.js module.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/node-semver

Package: node-set-blocking
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0-2
Description: set blocking stdio and stderr
set blocking stdio and stderr ensuring that terminal output does not truncate
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/yargs/set-blocking

Package: node-signal-exit
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 27
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.0.6+~3.0.1-1
Provides: node-types-signal-exit (= 3.0.1)
Description: Fire an event no matter how a process exits
When you want to fire an event no matter how a process exits:
reaching the end of execution.
explicitly having process.exit(code) called.
having process.kill(pid, sig) called.
receiving a fatal signal from outside the process
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tapjs/signal-exit

Package: node-slash
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.0.0-2
Description: Node.js library to convert Windows backslash paths to slash paths
node-slash provides a simple way to convert Windows backslash paths to slash
paths: 'foo\bar' becomes 'foo/bar'
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/slash

Package: node-slice-ansi
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 5.0.0+~cs9.0.0-4
Replaces: node-string-width (<< 4.2.3+~9.2.2~)
Provides: node-is-fullwidth-code-point (= 4.0.0), node-types-slice-ansi (= 5.0.0)
Depends: node-ansi-styles
Breaks: node-cli-truncate (<< 2.1.0-4~), node-string-width (<< 4.2.3+~cs13.2.3~)
Description: Slice a string with ANSI escape codes
Escape codes are used for formatting, color, and other output options on video
text terminals.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/chalk/slice-ansi

Package: node-source-map
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 138
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.7.0++dfsg2+really.0.6.1-9
Provides: node-types-source-map (= 0.7.0++dfsg2+really.0.6.1-9)
Depends: libjs-source-map (= 0.7.0++dfsg2+really.0.6.1-9)
Description: Mozilla source map generator and consumer - Node.js module
Mozilla implementation of source map generator and consumer, for source
maps written in the Asynchronous Module Definition format.
.
Source maps provide a language-agnostic way to compile back production
code to the original source code.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/mozilla/source-map

Package: node-source-map-support
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 48
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.5.21+ds+~0.5.4-1
Provides: node-types-source-map-support (= 0.5.4)
Depends: nodejs, node-source-map
Description: Fixes stack traces for files with source maps
This module uses source-map to replace the paths and line numbers
of source-mapped files with their original counterparts in the real
sources.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@alioth-lists.debian.net>
Homepage: https://github.com/evanw/node-source-map-support

Package: node-spdx-correct
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 24
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.1.1-2
Depends: node-spdx-license-ids (>= 3.0.0), node-spdx-expression-parse (>= 3.0.0)
Description: correct invalid SPDX identifiers
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/kemitchell/spdx-correct.js

Package: node-spdx-exceptions
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.3.0-2
Description: list of SPDX standard license exceptions
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/kemitchell/spdx-exceptions.json

Package: node-spdx-expression-parse
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 30
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.1+~3.0.1-1
Provides: node-types-spdx-expression-parse (= 3.0.1)
Depends: node-spdx-exceptions (>= 2.0.1), node-spdx-license-ids (>= 3.0.0)
Description: parse SPDX license expressions
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/kemitchell/spdx-expression-parse.js

Package: node-spdx-license-ids
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 27
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.0.11-1
Provides: node-get-spdx-license-ids (= 2.1.0)
Description: List of SPDX license identifiers
A list of SPDX license identifiers. The SPDX License List is a list of
commonly found licenses and exceptions used for open source and other
collaborative software.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/shinnn/spdx-license-ids

Package: node-sprintf-js
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 29
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.1.2+ds1+~1.1.2-1
Provides: node-types-sprintf-js
Depends: libjs-sprintf-js (= 1.1.2+ds1+~1.1.2-1)
Description: Node.js Pure JavaScript sprintf implementation
node-sprintf-js is a javascript implementation of C sprintf (3).
This function composes a string with the same text that would be printed if
format was used on printf, but instead of being printed, the content is
stored as a string in the buffer pointed by a str argument.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/alexei/sprintf.js

Package: node-ssri
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 60
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 8.0.1-2
Depends: node-yallist (>= 4.0.0), nodejs
Description: Utility for parsing, serializing, generating and verifying ssri metadata
SSRI, short for Standard Subresource Integrity, is a Node.js utility for
parsing, manipulating, serializing, generating and verifying Subresource
Integrity hashes according to SRI spec.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/ssri#readme

Package: node-stack-utils
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 28
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.5+~2.0.1-1
Provides: node-types-stack-utils (= 2.0.1)
Depends: nodejs, node-escape-string-regexp
Description: Captures and cleans stack traces
This modules provides API for working with nodejs stack traces.
Ones could create new stack traces instance simulating for instance
deep call of function, or clean existing stack trace. This API
includes function to call up and down on stack trace.
.
In computing, a stack trace (also called stack backtrace or
stack traceback) is a report of the active stack frames
at a certain point in time during the execution of a program.
Programmers commonly use stack tracing during interactive
and post-mortem debugging. A stack trace allows tracking
the sequence of nested functions called - up to the point
where the stack trace is generated.
In a post-mortem scenario this extends up to the function
where the failure occurred
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tapjs/stack-utils#readme

Package: node-stealthy-require
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 20
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.1.1-5
Description: require function that bypasses the require cache.
This is probably the closest you can currently get to require something in
node.js with completely bypassing the require cache.
.
stealthy-require works like this:
.

- It clears the require cache.
- It calls a callback in which you require your module(s) without the cache
  kicking in.
- It clears the cache again and restores its old state.
  .
  Node.js is an event-based server-side JavaScript engine.
  Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
  Homepage: https://github.com/analog-nico/stealthy-require#readme

Package: node-string-decoder
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 26
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.3.0-5
Depends: node-safe-buffer
Description: string_decoder module from Node core for browsers
node-string-decoder provides a string_decoder module compatible with
string_decoder module from Node.js core but adapted for
browsers context.
.
Node.js string_decoder module provides an API for decoding Buffer objects
into strings in a manner that preserves encoded multi-byte UTF-8 and
UTF-16 characters.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/nodejs/string_decoder

Package: node-string-width
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 122
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.2.3+~cs13.2.3-1
Provides: node-emoji-regex (= 9.2.2), node-types-string-width (= 4.0.1)
Depends: node-slice-ansi (>= 5.0.0+~cs9.0.0-2~), node-is-fullwidth-code-point, node-strip-ansi, node-wcwidth.js
Description: Get the visual width of a string
Some Unicode characters use more or less than the normal width when output
to the command-line.
.
This nodejs module gets the visual width of a string i.e. the actual
number of columns required to display it.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/string-width

Package: node-strip-ansi
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.0.1-1
Depends: nodejs, node-ansi-regex
Description: Strip ANSI escape codes
This module strips ANSI escape codes.
.
To report a security vulnerability, please use the Tidelift security contact.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/chalk/strip-ansi

Package: node-supports-color
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 26
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 8.1.1+~8.1.1-1
Provides: node-types-supports-color (= 8.1.1)
Depends: node-has-flag
Description: Detect whether a terminal supports color in Node.js
supports-color is a Node.js module which provides an API to detect whether a
terminal supports color.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/sindresorhus/supports-color

Package: node-tap
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 211
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 12.0.1+ds-4
Provides: node-bind-obj-methods (= 2.0.0), node-fs-exists-cached (= 1.0.0), node-function-loop (= 1.0.1), node-own-or (= 1.0.0), node-own-or-env (= 1.0.1), node-trivial-deferred (= 1.0.1), node-tsame (= 2.0.0), node-yapool (= 1.0.0)
Depends: nodejs, node-clean-yaml-object, node-supports-color, node-foreground-child, node-glob, node-isexe, node-js-yaml (>= 4~), node-mkdirp, node-rimraf, node-signal-exit, node-source-map-support, node-stack-utils, node-tap-mocha-reporter, node-tap-parser, node-tmatch, node-write-file-atomic
Recommends: node-coveralls, node-opener
Suggests: node-nyc (>= 11.8.0)
Description: Test-Anything-Protocol module for Node.js
Utilities for writing test harnesses complying with TAP output format.
.
TAP is a simple text-based interface between testing modules
implemented in many popular languages.
.
This package includes leaf package node-bind-obj-methods,
node-fs-exists-cached, node-function-loop, node-own-or, node-own-or-env,
node-trivial-deferred, node-tsame, node-yapool
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tapjs/node-tap

Package: node-tap-mocha-reporter
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 142
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.7+ds-2
Depends: node-debug, node-diff, node-escape-string-regexp, node-glob, node-js-yaml, node-strip-ansi, node-supports-color, node-tap-parser, nodejs:any
Enhances: node-tap
Description: Format a TAP stream using Mocha's set of reporters
This module allows one to format node-tap output like output
of Mocha test framework.
.
node-tap is a Node.js implementation of TAP a simple text-based interface
shared between testing modules implemented in many popular languages.
.
Mocha is a feature-rich JavaScript test framework running
on Node.js and browser, making asynchronous testing
simple.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/tapjs/tap-mocha-reporter

Package: node-tap-parser
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 69
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 7.0.0+ds1-6
Provides: node-events-to-array (= 1.1.2)
Depends: node-js-yaml, nodejs:any
Description: Test anything protocol stream parser - Node.js module
This module parses tap-formatted input as a stream of JavaScript
objects.
.
It is mainly used to extend tap reporters in various test setups.
.
This package also include leaf package node-events-to-array.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/substack/tap-parser

Package: node-tar
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 178
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 6.1.11+ds1+~cs6.0.6-1
Provides: node-types-tar (= 4.0.5)
Depends: node-chownr, node-mkdirp (>= 1), node-minipass, node-safe-buffer, node-yallist (>= 4.0~)
Description: read and write portable tar archives module for Node.js
node-tar is able to read and write tar archives generated by
bsdtar, gnutar, solaris posix tar, and "Schilly" tar.
node-tar is a well-tested essential piece of software for npm,
the Node.js package manager.
.
This package includes components: chownr, minipass, fs-minipass,
minizlib.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/node-tar

Package: node-text-table
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 0.2.0-4
Description: borderless text tables with alignment
Generate borderless text table strings suitable for printing to stdout.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/substack/text-table

Package: node-time-stamp
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.2.0-1
Description: get a formatted timestamp
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/jonschlinkert/time-stamp

Package: node-tmatch
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 5.0.0-4
Description: Match an object against a "pattern" object - Node.js module
This module checks weter a value matches a given pattern.
A pattern is an object with a set of fields that must be in
the test object, or a regular expression that a test string
must match, or any combination thereof.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/tmatch

Package: node-tough-cookie
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 105
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.0.0-2
Provides: node-types-tough-cookie (= 4.0.0)
Depends: node-psl, node-punycode, node-universalify
Description: RFC6265 Cookies and Cookie Jar for node.js
This library just provides a way to read and write RFC6265 HTTP cookie
headers.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/salesforce/tough-cookie

Package: node-typedarray-to-buffer
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 14
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.0.0-2
Depends: libjs-typedarray-to-buffer (= 4.0.0-2), node-is-typedarray
Description: JavaScript utility converting TypedArray to buffer without copy
Convert a typed array to a Buffer without a copy.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/feross/typedarray-to-buffer

Package: node-unique-filename
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.1.1+ds-1
Depends: nodejs, node-imurmurhash
Description: unique filename for use in temporary directories or caches
This module can be used to generate a unique filename for use in temporary
directories or caches.
.
For example, if you pass os.tmpdir() as an argument, it returns something
like: /tmp/912ec803b2ce49e4a541068d495ab570.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/iarna/unique-filename

Package: node-universalify
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 15
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2.0.0-3
Description: Make a callback- or promise-based function support both promises and callbacks
This package provides ways to make a callback- or promise-based function
support both promises and callbacks.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@alioth-lists.debian.net>
Homepage: https://github.com/RyanZim/universalify

Package: node-util-deprecate
Status: install ok installed
Priority: optional
Section: web
Installed-Size: 19
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.2-3
Description: Node.js's `util.deprecate()` function with browser support
In Node.js, this module simply re-exports the util.deprecate() function.
.
In the web browser (i.e. via browserify), a browser-specific
implementation of the util.deprecate() function is used.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/TooTallNate/util-deprecate

Package: node-validate-npm-package-license
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 17
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.4-2
Depends: node-spdx-correct, node-spdx-expression-parse
Description: Tells if a string is a valid npm package license string
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/kemitchell/validate-npm-package-license.js

Package: node-validate-npm-package-name
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.0-4
Depends: node-builtins (>= 3)
Description: Checks if a string is a valid npm package name
This module can determine if a string is valid to be used a npm module name.
This module will show conformance to old naming rules and new naming rules
separately.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/validate-npm-package-name

Package: node-wcwidth.js
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 21
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.0.2-1
Depends: node-defaults
Description: wcwidth.js is a javascript porting of C's wcwidth()
wcwidth.js is a simple javascript porting of wcwidth()
implemented in C by Markus Kuhn.
.
wcwidth() and its string version, wcswidth() are defined by
IEEE Std 1002.1-2001, a.k.a. POSIX.1-2001, and return the
number of columns used to represent a wide character and
string on fixed-width output devices like terminals.
Markus's implementation assumes wide characters to be
encoded in ISO 10646, which is almost true for JavaScript;
almost because JavaScript uses UCS-2 and has problems
with surrogate pairs. wcwidth.js converts surrogate pairs
to Unicode code points to handle them correctly.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: http://code.woong.org/wcwidth.js

Package: node-webidl-conversions
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 92
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: jsbundle-web-interfaces (1.1.0+~cs15.1.20180823-2)
Version: 7.0.0~1.1.0+~cs15.1.20180823-2
Provides: node-types-webidl-conversions (= 6.1.1~1.1.0+~cs15.1.20180823-2)
Description: web IDL type conversions on JavaScript values - Node.js library
Webidl-conversions implements, in JavaScript, the algorithms
to convert a given JavaScript value according to a given Web IDL type.
.
Web IDL is an interface description language (IDL) format
for describing application programming interfaces (APIs)
that are intended to be implemented in web browsers.
.
This package provides webidl-conversions usable with Node.js -
an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>

Package: node-whatwg-fetch
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 61
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.6.2-5
Provides: libjs-whatwg-fetch (= 3.6.2-5)
Breaks: libjs-fetch (<< 3.5.0-2~)
Description: window.fetch JavaScript polyfill
The fetch() function is a Promise-based mechanism for programmatically making
web requests in the browser. This project is a polyfill that implements a
subset of the standard Fetch specification, enough to make fetch a viable
replacement for most uses of XMLHttpRequest in traditional web applications.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/github/fetch#readme

Package: node-which
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 30
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.0.2+~cs1.3.2-2
Provides: node-types-which (= 1.3.2)
Depends: node-isexe (>= 2.0.0-5~), nodejs:any
Description: Cross-platform 'which' module for Node.js
node-which finds the first instance of a specified executable
in the PATH environment variable, simulating the behaviour of
the standard "which" program.
node-which supports all platforms supported by Node.js.
.
This is the module only, the binary being totally useless.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/node-which

Package: node-wide-align
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 16
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.1.3-4
Depends: node-string-width
Description: Wide-character aware text alignment function
Wide-character aware text alignment function for use on the console or with
fixed width fonts.
.
This library is a dependency for webpack. Webpack takes code targeted at
node.js and makes it run in the browser. Node.js comes with API of its own
that is not available in the browsers. Webpack exposes this code
to programs that are unaware they are running in a browser.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/iarna/wide-align#readme

Package: node-wrappy
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 14
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.0.2-2
Description: Callback wrapping utility
Returns a wrapper function that returns a wrapped callback
The wrapper function should do some stuff, and return a
presumably different callback function.
This makes sure that own properties are retained, so that
decorations and such are not lost along the way.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/npm/wrappy

Package: node-write-file-atomic
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 3.0.3+~3.0.2-1
Provides: node-types-write-file-atomic (= 3.0.2)
Depends: node-imurmurhash, node-is-typedarray, node-signal-exit, node-typedarray-to-buffer, nodejs
Description: Write files in an atomic fashion w/configurable ownership
This is an extension for node's `fs.writeFile` that makes its operation atomic
and allows you set ownership (uid/gid of the file).
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/iarna/write-file-atomic

Package: node-ws
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 209
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 8.5.0+~cs13.3.3-2
Provides: node-types-ws (= 8.2.3), node-wscat (= 5.1.0)
Depends: node-commander, node-https-proxy-agent, node-read, nodejs:any
Breaks: node-websocket-stream (<< 5.4.0-5~)
Description: RFC-6455 WebSocket implementation module for Node.js
ws is a simple to use websocket implementation, up-to-date against RFC-6455,
and probably the fastest WebSocket library for Node.js.
.
Passes the quite extensive Autobahn test suite. See
http://einaros.github.com/ws for the full reports.
.
It also provides wscat, a command-line tool which can either act
as a server or a client, and is useful for debugging websocket services.
.
Node.js is an event-based server-side javascript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/websockets/ws

Package: node-yallist
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 31
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 4.0.0+~4.0.1-1
Provides: node-types-yallist (= 4.0.1)
Description: Double linked list implementation for Node.js
This module allows one to create a double linked list that
exposes many array-like methods like push, unshift, forEach,
reduce, and more specific methods like forEachReverse or
mapReverse.
.
Node.js is an event-based server-side JavaScript engine.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://github.com/isaacs/yallist

Package: nodejs
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 910
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Version: 12.22.9~dfsg-1ubuntu3
Provides: node-types-node (= 12.20.42~12.22.9~dfsg-1ubuntu3)
Depends: libc6 (>= 2.34), libnode72 (= 12.22.9~dfsg-1ubuntu3)
Recommends: ca-certificates, nodejs-doc
Suggests: npm
Breaks: node-babel-runtime (<< 7), node-typescript-types (<< 20210110~)
Description: evented I/O for V8 javascript - runtime executable
Node.js is a platform built on Chrome's JavaScript runtime for easily
building fast, scalable network applications. Node.js uses an
event-driven, non-blocking I/O model that makes it lightweight and
efficient, perfect for data-intensive real-time applications that run
across distributed devices.
.
Node.js is bundled with several useful libraries to handle server
tasks:
.
System, Events, Standard I/O, Modules, Timers, Child Processes, POSIX,
HTTP, Multipart Parsing, TCP, DNS, Assert, Path, URL, Query Strings.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@alioth-lists.debian.net>
Homepage: https://nodejs.org/

Package: nodejs-doc
Status: install ok installed
Priority: optional
Section: doc
Installed-Size: 9282
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: nodejs
Version: 12.22.9~dfsg-1ubuntu3
Depends: libjs-highlight.js
Recommends: nodejs
Description: API documentation for Node.js, the javascript platform
Node.js is a platform built on Chrome's JavaScript runtime for easily
building fast, scalable network applications. Node.js uses an
event-driven, non-blocking I/O model that makes it lightweight and
efficient, perfect for data-intensive real-time applications that run
across distributed devices.
.
Node.js is bundled with several useful libraries to handle server
tasks:
.
System, Events, Standard I/O, Modules, Timers, Child Processes, POSIX,
HTTP, Multipart Parsing, TCP, DNS, Assert, Path, URL, Query Strings.
.
This package contains API documentation for Node.js.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@alioth-lists.debian.net>
Homepage: https://nodejs.org/

Package: npm
Status: install ok installed
Priority: optional
Section: javascript
Installed-Size: 2647
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 8.5.1~ds-1
Provides: arborist (= 4.3.1), node-npm (= 8.5.1), node-npm-packlist (= 3.0.0), node-npmcli-arborist (= 4.3.1), node-npmcli-ci-detect (= 2.0.0), node-npmcli-config (= 3.0.0), node-npmcli-disparity-colors (= 1.0.1), node-npmcli-fs (= 1.1.0), node-npmcli-git (= 2.1.0), node-npmcli-installed-package-contents (= 1.0.7), node-npmcli-map-workspaces (= 2.0.0), node-npmcli-metavuln-calculator (= 2.0.0), node-npmcli-name-from-folder (= 1.0.1), node-npmcli-node-gyp (= 1.0.3), node-npmcli-package-json (= 1.0.1), node-npmcli-promise-spawn (= 1.3.2), node-npmcli-run-script (= 2.0.0), node-pacote (= 12.0.3), node-qrcode-terminal (= 0.12.0), npm-packlist (= 3.0.0), pacote (= 12.0.3), qrcode-terminal (= 0.12.0)
Depends: ca-certificates, node-abbrev, node-agent-base, node-ansistyles, node-aproba, node-archy, node-asap, node-cacache, node-chalk, node-chownr, node-cli-table3, node-colors, node-columnify, node-debug, node-depd, node-emoji-regex, node-encoding, node-glob, node-got, node-graceful-fs, node-gyp, node-hosted-git-info, node-https-proxy-agent, node-ini, node-ip, node-ip-regex, node-json-parse-better-errors, node-jsonparse, node-lru-cache, node-minimatch, node-minipass, node-mkdirp, node-ms, node-negotiator, node-nopt, node-normalize-package-data, node-npm-bundled, node-npm-package-arg, node-npmlog, node-once, node-promise-retry, node-promzard, node-read, node-read-package-json, node-rimraf, node-semver, node-ssri, node-string-width, node-strip-ansi, node-tar, node-text-table, node-validate-npm-package-license, node-validate-npm-package-name, node-which, node-wrappy, node-write-file-atomic, node-yallist, nodejs:any (>= 10)
Recommends: git, node-tap
Suggests: node-opener
Description: package manager for Node.js
Node.js is an event-based server-side javascript engine.
.
npm is the package manager for the Node JavaScript platform. It puts
modules in place so that node can find them, and manages dependency
conflicts intelligently.
.
It is extremely configurable to support a wide variety of use cases.
Most commonly, it is used to publish, discover, install, and develop
node programs.
.
Install also node-opener to have full npm features enabled.
Original-Maintainer: Debian Javascript Maintainers <pkg-javascript-devel@lists.alioth.debian.org>
Homepage: https://docs.npmjs.com/

Package: ntfs-3g
Status: install ok installed
Priority: optional
Section: otherosfs
Installed-Size: 1300
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1:2021.8.22-3ubuntu1.1
Depends: libc6 (>= 2.34), libgcrypt20 (>= 1.9.0), libgnutls30 (>= 3.7.2), libntfs-3g89 (= 1:2021.8.22-3ubuntu1.1)
Pre-Depends: fuse3
Description: read/write NTFS driver for FUSE
NTFS-3G uses FUSE (Filesystem in Userspace) to provide support for the NTFS
filesystem used by Microsoft Windows.
Homepage: https://github.com/tuxera/ntfs-3g/wiki
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>

Package: open-iscsi
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 1221
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.1.5-1ubuntu1
Depends: debconf (>= 0.5) | debconf-2.0, init-system-helpers (>= 1.51), libc6 (>= 2.34), libisns0, libkmod2 (>= 5~), libmount1 (>= 2.24.2), libopeniscsiusr (>= 2.1.5), libssl3 (>= 3.0.0~~alpha1), libsystemd0, udev
Pre-Depends: debconf | debconf-2.0
Recommends: busybox-initramfs, finalrd (>= 3)
Conffiles:
/etc/default/open-iscsi 5744c65409cbdea2bcf5b99dbff89e96
/etc/init.d/iscsid f45c4e0127bafee72454ce97a7ce2f6c
/etc/init.d/open-iscsi b17044873b86412cbadeba711edcc41a
/etc/iscsi/iscsid.conf 71f8f1fd14d91dc776aee2ee7fb6c70f
Description: iSCSI initiator tools
The Open-iSCSI project is a high-performance, transport independent,
multi-platform implementation of RFC3720 iSCSI.
.
Open-iSCSI is partitioned into user and kernel parts.
.
The kernel portion of Open-iSCSI is a from-scratch code
licensed under GPL. The kernel part implements iSCSI data path
(that is, iSCSI Read and iSCSI Write), and consists of three
loadable modules: scsi_transport_iscsi.ko, libiscsi.ko and iscsi_tcp.ko.
.
User space contains the entire control plane: configuration
manager, iSCSI Discovery, Login and Logout processing,
connection-level error processing, Nop-In and Nop-Out handling,
and (in the future:) Text processing, iSNS, SLP, Radius, etc.
.
The user space Open-iSCSI consists of a daemon process called
iscsid, and a management utility iscsiadm.
.
This package includes a daemon, iscsid, and a management utility,
iscsiadm.
Homepage: https://www.open-iscsi.com/
Original-Maintainer: Debian iSCSI Maintainers <open-iscsi@packages.debian.org>

Package: open-vm-tools
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 3010
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2:11.3.5-1ubuntu4.1
Depends: libc6 (>= 2.34), libdrm2 (>= 2.4.3), libfuse3-3 (>= 3.2.3), libgcc-s1 (>= 3.3), libglib2.0-0 (>= 2.31.8), libmspack0 (>= 0.4), libssl3 (>= 3.0.0~~alpha1), libtirpc3 (>= 1.0.2), libudev1 (>= 183), libxml2 (>= 2.7.4), libxmlsec1 (>= 1.2.33), libxmlsec1-openssl (>= 1.2.33), pciutils, iproute2, lsb-release
Pre-Depends: init-system-helpers (>= 1.54~)
Recommends: ethtool, zerofree, fuse3
Suggests: open-vm-tools-desktop, cloud-init
Conffiles:
/etc/init.d/open-vm-tools aeead08272288e4dfbaaf30d0c250726
/etc/pam.d/vmtoolsd c8d3eb12e396c1824018eea75e5f9d56
/etc/vmware-tools/poweroff-vm-default 370468e5f19a306e29d39fbf7b72cf08
/etc/vmware-tools/poweron-vm-default 370468e5f19a306e29d39fbf7b72cf08
/etc/vmware-tools/resume-vm-default 370468e5f19a306e29d39fbf7b72cf08
/etc/vmware-tools/scripts/vmware/network e1dc72426f8f60ee6a568878cf6421ce
/etc/vmware-tools/statechange.subr 9ebfc4a9aa22fe49491ad4ac47d4d22c
/etc/vmware-tools/suspend-vm-default 370468e5f19a306e29d39fbf7b72cf08
/etc/vmware-tools/tools.conf 76d7075ddb1a4266cb7e43f3a50181b7
/etc/vmware-tools/tools.conf.example 63ba6e744665e5d9c2efbe605c04c466
/etc/vmware-tools/vgauth.conf 08a49e9affbd864b51b8b77251accd89
/etc/vmware-tools/vgauth/schemas/XMLSchema-hasFacetAndProperty.xsd 9308e8b04cbf7d2748a287ace40878ea
/etc/vmware-tools/vgauth/schemas/XMLSchema-instance.xsd e1059f0307358c02766193e5e24c107b
/etc/vmware-tools/vgauth/schemas/XMLSchema.dtd 86eafc21ca4ab293b7515e453c2b5dfe
/etc/vmware-tools/vgauth/schemas/XMLSchema.xsd 54f86ef1a7a41930ba250151f143069b
/etc/vmware-tools/vgauth/schemas/catalog.xml de4f8846e6e571af9feddd834b33a9be
/etc/vmware-tools/vgauth/schemas/datatypes.dtd c61228050bb7c1c28a7f659f86a6e6c9
/etc/vmware-tools/vgauth/schemas/saml-schema-assertion-2.0.xsd 612084dbce32687eef288f56569de391
/etc/vmware-tools/vgauth/schemas/xenc-schema.xsd 4e7be0e2cae08227fd9ddb261c1e4e93
/etc/vmware-tools/vgauth/schemas/xml.xsd d4314590e7e7aaf6bcd508be0fd1c614
/etc/vmware-tools/vgauth/schemas/xmldsig-core-schema.xsd dff329f34df298d952d2e800a097c431
Description: Open VMware Tools for virtual machines hosted on VMware (CLI)
The Open Virtual Machine Tools (open-vm-tools) project is an open source
implementation of VMware Tools. It is a suite of virtualization utilities and
drivers to improve the functionality, user experience and administration of
VMware virtual machines.
.
This package contains only the core user-space programs and libraries.
Homepage: https://github.com/vmware/open-vm-tools
Original-Maintainer: Bernd Zeimetz <bzed@debian.org>

Package: openssh-client
Status: install ok installed
Priority: standard
Section: net
Installed-Size: 3079
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: openssh
Version: 1:8.9p1-3
Replaces: openssh-sk-helper, ssh, ssh-krb5
Provides: rsh-client, ssh-client
Depends: adduser (>= 3.10), dpkg (>= 1.7.0), passwd, libc6 (>= 2.34), libedit2 (>= 2.11-20080614-0), libfido2-1 (>= 1.8.0), libgssapi-krb5-2 (>= 1.17), libselinux1 (>= 3.1~), libssl3 (>= 3.0.1), zlib1g (>= 1:1.1.4)
Recommends: xauth
Suggests: keychain, libpam-ssh, monkeysphere, ssh-askpass
Breaks: openssh-sk-helper
Conflicts: sftp
Conffiles:
/etc/ssh/ssh_config 8a5bddc82befb71d8ef34cc903d3d077
Description: secure shell (SSH) client, for secure access to remote machines
This is the portable version of OpenSSH, a free implementation of
the Secure Shell protocol as specified by the IETF secsh working
group.
.
Ssh (Secure Shell) is a program for logging into a remote machine
and for executing commands on a remote machine.
It provides secure encrypted communications between two untrusted
hosts over an insecure network. X11 connections and arbitrary TCP/IP
ports can also be forwarded over the secure channel.
It can be used to provide applications with a secure communication
channel.
.
This package provides the ssh, scp and sftp clients, the ssh-agent
and ssh-add programs to make public key authentication more convenient,
and the ssh-keygen, ssh-keyscan, ssh-copy-id and ssh-argv0 utilities.
.
In some countries it may be illegal to use any encryption at all
without a special permit.
.
ssh replaces the insecure rsh, rcp and rlogin programs, which are
obsolete for most purposes.
Original-Maintainer: Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>
Homepage: http://www.openssh.com/

Package: openssh-server
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 1501
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: openssh
Version: 1:8.9p1-3
Replaces: openssh-client (<< 1:7.9p1-8), ssh, ssh-krb5
Provides: ssh-server
Depends: adduser (>= 3.9), dpkg (>= 1.9.0), libpam-modules (>= 0.72-9), libpam-runtime (>= 0.76-14), lsb-base (>= 4.1+Debian3), openssh-client (= 1:8.9p1-3), openssh-sftp-server, procps, ucf (>= 0.28), debconf (>= 0.5) | debconf-2.0, libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), libcom-err2 (>= 1.43.9), libcrypt1 (>= 1:4.1.0), libgssapi-krb5-2 (>= 1.17), libkrb5-3 (>= 1.13~alpha1+dfsg), libpam0g (>= 0.99.7.1), libselinux1 (>= 3.1~), libssl3 (>= 3.0.1), libsystemd0, libwrap0 (>= 7.6-4~), zlib1g (>= 1:1.1.4)
Pre-Depends: init-system-helpers (>= 1.54~)
Recommends: default-logind | logind | libpam-systemd, ncurses-term, xauth, ssh-import-id
Suggests: molly-guard, monkeysphere, ssh-askpass, ufw
Conflicts: sftp, ssh-socks, ssh2
Conffiles:
/etc/default/ssh 500e3cf069fe9a7b9936108eb9d9c035
/etc/init.d/ssh 3649a6fe8c18ad1d5245fd91737de507
/etc/pam.d/sshd 8b4c7a12b031424b2a9946881da59812
/etc/ssh/moduli e8fbe2dcefa45888cf7341d78d8258ce
/etc/ufw/applications.d/openssh-server 486b78d54b93cc9fdc950c1d52ff479e
Description: secure shell (SSH) server, for secure access from remote machines
This is the portable version of OpenSSH, a free implementation of
the Secure Shell protocol as specified by the IETF secsh working
group.
.
Ssh (Secure Shell) is a program for logging into a remote machine
and for executing commands on a remote machine.
It provides secure encrypted communications between two untrusted
hosts over an insecure network. X11 connections and arbitrary TCP/IP
ports can also be forwarded over the secure channel.
It can be used to provide applications with a secure communication
channel.
.
This package provides the sshd server.
.
In some countries it may be illegal to use any encryption at all
without a special permit.
.
sshd replaces the insecure rshd program, which is obsolete for most
purposes.
Original-Maintainer: Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>
Homepage: http://www.openssh.com/

Package: openssh-sftp-server
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 101
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: openssh
Version: 1:8.9p1-3
Replaces: openssh-server (<< 1:6.5p1-5)
Depends: openssh-client (= 1:8.9p1-3), libc6 (>= 2.34), libssl3 (>= 3.0.0~~alpha1)
Recommends: openssh-server | ssh-server
Breaks: openssh-server (<< 1:6.5p1-5)
Enhances: openssh-server, ssh-server
Description: secure shell (SSH) sftp server module, for SFTP access from remote machines
This is the portable version of OpenSSH, a free implementation of
the Secure Shell protocol as specified by the IETF secsh working
group.
.
Ssh (Secure Shell) is a program for logging into a remote machine
and for executing commands on a remote machine.
It provides secure encrypted communications between two untrusted
hosts over an insecure network. X11 connections and arbitrary TCP/IP
ports can also be forwarded over the secure channel.
It can be used to provide applications with a secure communication
channel.
.
This package provides the SFTP server module for the SSH server. It
is needed if you want to access your SSH server with SFTP. The SFTP
server module also works with other SSH daemons like dropbear.
.
OpenSSH's sftp and sftp-server implement revision 3 of the SSH filexfer
protocol described in:
.
http://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt
.
Newer versions of the draft will not be supported, though some features
are individually implemented as extensions.
Original-Maintainer: Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>
Homepage: http://www.openssh.com/

Package: openssl
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 2053
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 3.0.2-0ubuntu1.6
Depends: libc6 (>= 2.34), libssl3 (>= 3.0.2-0ubuntu1.2)
Suggests: ca-certificates
Conffiles:
/etc/ssl/openssl.cnf 6b4a72a4ce84bab35d884e536295e14f
Description: Secure Sockets Layer toolkit - cryptographic utility
This package is part of the OpenSSL project's implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
.
It contains the general-purpose command line binary /usr/bin/openssl,
useful for cryptographic operations such as:

- creating RSA, DH, and DSA key parameters;
- creating X.509 certificates, CSRs, and CRLs;
- calculating message digests;
- encrypting and decrypting with ciphers;
- testing SSL/TLS clients and servers;
- handling S/MIME signed or encrypted mail.
  Homepage: https://www.openssl.org/
  Original-Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>

Package: overlayroot
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 66
Maintainer: Scott Moser <smoser@ubuntu.com>
Architecture: all
Source: cloud-initramfs-tools
Version: 0.47ubuntu1
Depends: cryptsetup, cryptsetup-bin, initramfs-tools
Suggests: haveged
Conffiles:
/etc/overlayroot.conf 40086f3ab7223af23f79225c60b4d47d
/etc/update-motd.d/97-overlayroot 51a409ec9a8608f9c5fa3f6605c78dd9
Description: use an overlayfs on top of a read-only root filesystem
This package adds functionality to an initramfs built by initramfs-tools.
When installed and configured, the initramfs will mount an overlayfs
filesystem on top of a read-only root volume.
.
The changes can be written to a in-memory temporary filesystem, a
filesystem on an existing block device, or a dmcrypt encrypted block
device.
Homepage: http://launchpad.net/cloud-initramfs-tools

Package: packagekit
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 1592
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.2.5-2ubuntu2
Depends: libglib2.0-bin, policykit-1, init-system-helpers (>= 1.52), libappstream4 (>= 0.10.0), libapt-pkg6.0 (>= 1.9.2), libc6 (>= 2.34), libgcc-s1 (>= 3.3.1), libglib2.0-0 (>= 2.61.2), libgstreamer1.0-0 (>= 1.0.0), libpackagekit-glib2-18 (>= 1.2.4), libpolkit-gobject-1-0 (>= 0.99), libsqlite3-0 (>= 3.5.9), libstdc++6 (>= 11), libsystemd0 (>= 214)
Recommends: packagekit-tools, systemd
Suggests: appstream
Breaks: plymouth (<< 0.9.5)
Conffiles:
/etc/PackageKit/PackageKit.conf 71da11578968301072133d233e91cd1e
/etc/PackageKit/Vendor.conf ea3d03c3310b5470d0273659815c312d
/etc/apt/apt.conf.d/20packagekit f9751c0229fd14ae8d7b69de0645f7b3
/etc/dbus-1/system.d/org.freedesktop.PackageKit.conf fded44ee0c8edb7e65b9649570db3574
Description: Provides a package management service
PackageKit allows performing simple software management tasks over a DBus
interface e.g. refreshing the cache, updating, installing and removing
software packages or searching for multimedia codecs and file handlers.
.
The work is done by backends which make use of the package manager shipped by
the corresponding distribution. PackageKit is not meant to replace
advanced tools like Synaptic.
.
The main benefits are:

- unified interface on several distributions
- fine grained privileges by using PolicyKit
- independency from a running desktop session during the processing
  Homepage: https://www.freedesktop.org/software/PackageKit/
  Original-Maintainer: Matthias Klumpp <mak@debian.org>

Package: packagekit-tools
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 123
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: packagekit
Version: 1.2.5-2ubuntu2
Depends: packagekit (= 1.2.5-2ubuntu2), libc6 (>= 2.34), libglib2.0-0 (>= 2.54), libpackagekit-glib2-18 (>= 1.2.5)
Description: Provides PackageKit command-line tools
PackageKit allows performing simple software management tasks over a DBus
interface e.g. refreshing the cache, updating, installing and removing
software packages or searching for multimedia codecs and file handlers.
.
This package provides the PackageKit command-line tools.
Homepage: https://www.freedesktop.org/software/PackageKit/
Original-Maintainer: Matthias Klumpp <mak@debian.org>

Package: parted
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 167
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 3.4-2build1
Depends: libc6 (>= 2.34), libparted2 (= 3.4-2build1), libreadline8 (>= 6.0), libtinfo6 (>= 6)
Suggests: parted-doc
Description: disk partition manipulator
GNU Parted is a program that allows you to create, destroy, resize,
move, and copy disk partitions. This is useful for creating space
for new operating systems, reorganizing disk usage, and copying data
to new hard disks.
.
This package contains the binary and manual page. Further
documentation is available in parted-doc.
.
Parted currently supports DOS, Mac, Sun, BSD, GPT, MIPS, and PC98
partitioning formats, as well as a "loop" (raw disk) type which
allows use on RAID/LVM. It can detect and remove ASFS/AFFS/APFS,
Btrfs, ext2/3/4, FAT16/32, HFS, JFS, linux-swap, UFS, XFS, and ZFS
file systems. Parted also has the ability to create and modify file
systems of some of these types, but using it to perform file system
operations is now deprecated.
.
The nature of this software means that any bugs could cause massive
data loss. While there are no such bugs known at the moment, they
could exist, so please back up all important files before running
it, and do so at your own risk.
Homepage: https://www.gnu.org/software/parted
Original-Maintainer: Parted Maintainer Team <parted-maintainers@alioth-lists.debian.net>

Package: passwd
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 2321
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: shadow
Version: 1:4.8.1-2ubuntu2
Depends: libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libpam0g (>= 0.99.7.1), libselinux1 (>= 3.1~), libsemanage2 (>= 2.0.3), libpam-modules
Recommends: sensible-utils
Conffiles:
/etc/default/useradd 559e87e86a6d1cb4b7f60a6f691d5150
/etc/pam.d/chfn 4d466e00a348ba426130664d795e8afa
/etc/pam.d/chpasswd 9900720564cb4ee98b7da29e2d183cb2
/etc/pam.d/chsh a6e9b589e90009334ffd030d819290a6
/etc/pam.d/newusers 1454e29bfa9f2a10836563e76936cea5
/etc/pam.d/passwd eaf2ad85b5ccd06cceb19a3e75f40c63
Description: change and administer password and group data
This package includes passwd, chsh, chfn, and many other programs to
maintain password and group data.
.
Shadow passwords are supported. See /usr/share/doc/passwd/README.Debian
Homepage: https://github.com/shadow-maint/shadow
Original-Maintainer: Shadow package maintainers <pkg-shadow-devel@lists.alioth.debian.org>

Package: pastebinit
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 152
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 1.5.1-1ubuntu1
Replaces: bikeshed (<< 1.21)
Depends: python3, python3-distro
Breaks: bikeshed (<< 1.21)
Description: command-line pastebin client
pastebinit is a command-line tool to send data to a "pastebin", a web site
which allows its users to upload snippets of text for public viewing.
Homepage: https://phab.lubuntu.me/source/pastebinit/
Original-Maintainer: Simon Quigley <tsimonq2@debian.org>

Package: patch
Status: install ok installed
Priority: optional
Section: vcs
Installed-Size: 229
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.7.6-7build2
Depends: libc6 (>= 2.34)
Suggests: ed, diffutils-doc
Description: Apply a diff file to an original
Patch will take a patch file containing any of the four forms
of difference listing produced by the diff program and apply
those differences to an original file, producing a patched
version.
Homepage: https://savannah.gnu.org/projects/patch/
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>

Package: pci.ids
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 1282
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.0~2022.01.22-1
Replaces: pciutils (<< 1:3.6.2-4~)
Breaks: pciutils (<< 1:3.6.2-4~)
Description: PCI ID Repository
This package contains the pci.ids file, a public repository of all known
ID's used in PCI devices: ID's of vendors, devices, subsystems and device
classes. It is used in various programs to display full human-readable
names instead of cryptic numeric codes.
Original-Maintainer: Guillem Jover <guillem@debian.org>
Homepage: https://pci-ids.ucw.cz/

Package: pciutils
Status: install ok installed
Priority: standard
Section: admin
Installed-Size: 172
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1:3.7.0-6
Depends: libc6 (>= 2.34), libkmod2 (>= 5~), libpci3 (= 1:3.7.0-6)
Suggests: bzip2, wget | curl | lynx-cur
Description: PCI utilities
This package contains various utilities for inspecting and setting of
devices connected to the PCI bus.
Original-Maintainer: Guillem Jover <guillem@debian.org>
Homepage: https://mj.ucw.cz/sw/pciutils/

Package: perl
Status: install ok installed
Priority: standard
Section: perl
Installed-Size: 717
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Version: 5.34.0-3ubuntu1
Replaces: perl-base (<< 5.34.0-2), perl-modules (<< 5.22.0~)
Provides: libansicolor-perl (= 5.01), libarchive-tar-perl (= 2.38), libattribute-handlers-perl (= 1.01), libautodie-perl (= 2.34), libcompress-raw-bzip2-perl (= 2.101), libcompress-raw-zlib-perl (= 2.101), libcompress-zlib-perl (= 2.102), libcpan-meta-perl (= 2.150010), libcpan-meta-requirements-perl (= 2.140), libcpan-meta-yaml-perl (= 0.018), libdigest-md5-perl (= 2.58), libdigest-perl (= 1.19), libdigest-sha-perl (= 6.02), libencode-perl (= 3.08), libexperimental-perl (= 0.024), libextutils-cbuilder-perl (= 0.280236), libextutils-command-perl (= 7.62), libextutils-install-perl (= 2.20), libextutils-parsexs-perl (= 3.430000), libfile-spec-perl (= 3.8000), libhttp-tiny-perl (= 0.076), libi18n-langtags-perl (= 0.45), libio-compress-base-perl (= 2.102), libio-compress-bzip2-perl (= 2.102), libio-compress-perl (= 2.102), libio-compress-zlib-perl (= 2.102), libio-zlib-perl (= 1.11), libjson-pp-perl (= 4.06000), liblocale-maketext-perl (= 1.29), liblocale-maketext-simple-perl (= 0.21.01), libmath-bigint-perl (= 1.999818), libmath-complex-perl (= 1.5902), libmime-base64-perl (= 3.16), libmodule-corelist-perl (= 5.20210520), libmodule-load-conditional-perl (= 0.74), libmodule-load-perl (= 0.36), libmodule-metadata-perl (= 1.000037), libnet-perl (= 1:3.13), libnet-ping-perl (= 2.74), libparams-check-perl (= 0.38), libparent-perl (= 0.238), libparse-cpan-meta-perl (= 2.150010), libperl-ostype-perl (= 1.010), libpod-escapes-perl (= 1.07), libpod-simple-perl (= 3.42), libstorable-perl (= 3.23), libsys-syslog-perl (= 0.36), libtest-harness-perl (= 3.43), libtest-simple-perl (= 1.302183), libtest-tester-perl (= 1.302183), libtest-use-ok-perl (= 1.302183), libthread-queue-perl (= 3.14), libthreads-perl (= 2.26), libthreads-shared-perl (= 1.62), libtime-hires-perl (= 1.9767), libtime-local-perl (= 1.3000), libtime-piece-perl (= 1.3401), libunicode-collate-perl (= 1.29), libversion-perl (= 1:0.9928), libversion-requirements-perl, podlators-perl (= 4.14)
Depends: perl-base (= 5.34.0-3ubuntu1), perl-modules-5.34 (>= 5.34.0-3ubuntu1), libperl5.34 (= 5.34.0-3ubuntu1)
Pre-Depends: dpkg (>= 1.17.17)
Recommends: netbase
Suggests: perl-doc, libterm-readline-gnu-perl | libterm-readline-perl-perl, make, libtap-harness-archive-perl
Breaks: apt-show-versions (<< 0.22.10), libdist-inkt-perl (<< 0.024-5), libmarc-charset-perl (<< 1.35-3), libperl-dev (<< 5.24.0~), perl-doc (<< 5.34.0-1), perl-modules-5.22, perl-modules-5.24, perl-modules-5.26 (<< 5.26.2-5)
Conflicts: libjson-pp-perl (<< 2.27200-2)
Conffiles:
/etc/perl/Net/libnet.cfg fb2946cae573b8ed3d654a180d458733
Description: Larry Wall's Practical Extraction and Report Language
Perl is a highly capable, feature-rich programming language with over
20 years of development. Perl 5 runs on over 100 platforms from
portables to mainframes. Perl is suitable for both rapid prototyping
and large scale development projects.
.
Perl 5 supports many programming styles, including procedural,
functional, and object-oriented. In addition to this, it is supported
by an ever-growing collection of reusable modules which accelerate
development. Some of these modules include Web frameworks, database
integration, networking protocols, and encryption. Perl provides
interfaces to C and C++ for custom extension development.
Homepage: http://dev.perl.org/perl5/
Original-Maintainer: Niko Tyni <ntyni@debian.org>

Package: perl-base
Essential: yes
Status: install ok installed
Priority: required
Section: perl
Installed-Size: 7775
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: perl
Version: 5.34.0-3ubuntu1
Replaces: libfile-path-perl (<< 2.18), libfile-temp-perl (<< 0.2311), libio-socket-ip-perl (<< 0.41), libscalar-list-utils-perl (<< 1:1.55), libsocket-perl (<< 2.031), libxsloader-perl (<< 0.30), perl (<< 5.10.1-12), perl-modules (<< 5.20.1-3)
Provides: libfile-path-perl (= 2.18), libfile-temp-perl (= 0.2311), libio-socket-ip-perl (= 0.41), libscalar-list-utils-perl (= 1:1.55), libsocket-perl (= 2.031), libxsloader-perl (= 0.30), perlapi-5.34.0
Pre-Depends: libc6 (>= 2.35), libcrypt1 (>= 1:4.1.0), dpkg (>= 1.17.17)
Suggests: perl, sensible-utils
Breaks: amanda-common (<< 1:3.3.9-2), backuppc (<< 3.3.1-2), bucardo (<< 5.5.0-1.1), debconf (<< 1.5.61), dh-haskell (<< 0.3), intltool (<< 0.51.0-4), kio-perldoc (<< 20.04.1-1), latexml (<< 0.8.4-2), libdevel-mat-dumper-perl (<< 0.42-3), libencode-arabic-perl (<< 14.2-2), libexception-class-perl (<< 1.42), libfile-path-perl (<< 2.18), libfile-spec-perl (<< 3.8000), libfile-temp-perl (<< 0.2311), libio-socket-ip-perl (<< 0.41), libmp3-tag-perl (<< 1.13-1.2), libsbuild-perl (<< 0.67.0-1), libscalar-list-utils-perl (<< 1:1.55), libsocket-perl (<< 2.031), libxsloader-perl (<< 0.30), mailagent (<< 1:3.1-81-2), perl (<< 5.34.0~), perl-modules (<< 5.34.0~), pod2pdf (<< 0.42-5.1), slic3r (<< 1.2.9+dfsg-6.1), slic3r-prusa (<< 1.37.0+dfsg-1.1), texinfo (<< 6.1.0.dfsg.1-8)
Conflicts: defoma (<< 0.11.12), doc-base (<< 0.10.3), mono-gac (<< 2.10.8.1-3), safe-rm (<< 0.8), update-inetd (<< 4.41)
Description: minimal Perl system
Perl is a scripting language used in many system scripts and utilities.
.
This package provides a Perl interpreter and the small subset of the
standard run-time library required to perform basic tasks. For a full
Perl installation, install "perl" (and its dependencies, "perl-modules-5.34"
and "perl-doc").
Homepage: http://dev.perl.org/perl5/
Original-Maintainer: Niko Tyni <ntyni@debian.org>

Package: perl-modules-5.34
Status: install ok installed
Priority: standard
Section: libs
Installed-Size: 17668
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: perl
Version: 5.34.0-3ubuntu1
Replaces: libansicolor-perl (<< 5.01), libarchive-tar-perl (<< 2.38), libattribute-handlers-perl (<< 1.01), libautodie-perl (<< 2.34), libcpan-meta-perl (<< 2.150010), libcpan-meta-requirements-perl (<< 2.140), libcpan-meta-yaml-perl (<< 0.018), libdigest-perl (<< 1.19), libexperimental-perl (<< 0.024), libextutils-cbuilder-perl (<< 0.280236), libextutils-command-perl (<< 7.62), libextutils-install-perl (<< 2.20), libextutils-parsexs-perl (<< 3.430000), libfile-spec-perl (<< 3.8000), libhttp-tiny-perl (<< 0.076), libi18n-langtags-perl (<< 0.45), libio-zlib-perl (<< 1.11), libjson-pp-perl (<< 4.06000), liblocale-maketext-perl (<< 1.29), liblocale-maketext-simple-perl (<< 0.21.01), libmath-bigint-perl (<< 1.999818), libmath-complex-perl (<< 1.5902), libmodule-corelist-perl (<< 5.20210520), libmodule-load-conditional-perl (<< 0.74), libmodule-load-perl (<< 0.36), libmodule-metadata-perl (<< 1.000037), libnet-perl (<< 1:3.13), libnet-ping-perl (<< 2.74), libparams-check-perl (<< 0.38), libparent-perl (<< 0.238), libparse-cpan-meta-perl (<< 2.150010), libperl-ostype-perl (<< 1.010), libpod-escapes-perl (<< 1.07), libpod-simple-perl (<< 3.42), libtest-harness-perl (<< 3.43), libtest-simple-perl (<< 1.302183), libtest-tester-perl (<< 1.302183), libtest-use-ok-perl (<< 1.302183), libthread-queue-perl (<< 3.14), libtime-local-perl (<< 1.3000), libunicode-collate-perl (<< 1.29), libversion-perl (<< 1:0.9928), perl-base (<< 5.22.0~), perl-modules, podlators-perl (<< 4.14)
Provides: perl-modules
Depends: perl-base (>= 5.34.0-1)
Pre-Depends: dpkg (>= 1.17.17)
Recommends: perl (>= 5.34.0-1)
Breaks: libansicolor-perl (<< 5.01), libarchive-tar-perl (<< 2.38), libattribute-handlers-perl (<< 1.01), libautodie-perl (<< 2.34), libcpan-meta-perl (<< 2.150010), libcpan-meta-requirements-perl (<< 2.140), libcpan-meta-yaml-perl (<< 0.018), libdigest-perl (<< 1.19), libexperimental-perl (<< 0.024), libextutils-cbuilder-perl (<< 0.280236), libextutils-command-perl (<< 7.62), libextutils-install-perl (<< 2.20), libextutils-parsexs-perl (<< 3.430000), libfile-spec-perl (<< 3.8000), libhttp-tiny-perl (<< 0.076), libi18n-langtags-perl (<< 0.45), libio-zlib-perl (<< 1.11), libjson-pp-perl (<< 4.06000), liblocale-maketext-perl (<< 1.29), liblocale-maketext-simple-perl (<< 0.21.01), libmath-bigint-perl (<< 1.999818), libmath-complex-perl (<< 1.5902), libmodule-corelist-perl (<< 5.20210520), libmodule-load-conditional-perl (<< 0.74), libmodule-load-perl (<< 0.36), libmodule-metadata-perl (<< 1.000037), libnet-perl (<< 1:3.13), libnet-ping-perl (<< 2.74), libparams-check-perl (<< 0.38), libparent-perl (<< 0.238), libparse-cpan-meta-perl (<< 2.150010), libperl-ostype-perl (<< 1.010), libpod-escapes-perl (<< 1.07), libpod-simple-perl (<< 3.42), libtest-harness-perl (<< 3.43), libtest-simple-perl (<< 1.302183), libtest-tester-perl (<< 1.302183), libtest-use-ok-perl (<< 1.302183), libthread-queue-perl (<< 3.14), libtime-local-perl (<< 1.3000), libunicode-collate-perl (<< 1.29), libversion-perl (<< 1:0.9928), maildirsync (<< 1.2-2.1), perl (<< 5.34.0~), podlators-perl (<< 4.14)
Conflicts: perl-modules (<< 5.22.0~)
Description: Core Perl modules
Architecture independent Perl modules. These modules are part of Perl and
required if the `perl' package is installed. . Note that this package only exists to save archive space and should be considered an internal implementation detail of the `perl' package.
Other packages should not depend on `perl-modules-5.34' directly, they should use `perl' (which depends on `perl-modules-5.34') instead.
Homepage: http://dev.perl.org/perl5/
Original-Maintainer: Niko Tyni <ntyni@debian.org>

Package: perl-openssl-defaults
Status: install ok installed
Priority: optional
Section: perl
Installed-Size: 27
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Version: 5build2
Provides: dh-sequence-perl-openssl, perl-openssl-abi-3
Depends: libc6 (>= 2.34), libssl3 (>= 3.0.0~~alpha1)
Breaks: libcrypt-openssl-bignum-perl (<< 0.07-2), libcrypt-openssl-dsa-perl (<< 0.18-2), libcrypt-openssl-pkcs10-perl (<< 0.16-2), libcrypt-openssl-pkcs12-perl (<< 0.7-3), libcrypt-openssl-rsa-perl (<< 0.28-5), libcrypt-openssl-x509-perl (<< 1.8.7-3), libcrypt-smime-perl (<< 0.19-2), libcrypt-ssleay-perl (<< 0.73.04-2), libnet-ssleay-perl (<< 1.78-2)
Description: version compatibility baseline for Perl OpenSSL packages
A subset of Perl XS module packages expose the OpenSSL binary interface
to Perl code. This can lead to incompatibilities if these packages are
linked against different versions of OpenSSL.
.
This package provides a virtual package "perl-openssl-abi-x" that
corresponds to the libssl-dev package SONAME it was built against.
The packages that need to stay compatible with each other can depend
on this.
.
Tools are also provided for generating this dependency with minimum
hassle. See the instructions in README.Debian.
Original-Maintainer: Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>

Package: pinentry-curses
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 92
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: pinentry
Version: 1.1.1-1build2
Provides: pinentry
Depends: libassuan0 (>= 2.1.0), libc6 (>= 2.34), libgpg-error0 (>= 1.16), libncursesw6 (>= 6), libtinfo6 (>= 6)
Suggests: pinentry-doc
Enhances: gnupg-agent
Description: curses-based PIN or pass-phrase entry dialog for GnuPG
This package contains a program that allows for secure entry of PINs or
pass phrases. That means it tries to take care that the entered
information is not swapped to disk or temporarily stored anywhere.
This functionality is particularly useful for entering pass phrases
when using encryption software such as GnuPG or e-mail clients using
the same. It uses an open protocol and is therefore not tied to
particular software.
.
The program contained in this package implements a PIN entry dialog
using the curses tool kit, meaning that it is useful for users
working in text mode without the X Window System. There are sibling
packages that implement PIN entry dialogs that use an X tool kit. If
you install any of the graphical packages then this package is not
necessary because the sibling packages automatically fall back to
text mode if X is not active.
Homepage: https://www.gnupg.org/related_software/pinentry/
Original-Maintainer: Debian GnuPG Maintainers <pkg-gnupg-maint@lists.alioth.debian.org>

Package: pkexec
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 65
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: policykit-1
Version: 0.105-33
Replaces: policykit-1 (<< 0.105-32~)
Depends: polkitd (= 0.105-33), libc6 (>= 2.34), libglib2.0-0 (>= 2.35.9), libpam0g (>= 0.99.7.1), libpolkit-agent-1-0 (= 0.105-33), libpolkit-gobject-1-0 (= 0.105-33)
Breaks: policykit-1 (<< 0.105-32~)
Description: run commands as another user with polkit authorization
polkit is an application-level toolkit for defining and handling the policy
that allows unprivileged processes to speak to privileged processes.
It was previously named PolicyKit.
.
pkexec is a setuid program to allow certain users to run commands as
root or as a different user, similar to sudo. Unlike sudo, it carries
out authentication and authorization by sending a request to polkit,
so it uses desktop environments' familiar prompting mechanisms for
authentication and uses polkit policies for authorization decisions.
.
By default, members of the 'sudo' Unix group can use pkexec to run any
command after authenticating. The authorization rules can be changed by
the local system administrator.
.
If this functionality is not required, removing the pkexec package will
reduce security risk by removing a setuid program.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://www.freedesktop.org/wiki/Software/polkit/

Package: plymouth
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 924
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.9.5+git20211018-1ubuntu3
Replaces: plymouth-drm (<< 0.9.0-6~), plymouth-themes (<< 0.9.0-8~)
Depends: init-system-helpers (>= 1.18), lsb-base (>= 3.0-6), systemd (>= 232-8~), udev (>= 232-8~), libc6 (>= 2.34), libdrm2 (>= 2.4.47), libplymouth5 (>= 0.9.5+git20211018-1ubuntu3)
Recommends: plymouth-theme-ubuntu-text | plymouth-theme
Suggests: desktop-base, plymouth-themes
Breaks: plymouth-drm (<< 0.9.0-6~), plymouth-themes (<< 0.9.0-8~)
Conflicts: console-common
Conffiles:
/etc/init.d/plymouth 707674e3b5b8fa048271dfe2490a0a09
/etc/init.d/plymouth-log 83b6676117e0e9b3f952e0fc625892ac
/etc/logrotate.d/bootlog 0f1e42d11052c238718996029ffb809b
Description: boot animation, logger and I/O multiplexer
Plymouth provides a boot-time I/O multiplexing framework - the most obvious
use for which is to provide an attractive graphical animation in place of
the text messages that normally get shown during boot. (The messages are
instead redirected to a logfile for later viewing.) However, in event-driven
boot systems Plymouth can also usefully handle user interaction such as
password prompts for encrypted file systems.
.
This package provides the basic framework, enabling a text-mode animation.
Homepage: http://www.freedesktop.org/wiki/Software/Plymouth
Original-Maintainer: Laurent Bigonville <bigon@debian.org>

Package: plymouth-theme-ubuntu-text
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 82
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: plymouth
Version: 0.9.5+git20211018-1ubuntu3
Provides: plymouth-theme
Depends: libc6 (>= 2.17), libplymouth5 (>= 0.9.2), plymouth (= 0.9.5+git20211018-1ubuntu3), lsb-release
Description: boot animation, logger and I/O multiplexer - ubuntu text theme
Plymouth provides a boot-time I/O multiplexing framework - the most obvious
use for which is to provide an attractive graphical animation in place of
the text messages that normally get shown during boot. (The messages are
instead redirected to a logfile for later viewing.) However, in event-driven
boot systems Plymouth can also usefully handle user interaction such as
password prompts for encrypted file systems.
.
This package contains the default ubuntu-text text theme used when no
support for a graphical theme is found on your system.
Homepage: http://www.freedesktop.org/wiki/Software/Plymouth
Original-Maintainer: Laurent Bigonville <bigon@debian.org>

Package: policykit-1
Status: install ok installed
Priority: optional
Section: oldlibs
Installed-Size: 29
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 0.105-33
Depends: pkexec (= 0.105-33), polkitd (= 0.105-33)
Description: transitional package for polkitd and pkexec
polkit is an application-level toolkit for defining and handling the policy
that allows unprivileged processes to speak to privileged processes.
It was previously named PolicyKit.
.
This transitional package depends on polkitd, the system service used by
polkit, and pkexec, a setuid program analogous to sudo. They were
historically packaged together, but have been separated so that users of
polkitd are not required to install pkexec.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://www.freedesktop.org/wiki/Software/polkit/

Package: polkitd
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 520
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: policykit-1
Version: 0.105-33
Replaces: policykit-1 (<< 0.105-32~)
Provides: polkitd-pkla (= 0.105-33)
Depends: dbus, default-logind | logind, libc6 (>= 2.34), libexpat1 (>= 2.0.1), libglib2.0-0 (>= 2.37.3), libpam0g (>= 0.99.7.1), libpolkit-agent-1-0 (= 0.105-33), libpolkit-gobject-1-0 (= 0.105-33), libsystemd0 (>= 213)
Breaks: policykit-1 (<< 0.105-32~)
Conffiles:
/etc/pam.d/polkit-1 7c794427f656539b0d4659b030904fe0
/etc/polkit-1/localauthority.conf.d/50-localauthority.conf 2adb9d174807b0a3521fabf03792fbc8
/etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf c4dbd2117c52f367f1e8b8c229686b10
Description: framework for managing administrative policies and privileges
PolicyKit is an application-level toolkit for defining and handling the policy
that allows unprivileged processes to speak to privileged processes.
.
It is a framework for centralizing the decision making process with respect to
granting access to privileged operations for unprivileged (desktop)
applications.
.
In a typical use of polkit, an unprivileged application such as gnome-disks
sends requests via D-Bus or other inter-process communication mechanisms
to a privileged system service such as udisks, which asks polkitd for
permission to process those requests. This allows the application to carry
out privileged tasks without making use of setuid, which avoids several
common sources of security vulnerabilities.
.
This package provides the polkitd D-Bus service and supporting programs.
The pkexec program is not included, and can be found in the pkexec package.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://www.freedesktop.org/wiki/Software/polkit/

Package: pollinate
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 92
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 4.33-3ubuntu2
Replaces: pollen (<< 4.21-1)
Depends: curl, adduser, xxd | vim-common
Breaks: pollen (<< 4.21-1)
Conffiles:
/etc/default/pollinate a9f810379e139b53608f090ebd954954
/etc/pollinate/entropy.ubuntu.com.pem 9f437b2251c81f7ddf7624ac761ba249
Description: seed the pseudo random number generator
This client will connect to one or more Pollen (entropy-as-a-service)
servers over an (optionally) encrypted connection and retrieve a random
seed over HTTP or HTTPS.
This is particularly useful at the first boot of cloud images and in
virtual machines, to seed a system's random number generator at
genesis, and is intended to supplement the /etc/init.d/urandom init script.
It can be used on physical machines, as well, to supplement the seeding
of the pseudo random number generator.
Homepage: http://launchpad.net/pollinate
Original-Maintainer: Thorsten Alteholz <debian@alteholz.de>

Package: powermgmt-base
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 25
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.36
Description: common utils for power management
This package ships "on_ac_power" which lets you determine whether
the system is powered from battery or an abundant supply. It's
recommended to use this tool over a simple sysfs check,
ConditionACPower or other ad-hoc methods which notoriously fail to
account for unobvious quirks, both old and new.
Original-Maintainer: Adam Borowski <kilobyte@angband.pl>

Package: procps
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 1388
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2:3.3.17-6ubuntu2
Replaces: manpages-de (<< 4.9.1-2), manpages-fr (<< 4.9.1-2), manpages-fr-extra (<< 20151231+nmu1), manpages-pl (<< 1:4.9.1-2)
Provides: watch
Depends: libc6 (>= 2.34), libncurses6 (>= 6), libncursesw6 (>= 6), libprocps8 (>= 2:3.3.16-1), libtinfo6 (>= 6), lsb-base (>= 3.0-10), init-system-helpers (>= 1.29~)
Recommends: psmisc
Breaks: guymager (<= 0.5.9-1), manpages-de (<< 4.9.1-2), manpages-fr (<< 4.9.1-2), manpages-fr-extra (<< 20151231+nmu1), manpages-pl (<< 1:4.9.1-2), open-vm-tools (<= 2011.12.20-562307-1)
Conffiles:
/etc/init.d/procps f9903aa0d9f2f10714269befb4cdba8f
/etc/sysctl.conf c0c09cba30da0565737cace8000d64ee
/etc/sysctl.d/10-console-messages.conf 154f6f5c5810d10bb303fb6a8e907c6a
/etc/sysctl.d/10-ipv6-privacy.conf e9473d12b4a7069d6a3ca8b694511ddf
/etc/sysctl.d/10-kernel-hardening.conf f85fded186d1ad70c5f69ca6a88e4de6
/etc/sysctl.d/10-magic-sysrq.conf b3059f2835f17c97265433fdfdee358f
/etc/sysctl.d/10-network-security.conf e2c60d912410543907a6c9ff21836ba8
/etc/sysctl.d/10-ptrace.conf 47f40494b2fc698e15549e0a4a79e81c
/etc/sysctl.d/10-zeropage.conf 8d7193abcc4dfedaf519dd03016a5e59
/etc/sysctl.d/README.sysctl 48e64ce233c8aba8e0693adf8cf4c464
Description: /proc file system utilities
This package provides command line and full screen utilities for browsing
procfs, a "pseudo" file system dynamically generated by the kernel to
provide information about the status of entries in its process table
(such as whether the process is running, stopped, or a "zombie").
.
It contains free, kill, pkill, pgrep, pmap, ps, pwdx, skill, slabtop,
snice, sysctl, tload, top, uptime, vmstat, w, and watch.
Homepage: https://gitlab.com/procps-ng/procps
Original-Maintainer: Craig Small <csmall@debian.org>

Package: psmisc
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 452
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 23.4-2build3
Replaces: manpages-de (<< 4.9.1-1)
Depends: libc6 (>= 2.34), libtinfo6 (>= 6)
Breaks: manpages-de (<< 4.9.1-1)
Description: utilities that use the proc file system
This package contains miscellaneous utilities that use the proc FS:
.

- fuser: identifies processes that are using files or sockets.
- killall: kills processes by name (e.g. "killall -HUP named").
- peekfd: shows the data traveling over a file descriptor.
- pstree: shows currently running processes as a tree.
- prtstat: print the contents of /proc/<pid>/stat
  Homepage: http://psmisc.sf.net/
  Original-Maintainer: Craig Small <csmall@debian.org>

Package: publicsuffix
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 330
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 20211207.1025-1
Provides: publicsuffix-dafsa
Description: accurate, machine-readable list of domain name suffixes
A machine-readable list of domain name suffixes that accept public
registration. Each suffix represents the part of a domain name which
is not under the control of the individual registrant, which makes
the list useful for grouping cookies, deciding same-origin policies,
collating spam, and other activities.
Original-Maintainer: Daniel Kahn Gillmor <dkg@fifthhorseman.net>
Homepage: https://publicsuffix.org

Package: python-apt-common
Status: install ok installed
Priority: important
Section: python
Installed-Size: 188
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: python-apt
Version: 2.3.0ubuntu2.1
Replaces: python-apt (<< 0.7.98+nmu1)
Breaks: python-apt (<< 0.7.98+nmu1)
Enhances: python-apt, python3-apt
Description: Python interface to libapt-pkg (locales)
The apt_pkg Python interface will provide full access to the internal
libapt-pkg structures allowing Python programs to easily perform a
variety of functions.
.
This package contains locales.
Original-Maintainer: APT Development Team <deity@lists.debian.org>

Package: python-babel-localedata
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 26407
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-babel
Version: 2.8.0+dfsg.1-7
Description: tools for internationalizing Python applications - locale data files
Babel is composed of two major parts. First tools to build and work with
gettext message catalogs. Second a Python interface to the CLDR (Common
Locale Data Repository), providing access to various locale display
names, localized number and date formatting, etc.
.
This package contains the locale data files used by both python-babel and
python3-babel.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: http://babel.pocoo.org/

Package: python3
Status: install ok installed
Priority: important
Section: python
Installed-Size: 90
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: python3-defaults
Version: 3.10.4-0ubuntu2
Replaces: python3-minimal (<< 3.1.2-2)
Provides: python3-profiler
Depends: python3.10 (>= 3.10.4-1~), libpython3-stdlib (= 3.10.4-0ubuntu2)
Pre-Depends: python3-minimal (= 3.10.4-0ubuntu2)
Suggests: python3-doc (>= 3.10.4-0ubuntu2), python3-tk (>= 3.9.10-2~), python3-venv (>= 3.10.4-0ubuntu2)
Description: interactive high-level object-oriented language (default python3 version)
Python, the high-level, interactive object oriented language,
includes an extensive class library with lots of goodies for
network programming, system administration, sounds and graphics.
.
This package is a dependency package, which depends on Debian's default
Python 3 version (currently v3.10).
Homepage: https://www.python.org/
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: python3-apport
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 594
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: apport
Version: 2.20.11-0ubuntu82.1
Depends: python3:any (>= 3.0~), python3-apt (>= 0.7.9), python3-httplib2, python3-problem-report (>= 0.94), lsb-release, python3-launchpadlib, python3-yaml
Recommends: apport
Description: Python 3 library for Apport crash report handling
This Python package provides high-level functions for creating and
handling apport crash reports:
.

- Query available and new reports.
- Add OS, packaging, and process runtime information to a report.
- Various frontend utility functions.
- Python hook to generate crash reports when Python scripts fail.
  Homepage: https://wiki.ubuntu.com/Apport

Package: python3-apt
Status: install ok installed
Priority: important
Section: python
Installed-Size: 705
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: python-apt
Version: 2.3.0ubuntu2.1
Replaces: python-apt (<< 0.7.98+nmu1)
Provides: python3.10-apt
Depends: python3 (<< 3.11), python3 (>= 3.10~), python3:any, libapt-pkg6.0 (>= 1.9.11~), libc6 (>= 2.33), libgcc-s1 (>= 3.3.1), libstdc++6 (>= 11), python-apt-common, distro-info-data
Recommends: lsb-release, iso-codes
Suggests: python3-apt-dbg, python-apt-doc, apt
Breaks: apt-xapian-index (<< 0.51~), kthresher (<= 1.4.0-1), python-apt (<< 0.7.98+nmu1)
Description: Python 3 interface to libapt-pkg
The apt_pkg Python 3 interface will provide full access to the internal
libapt-pkg structures allowing Python 3 programs to easily perform a
variety of functions, such as:
.

- Access to the APT configuration system
- Access to the APT package information database
- Parsing of Debian package control files, and other files with a
  similar structure
  .
  The included 'aptsources' Python interface provides an abstraction of
  the sources.list configuration on the repository and the distro level.
  Original-Maintainer: APT Development Team <deity@lists.debian.org>

Package: python3-attr
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 207
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-attrs
Version: 21.2.0-1
Depends: python3:any
Suggests: python-attr-doc
Description: Attributes without boilerplate (Python 3)
attrs is an MIT-licensed Python package with class decorators that ease the
chores of implementing the most common attribute-related object protocols.
.
You just specify the attributes to work with and attrs gives you:

- a nice human-readable **repr**,
- a complete set of comparison methods,
- an initializer,
- and much more
  without writing dull boilerplate code again and again.
  .
  This package contains attrs packaged for Python 3.
  Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
  Homepage: https://attrs.readthedocs.org/

Package: python3-automat
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 141
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: automat
Version: 20.2.0-1
Depends: python3-attr, python3-six, python3:any
Description: Self-service finite-state machines for the programmer on the go
Automat is a library for concise, idiomatic Python expression of
finite-state automata (particularly deterministic finite-state
transducers).
Original-Maintainer: Debian Python Modules Team <python-modules-team@lists.alioth.debian.org>
Homepage: https://pypi.python.org/pypi/Automat

Package: python3-babel
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 418
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-babel
Version: 2.8.0+dfsg.1-7
Depends: python-babel-localedata (= 2.8.0+dfsg.1-7), python3-pkg-resources, python3-tz, python3:any
Description: tools for internationalizing Python applications - Python 3.x
Babel is composed of two major parts. First tools to build and work with
gettext message catalogs. Second a Python interface to the CLDR (Common
Locale Data Repository), providing access to various locale display
names, localized number and date formatting, etc.
.
This package provides the Python 3.x module.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: http://babel.pocoo.org/

Package: python3-bcrypt
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 90
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: python-bcrypt
Version: 3.2.0-1build1
Depends: python3 (>= 3~), python3-cffi-backend-api-min (<= 9729), python3-cffi-backend-api-max (>= 9729), python3-six (>= 1.4.1), python3:any, libc6 (>= 2.14)
Description: password hashing library for Python 3
bcrypt is a Python module which provides a password hashing method based on
the Blowfish password hashing algorithm, as described in
"A Future-Adaptable Password Scheme" by Niels Provos and David Mazieres:
http://static.usenix.org/events/usenix99/provos.html.
.
This package provides the bcrypt Python module for Python 3.x.
Homepage: https://github.com/pyca/bcrypt
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>

Package: python3-blinker
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 55
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: blinker
Version: 1.4+dfsg1-0.4
Depends: python3:any
Suggests: python-blinker-doc
Description: fast, simple object-to-object and broadcast signaling library
Blinker provides a fast dispatching system that allows any number of
interested parties to subscribe to events, or "signals".
.
Signal receivers can subscribe to specific senders or receive signals
sent by any sender.
.
This package contains the Python 3 version.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://pythonhosted.org/blinker/

Package: python3-certifi
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 324
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-certifi
Version: 2020.6.20-1
Depends: ca-certificates, python3:any
Description: root certificates for validating SSL certs and verifying TLS hosts (python3)
Certifi is a carefully curated collection of Root Certificates for
validating the trustworthiness of SSL certificates while verifying
the identity of TLS hosts. It has been extracted from the Requests
project.
.
The version of certifi in this Debian package is patched to return
the location of Debian-provided CA certificates, instead of those
packaged by upstream.
.
This is the python3 package.
Original-Maintainer: Sebastien Delafond <seb@debian.org>
Homepage: https://github.com/certifi/python-certifi

Package: python3-cffi-backend
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 218
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: python-cffi
Version: 1.15.0-1build2
Provides: python3-cffi-backend-api-9729, python3-cffi-backend-api-max (= 10495), python3-cffi-backend-api-min (= 9729)
Depends: python3 (<< 3.11), python3 (>= 3.10~), libc6 (>= 2.34), libffi8 (>= 3.4)
Description: Foreign Function Interface for Python 3 calling C code - runtime
Convenient and reliable way of calling C code from Python 3.
.
The aim of this project is to provide a convenient and reliable way of calling
C code from Python. It keeps Python logic in Python, and minimises the C
required. It is able to work at either the C API or ABI level, unlike most
other approaches, that only support the ABI level.
.
This package contains the runtime support for pre-built cffi modules.
Homepage: https://cffi.readthedocs.org/
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>

Package: python3-chardet
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 1068
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: chardet
Version: 4.0.0-1
Replaces: python-chardet (<< 3.0.4-6)
Depends: python3:any, python3-pkg-resources
Breaks: python-chardet (<< 3.0.4-6)
Description: universal character encoding detector for Python3
Chardet takes a sequence of bytes in an unknown character encoding, and
attempts to determine the encoding.
.
Supported encodings:

- ASCII, UTF-8, UTF-16 (2 variants), UTF-32 (4 variants)
- Big5, GB2312, EUC-TW, HZ-GB-2312, ISO-2022-CN (Traditional and Simplified
  Chinese)
- EUC-JP, SHIFT_JIS, ISO-2022-JP (Japanese)
- EUC-KR, ISO-2022-KR (Korean)
- KOI8-R, MacCyrillic, IBM855, IBM866, ISO-8859-5, windows-1251 (Cyrillic)
- ISO-8859-2, windows-1250 (Hungarian)
- ISO-8859-5, windows-1251 (Bulgarian)
- windows-1252 (English)
- ISO-8859-7, windows-1253 (Greek)
- ISO-8859-8, windows-1255 (Visual and Logical Hebrew)
- TIS-620 (Thai)
  .
  This library is a port of the auto-detection code in Mozilla.
  .
  This package contains the Python 3 version of the library.
  Original-Maintainer: Piotr Ożarowski <piotr@debian.org>
  Homepage: https://github.com/chardet/chardet

Package: python3-click
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 366
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-click
Version: 8.0.3-1
Depends: python3-colorama, python3-importlib-metadata | python3 (>> 3.8), python3:any
Breaks: python3-click-threading (<< 0.5.0)
Description: Wrapper around optparse for command line utilities - Python 3.x
Click is a Python package for creating beautiful command line interfaces
in a composable way with as little code as necessary. It's the "Command
Line Interface Creation Kit". It's highly configurable but comes with
sensible defaults out of the box.
.
It aims to make the process of writing command line tools quick and fun
while also preventing any frustration caused by the inability to implement
an intended CLI API.
.
This is the Python 3 compatible package.
Original-Maintainer: Sandro Tosi <morph@debian.org>
Homepage: https://github.com/pallets/click

Package: python3-colorama
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 91
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-colorama
Version: 0.4.4-1
Depends: python3:any (>= 3.6~)
Description: Cross-platform colored terminal text in Python - Python 3.x
Python-colorama provides a simple cross-platform API to print colored terminal
text from Python applications.
.
ANSI escape character sequences are commonly used to produce colored terminal
text on Unix. Colorama provides some shortcuts to generate these sequences.
.
This has the happy side-effect that existing applications or libraries which
already use ANSI sequences to produce colored output on Linux.
.
This package provides the module for Python 3.
Original-Maintainer: Gürkan Myczko <gurkan@phys.ethz.ch>
Homepage: https://github.com/tartley/colorama

Package: python3-commandnotfound
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 59
Maintainer: Michael Vogt <michael.vogt@ubuntu.com>
Architecture: all
Source: command-not-found
Version: 22.04.0
Replaces: command-not-found (<< 0.3ubuntu7)
Depends: lsb-release, python3-apt, python3-gdbm, python3:any
Description: Python 3 bindings for command-not-found.
This package will install the Python 3 library for command_not_found tool.
Original-Maintainer: Zygmunt Krynicki <zkrynicki@gmail.com>

Package: python3-configobj
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 160
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: configobj
Version: 5.0.6-5
Depends: python3-six, python3:any
Suggests: python-configobj-doc
Description: simple but powerful config file reader and writer for Python 3
ConfigObj is a simple but powerful config file reader and writer: an
ini file round tripper. Its main feature is that it is very easy to
use, with a straightforward programmer's interface and a simple
syntax for config files. It has lots of other features, though:
.

- Nested sections (subsections), to any level
- List values
- Multiple line values
- String interpolation (substitution)
- Integrated with a powerful validation system
  - including automatic type checking/conversion
  - and allowing default values
  - repeated sections
- All comments in the file are preserved
- The order of keys/sections is preserved
- Full Unicode support
- Powerful unrepr mode for storing/retrieving Python data-types
  .
  This is the Python 3 version of the package.
  Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
  Homepage: http://www.voidspace.org.uk/python/configobj.html

Package: python3-constantly
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 40
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: constantly
Version: 15.1.0-2
Depends: python3:any
Description: Symbolic constants in Python
A library that provides symbolic constant support. It includes
collections and constants with text, numeric, and bit flag
values.
.
Originally twisted.python.constants from the Twisted project.
.
This package provides the Python 3.x module.
Original-Maintainer: Debian Python Modules Team <python-modules-team@lists.alioth.debian.org>
Homepage: https://github.com/twisted/constantly

Package: python3-cryptography
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 1587
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: python-cryptography
Version: 3.4.8-1ubuntu2
Depends: python3 (>= 3~), python3-cffi-backend-api-min (<= 9729), python3-cffi-backend-api-max (>= 9729), python3:any, libc6 (>= 2.14), libssl3 (>= 3.0.0~~alpha1)
Suggests: python-cryptography-doc, python3-cryptography-vectors
Breaks: python3-openssl (<< 16.0.0)
Description: Python library exposing cryptographic recipes and primitives (Python 3)
The cryptography library is designed to be a "one-stop-shop" for
all your cryptographic needs in Python.
.
As an alternative to the libraries that came before it, cryptography
tries to address some of the issues with those libraries:

- Lack of PyPy and Python 3 support.
- Lack of maintenance.
- Use of poor implementations of algorithms (i.e. ones with known
  side-channel attacks).
- Lack of high level, "Cryptography for humans", APIs.
- Absence of algorithms such as AES-GCM.
- Poor introspectability, and thus poor testability.
- Extremely error prone APIs, and bad defaults.
  .
  This package contains the Python 3 version of cryptography.
  Homepage: https://cryptography.io/
  Original-Maintainer: Tristan Seligmann <mithrandi@debian.org>

Package: python3-dbus
Status: install ok installed
Priority: important
Section: python
Installed-Size: 417
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: dbus-python
Version: 1.2.18-3build1
Provides: python3.10-dbus
Depends: python3 (<< 3.11), python3 (>= 3.10~), python3:any, libc6 (>= 2.4), libdbus-1-3 (>= 1.9.14), libglib2.0-0 (>= 2.40)
Recommends: python3-gi
Suggests: python-dbus-doc
Description: simple interprocess messaging system (Python 3 interface)
D-Bus is a message bus, used for sending messages between applications.
Conceptually, it fits somewhere in between raw sockets and CORBA in
terms of complexity.
.
This package provides a Python 3 interface to D-Bus.
.
See the dbus description for more information about D-Bus in general.
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>
Homepage: https://www.freedesktop.org/wiki/Software/DBusBindings#Python

Package: python3-debconf
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: debconf
Version: 1.5.79ubuntu1
Replaces: debconf (<< 1.5.64)
Depends: debconf (= 1.5.79ubuntu1), python3:any
Breaks: debconf (<< 1.5.64)
Description: interact with debconf from Python 3
Debconf is a configuration management system for debian packages. Packages
use Debconf to ask questions when they are installed.
.
This package provides a debconf module to allow Python 3 programs to
interact with a debconf frontend.
Original-Maintainer: Debconf Developers <debconf-devel@lists.alioth.debian.org>

Package: python3-debian
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 552
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-debian
Version: 0.1.43ubuntu1
Depends: python3-chardet, zstd, python3:any
Recommends: python3-apt
Suggests: gpgv
Description: Python 3 modules to work with Debian-related data formats
This package provides Python 3 modules that abstract many formats of Debian
related files. Currently handled are:

- Debtags information (debian.debtags module)
- debian/changelog (debian.changelog module)
- Packages files, pdiffs (debian.debian_support module)
- Control files of single or multiple RFC822-style paragraphs, e.g.
  debian/control, .changes, .dsc, Packages, Sources, Release, etc.
  (debian.deb822 module)
- Raw .deb and .ar files, with (read-only) access to contained
  files and meta-information
  Homepage: https://salsa.debian.org/python-debian-team/python-debian
  Original-Maintainer: Debian python-debian Maintainers <pkg-python-debian-maint@lists.alioth.debian.org>

Package: python3-distro
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 77
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: python-distro
Version: 1.7.0-1
Depends: lsb-release, python3:any
Description: Linux OS platform information API
distro (for: Linux Distribution) provides information about the Linux
distribution it runs on, such as a reliable machine-readable ID, or version
information.
.
It is a renewed alternative implementation for Python's original
platform.linux_distribution function, but it also provides much more
functionality which isn't necessarily Python bound like a command-line
interface.
.
This is the Python 3 version of the library.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/python-distro/distro

Package: python3-distro-info
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 35
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: distro-info
Version: 1.1build1
Depends: distro-info-data (>= 0.46), python3:any
Description: information about distributions' releases (Python 3 module)
Information about all releases of Debian and Ubuntu.
.
This package contains a Python 3 module for parsing the data in
distro-info-data. There is also a command line interface in the distro-info
package.
Original-Maintainer: Benjamin Drung <bdrung@debian.org>

Package: python3-distupgrade
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 638
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: ubuntu-release-upgrader
Version: 1:22.04.13
Replaces: python3-update-manager (<< 1:0.165)
Depends: python3:any, python3-update-manager (>= 1:19.04.2~), python3-apt (>= 0.8.5~), python3-dbus, python3-distro-info, python3-yaml, gpgv, lsb-release, sensible-utils, procps
Breaks: python3-update-manager (<< 1:0.165)
Description: manage release upgrades
This is the DistUpgrade Python 3 module

Package: python3-distutils
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 675
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: python3-stdlib-extensions
Version: 3.10.4-0ubuntu1
Replaces: libpython3.6-stdlib (<< 3.6.4~rc1-2), libpython3.7-stdlib (<< 3.7.0~a3-2)
Provides: python3.10-distutils
Depends: python3:any (>= 3.10.1-0~), python3:any (<< 3.11), python3-lib2to3 (= 3.10.4-0ubuntu1)
Breaks: libpython3.10-stdlib (<< 3.10.0~b1), libpython3.6-stdlib (<< 3.6.5~rc1-3), libpython3.7-stdlib (<< 3.7.0~b2-2), libpython3.8-stdlib (<< 3.8.0~b2-5)
Description: distutils package for Python 3.x
Distutils package for Python 3.x. This package contains the distutils module
from the Python standard library.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: python3-gdbm
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 57
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: python3-stdlib-extensions
Version: 3.10.4-0ubuntu1
Provides: python3.10-gdbm
Depends: python3 (>= 3.10.1-0~), python3 (<< 3.11), libc6 (>= 2.4), libgdbm6 (>= 1.16)
Suggests: python3-gdbm-dbg
Description: GNU dbm database support for Python 3.x
GNU dbm database module for Python 3.x. Install this if you want to
create or read GNU dbm database files with Python.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: python3-gi
Status: install ok installed
Priority: important
Section: python
Installed-Size: 747
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: pygobject
Version: 3.42.1-0ubuntu1
Depends: gir1.2-glib-2.0 (>= 1.48.0), python3 (<< 3.11), python3 (>= 3.10~), python3:any, libc6 (>= 2.14), libffi8 (>= 3.4), libgirepository-1.0-1 (>= 1.62.0-4~), libgirepository-1.0-1-with-libffi8 (>= 1.62.0-4~), libglib2.0-0 (>= 2.56.0)
Description: Python 3 bindings for gobject-introspection libraries
GObject is an abstraction layer that allows programming with an object
paradigm that is compatible with many languages. It is a part of Glib,
the core library used to build GTK+ and GNOME.
.
This package contains the Python 3 binding generator for libraries that
support gobject-introspection, i. e. which ship a gir1.2-<name>-<version>
package. With these packages, the libraries can be used from Python 3.
Homepage: https://wiki.gnome.org/Projects/PyGObject
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: python3-hamcrest
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 166
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: pyhamcrest
Version: 2.0.2-2
Depends: python3:any
Description: Hamcrest framework for matcher objects (Python 3)
PyHamcrest is a framework for writing matcher objects, allowing you to
declaratively define "match" rules. There are a number of situations where
matchers are invaluable, such as UI validation, or data filtering, but it is in
the area of writing flexible tests that matchers are most commonly used. This
tutorial shows you how to use PyHamcrest for unit testing.
.
When writing tests it is sometimes difficult to get the balance right between
overspecifying the test (and making it brittle to changes), and not specifying
enough (making the test less valuable since it continues to pass even when the
thing being tested is broken). Having a tool that allows you to pick out
precisely the aspect under test and describe the values it should have, to a
controlled level of precision, helps greatly in writing tests that are
"just right." Such tests fail when the behavior of the aspect under test
deviates from the expected behavior, yet continue to pass when minor,
unrelated changes to the behaviour are made.
.
This package provides the Python 3.x modules.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: http://hamcrest.org/

Package: python3-httplib2
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 131
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-httplib2
Version: 0.20.2-2
Depends: ca-certificates, python3-pyparsing, python3:any
Breaks: python3-pysimplesoap (<< 1.16-2.1), python3-wsgi-intercept (<< 1.9.0)
Description: comprehensive HTTP client library written for Python3
httplib2.py supports many features left out of other HTTP libraries.

- HTTP and HTTPS
- Keep-Alive
- Authentication
- Caching
- All Methods
- Redirects
- Compression
- Lost update support
- Unit Tested
  .
  This package provides module for python3 series.
  Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
  Homepage: https://github.com/httplib2/httplib2

Package: python3-hyperlink
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 228
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: hyperlink
Version: 21.0.0-3
Depends: python3-idna (>= 2.5), python3:any
Description: Immutable, Pythonic, correct URLs.
Hyperlink provides a pure-Python implementation of immutable URLs. Based on
RFC 3986 and 3987, the Hyperlink URL makes working with both URIs and IRIs
easy.
.
This package provides the Python 3.x module.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/python-hyper/hyperlink

Package: python3-idna
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 299
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: python-idna
Version: 3.3-1
Depends: python3:any
Description: Python IDNA2008 (RFC 5891) handling (Python 3)
A library to support the Internationalised Domain Names in Applications (IDNA)
protocol as specified in RFC 5891. This version of the protocol is often
referred to as “IDNA2008” and can produce different results from the earlier
standard from 2003.
.
The library is also intended to act as a suitable drop-in replacement for the
“encodings.idna” module that comes with the Python standard library but
currently only supports the older 2003 specification.
.
This package contains the module for Python 3.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/kjd/idna

Package: python3-importlib-metadata
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 67
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-importlib-metadata
Version: 4.6.4-1
Depends: python3-zipp (>= 0.5), python3:any
Description: library to access the metadata for a Python package - Python 3.x
Provides an API for accessing an installed package’s metadata, such as its
entry points or its top-level name. This functionality intends to replace
most uses of pkg_resources entry point API and metadata API.
.
This package contains Python 3.x module.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/python/importlib_metadata

Package: python3-incremental
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 99
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: incremental
Version: 21.3.0-1
Depends: python3:any
Recommends: python3-click, python3-twisted
Description: Library for versioning Python projects
Incremental is a small library that versions your Python projects.
.
This package provides the Python 3.x module.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/twisted/incremental

Package: python3-jeepney
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 186
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: jeepney
Version: 0.7.1-3
Depends: python3:any
Description: pure Python D-Bus interface
Jeepney is a pure Python implementation of D-Bus messaging. It has an
I/O-free core, and integration modules for different event loops.
.
D-Bus is an inter-process communication system, mainly used in Linux.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://gitlab.com/takluyver/jeepney

Package: python3-jinja2
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 544
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: jinja2
Version: 3.0.3-1
Replaces: python-jinja2 (<< 2.11.1-1)
Depends: python3-babel, python3-markupsafe (>= 2.0), python3:any
Recommends: python3-pkg-resources
Suggests: python-jinja2-doc
Breaks: python-jinja2 (<< 2.11.1-1)
Description: small but fast and easy to use stand-alone template engine
Jinja2 is a template engine written in pure Python. It provides a Django
inspired non-XML syntax but supports inline expressions and an optional
sandboxed environment.
.
The key-features are:

- Configurable syntax. If you are generating LaTeX or other formats with
  Jinja2 you can change the delimiters to something that integrates better
  into the LaTeX markup.
- Fast. While performance is not the primarily target of Jinja2 it’s
  surprisingly fast. The overhead compared to regular Python code was reduced
  to the very minimum.
- Easy to debug. Jinja2 integrates directly into the Python traceback system
  which allows you to debug Jinja2 templates with regular Python debugging
  helpers.
- Secure. It’s possible to evaluate untrusted template code if the optional
  sandbox is enabled. This allows Jinja2 to be used as templating language
  for applications where users may modify the template design.
  Original-Maintainer: Piotr Ożarowski <piotr@debian.org>
  Homepage: http://jinja.pocoo.org/

Package: python3-json-pointer
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 44
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-json-pointer
Version: 2.0-0ubuntu1
Depends: python3:any
Description: resolve JSON pointers - Python 3.x
Python-json-pointer is a small library to resolve JSON pointers according to
the IETF draft specification. JSON Pointer defines a string syntax for
identifying a specific value within a JavaScript Object Notation (JSON)
document.
.
This package provides the module for Python 3.x.
Original-Maintainer: Debian OpenStack <team+openstack@tracker.debian.org>
Homepage: https://github.com/stefankoegl/python-json-pointer

Package: python3-jsonpatch
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 59
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-json-patch
Version: 1.32-2
Depends: python3-json-pointer, python3:any
Description: library to apply JSON patches - Python 3.x
Python-json-patch is a Python module (a library) to apply JSON Patches
according to the IETF draft specification.
.
From the IETF site:
.
JavaScript Object Notation (JSON) [RFC4627] is a common format for the
exchange and storage of structured data. HTTP PATCH [RFC5789] extends the
Hypertext Transfer Protocol (HTTP) [RFC2616] with a method to perform partial
modifications to resources.
.
JSON Patch is a format (identified by the media type "application/
json-patch") for expressing a sequence of operations to apply to a target JSON
document, suitable for use with the HTTP PATCH method.
.
This format is also potentially useful in other cases when it's necessary to
make partial updates to a JSON document.
.
This package provides the Python 3.x module.
Original-Maintainer: Debian OpenStack <team+openstack@tracker.debian.org>
Homepage: https://github.com/stefankoegl/python-json-patch

Package: python3-jsonschema
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 259
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-jsonschema
Version: 3.2.0-0ubuntu2
Depends: python3-attr, python3-pkg-resources, python3-setuptools, python3-six (>= 1.11.0), python3-importlib-metadata, python3-pyrsistent, python3:any
Suggests: python-jsonschema-doc
Description: An(other) implementation of JSON Schema (Draft 3 and 4) - Python 3.x
JSON Schema is a specification for a JSON-based format for defining
the structure of JSON data. JSON Schema provides a contract for what
JSON data is required for a given application and how it can be
modified, much like what XML Schema provides for XML. JSON Schema is
intended to provide validation, documentation, and interaction control
of JSON data.
.
This package contains the Python 3.x module.
Original-Maintainer: Debian OpenStack <team+openstack@tracker.debian.org>
Homepage: https://github.com/Julian/jsonschema

Package: python3-jwt
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 82
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: pyjwt
Version: 2.3.0-1ubuntu0.2
Depends: python3:any
Recommends: python3-cryptography
Suggests: python3-crypto
Description: Python 3 implementation of JSON Web Token
PyJWT implements the JSON Web Token draft 01, a way of representing
signed content using JSON data structures.
.
Supported algorithms for cryptographic signing:
.

- HS256 - HMAC using SHA-256 hash algorithm (default)
- HS384 - HMAC using SHA-384 hash algorithm
- HS512 - HMAC using SHA-512 hash algorithm
- RS256 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash
  algorithm
- RS384 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash
  algorithm
- RS512 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash
  algorithm
  .
  Supported reserved claim names:

* "exp" (Expiration Time) Claim
  .
  This package contains the Python 3 version of the library.
  Homepage: https://github.com/jpadilla/pyjwt
  Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>

Package: python3-keyring
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 154
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-keyring
Version: 23.5.0-1
Depends: python3-importlib-metadata (>= 3.6), python3-jeepney (>= 0.4.2), python3-secretstorage (>= 3.2), python3:any
Suggests: gir1.2-secret-1, gnome-keyring, libkf5wallet-bin, python3-dbus, python3-gi, python3-keyrings.alt
Breaks: python3-keyrings.alt (<< 3.1), python3-wheel (<< 0.27)
Description: store and access your passwords safely
The Python keyring library provides an easy way to access the system
keyring service (e.g Gnome-Keyring, KWallet) from Python.
It can be used in any application that needs safe password storage.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/jaraco/keyring

Package: python3-launchpadlib
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 1762
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-launchpadlib
Version: 1.10.16-1
Depends: python3-httplib2, python3-keyring, python3-lazr.restfulclient, python3-lazr.uri, python3:any
Suggests: python3-pkg-resources, python3-testresources
Description: Launchpad web services client library (Python 3)
A free Python library for scripting Launchpad through its web services
interface.
.
It currently provides access to the following parts of Launchpad:

- People and Teams
- Team memberships
- Bugs and bugtasks
  .
  The Launchpad API is currently in beta, and may well change in ways
  incompatible with this library.
  .
  This package is for Python 3.
  Original-Maintainer: Stefano Rivera <stefanor@debian.org>
  Homepage: https://launchpad.net/launchpadlib

Package: python3-lazr.restfulclient
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 183
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: lazr.restfulclient
Version: 0.14.4-1
Depends: python3-httplib2 (>= 0.7.7), python3-lazr.uri, python3-wadllib (>= 1.1.4), python3-distro, python3-oauthlib, python3-pkg-resources, python3-six, python3:any
Description: client for lazr.restful-based web services (Python 3)
A programmable client library that takes advantage of the commonalities
among lazr.rest web services to provide added functionality on top
of wadllib.
.
This package is for Python 3.
Original-Maintainer: Stefano Rivera <stefanor@debian.org>
Homepage: https://launchpad.net/lazr.restfulclient

Package: python3-lazr.uri
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 75
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: lazr.uri
Version: 1.0.6-2
Depends: python3-importlib-metadata | python3 (>> 3.8), python3-pkg-resources, python3:any
Description: library for parsing, manipulating, and generating URIs
A self-contained, easily reusable, Python library for parsing,
manipulating and generating URIs. With it you can extract parts
of a URL, compare URIs to see if one contains another, search for
URIs in text, and many other things.
.
This package contains the library for Python 3.x.
Original-Maintainer: Stefano Rivera <stefanor@debian.org>
Homepage: https://launchpad.net/lazr.uri

Package: python3-lib2to3
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 367
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: python3-stdlib-extensions
Version: 3.10.4-0ubuntu1
Replaces: libpython3.6-stdlib (<< 3.6.4~rc1-2), libpython3.7-stdlib (<< 3.7.0~a3-3), python3.6-2to3 (<< 3.6.4-2), python3.7-2to3 (<< 3.7.0~a3-3)
Provides: python3.10-lib2to3
Depends: python3:any (>= 3.10.1-0~), python3:any (<< 3.11)
Breaks: libpython3.10-stdlib (<< 3.10.0~b1), libpython3.6-stdlib (<< 3.6.4~rc1-2), libpython3.7-stdlib (<< 3.7.0~a3-3), python3.6-2to3 (<< 3.6.4-2), python3.7-2to3 (<< 3.7.0~a3-3)
Description: Interactive high-level object-oriented language (lib2to3)
Python is a high-level, interactive, object-oriented language. It
includes an extensive class library with lots of goodies for
network programming, system administration, sounds and graphics.
.
This package contains the lib2to3 library, a Python2 to Python3 converter.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: python3-markupsafe
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 50
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: markupsafe
Version: 2.0.1-2build1
Depends: python3 (<< 3.11), python3 (>= 3.10~), python3:any, libc6 (>= 2.14)
Description: HTML/XHTML/XML string library
MarkupSafe is a Python library implementing a unicode subclass that is
aware of HTML escaping rules. It can be used to implement automatic
string escaping.
Original-Maintainer: Piotr Ożarowski <piotr@debian.org>
Homepage: https://palletsprojects.com/p/markupsafe/

Package: python3-minimal
Status: install ok installed
Priority: important
Section: python
Installed-Size: 122
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: python3-defaults
Version: 3.10.4-0ubuntu2
Depends: dpkg (>= 1.13.20)
Pre-Depends: python3.10-minimal (>= 3.10.4-1~)
Description: minimal subset of the Python language (default python3 version)
This package contains the interpreter and some essential modules. It's used
in the boot process for some basic tasks.
See /usr/share/doc/python3.10-minimal/README.Debian for a list of the modules
contained in this package.
Homepage: https://www.python.org/
Cnf-Visible-Pkgname: python3
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: python3-more-itertools
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 226
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: more-itertools
Version: 8.10.0-2
Depends: python3:any
Description: library with routines for operating on iterables, beyond itertools (Python 3)
Python's itertools library is a gem - you can compose elegant solutions
for a variety of problems with the functions it provides.
More-itertools collects additional building blocks, recipes,
and routines for working with Python iterables.
.
This package contains the module for Python 3.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/more-itertools/more-itertools/

Package: python3-netifaces
Status: install ok installed
Priority: important
Section: python
Installed-Size: 54
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: netifaces
Version: 0.11.0-1build2
Depends: python3 (<< 3.11), python3 (>= 3.10~), libc6 (>= 2.4)
Description: portable network interface information - Python 3.x
netifaces provides a (hopefully portable-ish) way for Python programmers to
get access to a list of the network interfaces on the local machine, and to
obtain the addresses of those network interfaces.
.
This package contains the module for Python 3.x.
Homepage: https://alastairs-place.net/projects/netifaces/
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>

Package: python3-newt
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 111
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: newt
Version: 0.52.21-5ubuntu2
Provides: python3.10-newt
Depends: libnewt0.52 (= 0.52.21-5ubuntu2), python3 (<< 3.11), python3 (>= 3.10~), python3:any, libc6 (>= 2.4)
Description: NEWT module for Python3
This module allows you to build a text UI for your Python3 scripts
using newt.
Homepage: https://pagure.io/newt
Original-Maintainer: Alastair McKinstry <mckinstry@debian.org>

Package: python3-oauthlib
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 556
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-oauthlib
Version: 3.2.0-1
Depends: python3:any, python3-blinker, python3-cryptography, python3-jwt (>= 1.0.0)
Description: generic, spec-compliant implementation of OAuth for Python3
OAuthLib is a generic utility which implements the logic of OAuth without
assuming a specific HTTP request object. It can be used to graft OAuth support
onto HTTP libraries.
.
OAuth 1 is fully supported per the RFC for both clients and providers.
.
OAuth 2 client and provider support for:
.

- Authorization Code Grant
- Implicit Grant
- Client Credentials Grant
- Resource Owner Password Credentials Grant
- Refresh Tokens
- Bearer Tokens
- Draft MAC tokens
- Token Revocation
- OpenID Connect Authentication
  .
  This package contains the Python 3 version of the library.
  Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
  Homepage: https://github.com/idan/oauthlib

Package: python3-openssl
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 238
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: pyopenssl
Version: 21.0.0-1
Depends: python3-cryptography (>= 3.3), python3-six (>= 1.5.2), python3:any
Suggests: python-openssl-doc, python3-openssl-dbg
Description: Python 3 wrapper around the OpenSSL library
High-level wrapper around a subset of the OpenSSL library, includes
.

- SSL.Connection objects, wrapping the methods of Python's portable
  sockets
- Callbacks written in Python
- Extensive error-handling mechanism, mirroring OpenSSL's error
  codes
  .
  A lot of the object methods do nothing more than calling a
  corresponding function in the OpenSSL library.
  .
  This package contains the Python 3 version of pyopenssl.
  Original-Maintainer: Sandro Tosi <morph@debian.org>
  Homepage: https://pyopenssl.org/

Package: python3-pexpect
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 200
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: pexpect
Version: 4.8.0-2ubuntu1
Depends: python3-ptyprocess, python3:any
Suggests: python-pexpect-doc
Description: Python 3 module for automating interactive applications
Pexpect is a pure Python 3 module for spawning child applications;
controlling them; and responding to expected patterns in their
output. Pexpect works like Don Libes' Expect. Pexpect allows your
script to spawn a child application and control it as if a human were
typing commands.
Homepage: https://github.com/pexpect/pexpect
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>

Package: python3-pkg-resources
Status: install ok installed
Priority: important
Section: python
Installed-Size: 580
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: setuptools
Version: 59.6.0-1.2
Depends: python3:any
Suggests: python3-setuptools
Description: Package Discovery and Resource Access using pkg_resources
The pkg_resources module provides an API for Python libraries to
access their resource files, and for extensible applications and
frameworks to automatically discover plugins. It also provides
runtime support for using C extensions that are inside zipfile-format
eggs, support for merging packages that have separately-distributed
modules or subpackages, and APIs for managing Python's current
"working set" of active packages.
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://pypi.python.org/pypi/setuptools

Package: python3-problem-report
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 180
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: apport
Version: 2.20.11-0ubuntu82.1
Depends: python3:any (>= 3.0~)
Description: Python 3 library to handle problem reports
This Python library provides an interface for creating, modifying,
and accessing standardized problem reports for program and kernel
crashes and packaging bugs.
.
These problem reports use standard Debian control format syntax
(RFC822).
Homepage: https://wiki.ubuntu.com/Apport

Package: python3-ptyprocess
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 59
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: ptyprocess
Version: 0.7.0-3
Depends: python3:any
Description: Run a subprocess in a pseudo terminal from Python 3
Launch a subprocess in a pseudo terminal (pty), and interact with both
the process and its pty.
.
Sometimes, piping stdin and stdout is not enough. There might be a password
prompt that doesn't read from stdin, output that changes when it's going to
a pipe rather than a terminal, or curses-style interfaces that rely on a
terminal. If you need to automate these things, running the process in a
pseudo terminal (pty) is the answer.
.
This package installs the library for Python 3.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/pexpect/ptyprocess

Package: python3-pyasn1
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 390
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: pyasn1
Version: 0.4.8-1
Depends: python3:any
Breaks: python3-pysnmp4 (<< 4.3.4)
Description: ASN.1 library for Python (Python 3 module)
This is an implementation of ASN.1 types and codecs in Python
programming language. It has been first written to support particular
protocol (SNMP) but then generalized to be suitable for a wide range
of protocols based on ASN.1 specification.
.
This package contains the Python 3 module.
Original-Maintainer: Jan Lübbe <jluebbe@debian.org>
Homepage: http://snmplabs.com/pyasn1/index.html

Package: python3-pyasn1-modules
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 363
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-pyasn1-modules
Version: 0.2.1-1
Depends: python3-pyasn1 (>= 0.4.1), python3-pyasn1 (<< 0.5.0), python3:any
Description: Collection of protocols modules written in ASN.1 language (Python 3)
This is a small but growing collection of ASN.1 data structures
expressed in Python terms using pyasn1 data model.
.
It's thought to be useful to protocol developers and testers.
.
Please note that pyasn1_modules is neither part of the pyasn1 package
nor related to it.
Original-Maintainer: Debian Python Modules Team <python-modules-team@lists.alioth.debian.org>
Homepage: http://pypi.python.org/pypi/pyasn1-modules

Package: python3-pyparsing
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 298
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: pyparsing
Version: 2.4.7-1
Depends: python3:any
Suggests: python-pyparsing-doc
Description: alternative to creating and executing simple grammars - Python 3.x
The parsing module is an alternative approach to creating and
executing simple grammars, vs. the traditional lex/yacc approach, or
the use of regular expressions. The parsing module provides a
library of classes that client code uses to construct the grammar
directly in Python code.
.
Here's an example:
.
from pyparsing import Word, alphas
greet = Word(alphas) + "," + Word(alphas) + "!"
hello = "Hello, World!"
print hello, "->", greet.parseString(hello)
.
This package contains the Python 3.x version of python-pyparsing.
Original-Maintainer: Debian Python Modules Team <python-modules-team@lists.alioth.debian.org>
Homepage: https://github.com/pyparsing/pyparsing/

Package: python3-pyrsistent
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 249
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: pyrsistent
Version: 0.18.1-1build1
Depends: python3 (<< 3.11), python3 (>= 3.10~), python3:any, libc6 (>= 2.14)
Description: persistent/functional/immutable data structures for Python
Pyrsistent is a number of persistent collections (sometimes referred
to as functional data structures). Persistent in the sense that they
are immutable.
.
All methods on a data structure that would normally mutate it instead
return a new copy of the structure containing the requested updates.
The original structure is left untouched.
.
The collection types and key features currently implemented are:
.

- PVector, similar to a python list
- PMap, similar to dict
- PSet, similar to set
- PRecord, a PMap on steroids with fixed fields, optional type and
  invariant checking and much more
- PClass, a Python class fixed fields, optional type and invariant
  checking and much more
- Checked collections, PVector, PMap and PSet with optional type
  and invariance checks and more
- PBag, similar to collections.Counter
- PList, a classic singly linked list
- PDeque, similar to collections.deque
- Immutable object type (immutable) built on the named tuple
- freeze and thaw functions to convert between pythons standard
  collections and pyrsistent collections.
- Flexible transformations of arbitrarily complex structures built
  from PMaps and PVectors.
  Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
  Homepage: https://github.com/tobgu/pyrsistent/

Package: python3-requests
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 230
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: requests
Version: 2.25.1+dfsg-2
Depends: python3-certifi, python3-chardet (>= 3.0.2), python3-idna, python3-urllib3 (>= 1.21.1), python3:any, ca-certificates
Suggests: python3-cryptography, python3-idna (>= 2.5), python3-openssl, python3-socks, python-requests-doc
Breaks: awscli (<< 1.11.139)
Description: elegant and simple HTTP library for Python3, built for human beings
Requests allow you to send HTTP/1.1 requests. You can add headers, form data,
multipart files, and parameters with simple Python dictionaries, and access
the response data in the same way. It's powered by httplib and urllib3, but
it does all the hard work and crazy hacks for you.
.
Features
.

- International Domains and URLs
- Keep-Alive & Connection Pooling
- Sessions with Cookie Persistence
- Browser-style SSL Verification
- Basic/Digest Authentication
- Elegant Key/Value Cookies
- Automatic Decompression
- Unicode Response Bodies
- Multipart File Uploads
- Connection Timeouts
  .
  This package contains the Python 3 version of the library.
  Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
  Homepage: http://python-requests.org

Package: python3-secretstorage
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 56
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-secretstorage
Version: 3.3.1-1
Depends: dbus, python3-jeepney (>= 0.6), python3-cryptography (>= 2.0), python3:any
Suggests: gnome-keyring (>= 2.30), python-secretstorage-doc
Description: Python module for storing secrets - Python 3.x version
Python-SecretStorage provides a way for securely storing passwords
and other secrets.
.
It uses D-Bus Secret Service API that is supported by GNOME Keyring
(>= 2.30) and KSecretsService.
.
It allows one to create, edit and delete secret items, manipulate
secret collections, and search for items matching given attributes.
It also supports locking and unlocking collections.
.
This package provides Python 3.x version of SecretStorage.
Original-Maintainer: Dmitry Shachnev <mitya57@debian.org>
Homepage: https://github.com/mitya57/secretstorage

Package: python3-serial
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 459
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: pyserial
Version: 3.5-1
Depends: python3:any
Suggests: python3-wxgtk3.0 | python3-wxgtk
Description: pyserial - module encapsulating access for the serial port
This module encapsulates the access for the serial port. It provides
back-ends for standard Python running on Windows, Linux, BSD (possibly
any POSIX compliant system). The module named "serial" automatically
selects the appropriate back-end.
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://github.com/pyserial/pyserial

Package: python3-service-identity
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 53
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-service-identity
Version: 18.1.0-6
Depends: python3-attr, python3-cryptography, python3-pyasn1, python3-pyasn1-modules, python3:any
Recommends: python3-idna
Description: Service identity verification for pyOpenSSL (Python 3 module)
Service_identity aspires to give you all the tools you need for verifying
whether a certificate is valid for the intended purposes.
.
In the simplest case, this means host name verification. However,
service_identity implements RFC 6125 fully and plans to add other
relevant RFCs too.
.
This package contains service_identity for Python 3.
Original-Maintainer: Debian Python Modules Team <python-modules-team@lists.alioth.debian.org>
Homepage: https://pypi.python.org/pypi/service_identity

Package: python3-setuptools
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 1747
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: setuptools
Version: 59.6.0-1.2
Depends: python3-pkg-resources (= 59.6.0-1.2), python3-distutils, python3:any
Suggests: python-setuptools-doc
Description: Python3 Distutils Enhancements
Extensions to the python-distutils for large or complex distributions.
Original-Maintainer: Matthias Klose <doko@debian.org>
Homepage: https://pypi.python.org/pypi/setuptools

Package: python3-six
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 59
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: six
Version: 1.16.0-3ubuntu1
Depends: python3:any
Breaks: libpython-stdlib (<< 2.7.18), python-minimal (<< 2.7.18)
Description: Python 2 and 3 compatibility library (Python 3 interface)
Six is a Python 2 and 3 compatibility library. It provides utility
functions for smoothing over the differences between the Python versions
with the goal of writing Python code that is compatible on both Python
versions.
.
This package provides Six on the Python 3 module path. It is complemented
by python-six and pypy-six.
Homepage: https://github.com/benjaminp/six
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>

Package: python3-software-properties
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 174
Maintainer: Michael Vogt <michael.vogt@ubuntu.com>
Architecture: all
Source: software-properties
Version: 0.99.22.3
Depends: gpg, iso-codes, lsb-release, python3, python3-apt (>= 0.6.20ubuntu16), python3-gi, python3-launchpadlib, python3:any
Recommends: unattended-upgrades
Description: manage the repositories that you install software from
This software provides an abstraction of the used apt repositories.
It allows you to easily manage your distribution and independent software
vendor software sources.

Package: python3-systemd
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 193
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: python-systemd
Version: 234-3ubuntu2
Depends: python3 (<< 3.11), python3 (>= 3.10~), python3:any, libc6 (>= 2.17), libsystemd0 (>= 246)
Description: Python 3 bindings for systemd
This package contains Python 3 bindings for native access to the
systemd facilities.
.
Functionality is separated into a number of modules:

- systemd.journal supports sending of structured messages to the
  journal and reading journal files
- systemd.daemon wraps parts of libsystemd useful for writing daemons
  and socket activation
- systemd.id128 provides functions for querying machine and boot
  identifiers and a list of message identifiers provided by systemd
- systemd.login wraps parts of libsystemd used to query logged in
  users and available seats and machines
  Homepage: http://www.freedesktop.org/wiki/Software/systemd
  Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: python3-twisted
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 12662
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: twisted
Version: 22.1.0-2ubuntu2.3
Replaces: python3-twisted-experimental
Depends: python3-bcrypt (>= 3.0.0), python3-cryptography (>= 2.5), python3-hamcrest, python3-idna, python3-openssl, python3-service-identity (>= 18.1.0), python3-attr (>= 19.2.0), python3-automat (>= 0.8.0), python3-constantly, python3-hyperlink, python3-incremental (>= 21.3.0), python3-zope.interface (>= 4.4.2), python3:any
Suggests: python3-pampy, python3-serial, python3-tk, python3-wxgtk4.0
Breaks: python3-h2 (<< 3.0.0), python3-treq (<< 20.9.0)
Conflicts: python3-twisted-experimental
Description: Event-based framework for internet applications
It includes a web server, a telnet server, a multiplayer RPG engine, a
generic client and server for remote object access, and APIs for creating
new protocols.
Homepage: https://twistedmatrix.com/
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>

Package: python3-tz
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 121
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-tz
Version: 2022.1-1
Depends: tzdata, python3:any
Description: Python3 version of the Olson timezone database
python-tz brings the Olson tz database into Python. This library allows
accurate and cross platform timezone calculations using Python 2.3 or higher.
It also solves the issue of ambiguous times at the end of daylight savings,
which you can read more about in the Python Library Reference
(datetime.tzinfo).
.
This package contains the Python 3 version of the library.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://pypi.python.org/pypi/pytz/

Package: python3-update-manager
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 255
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: update-manager
Version: 1:22.04.9
Replaces: update-manager-core (<< 1:0.163)
Depends: python3:any (>= 3.2~), python3-apt (>= 0.8.5~), python3-distro-info, python3-distupgrade, lsb-release
Suggests: python3-launchpadlib
Breaks: python3-distupgrade (<< 1:16.10.10), update-manager-core (<< 1:0.163)
Description: python 3.x module for update-manager
Python module for update-manager (UpdateManager).
.
This package contains the python 3.x version of this module.

Package: python3-urllib3
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 457
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-urllib3
Version: 1.26.5-1~exp1
Depends: python3:any, python3-six
Recommends: ca-certificates
Suggests: python3-cryptography, python3-idna, python3-openssl, python3-socks
Description: HTTP library with thread-safe connection pooling for Python3
urllib3 supports features left out of urllib and urllib2 libraries.
.

- Re-use the same socket connection for multiple requests (HTTPConnectionPool
  and HTTPSConnectionPool) (with optional client-side certificate
  verification).
- File posting (encode_multipart_formdata).
- Built-in redirection and retries (optional).
- Supports gzip and deflate decoding.
- Thread-safe and sanity-safe.
- Small and easy to understand codebase perfect for extending and
  building upon.
  .
  This package contains the Python 3 version of the library.
  Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
  Homepage: https://urllib3.readthedocs.org

Package: python3-wadllib
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 365
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-wadllib
Version: 1.3.6-1
Depends: python3-lazr.uri, python3-pkg-resources, python3:any
Description: Python 3 library for navigating WADL files
The Web Application Description Language (WADL) is an XML vocabulary for
describing the capabilities of HTTP resources. wadllib can be used in
conjunction with an HTTP library to navigate and manipulate those resources.
.
This package provides wadllib for Python 3.x.
Original-Maintainer: Stefano Rivera <stefanor@debian.org>
Homepage: https://launchpad.net/wadllib

Package: python3-yaml
Status: install ok installed
Priority: important
Section: python
Installed-Size: 529
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: pyyaml
Version: 5.4.1-1ubuntu1
Depends: python3 (<< 3.11), python3 (>= 3.10~), python3:any, libc6 (>= 2.14), libyaml-0-2
Breaks: libpython-stdlib (<< 2.7.18), python-minimal (<< 2.7.18), python-yaml (<< 5.3.1-2)
Description: YAML parser and emitter for Python3
Python3-yaml is a complete YAML 1.1 parser and emitter for Python3. It can
parse all examples from the specification. The parsing algorithm is simple
enough to be a reference for YAML parser implementors. A simple extension API
is also provided. The package is built using libyaml for improved speed.
Homepage: https://github.com/yaml/pyyaml
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>

Package: python3-zipp
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 25
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: python-zipp
Version: 1.0.0-3
Depends: python3-more-itertools, python3:any
Description: pathlib-compatible Zipfile object wrapper - Python 3.x
A backport of the Path object to older versions of Python.
It's pathlib-compatible interface for zip files using zipfile object inside.
.
This package contains Python 3.x module.
Original-Maintainer: Debian Python Modules Team <python-modules-team@lists.alioth.debian.org>
Homepage: https://github.com/jaraco/zipp

Package: python3-zope.interface
Status: install ok installed
Priority: optional
Section: zope
Installed-Size: 961
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: zope.interface
Version: 5.4.0-1build1
Provides: python3-zope, python3.10-zope.interface
Depends: python3 (<< 3.11), python3 (>= 3.10~), python3-pkg-resources, python3:any, libc6 (>= 2.4)
Description: Interfaces for Python3
This package provides an implementation of object interfaces for Python.
Interfaces are a mechanism for labeling objects as conforming to a given API
or contract. So, this package can be considered as implementation of the
Design By Contract methodology support in Python.
.
This is the Python 3 version.
Original-Maintainer: Debian Python Team <team+python@tracker.debian.org>
Homepage: https://github.com/zopefoundation/zope.interface

Package: python3.10
Status: install ok installed
Priority: important
Section: python
Installed-Size: 611
Maintainer: Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Version: 3.10.4-3ubuntu0.1
Depends: python3.10-minimal (= 3.10.4-3ubuntu0.1), libpython3.10-stdlib (= 3.10.4-3ubuntu0.1), media-types | mime-support
Suggests: python3.10-venv, python3.10-doc, binutils
Breaks: python3-all (<< 3.6.5~rc1-1), python3-dev (<< 3.6.5~rc1-1), python3-venv (<< 3.6.5-2)
Description: Interactive high-level object-oriented language (version 3.10)
Python is a high-level, interactive, object-oriented language. Its 3.10 version
includes an extensive class library with lots of goodies for
network programming, system administration, sounds and graphics.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: python3.10-minimal
Status: install ok installed
Priority: important
Section: python
Installed-Size: 5895
Maintainer: Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: allowed
Source: python3.10
Version: 3.10.4-3ubuntu0.1
Depends: libpython3.10-minimal (= 3.10.4-3ubuntu0.1), libexpat1 (>= 2.1~beta3), zlib1g (>= 1:1.2.0)
Pre-Depends: libc6 (>= 2.35)
Recommends: python3.10
Suggests: binfmt-support
Conflicts: binfmt-support (<< 1.1.2)
Description: Minimal subset of the Python language (version 3.10)
This package contains the interpreter and some essential modules. It can
be used in the boot process for some basic tasks.
See /usr/share/doc/python3.10-minimal/README.Debian for a list of the modules
contained in this package.
Cnf-Visible-Pkgname: python3.10
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: readline-common
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 80
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: readline
Version: 8.1.2-1
Replaces: libreadline-common, libreadline4 (<< 4.3-16), libreadline5 (<< 5.0-11)
Depends: dpkg (>= 1.15.4) | install-info
Suggests: readline-doc
Conflicts: libreadline-common, libreadline5 (<< 5.0-11)
Description: GNU readline and history libraries, common files
The GNU readline library aids in the consistency of user interface
across discrete programs that need to provide a command line
interface.
.
The GNU history library provides a consistent user interface for
recalling lines of previously typed input.
Original-Maintainer: Matthias Klose <doko@debian.org>

Package: rpcsvc-proto
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 245
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.4.2-0ubuntu6
Replaces: libc6-dev (<< 2.32), libc6-dev-bin (<< 2.32)
Depends: libc6 (>= 2.34)
Breaks: libc6-dev (<< 2.32), libc6-dev-bin (<< 2.32)
Description: RPC protocol compiler and definitions
rpcgen is a tool that generates C code to implement an RPC protocol. The input
to rpcgen is a language similar to C known as RPC Language (Remote Procedure
Call Language).
.
This package also includes several rpcsvc header files and RPC protocol
definitions from SunRPC sources that were previously shipped by glibc.
Homepage: https://github.com/thkukuk/rpcsvc-proto
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>

Package: rsync
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 742
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 3.2.3-8ubuntu3
Depends: lsb-base, libacl1 (>= 2.2.23), libc6 (>= 2.34), liblz4-1 (>= 0.0~r130), libpopt0 (>= 1.14), libssl3 (>= 3.0.0~~alpha1), libxxhash0 (>= 0.8.0), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Pre-Depends: init-system-helpers (>= 1.54~)
Suggests: openssh-client, openssh-server, python3
Conffiles:
/etc/default/rsync b8fd9efa75e2bda2583b0d7c0892a073
/etc/init.d/rsync 59aa13cd1a70ff254a2991ad0c522ea5
Description: fast, versatile, remote (and local) file-copying tool
rsync is a fast and versatile file-copying tool which can copy locally
and to/from a remote host. It offers many options to control its behavior,
and its remote-update protocol can minimize network traffic to make
transferring updates between machines fast and efficient.
.
It is widely used for backups and mirroring and as an improved copy
command for everyday use.
.
This package provides both the rsync command line tool and optional
daemon functionality.
Homepage: https://rsync.samba.org/
Original-Maintainer: Paul Slootman <paul@debian.org>

Package: rsyslog
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 1750
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 8.2112.0-2ubuntu2.2
Provides: linux-kernel-log-daemon, system-log-daemon
Depends: libc6 (>= 2.34), libestr0 (>= 0.1.4), libfastjson4 (>= 0.99.8), libsystemd0 (>= 246), libuuid1 (>= 2.16), zlib1g (>= 1:1.1.4), adduser, ucf
Recommends: logrotate
Suggests: rsyslog-mysql | rsyslog-pgsql, rsyslog-mongodb, rsyslog-doc, rsyslog-openssl | rsyslog-gnutls, rsyslog-gssapi, rsyslog-relp, apparmor (>= 2.8.96~2541-0ubuntu4~)
Conflicts: linux-kernel-log-daemon, system-log-daemon
Conffiles:
/etc/apparmor.d/usr.sbin.rsyslogd 648eb046586f8a0d7f2ca87ba836bd14
/etc/logcheck/ignore.d.server/rsyslog 80e9fc074b97751dd4de99855bb8d0e0
/etc/logrotate.d/rsyslog 46de15167e065fe1d21b8cd9accc2c48
/etc/rsyslog.conf 8f03326e3d7284ef50ac6777ef8a4fb8
Description: reliable system and kernel logging daemon
Rsyslog is a multi-threaded implementation of syslogd (a system utility
providing support for message logging), with features that include:

- reliable syslog over TCP, SSL/TLS and RELP
- on-demand disk buffering
- email alerting
- writing to MySQL or PostgreSQL databases (via separate output plugins)
- permitted sender lists
- filtering on any part of the syslog message
- on-the-wire message compression
- fine-grained output format control
- failover to backup destinations
- enterprise-class encrypted syslog relaying
  .
  It is the default syslogd on Debian systems.
  Homepage: https://www.rsyslog.com/
  Original-Maintainer: Michael Biebl <biebl@debian.org>

Package: run-one
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 44
Maintainer: Dustin Kirkland <kirkland@ubuntu.com>
Architecture: all
Version: 1.17-0ubuntu1
Replaces: bikeshed (<< 1.8)
Depends: procps
Breaks: bikeshed (<< 1.8)
Enhances: anacron, cron
Description: run just one instance of a command and its args at a time
This utility will run just one instance at a time of some command and
unique set of arguments (useful for cronjobs, eg).
Homepage: http://launchpad.net/run-one

Package: sbsigntool
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 225
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 0.9.4-2ubuntu2
Depends: libc6 (>= 2.34), libssl3 (>= 3.0.0~~alpha1), libuuid1 (>= 2.16)
Description: Tools to manipulate signatures on UEFI binaries and drivers
This package installs tools which can cryptographically sign EFI binaries and
drivers.
Original-Maintainer: Debian EFI Team <debian-efi@lists.debian.org>

Package: screen
Status: install ok installed
Priority: standard
Section: misc
Installed-Size: 1005
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 4.9.0-1
Depends: libc6 (>= 2.34), libcrypt1 (>= 1:4.1.0), libpam0g (>= 0.99.7.1), libtinfo6 (>= 6), libutempter0 (>= 1.1.5)
Suggests: byobu | screenie | iselect (>= 1.4.0-1), ncurses-term
Conffiles:
/etc/init.d/screen-cleanup 44ec7824f5ef10df73e92ad064331ea0
/etc/screenrc 12c245238eb8b653625bba27dc81df6a
Description: terminal multiplexer with VT100/ANSI terminal emulation
GNU Screen is a terminal multiplexer that runs several separate "screens" on
a single physical character-based terminal. Each virtual terminal emulates a
DEC VT100 plus several ANSI X3.64 and ISO 2022 functions. Screen sessions
can be detached and resumed later on a different terminal.
.
Screen also supports a whole slew of other features, including configurable
input and output translation, serial port support, configurable logging,
and multi-user support.
Original-Maintainer: Axel Beckert <abe@debian.org>
Homepage: https://savannah.gnu.org/projects/screen

Package: secureboot-db
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 29
Maintainer: Steve Langasek <steve.langasek@ubuntu.com>
Architecture: amd64
Version: 1.8
Depends: sbsigntool
Description: Secure Boot updates for DB and DBX
Systems with Secure Boot enabled have portions of the system signed by entries
in the Secure Boot DB. This package provides a mechanism for delivering
updates to DB and the corresponding blacklist database, DBX.

Package: sed
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 328
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 4.8-1ubuntu2
Pre-Depends: libacl1 (>= 2.2.23), libc6 (>= 2.34), libselinux1 (>= 3.1~)
Description: GNU stream editor for filtering/transforming text
sed reads the specified files or the standard input if no
files are specified, makes editing changes according to a
list of commands, and writes the results to the standard
output.
Homepage: https://www.gnu.org/software/sed/
Original-Maintainer: Clint Adams <clint@debian.org>

Package: sensible-utils
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 59
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.0.17
Replaces: debianutils (<= 2.32.3), manpages-pl (<= 20060617-3~)
Description: Utilities for sensible alternative selection
This package provides a number of small utilities which are used
by programs to sensibly select and spawn an appropriate browser,
editor, or pager.
.
The specific utilities included are: sensible-browser sensible-editor
sensible-pager
Original-Maintainer: Anibal Monsalve Salazar <anibal@debian.org>

Package: session-migration
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 50
Maintainer: Didier Roche <didrocks@ubuntu.com>
Architecture: amd64
Version: 0.3.6
Depends: libc6 (>= 2.34), libglib2.0-0 (>= 2.51.1), init-system-helpers (>= 1.52)
Description: Tool to migrate in user session settings
This tool is used to migrate in session user data when a program is evolving
its configuration, or needing to have files moved and so on.
.
This program is generally autostarted at the very beginning of the session
and integrates caching capability.
Homepage: https://launchpad.net/session-migration

Package: sg3-utils
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 2789
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.46-1build1
Replaces: sg-utils
Depends: libc6 (>= 2.34), libsgutils2-2 (>= 1.46)
Conflicts: cdwrite, sg-utils
Description: utilities for devices using the SCSI command set
Most OSes have SCSI pass-through interfaces that enable user space programs
to send SCSI commands to a device and fetch the response. With SCSI to ATA
Translation (SAT) many ATA disks now can process SCSI commands. Typically
each utility in this package implements one SCSI command. See the draft
standards at www.t10.org for SCSI command definitions plus SAT. ATA
commands are defined in the draft standards at www.t13.org . For a mapping
between supported SCSI and ATA commands and utility names in this package
see the COVERAGE file.
Homepage: http://sg.danny.cz/sg/
Original-Maintainer: Ritesh Raj Sarraf <rrs@debian.org>

Package: sg3-utils-udev
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 34
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: sg3-utils
Version: 1.46-1build1
Depends: sg3-utils, initramfs-tools-core, initramfs-tools | linux-initramfs-tool
Description: utilities for devices using the SCSI command set (udev rules)
Most OSes have SCSI pass-through interfaces that enable user space programs
to send SCSI commands to a device and fetch the response. With SCSI to ATA
Translation (SAT) many ATA disks now can process SCSI commands. Typically
each utility in this package implements one SCSI command. See the draft
standards at www.t10.org for SCSI command definitions plus SAT. ATA
commands are defined in the draft standards at www.t13.org . For a mapping
between supported SCSI and ATA commands and utility names in this package
see the COVERAGE file.
.
udev rules which are associated with the utilities in the sg3-utils package.
Homepage: http://sg.danny.cz/sg/
Original-Maintainer: Ritesh Raj Sarraf <rrs@debian.org>

Package: shared-mime-info
Status: install ok installed
Priority: important
Section: misc
Installed-Size: 2744
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.1-2
Depends: libc6 (>= 2.34), libglib2.0-0 (>= 2.35.9), libxml2 (>= 2.7.4)
Description: FreeDesktop.org shared MIME database and spec
This is the shared MIME-info database from the X Desktop Group. It is required
by any program complying to the Shared MIME-Info Database spec, which is also
included in this package.
.
At this time at least ROX, GNOME, KDE and Xfce use this database.
Original-Maintainer: Debian freedesktop.org maintainers <pkg-freedesktop-maintainers@lists.alioth.debian.org>
Homepage: https://freedesktop.org/wiki/Software/shared-mime-info

Package: show-motd
Status: install ok installed
Priority: extra
Section: admin
Installed-Size: 16
Maintainer: Dustin Kirkland <kirkland@ubuntu.com>
Architecture: all
Source: update-motd
Version: 3.10
Depends: update-motd (>= 3.6-0ubuntu1.19.10.0)
Breaks: base-files (<< 11ubuntu2), libpam-modules (<< 1.3.1-5ubuntu1.19.10.0), ubuntu-release-upgrader-core (<< 1:20.04.5), update-notifier-common (<< 3.192.26.1)
Conffiles:
/etc/profile.d/update-motd.sh 5eec46be02bc254b7f3a0dc5e0616763
Description: show message of the day in interactive shells
.
This package installs a script in /etc/profile.d that dynamically
generates and shows a message-of-the-day in inteactive shells by
running scripts installed in /etc/update-motd.d.
.
Showing the message-of-the-day in shells is useful when pam_motd does
not show it, for example when starting the interactive shell does not
require login.

Package: sl
Status: install ok installed
Priority: optional
Section: games
Installed-Size: 59
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 5.02-1
Depends: libc6 (>= 2.2.5), libncurses6 (>= 6), libtinfo6 (>= 6)
Description: Correct you if you type `sl' by mistake
Sl is a program that can display animations aimed to correct you
if you type 'sl' by mistake.
SL stands for Steam Locomotive.
Original-Maintainer: Markus Frosch <lazyfrosch@debian.org>
Homepage: https://github.com/mtoyoda/sl

Package: snapd
Status: install ok installed
Priority: optional
Section: devel
Installed-Size: 93173
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2.56.2+22.04ubuntu1
Replaces: snap-confine (<< 2.23), snapd-xdg-open (<= 0.0.0), ubuntu-core-launcher (<< 2.22), ubuntu-snappy (<< 1.9), ubuntu-snappy-cli (<< 1.9)
Depends: adduser, apparmor (>= 2.10.95-0ubuntu2.2), ca-certificates, openssh-client, squashfs-tools, systemd, udev, libc6 (>= 2.34), libfuse3-3 (>= 3.2.3), liblzma5 (>= 5.1.1alpha+20110809), liblzo2-2 (>= 2.02), libudev1 (>= 183), zlib1g (>= 1:1.1.4), default-dbus-session-bus | dbus-session-bus
Recommends: gnupg, fuse3 (>= 3.10.5-1) | fuse
Suggests: zenity | kdialog
Breaks: snap-confine (<< 2.23), snapd-xdg-open (<= 0.0.0), ubuntu-core-launcher (<< 2.22), ubuntu-snappy (<< 1.9), ubuntu-snappy-cli (<< 1.9)
Conflicts: snap (<< 2013-11-29-1ubuntu1)
Conffiles:
/etc/apparmor.d/usr.lib.snapd.snap-confine.real 0558d50ed5bbcd8f424707a0aaeb6ae5
/etc/apt/apt.conf.d/20snapd.conf e0e08d8267c66b9f81340dd6500cb67a
/etc/profile.d/apps-bin-path.sh cf10aed8bb987ded8b7f4ba4303c1e9b
/etc/xdg/autostart/snap-userd-autostart.desktop 4aaaa2fe36462a072a72e09cad553362
Description: Daemon and tooling that enable snap packages
Install, configure, refresh and remove snap packages. Snaps are
'universal' packages that work across many different Linux systems,
enabling secure distribution of the latest apps and utilities for
cloud, servers, desktops and the internet of things.
.
Start with 'snap list' to see installed snaps.
Built-Using: apparmor (= 3.0.4-2ubuntu2.1), libcap2 (= 1:2.44-1build3), libseccomp (= 2.5.3-2ubuntu2)
Homepage: https://github.com/snapcore/snapd

Package: software-properties-common
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 216
Maintainer: Michael Vogt <michael.vogt@ubuntu.com>
Architecture: all
Source: software-properties
Version: 0.99.22.3
Replaces: python-software-properties (<< 0.85), python3-software-properties (<< 0.85)
Depends: ca-certificates, gir1.2-glib-2.0, gir1.2-packagekitglib-1.0 (>= 1.1.0-2), packagekit, python-apt-common (>= 0.9), python3, python3-dbus, python3-gi, python3-software-properties (= 0.99.22.3), python3:any
Breaks: python-software-properties (<< 0.85), python3-software-properties (<< 0.85)
Conffiles:
/etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf cc3c01a5b5e8e05d40c9c075f44c43ea
Description: manage the repositories that you install software from (common)
This software provides an abstraction of the used apt repositories.
It allows you to easily manage your distribution and independent software
vendor software sources.
.
This package contains the common files for software-properties like the
D-Bus backend.

Package: sosreport
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 2708
Maintainer: Eric Desrochers <slashd@ubuntu.com>
Architecture: amd64
Version: 4.3-1ubuntu2
Depends: python3-pexpect, python3:any
Conffiles:
/etc/sos/sos.conf afbb6b104e5e905315fb573db86c1e0b
Description: Set of tools to gather troubleshooting data from a system
Sos is a set of tools that gathers information about system
hardware and configuration. The information can then be used for
diagnostic purposes and debugging. Sos is commonly used to help
support technicians and developers.
Homepage: https://github.com/sosreport/sos

Package: squashfs-tools
Status: install ok installed
Priority: optional
Section: kernel
Installed-Size: 414
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1:4.5-3build1
Depends: libc6 (>= 2.34), liblz4-1 (>= 0.0~r130), liblzma5 (>= 5.1.1alpha+20120614), liblzo2-2 (>= 2.02), libzstd1 (>= 1.4.0), zlib1g (>= 1:1.1.4)
Description: Tool to create and append to squashfs filesystems
Squashfs is a highly compressed read-only filesystem for Linux. It uses zlib
compression to compress both files, inodes and directories. Inodes in the
system are very small and all blocks are packed to minimise data overhead.
Block sizes greater than 4K are supported up to a maximum of 64K.
.
Squashfs is intended for general read-only filesystem use, for archival use
(i.e. in cases where a .tar.gz file may be used), and in constrained block
device/memory systems (e.g. embedded systems) where low overhead is needed.
Homepage: https://github.com/plougher/squashfs-tools
Original-Maintainer: Laszlo Boszormenyi (GCS) <gcs@debian.org>

Package: ssh-import-id
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 53
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 5.11-0ubuntu1
Depends: ca-certificates, openssh-client, python3-distro, wget, python3:any
Recommends: openssh-server
Conffiles:
/etc/ssh/ssh_import_id 8bfa390040fbeeae70bec14f2dccaf11
Description: securely retrieve an SSH public key and install it locally
This utility will securely contact a public keyserver (Launchpad.net by
default, but Github.com is also supported), retrieve one or more user's
public keys, and append these to the current user's ~/.ssh/authorized_keys
file.
Homepage: http://launchpad.net/ssh-import-id
Original-Maintainer: Andrew Starr-Bochicchio <asb@debian.org>

Package: strace
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 2000
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 5.16-0ubuntu3
Depends: libc6 (>= 2.34), libunwind8
Description: System call tracer
strace is a system call tracer: i.e. a debugging tool which prints out
a trace of all the system calls made by another process/program.
The program to be traced need not be recompiled for this, so you can
use it on binaries for which you don't have source.
.
System calls and signals are events that happen at the user/kernel
interface. A close examination of this boundary is very useful for bug
isolation, sanity checking and attempting to capture race conditions.
Homepage: https://strace.io
Original-Maintainer: Steve McIntyre <93sam@debian.org>

Package: sudo
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 2504
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.9.9-1ubuntu2
Replaces: sudo-ldap
Depends: libaudit1 (>= 1:2.2.1), libc6 (>= 2.34), libpam0g (>= 0.99.7.1), libselinux1 (>= 3.1~), zlib1g (>= 1:1.2.0.2), libpam-modules, lsb-base
Conflicts: sudo-ldap
Conffiles:
/etc/pam.d/sudo b3a1b916bf62a2cc3280f7f9b94844ff
/etc/pam.d/sudo-i ce9740f66cedf7716e26950abfe556fa
/etc/sudo.conf efb56b1b282fa4cad1b6c0f05137bb08
/etc/sudo_logsrvd.conf 09ceda2c98f43e0fbb79bed7c82dba45
/etc/sudoers 791aa979aa5e859f9ba0112a9512158c
/etc/sudoers.d/README 44c75ff004a18eeefdde4c998914d6d3
Description: Provide limited super user privileges to specific users
Sudo is a program designed to allow a sysadmin to give limited root
privileges to users and log root activity. The basic philosophy is to give
as few privileges as possible but still allow people to get their work done.
.
This version is built with minimal shared library dependencies, use the
sudo-ldap package instead if you need LDAP support for sudoers.
Homepage: https://www.sudo.ws/
Original-Maintainer: Sudo Maintainers <sudo@packages.debian.org>

Package: systemd
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 16288
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 249.11-0ubuntu3.4
Provides: systemd-sysusers (= 249.11-0ubuntu3.4), systemd-tmpfiles (= 249.11-0ubuntu3.4)
Depends: libacl1 (>= 2.2.23), libapparmor1 (>= 2.13), libaudit1 (>= 1:2.2.1), libcrypt1 (>= 1:4.4.0), libcryptsetup12 (>= 2:2.4), libgnutls30 (>= 3.7.2), libgpg-error0 (>= 1.14), libip4tc2 (>= 1.8.3), libkmod2 (>= 5~), liblz4-1 (>= 0.0~r130), libmount1 (>= 2.30), libpam0g (>= 0.99.7.1), libseccomp2 (>= 2.4.1), libssl3 (>= 3.0.0~~alpha1), libsystemd0 (= 249.11-0ubuntu3.4), util-linux (>= 2.27.1), mount (>= 2.26), adduser
Pre-Depends: libblkid1 (>= 2.24), libc6 (>= 2.34), libcap2 (>= 1:2.24-9~), libgcrypt20 (>= 1.9.0), liblz4-1 (>= 0.0~r122), liblzma5 (>= 5.1.1alpha+20120614), libselinux1 (>= 3.1~), libzstd1 (>= 1.4.0)
Recommends: default-dbus-system-bus | dbus-system-bus, networkd-dispatcher, systemd-timesyncd | time-daemon
Suggests: systemd-container, libfido2-1, libtss2-esys-3.0.2-0, libtss2-mu0, libtss2-rc0, policykit-1
Breaks: resolvconf (<< 1.83~), udev (<< 247~)
Conflicts: consolekit, libpam-ck-connector, systemd-shim
Conffiles:
/etc/systemd/journald.conf d2187d732ab2911016a4d4017c155dbb
/etc/systemd/logind.conf 01fce0d0c11426fd7561a6b3bc907ed6
/etc/systemd/networkd.conf f461eed370e565cbe9890dd6b2c43996
/etc/systemd/pstore.conf ea1d43113c41edaacb39180d60a50b08
/etc/systemd/resolved.conf f87758687f627a75dfac54727cf08462
/etc/systemd/sleep.conf b15f42ea3ac089d0c96067de38268ff6
/etc/systemd/system.conf edb0a583ef891cdbe4c5611f24907e9c
/etc/systemd/user.conf e9c22208d3f0f96ef04eb5fbfecf5d2e
Description: system and service manager
systemd is a system and service manager for Linux. It provides aggressive
parallelization capabilities, uses socket and D-Bus activation for starting
services, offers on-demand starting of daemons, keeps track of processes using
Linux control groups, maintains mount and automount points and implements an
elaborate transactional dependency-based service control logic.
.
systemd is compatible with SysV and LSB init scripts and can work as a
drop-in replacement for sysvinit.
.
Installing the systemd package will not switch your init system unless you
boot with init=/lib/systemd/systemd or install systemd-sysv in addition.
Homepage: https://www.freedesktop.org/wiki/Software/systemd
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: systemd-sysv
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 195
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: systemd
Version: 249.11-0ubuntu3.4
Replaces: sysvinit-core
Depends: systemd (= 249.11-0ubuntu3.4)
Pre-Depends: systemd
Recommends: libpam-systemd, libnss-systemd
Conflicts: file-rc, systemd-shim, sysvinit-core
Description: system and service manager - SysV links
systemd is a system and service manager for Linux. It provides aggressive
parallelization capabilities, uses socket and D-Bus activation for starting
services, offers on-demand starting of daemons, keeps track of processes using
Linux control groups, maintains mount and automount points and implements an
elaborate transactional dependency-based service control logic.
.
systemd is compatible with SysV and LSB init scripts and can work as a
drop-in replacement for sysvinit.
.
This package provides the manual pages and links needed for systemd
to replace sysvinit. Installing systemd-sysv will overwrite /sbin/init with a
link to systemd.
Homepage: https://www.freedesktop.org/wiki/Software/systemd
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: systemd-timesyncd
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 266
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: systemd
Version: 249.11-0ubuntu3.4
Replaces: systemd (<< 245.4-2~), time-daemon
Provides: time-daemon
Depends: libc6 (>= 2.34), systemd (= 249.11-0ubuntu3.4), adduser
Breaks: systemd (<< 245.4-2~)
Conflicts: time-daemon
Conffiles:
/etc/dhcp/dhclient-exit-hooks.d/timesyncd c66e563f4050725592e2da20a4e1bfef
/etc/systemd/timesyncd.conf 01ca3edea53f3dcc591db0c2f330b538
Description: minimalistic service to synchronize local time with NTP servers
The package contains the systemd-timesyncd system service that may be used to
synchronize the local system clock with a remote Network Time Protocol server.
Homepage: https://www.freedesktop.org/wiki/Software/systemd
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: sysvinit-utils
Essential: yes
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 83
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: sysvinit
Version: 3.01-1ubuntu1
Depends: lsb-base (>= 11.0.0~), libc6 (>= 2.34)
Description: System-V-like utilities
This package contains the important System-V-like utilities.
.
Specifically, this package includes:
init-d-script, fstab-decode, killall5, pidof
Homepage: https://savannah.nongnu.org/projects/sysvinit
Original-Maintainer: Debian sysvinit maintainers <debian-init-diversity@chiark.greenend.org.uk>

Package: tar
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 956
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.34+dfsg-1build3
Replaces: cpio (<< 2.4.2-39)
Pre-Depends: libacl1 (>= 2.2.23), libc6 (>= 2.34), libselinux1 (>= 3.1~)
Suggests: bzip2, ncompress, xz-utils, tar-scripts, tar-doc
Breaks: dpkg-dev (<< 1.14.26)
Conflicts: cpio (<= 2.4.2-38)
Description: GNU version of the tar archiving utility
Tar is a program for packaging a set of files as a single archive in tar
format. The function it performs is conceptually similar to cpio, and to
things like PKZIP in the DOS world. It is heavily used by the Debian package
management system, and is useful for performing system backups and exchanging
sets of files with others.
Homepage: https://www.gnu.org/software/tar/
Original-Maintainer: Janos Lenart <ocsi@debian.org>

Package: tcl
Status: install ok installed
Priority: optional
Section: interpreters
Installed-Size: 22
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: tcltk-defaults
Version: 8.6.11+1build2
Provides: tclsh
Depends: tcl8.6 (>= 8.6.11+dfsg-1~)
Breaks: tcl8.3 (<< 8.3.5-15), tcl8.4 (<< 8.4.20-2), tcl8.5 (<< 8.5.14-3), tcl8.6 (<< 8.6.0-2)
Description: Tool Command Language (default version) - shell
Tcl is a powerful, easy to use, embeddable, cross-platform interpreted
scripting language.
.
This package is a dependency package, which depends on Debian's default
Tcl version (currently 8.6).
Original-Maintainer: Debian Tcl/Tk Packagers <pkg-tcltk-devel@lists.alioth.debian.org>

Package: tcl8.6
Status: install ok installed
Priority: optional
Section: interpreters
Installed-Size: 49
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 8.6.12+dfsg-1build1
Depends: libc6 (>= 2.34), libtcl8.6 (>= 8.6.0)
Suggests: tcl-tclreadline
Conflicts: tcl74 (<= 7.4p3-2)
Description: Tcl (the Tool Command Language) v8.6 - shell
Tcl is a powerful, easy to use, embeddable, cross-platform interpreted
scripting language. This package contains the Tcl shell which you need
to run Tcl scripts. This version includes thread support.
Homepage: http://www.tcl.tk/
Original-Maintainer: Debian Tcl/Tk Packagers <pkg-tcltk-devel@lists.alioth.debian.org>

Package: tcpdump
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 1374
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 4.99.1-3build2
Replaces: apparmor-profiles-extra (<< 1.12~)
Depends: adduser, libc6 (>= 2.34), libpcap0.8 (>= 1.9.0), libssl3 (>= 3.0.0~~alpha1)
Suggests: apparmor (>= 2.3)
Breaks: apparmor-profiles-extra (<< 1.12~)
Conffiles:
/etc/apparmor.d/usr.bin.tcpdump 0b6ea9677363d3cfd073a4a52ef52cee
Description: command-line network traffic analyzer
This program allows you to dump the traffic on a network. tcpdump
is able to examine IPv4, ICMPv4, IPv6, ICMPv6, UDP, TCP, SNMP, AFS
BGP, RIP, PIM, DVMRP, IGMP, SMB, OSPF, NFS and many other packet
types.
.
It can be used to print out the headers of packets on a network
interface, filter packets that match a certain expression. You can
use this tool to track down network problems, to detect attacks
or to monitor network activities.
Homepage: https://www.tcpdump.org/
Original-Maintainer: Romain Francoise <rfrancoise@debian.org>

Package: telnet
Status: install ok installed
Priority: standard
Section: net
Installed-Size: 154
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: netkit-telnet
Version: 0.17-44build1
Replaces: netstd
Provides: telnet-client
Depends: libc6 (>= 2.34), libstdc++6 (>= 5), netbase
Description: basic telnet client
The telnet command is used for interactive communication with another host
using the TELNET protocol.
.
For the purpose of remote login, the present client executable should be
depreciated in favour of an ssh-client, or in some cases with variants like
telnet-ssl or Kerberized TELNET clients. The most important reason is that
this implementation exchanges user name and password in clear text.
.
On the other hand, the present program does satisfy common use cases of
network diagnostics, like protocol testing of SMTP services, so it can
become handy enough.
Homepage: http://www.hcs.harvard.edu/~dholland/computers/netkit.html
Original-Maintainer: Debian QA Group <packages@qa.debian.org>

Package: thin-provisioning-tools
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 1421
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.9.0-2ubuntu1
Depends: libaio1 (>= 0.3.93), libc6 (>= 2.34), libexpat1 (>= 2.0.1), libgcc-s1 (>= 3.0), libstdc++6 (>= 11)
Description: Tools for handling thinly provisioned device-mapper meta-data
This package contains tools to handle meta-data from the device-mapper
thin target. This target allows the use of a single backing store for multiple
thinly provisioned volumes. Numerous snapshots can be taken from such
volumes. The tools can check the meta-data for consistency, repair damaged
information and dump or restore the meta-data in textual form.
Original-Maintainer: Debian LVM Team <team+lvm@tracker.debian.org>

Package: tilix
Status: install ok installed
Priority: optional
Section: gnome
Installed-Size: 3415
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.9.4-2build1
Replaces: terminix (<< 1.5.4-1~)
Provides: x-terminal-emulator
Depends: tilix-common (= 1.9.4-2build1), dconf-gsettings-backend | gsettings-backend, libc6 (>= 2.34), libgtkd-3-0 (>= 3.10.0), libphobos2-ldc-shared98 (>= 1:1.28.0), libunwind8, libvted-3-0 (>= 3.10.0), libx11-6
Suggests: python-nautilus
Breaks: terminix (<< 1.5.4-1~)
Description: Tiling terminal emulator for GNOME
Tilix is a feature-rich tiling terminal emulator following the
GNOME human interface design guidelines.
Its many features include:
.

- Layout terminals in any fashion by splitting them horizontally or
  vertically.
- Terminals can be re-arranged using drag and drop both within and
  between windows.
- Terminals can be detached into a new window via drag and drop.
- Input can be synchronized between terminals so commands typed in
  one terminal are replicated to the others.
- Supports notifications when processes are completed out of view.
  Homepage: https://gnunn1.github.io/tilix-web/
  Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: tilix-common
Status: install ok installed
Priority: optional
Section: gnome
Installed-Size: 1422
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: tilix
Version: 1.9.4-2build1
Replaces: terminix-common (<< 1.5.4-1~)
Breaks: terminix-common (<< 1.5.4-1~)
Description: Tiling terminal emulator - data files
Tilix is a feature-rich tiling terminal emulator following the
GNOME human interface design guidelines.
.
This package contains architecture independent data.
Homepage: https://gnunn1.github.io/tilix-web/
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: time
Status: install ok installed
Priority: standard
Section: utils
Installed-Size: 126
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.9-0.1build2
Depends: libc6 (>= 2.34)
Description: GNU time program for measuring CPU resource usage
The 'time' command runs another program, then displays information
about the resources used by that program, collected by the system while
the program was running. You can select which information is reported
and the format in which it is shown, or have 'time' save the information
in a file instead of display it on the screen.
.
The resources that 'time' can report on fall into the general
categories of time, memory, I/O, and IPC calls.
.
The GNU version can format the output in arbitrary ways by using a
printf-style format string to include various resource measurements.
Homepage: https://www.gnu.org/software/time
Original-Maintainer: Bob Proulx <bob@proulx.com>

Package: tmux
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 1026
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 3.2a-4build1
Depends: libc6 (>= 2.34), libevent-core-2.1-7 (>= 2.1.8-stable), libtinfo6 (>= 6), libutempter0 (>= 1.1.5)
Description: terminal multiplexer
tmux enables a number of terminals (or windows) to be accessed and
controlled from a single terminal like screen. tmux runs as a
server-client system. A server is created automatically when necessary
and holds a number of sessions, each of which may have a number of
windows linked to it. Any number of clients may connect to a session,
or the server may be controlled by issuing commands with tmux.
Communication takes place through a socket, by default placed in /tmp.
Moreover tmux provides a consistent and well-documented command
interface, with the same syntax whether used interactively, as a key
binding, or from the shell. It offers a choice of vim or Emacs key
layouts.
Homepage: https://tmux.github.io/
Original-Maintainer: Romain Francoise <rfrancoise@debian.org>

Package: tnftp
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 231
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 20210827-4build1
Replaces: lukemftp
Provides: ftp
Depends: libc6 (>= 2.34), libedit2 (>= 2.11-20080614-0), libssl3 (>= 3.0.0~~alpha1)
Conflicts: lukemftp
Description: enhanced ftp client
tnftp is what many users affectionately call the enhanced ftp
client in NetBSD (http://www.netbsd.org).
.
This package is a `port' of the NetBSD ftp client to other systems. . The enhancements over the standard ftp client in 4.4BSD include: * command-line editing within ftp * command-line fetching of URLS, including support for: - http proxies (c.f: $http_proxy, $ftp_proxy) - authentication * context sensitive command and filename completion * dynamic progress bar * IPv6 support (from the WIDE project) * modification time preservation * paging of local and remote files, and of directory listings (c.f: `lpage', `page', `pdir')
_ passive mode support, with fallback to active mode
_ `set option' override of ftp environment variables * TIS Firewall Toolkit gate ftp proxy support (c.f: `gate') \* transfer-rate throttling (c.f: `-T', `rate')
Homepage: http://en.wikipedia.org/wiki/Tnftp
Original-Maintainer: xiao sheng wen <atzlinux@sina.com>

Package: tpm-udev
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 18
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 0.6
Depends: adduser, udev
Description: udev rules for TPM modules
This package provides udev rules for the TPM modules. Both TPM1 or TPM2 need
this package to be installed to provide proper permissions of the TPM.
Original-Maintainer: Ying-Chun Liu (PaulLiu) <paulliu@debian.org>

Package: tzdata
Status: install ok installed
Priority: required
Section: localization
Installed-Size: 3786
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2022c-0ubuntu0.22.04.0
Provides: tzdata-bookworm
Depends: debconf (>= 0.5) | debconf-2.0
Description: time zone and daylight-saving time data
This package contains data required for the implementation of
standard local time for many representative locations around the
globe. It is updated periodically to reflect changes made by
political bodies to time zone boundaries, UTC offsets, and
daylight-saving rules.
Homepage: https://www.iana.org/time-zones
Original-Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>

Package: ubuntu-advantage-tools
Status: install ok installed
Priority: important
Section: misc
Installed-Size: 694
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 27.10.1~22.04.1
Depends: debconf (>= 0.5) | debconf-2.0, python3-yaml, python3:any, libapt-pkg6.0 (>= 0.8.0), libc6 (>= 2.34), libgcc-s1 (>= 3.3.1), libjson-c5 (>= 0.15), libstdc++6 (>= 9), python3-apt, python3-pkg-resources, distro-info (>= 0.18ubuntu0.18.04.1)
Conffiles:
/etc/apt/apt.conf.d/20apt-esm-hook.conf 6de2d22c521bde4436fb69632b2474f5
/etc/logrotate.d/ubuntu-advantage-tools 852ec664fd0f1ecb26e726f5e801e9fd
/etc/ubuntu-advantage/help_data.yaml 11a66ff5144cbe43abfcb0a111f23a4f
/etc/ubuntu-advantage/uaclient.conf b784d56f8f03f9db486f8714591caf6a
/etc/update-manager/release-upgrades.d/ubuntu-advantage-upgrades.cfg 82b5d8872cdcde8d3a0f68112de703fa
/etc/update-motd.d/88-esm-announce 7f0b28e0686f924c5784bcb5dddc09d2
/etc/update-motd.d/91-contract-ua-esm-status 5845228f6642bb4ec1bc21410454f6ad
Description: management tools for Ubuntu Advantage
Ubuntu Advantage is the professional package of tooling, technology
and expertise from Canonical, helping organisations around the world
manage their Ubuntu deployments.
.
Subscribers to Ubuntu Advantage will find helpful tools for accessing
services in this package.
Homepage: https://ubuntu.com/advantage

Package: ubuntu-keyring
Status: install ok installed
Priority: important
Section: misc
Installed-Size: 41
Maintainer: Dimitri John Ledkov <dimitri.ledkov@canonical.com>
Architecture: all
Multi-Arch: foreign
Version: 2021.03.26
Replaces: ubuntu-cloudimage-keyring (<< 2018.02.05)
Breaks: ubuntu-cloudimage-keyring (<< 2018.02.05)
Description: GnuPG keys of the Ubuntu archive
The Ubuntu project digitally signs its Release files. This package
contains the archive keys used for that.

Package: ubuntu-minimal
Status: install ok installed
Priority: important
Section: metapackages
Installed-Size: 53
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: ubuntu-meta
Version: 1.481
Depends: adduser, apt, apt-utils, console-setup, debconf, debconf-i18n, e2fsprogs, eject, init, iproute2, iputils-ping, isc-dhcp-client, kbd, kmod, less, locales, lsb-release, mawk, mount, netbase, netcat-openbsd, netplan.io, passwd, procps, python3, sensible-utils, sudo, tzdata, ubuntu-advantage-tools, ubuntu-keyring, udev, vim-tiny, whiptail
Recommends: rsyslog, usrmerge
Description: Minimal core of Ubuntu
This package depends on all of the packages in the Ubuntu minimal system,
that is a functional command-line system with the following capabilities:
.

- Boot
- Detect hardware
- Connect to a network
- Install packages
- Perform basic diagnostics
  .
  It is also used to help ensure proper upgrades, so it is recommended that
  it not be removed.

Package: ubuntu-mono
Status: install ok installed
Priority: optional
Section: gnome
Installed-Size: 5587
Maintainer: Ubuntu Artwork Team <ubuntu-art@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: ubuntu-themes
Version: 20.10-0ubuntu2
Depends: adwaita-icon-theme, hicolor-icon-theme, humanity-icon-theme
Description: Ubuntu Mono Icon theme
Dark and Light panel icons to make your desktop beautiful.
Homepage: https://launchpad.net/ubuntu-themes

Package: ubuntu-release-upgrader-core
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 340
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: ubuntu-release-upgrader
Version: 1:22.04.13
Replaces: update-manager (<< 1:0.165), update-manager-core (<< 1:0.165)
Depends: python3:any, python3-distupgrade (= 1:22.04.13), ca-certificates
Recommends: libpam-modules (>= 1.0.1-9ubuntu3)
Breaks: software-properties (<< 0.9.27), update-manager (<< 1:0.165), update-manager-core (<< 1:0.165)
Conffiles:
/etc/update-manager/meta-release 25ba16c3215bff43f0272d3d93103f15
/etc/update-manager/release-upgrades 54fd85e86c6bc2db8d7cc3c18013e3aa
/etc/update-motd.d/91-release-upgrade 6147b099ff496ef5949d94451791bc4b
Description: manage release upgrades
This is the core of the Ubuntu Release Upgrader

Package: ubuntu-server
Status: install ok installed
Priority: optional
Section: metapackages
Installed-Size: 53
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: ubuntu-meta
Version: 1.481
Depends: apport, bcache-tools, btrfs-progs, byobu, cloud-guest-utils, cloud-initramfs-copymods, cloud-initramfs-dyn-netconf, curl, dirmngr, ethtool, fonts-ubuntu-console, git, gnupg, htop, lvm2, mdadm, motd-news-config, multipath-tools, overlayroot, patch, pollinate, screen, software-properties-common, sosreport, tmux, update-notifier-common, vim, xfsprogs
Recommends: fwupd, landscape-common, lxd-agent-loader, needrestart, open-iscsi, open-vm-tools, snapd, unattended-upgrades
Description: The Ubuntu Server system
This package depends on all of the packages in the Ubuntu Server system
.
It is also used to help ensure proper upgrades, so it is recommended that
it not be removed.

Package: ubuntu-standard
Status: install ok installed
Priority: optional
Section: metapackages
Installed-Size: 53
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: ubuntu-meta
Version: 1.481
Depends: bind9-dnsutils, busybox-static, cpio, cron, dmidecode, dosfstools, ed, file, ftp, hdparm, info, libpam-systemd, logrotate, lshw, lsof, man-db, media-types, nftables, parted, pciutils, psmisc, rsync, strace, time, usbutils, wget, xz-utils
Recommends: apparmor, bash-completion, command-not-found, friendly-recovery, iptables, iputils-tracepath, irqbalance, manpages, mtr-tiny, nano, ntfs-3g, openssh-client, plymouth, plymouth-theme-ubuntu-text, tcpdump, telnet, ufw, update-manager-core, uuid-runtime
Description: The Ubuntu standard system
This package depends on all of the packages in the Ubuntu standard system.
This set of packages provides a comfortable command-line Unix-like
environment.
.
It is also used to help ensure proper upgrades, so it is recommended that
it not be removed.

Package: ubuntu-wsl
Status: install ok installed
Priority: optional
Section: metapackages
Installed-Size: 53
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: ubuntu-meta
Version: 1.481
Depends: apport, binutils, byobu, curl, dirmngr, fonts-ubuntu, git, gnupg, htop, patch, screen, software-properties-common, tmux, vim, wsl-setup
Recommends: dbus-x11, motd-news-config, show-motd, snapd, unattended-upgrades
Description: Ubuntu on Windows tools - Windows Subsystem for Linux integration
Utilities for integrating Ubuntu well into the WSL environment.
.
It is also used to help ensure proper upgrades, so it is recommended that
it not be removed.

Package: ucf
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 232
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.0043
Depends: debconf (>= 1.5.19), coreutils (>= 5.91), sensible-utils
Conffiles:
/etc/ucf.conf 5565b8b26108c49ba575ba452cd69b3e
Description: Update Configuration File(s): preserve user changes to config files
Debian policy mandates that user changes to configuration files must be
preserved during package upgrades. The easy way to achieve this behavior
is to make the configuration file a 'conffile', in which case dpkg
handles the file specially during upgrades, prompting the user as
needed.
.
This is appropriate only if it is possible to distribute a default
version that will work for most installations, although some system
administrators may choose to modify it. This implies that the
default version will be part of the package distribution, and must
not be modified by the maintainer scripts during installation (or at
any other time).
.
This script attempts to provide conffile-like handling for files that
may not be labelled conffiles, and are not shipped in a Debian package,
but handled by the postinst instead. This script allows one to
maintain files in /etc, preserving user changes and in general
offering the same facilities while upgrading that dpkg normally
provides for 'conffiles'.
.
Additionally, this script provides facilities for transitioning a
file that had not been provided with conffile-like protection to come
under this schema, and attempts to minimize questions asked at
installation time. Indeed, the transitioning facility is better than the
one offered by dpkg while transitioning a file from a non-conffile to
conffile status.
Original-Maintainer: Manoj Srivastava <srivasta@debian.org>

Package: udev
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 9497
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: systemd
Version: 249.11-0ubuntu3.4
Depends: libacl1 (>= 2.2.23), libblkid1 (>= 2.37.2), libc6 (>= 2.34), libcap2 (>= 1:2.24-9~), libkmod2 (>= 5~), libselinux1 (>= 3.1~), adduser, libudev1 (= 249.11-0ubuntu3.4), util-linux (>= 2.27.1)
Breaks: systemd (<< 249.11-0ubuntu3.4)
Conflicts: hal
Conffiles:
/etc/init.d/udev e9424814d107af7d8f58a22b1011810a
/etc/udev/udev.conf bf60be80a4cc51271a1618edf5a6d66f
Description: /dev/ and hotplug management daemon
udev is a daemon which dynamically creates and removes device nodes from
/dev/, handles hotplug events and loads drivers at boot time.
Homepage: https://www.freedesktop.org/wiki/Software/systemd
Original-Maintainer: Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>

Package: udisks2
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 1176
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.9.4-1ubuntu2
Depends: dbus, libblockdev-fs2, libblockdev-loop2, libblockdev-part2, libblockdev-swap2, parted, udev, libacl1 (>= 2.2.23), libatasmart4 (>= 0.13), libblockdev-utils2 (>= 2.24), libblockdev2 (>= 2.25), libc6 (>= 2.34), libglib2.0-0 (>= 2.50), libgudev-1.0-0 (>= 165), libmount1 (>= 2.30), libpolkit-agent-1-0 (>= 0.102), libpolkit-gobject-1-0 (>= 0.102), libsystemd0 (>= 209), libudisks2-0 (>= 2.9.0), libuuid1 (>= 2.16)
Recommends: dosfstools, e2fsprogs, eject, libblockdev-crypto2, ntfs-3g, policykit-1, libpam-systemd
Suggests: btrfs-progs, f2fs-tools, libblockdev-mdraid2, mdadm, nilfs-tools, reiserfsprogs, udftools, udisks2-bcache, udisks2-btrfs, udisks2-lvm2, udisks2-zram, xfsprogs, exfatprogs
Conffiles:
/etc/udisks2/mount_options.conf.example 590c5abc453c373b1db7e4ded4af43d1
/etc/udisks2/udisks2.conf cdca35d6490b9ff83f095070039ec117
Description: D-Bus service to access and manipulate storage devices
The udisks daemon serves as an interface to system block devices,
implemented via D-Bus. It handles operations such as querying, mounting,
unmounting, formatting, or detaching storage devices such as hard disks
or USB thumb drives.
.
This package also provides the udisksctl utility, which can be used to
trigger these operations from the command line (if permitted by
PolicyKit).
.
Creating or modifying file systems such as XFS, RAID, or LUKS encryption
requires that the corresponding mkfs.\* and admin tools are installed, such as
dosfstools for VFAT, xfsprogs for XFS, or cryptsetup for LUKS.
Homepage: https://www.freedesktop.org/wiki/Software/udisks
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

Package: ufw
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 830
Maintainer: Jamie Strandboge <jdstrand@ubuntu.com>
Architecture: all
Version: 0.36.1-4build1
Depends: iptables, lsb-base (>= 3.0-6), ucf, python3:any, debconf (>= 0.5) | debconf-2.0
Suggests: rsyslog
Conffiles:
/etc/default/ufw a921dd9d167380b04de4bc911915ea44
/etc/init.d/ufw 4156943ab8a824fcf4b04cc1362eb230
/etc/logrotate.d/ufw 969308e0ddfb74505f0da47b49ada218
/etc/rsyslog.d/20-ufw.conf 98e2f72c9c65ca8d6299886b524e80d1
/etc/ufw/sysctl.conf 7723079fc108eda8f57eddab3079c70a
Description: program for managing a Netfilter firewall
The Uncomplicated FireWall is a front-end for iptables, to make managing a
Netfilter firewall easier. It provides a command line interface with syntax
similar to OpenBSD's Packet Filter. It is particularly well-suited as a
host-based firewall.
Homepage: https://launchpad.net/ufw

Package: unattended-upgrades
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 436
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 2.8ubuntu1
Depends: debconf (>= 0.5) | debconf-2.0, debconf, python3, python3-apt (>= 1.9.6~), python3-dbus, python3-distro-info, ucf, lsb-release, lsb-base, xz-utils
Recommends: systemd-sysv | cron | cron-daemon | anacron
Suggests: bsd-mailx, default-mta | mail-transport-agent, needrestart, powermgmt-base, python3-gi
Conffiles:
/etc/init.d/unattended-upgrades 290829a5efc55b7c435de0bb769f217b
/etc/kernel/postinst.d/unattended-upgrades f296826482cb797aeef13554e093dbca
/etc/logrotate.d/unattended-upgrades e45049ee847f069a99e3e6ec39155d4a
/etc/pm/sleep.d/10_unattended-upgrades-hibernate 0f5d54aa2dd322c805c90e409fc2724a
/etc/update-motd.d/92-unattended-upgrades afa7546d3fe561e1f5783f7b9cf72096
Description: automatic installation of security upgrades
This package can download and install security upgrades automatically
and unattended, taking care to only install packages from the
configured APT source, and checking for dpkg prompts about
configuration file changes.
.
This script is the backend for the APT::Periodic::Unattended-Upgrade
option.
Original-Maintainer: Michael Vogt <mvo@debian.org>

Package: update-manager-core
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 192
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Source: update-manager
Version: 1:22.04.9
Replaces: update-manager (<< 1:0.146.2)
Depends: python3:any (>= 3.2~), python3-update-manager (= 1:22.04.9), python3-distro-info, distro-info-data, lsb-release, ubuntu-release-upgrader-core (>= 1:18.04.9), ubuntu-advantage-tools
Recommends: libpam-modules (>= 1.0.1-9ubuntu3)
Breaks: computer-janitor (<= 1.11-0ubuntu1), update-manager (<< 1:0.146.2)
Description: manage release upgrades
This is the core of update-manager and the release upgrader

Package: update-motd
Status: install ok installed
Priority: extra
Section: admin
Installed-Size: 22
Maintainer: Dustin Kirkland <kirkland@ubuntu.com>
Architecture: all
Version: 3.10
Depends: libpam-modules (>= 1.0.1-9ubuntu3)
Description: complements pam_motd in libpam-modules
.
This package installs a script that immediately dynamically generates
a message-of-the-day by running scripts installed in /etc/update-motd.d,
in lexical order.
.
Other packages, or system administrators should symlink scripts into
/etc/update-motd.d, pre-pending a 2-digit number to handle ordering.
.
The functionality formerly provided by this package is now integrated into
pam_motd, in libpam-modules.

Package: update-notifier-common
Status: install ok installed
Priority: optional
Section: gnome
Installed-Size: 1137
Maintainer: Michael Vogt <michael.vogt@ubuntu.com>
Architecture: all
Source: update-notifier
Version: 3.192.54
Replaces: update-notifier (<< 0.75.1)
Depends: python3:any, python3-apt, python3-dbus, python3-debian, python3-debconf | debconf (<< 1.5.64~), python3-distro-info, lsb-release, patch, update-manager-core (>= 1:17.04.2)
Pre-Depends: dpkg (>= 1.15.7.2), apt (>= 1.1~)
Recommends: libpam-modules (>= 1.0.1-9ubuntu3)
Suggests: policykit-1
Conffiles:
/etc/apt/apt.conf.d/10periodic 03ddb526e156071de0667748b6ac1d33
/etc/apt/apt.conf.d/15update-stamp b9de0ac9e2c9854b1bb213e362dc4e41
/etc/apt/apt.conf.d/20archive 9e28a07261e6ad5ede22d5286291ca23
/etc/apt/apt.conf.d/99update-notifier 8c8636b1123964162e9a1127f237ba7b
/etc/update-motd.d/90-updates-available eaddabe4cbd443e9da6b14452b0a8fe5
/etc/update-motd.d/95-hwe-eol 0205f1a3306acc0b76f0b0a0fb6462c3
/etc/update-motd.d/98-fsck-at-reboot 16003ee8c8c80a565a98a7696cee04c0
/etc/update-motd.d/98-reboot-required 1c4d534d0abd44d566899e47c4f22786
Description: Files shared between update-notifier and other packages
Apt setup files and reboot notification scripts shared between
update-notifier and other packages, notably for server use cases.

Package: usb-modeswitch
Status: install ok installed
Priority: optional
Section: comm
Installed-Size: 139
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2.6.1-3ubuntu2
Depends: tcl, usb-modeswitch-data, libc6 (>= 2.34), libusb-1.0-0 (>= 2:1.0.9)
Suggests: comgt, wvdial
Conffiles:
/etc/usb_modeswitch.conf b7f857804762b4a81a71c93a2fe1207f
Description: mode switching tool for controlling "flip flop" USB devices
Several new USB devices have their proprietary Windows drivers onboard,
especially WAN dongles. When plugged in for the first time, they act
like a flash storage and start installing the driver from there. If
the driver is already installed, the storage device vanishes and
a new device, such as an USB modem, shows up. This is called the
"ZeroCD" feature.
.
On Debian, this is not needed, since the driver is included as a
Linux kernel module, such as "usbserial". However, the device still
shows up as "usb-storage" by default. usb-modeswitch solves that
issue by sending the command which actually performs the switching
of the device from "usb-storage" to "usbserial".
.
This package contains the binaries and the brother scripts.
Homepage: https://www.draisberghof.de/usb_modeswitch/
Original-Maintainer: Thorsten Alteholz <debian@alteholz.de>

Package: usb-modeswitch-data
Status: install ok installed
Priority: optional
Section: comm
Installed-Size: 94
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Version: 20191128-4
Replaces: usb-modeswitch-data-packed
Provides: usb-modeswitch-data-packed
Recommends: udev, usb-modeswitch (>= 2.4.0)
Breaks: usb-modeswitch (<< 2.4.0)
Conflicts: usb-modeswitch-data-packed
Description: mode switching data for usb-modeswitch
Several new USB devices have their proprietary Windows drivers onboard,
especially WAN dongles. When plugged in for the first time, they act
like a flash storage and start installing the driver from there. If
the driver is already installed, the storage device vanishes and
a new device, such as an USB modem, shows up. This is called the
"ZeroCD" feature.
.
On Debian, this is not needed, since the driver is included as a
Linux kernel module, such as "usbserial". However, the device still
shows up as "usb-storage" by default. usb-modeswitch solves that
issue by sending the command which actually performs the switching
of the device from "usb-storage" to "usbserial".
.
This package contains the commands data needed for usb-modeswitch.
Original-Maintainer: Debian QA Group <packages@qa.debian.org>
Homepage: https://www.draisberghof.de/usb_modeswitch/

Package: usb.ids
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 715
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 2022.04.02-1
Replaces: usbutils (<< 1:008-1)
Breaks: usbutils (<< 1:008-1)
Description: USB ID Repository
This package contains the usb.ids file, a public repository of all known
ID's used in USB devices: ID's of vendors, devices, subsystems and device
classes. It is used in various programs to display full human-readable
names instead of cryptic numeric codes.
Original-Maintainer: Aurelien Jarno <aurel32@debian.org>
Homepage: http://www.linux-usb.org/usb-ids.html

Package: usbutils
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 325
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1:014-1build1
Depends: libc6 (>= 2.34), libudev1 (>= 196), libusb-1.0-0 (>= 2:1.0.22)
Breaks: hwdata (<< 0.334-1~), isenkram (<< 0.45~), kinfocenter (<< 4:5.14.5-2~), libosinfo-1.0-0 (<< 1.8.0-1~), usbip (<< 2.0+5.10.4-1~)
Description: Linux USB utilities
This package contains the lsusb utility for inspecting the devices
connected to the USB bus. It shows a graphical representation of the
devices that are currently plugged in, showing the topology of the
USB bus. It also displays information on each individual device on
the bus.
Homepage: https://github.com/gregkh/usbutils
Original-Maintainer: Aurelien Jarno <aurel32@debian.org>

Package: usrmerge
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 200
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 25ubuntu2
Depends: perl-base (>= 5.32.1-3)
Breaks: cruft-ng (<< 0.4.4~), initramfs-tools (<< 0.121~)
Conflicts: acl (<< 2.2.52-3~), arptables (<< 0.0.4+snapshot20181021-1~), coreutils (<< 8.24-1~), cryptsetup (<< 2:1.7.0-1~), davfs2 (<< 1.5.2-1.2~), debianutils (<< 4.5~), ebtables (<< 2.0.10.4+snapshot20181205-1~), elvis-tiny (<< 1.4-24~), kbd (<< 2.0.3-1~), ksh (<< 93u+20120801-3.1~), less (<< 481-2~), libbrlapi-dev (<< 5.3.1-1~), libdm0-dev, libjson-c-dev (<< 0.12.1-1.1~), libpng12-0 (<< 1.2.54-4~), libusb-0.1-4 (<< 2:0.1.12-28~), mksh (<< 52b-1~), molly-guard (<< 0.7.1+exp1~), musl-dev (<< 1.1.9-1.1~), nano (<< 2.3.99pre3-1~), open-iscsi (<< 2.0.873+git0.3b4b4500-13~), open-vm-tools (<< 2:10.0.5-3227872-2~), policycoreutils (<< 2.4-4~), safe-rm (<< 0.12-6~), tcsh (<< 6.18.01-4~), vsearch (<< 1.9.5-2~), xfsdump (<< 3.1.6+nmu1~), xfslibs-dev (<< 4.9.0+nmu1~), yp-tools (<< 3.3-5~), zsh (<< 5.2-4~)
Description: Convert the system to the merged /usr directories scheme
This package will automatically convert the system to the merged
/usr directory scheme, in which the /{bin,sbin,lib}/ directories are
symlinked to their counterparts in /usr/.
.
There is no automatic method to restore the precedent configuration, so
there is no going back once this package has been installed.
Homepage: https://wiki.debian.org/UsrMerge
Original-Maintainer: Marco d'Itri <md@linux.it>

Package: util-linux
Essential: yes
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 3399
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 2.37.2-4ubuntu3
Replaces: hardlink
Provides: hardlink
Pre-Depends: libaudit1 (>= 1:2.2.1), libblkid1 (>= 2.37.2), libc6 (>= 2.34), libcap-ng0 (>= 0.7.9), libcrypt1 (>= 1:4.1.0), libmount1 (>= 2.37.2), libpam0g (>= 0.99.7.1), libselinux1 (>= 3.1~), libsmartcols1 (>= 2.34), libsystemd0, libtinfo6 (>= 6), libudev1 (>= 183), libuuid1 (>= 2.16), zlib1g (>= 1:1.1.4)
Suggests: dosfstools, kbd, util-linux-locales
Conflicts: hardlink
Conffiles:
/etc/init.d/hwclock.sh c06bc68c12cbdd9c7f60ba25ee587efe
/etc/pam.d/runuser b8b44b045259525e0fae9e38fdb2aeeb
/etc/pam.d/runuser-l 2106ea05877e8913f34b2c77fa02be45
/etc/pam.d/su 60fbbe65c90d741bc0d380543cefe8af
/etc/pam.d/su-l 756fef5687fecc0d986e5951427b0c4f
Description: miscellaneous system utilities
This package contains a number of important utilities, most of which
are oriented towards maintenance of your system. Some of the more
important utilities included in this package allow you to view kernel
messages, create new filesystems, view block device information,
interface with real time clock, etc.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: uuid-runtime
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 197
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: util-linux
Version: 2.37.2-4ubuntu3
Depends: adduser, libc6 (>= 2.34), libsmartcols1 (>= 2.27~rc1), libsystemd0, libuuid1 (>= 2.31.1)
Pre-Depends: libuuid1, init-system-helpers (>= 1.54~)
Conffiles:
/etc/init.d/uuidd 29b6e6ae2de1365c06806e18f18d8fab
Description: runtime components for the Universally Unique ID library
The libuuid library generates and parses 128-bit Universally Unique
IDs (UUIDs). A UUID is an identifier that is unique within the space
of all such identifiers across both space and time. It can be used for
multiple purposes, from tagging objects with an extremely short lifetime
to reliably identifying very persistent objects across a network.
.
See RFC 4122 for more information.
.
This package contains the uuidgen program and the uuidd daemon.
.
The uuidd daemon is used to generate UUIDs, especially time-based
UUIDs, in a secure and guaranteed-unique fashion, even in the face of
large numbers of threads trying to grab UUIDs running on different CPUs.
It is used by libuuid as well as the uuidgen program.
Homepage: https://www.kernel.org/pub/linux/utils/util-linux/
Original-Maintainer: util-linux packagers <util-linux@packages.debian.org>

Package: vim
Status: install ok installed
Priority: optional
Section: editors
Installed-Size: 3916
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 2:8.2.3995-1ubuntu2
Provides: editor
Depends: vim-common (= 2:8.2.3995-1ubuntu2), vim-runtime (= 2:8.2.3995-1ubuntu2), libacl1 (>= 2.2.23), libc6 (>= 2.34), libgpm2 (>= 1.20.7), libpython3.10 (>= 3.10.0), libselinux1 (>= 3.1~), libsodium23 (>= 1.0.14), libtinfo6 (>= 6)
Suggests: ctags, vim-doc, vim-scripts
Description: Vi IMproved - enhanced vi editor
Vim is an almost compatible version of the UNIX editor Vi.
.
Many new features have been added: multi level undo, syntax
highlighting, command line history, on-line help, filename
completion, block operations, folding, Unicode support, etc.
.
This package contains a version of vim compiled with a rather
standard set of features. This package does not provide a GUI
version of Vim. See the other vim-\* packages if you need more
(or less).
Homepage: https://www.vim.org/
Original-Maintainer: Debian Vim Maintainers <team+vim@tracker.debian.org>

Package: vim-common
Status: install ok installed
Priority: important
Section: editors
Installed-Size: 376
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: vim
Version: 2:8.2.3995-1ubuntu2
Depends: xxd
Recommends: vim | vim-gtk3 | vim-athena | vim-nox | vim-tiny
Conffiles:
/etc/vim/vimrc e782ef3054004f773d556475cfad5870
Description: Vi IMproved - Common files
Vim is an almost compatible version of the UNIX editor Vi.
.
This package contains files shared by all non GUI-enabled vim variants
available in Debian. Examples of such shared files are: manpages and
configuration files.
Homepage: https://www.vim.org/
Original-Maintainer: Debian Vim Maintainers <team+vim@tracker.debian.org>

Package: vim-runtime
Status: install ok installed
Priority: optional
Section: editors
Installed-Size: 32777
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: vim
Version: 2:8.2.3995-1ubuntu2
Recommends: vim | vim-gtk3 | vim-athena | vim-nox | vim-tiny
Breaks: vim-tiny (<< 2:8.2.3995-1ubuntu2)
Enhances: vim-tiny
Description: Vi IMproved - Runtime files
Vim is an almost compatible version of the UNIX editor Vi.
.
This package contains vimtutor and the architecture independent runtime
files, used, if available, by all vim variants available in Debian.
Example of such runtime files are: online documentation, rules for
language-specific syntax highlighting and indentation, color schemes,
and standard plugins.
Homepage: https://www.vim.org/
Original-Maintainer: Debian Vim Maintainers <team+vim@tracker.debian.org>

Package: vim-tiny
Status: install ok installed
Priority: important
Section: editors
Installed-Size: 1718
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: vim
Version: 2:8.2.3995-1ubuntu2
Provides: editor
Depends: vim-common (= 2:8.2.3995-1ubuntu2), libacl1 (>= 2.2.23), libc6 (>= 2.34), libselinux1 (>= 3.1~), libtinfo6 (>= 6)
Suggests: indent
Conffiles:
/etc/vim/vimrc.tiny d587d5897899e491dae0f4a7b780642a
Description: Vi IMproved - enhanced vi editor - compact version
Vim is an almost compatible version of the UNIX editor Vi.
.
This package contains a minimal version of Vim compiled with no GUI and
a small subset of features. This package's sole purpose is to provide
the vi binary for base installations.
.
If a vim binary is wanted, try one of the following more featureful
packages: vim, vim-nox, vim-athena, or vim-gtk3.
Homepage: https://www.vim.org/
Original-Maintainer: Debian Vim Maintainers <team+vim@tracker.debian.org>

Package: wamerican
Status: install ok installed
Priority: standard
Section: text
Installed-Size: 1004
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: scowl
Version: 2020.12.07-2
Provides: wordlist
Depends: debconf (>= 0.5) | debconf-2.0
Description: American English dictionary words for /usr/share/dict
This package provides the file /usr/share/dict/american-english
containing a list of English words with American spellings.
This list can be used by spelling checkers, and by programs such
as look(1).
.
There are also -small, -large, and -huge versions of this word list,
and there are wbritish* and wcanadian* packages as well.
Original-Maintainer: Don Armstrong <don@debian.org>
Homepage: http://wordlist.sourceforge.net/

Package: wbritish
Status: install ok installed
Priority: optional
Section: text
Installed-Size: 996
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: scowl
Version: 2020.12.07-2
Provides: wordlist
Depends: dictionaries-common (>= 0.20), debconf (>= 0.5) | debconf-2.0
Description: British English dictionary words for /usr/share/dict
This package provides the file /usr/share/dict/british-english
containing a list of English words with British spellings.
This list can be used by spelling checkers, and by programs such
as look(1).
.
There are also -small, -large, and -huge versions of this word list,
and there are wamerican* and wcanadian* packages as well.
Original-Maintainer: Don Armstrong <don@debian.org>
Homepage: http://wordlist.sourceforge.net/

Package: wget
Status: install ok installed
Priority: standard
Section: web
Installed-Size: 984
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1.21.2-2ubuntu1
Depends: libc6 (>= 2.34), libidn2-0 (>= 0.6), libpcre2-8-0 (>= 10.22), libpsl5 (>= 0.16.0), libssl3 (>= 3.0.0~~alpha1), libuuid1 (>= 2.16), zlib1g (>= 1:1.1.4)
Recommends: ca-certificates
Conflicts: wget-ssl
Conffiles:
/etc/wgetrc c43064699caf6109f4b3da0405c06ebb
Description: retrieves files from the web
Wget is a network utility to retrieve files from the web
using HTTP(S) and FTP, the two most widely used internet
protocols. It works non-interactively, so it will work in
the background, after having logged off. The program supports
recursive retrieval of web-authoring pages as well as FTP
sites -- you can use Wget to make mirrors of archives and
home pages or to travel the web like a WWW robot.
.
Wget works particularly well with slow or unstable connections
by continuing to retrieve a document until the document is fully
downloaded. Re-getting files from where it left off works on
servers (both HTTP and FTP) that support it. Both HTTP and FTP
retrievals can be time stamped, so Wget can see if the remote
file has changed since the last retrieval and automatically
retrieve the new version if it has.
.
Wget supports proxy servers; this can lighten the network load,
speed up retrieval, and provide access behind firewalls.
Homepage: https://www.gnu.org/software/wget/
Original-Maintainer: Noël Köthe <noel@debian.org>

Package: whiptail
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 72
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: newt
Version: 0.52.21-5ubuntu2
Depends: libc6 (>= 2.34), libnewt0.52 (>= 0.52.21), libpopt0 (>= 1.14), libslang2 (>= 2.2.4)
Description: Displays user-friendly dialog boxes from shell scripts
Whiptail is a "dialog" replacement using newt instead of ncurses. It
provides a method of displaying several different types of dialog boxes
from shell scripts. This allows a developer of a script to interact with
the user in a much friendlier manner.
Homepage: https://pagure.io/newt
Original-Maintainer: Alastair McKinstry <mckinstry@debian.org>

Package: wsl-setup
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 28
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 0.2
Depends: libc6 (>= 2.34), libsystemd0 (>= 221)
Description: WSL setup snap launcher
This package helps setting up a mock snap environment on WSL to start
the ubuntu-desktop-installer in system_setup mode.
It will be deprecated once snap is supported on WSL.
Homepage: https://github.com/ubuntu/wsl-setup

Package: x11-common
Status: install ok installed
Priority: optional
Section: x11
Installed-Size: 311
Maintainer: Ubuntu X-SWAT <ubuntu-x@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: xorg
Version: 1:7.7+23ubuntu2
Depends: lsb-base (>= 1.3-9ubuntu2)
Conffiles:
/etc/X11/Xreset 05d188ccac2f3360af8fe0c216640233
/etc/X11/Xreset.d/README b344c222b5daf81926fd3270df374b5f
/etc/X11/Xresources/x11-common b640adb1cd646ec097f8df5b6deca9f0
/etc/X11/Xsession 1ec5f844cc2d850a8d98aed509e3198c
/etc/X11/Xsession.d/20x11-common_process-args 6957432229b7305a40cb84a7a63edd4e
/etc/X11/Xsession.d/30x11-common_xresources 61cebe25ee0c64e981b88958dfee6f9c
/etc/X11/Xsession.d/35x11-common_xhost-local 3080616d080574d7b06c2b2a20af53dd
/etc/X11/Xsession.d/40x11-common_xsessionrc db544c8543d1cb3762b9859288e77040
/etc/X11/Xsession.d/50x11-common_determine-startup b4570043736ae7f22947067b6d28ab8d
/etc/X11/Xsession.d/60x11-common_xdg_path b4d4976a8dfa6ca2123f840fbfee76c7
/etc/X11/Xsession.d/90x11-common_ssh-agent 71116d351e6eab4ecce9b84229a4ece0
/etc/X11/Xsession.d/99x11-common_start 3874d5e8f3ec888f69adb126e223e168
/etc/X11/Xsession.options 210cd520efa87a5197cac01e10b3a84a
/etc/X11/rgb.txt 09ee098b83d94c7c046d6b55ebe84ae1
/etc/init.d/x11-common b121acab13ded0fb7e9bc90ad55c9a43
Description: X Window System (X.Org) infrastructure
x11-common contains the filesystem infrastructure required for further
installation of the X Window System in any configuration; it does not
provide a full installation of clients, servers, libraries, and utilities
required to run the X Window System.
.
A number of terms are used to refer to the X Window System, including "X",
"X Version 11", "X11", "X11R6", and "X11R7". The version of X used in
Debian is derived from the version released by the X.Org Foundation, and
is thus often also referred to as "X.Org". All of the preceding quoted
terms are functionally interchangeable in an Debian system.
Homepage: https://www.x.org/
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: x11-utils
Status: install ok installed
Priority: optional
Section: x11
Installed-Size: 709
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 7.7+5build2
Depends: libc6 (>= 2.34), libfontconfig1 (>= 2.12.6), libfontenc1 (>= 1:1.1.4), libgl1, libx11-6, libx11-xcb1 (>= 2:1.7.2), libxaw7 (>= 2:1.0.14), libxcb-shape0, libxcb1 (>= 1.6), libxcomposite1 (>= 1:0.4.5), libxext6, libxft2 (>> 2.1.1), libxi6, libxinerama1 (>= 2:1.1.4), libxkbfile1 (>= 1:1.1.0), libxmu6 (>= 2:1.1.3), libxmuu1 (>= 2:1.1.3), libxrandr2 (>= 2:1.2.0), libxrender1, libxt6 (>= 1:1.1.0), libxtst6, libxv1, libxxf86dga1, libxxf86vm1
Suggests: mesa-utils
Conffiles:
/etc/X11/app-defaults/Editres 52c854cc7c64da8bebd2cc12ed598f55
/etc/X11/app-defaults/Editres-color 5ec5d0e8c953faaa06af647650f30ce6
/etc/X11/app-defaults/Viewres 4f77da598593ff07cda9d2d147a07772
/etc/X11/app-defaults/Viewres-color ff9c397a80443790a97b909050f63282
/etc/X11/app-defaults/XFontSel 183bca665ae87e3943bdb4362d21973d
/etc/X11/app-defaults/Xfd a8b4d28d2ad895e40cfb6fb9c69eeecd
/etc/X11/app-defaults/Xmessage eed84b35dde8b18e7dcfc80e75c1da67
/etc/X11/app-defaults/Xmessage-color ca383db9e4e9648bda0952ad6b8a2115
Description: X11 utilities
An X client is a program that interfaces with an X server (almost always via
the X libraries), and thus with some input and output hardware like a
graphics card, monitor, keyboard, and pointing device (such as a mouse).
.
This package provides a miscellaneous assortment of X utilities
that ship with the X Window System, including:

- appres, editres, listres and viewres, which query the X resource database;
- luit, a filter that can be run between an arbitrary application and a
  UTF-8 terminal emulator;
- xdpyinfo, a display information utility for X;
- xdriinfo, query configuration information of DRI drivers;
- xev, an X event displayer;
- xfd, a tool that displays all the glyphs in a given X font;
- xfontsel, a tool for browsing and selecting X fonts;
- xkill, a tool for terminating misbehaving X clients;
- xlsatoms, which lists interned atoms defined on an X server;
- xlsclients, which lists client applications running on an X display;
- xlsfonts, a server font list displayer;
- xmessage, a tool to display message or dialog boxes;
- xprop, a property displayer for X;
- xvinfo, an Xv extension information utility for X;
- xwininfo, a window information utility for X;
  .
  The editres and viewres programs use bitmap images provided by the
  xbitmaps package. The luit program requires locale information from
  the libx11-data package.
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: x11-xserver-utils
Status: install ok installed
Priority: optional
Section: x11
Installed-Size: 567
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 7.7+9build1
Replaces: iceauth, sessreg, xbase-clients (<< 1:7.3), xgamma, xhost, xmodmap, xrandr, xrdb, xrefresh, xrgb, xset, xsetmode, xsetpointer, xsetroot, xstdcmap, xutils (<< 1:7.2), xvidtune
Depends: libc6 (>= 2.34), libice6 (>= 1:1.0.0), libx11-6, libxaw7 (>= 2:1.0.14), libxcursor1 (>> 1.1.2), libxext6, libxi6, libxmu6 (>= 2:1.1.3), libxmuu1 (>= 2:1.1.3), libxrandr2 (>= 2:1.5.0), libxt6, libxxf86vm1, cpp
Suggests: nickle, cairo-5c, xorg-docs-core
Breaks: arandr (<< 0.1.9)
Conflicts: iceauth, sessreg, xgamma, xhost, xmodmap, xrandr, xrdb, xrefresh, xrgb, xset, xsetmode, xsetpointer, xsetroot, xstdcmap, xvidtune
Conffiles:
/etc/X11/app-defaults/Xvidtune 0493a0782b498e9f0dee51a4013a80e6
Description: X server utilities
An X client is a program that interfaces with an X server (almost always via
the X libraries), and thus with some input and output hardware like a
graphics card, monitor, keyboard, and pointing device (such as a mouse).
.
This package provides a miscellaneous assortment of X Server utilities
that ship with the X Window System, including:

- iceauth, a tool for manipulating ICE protocol authorization records;
- rgb;
- sessreg, a simple program for managing utmp/wtmp entries;
- xcmsdb, a device color characteristic utility for the X Color Management
  System;
- xgamma, a tool for querying and setting a monitor's gamma correction;
- xhost, a very dangerous program that you should never use;
- xmodmap, a utility for modifying keymaps and pointer button mappings in X;
- xrandr, a command-line interface to the RandR extension;
- xrdb, a tool to manage the X server resource database;
- xrefresh, a tool that forces a redraw of the X screen;
- xset, a tool for setting miscellaneous X server parameters;
- xsetmode and xsetpointer, tools for handling X Input devices;
- xsetroot, a tool for tailoring the appearance of the root window;
- xstdcmap, a utility to selectively define standard colormap properties;
- xvidtune, a tool for customizing X server modelines for your monitor.
  Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: xauth
Status: install ok installed
Priority: optional
Section: x11
Installed-Size: 77
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 1:1.1-1build2
Depends: libc6 (>= 2.34), libx11-6, libxau6 (>= 1:1.0.9), libxext6, libxmuu1 (>= 2:1.1.3)
Description: X authentication utility
xauth is a small utility to read and manipulate Xauthority files, which
are used by servers and clients alike to control authentication and access
to X sessions.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>

Package: xdg-user-dirs
Status: install ok installed
Priority: important
Section: utils
Installed-Size: 542
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 0.17-2ubuntu4
Depends: libc6 (>= 2.34)
Conffiles:
/etc/xdg/autostart/xdg-user-dirs.desktop 284e639a243bfb86fc415ce448e8fa35
/etc/xdg/user-dirs.conf 602a95ec7fe4068512bebb712c41102d
/etc/xdg/user-dirs.defaults b8595963fe74aeb65e854ba9da7f1acb
Description: tool to manage well known user directories
xdg-user-dirs is a tool to help manage "well known" user directories
like the desktop folder and the music folder. It also handles
localization (i.e. translation) of the filenames.
.
The way it works is that xdg-user-dirs-update is run very early in the
login phase. This program reads a configuration file, and a set of
default directories. It then creates localized versions of these
directories in the users home directory and sets up a config file in
$(XDG_CONFIG_HOME)/user-dirs.dirs (XDG_CONFIG_HOME defaults to
~/.config) that applications can read to find these directories.
Homepage: http://www.freedesktop.org/wiki/Software/xdg-user-dirs
Original-Maintainer: Debian GNOME Maintainers <pkg-gnome-maintainers@lists.alioth.debian.org>

Package: xdg-utils
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 323
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 1.1.3-4.1ubuntu3~22.04.1
Recommends: libfile-mimeinfo-perl, libnet-dbus-perl, libx11-protocol-perl, x11-utils, x11-xserver-utils
Description: desktop integration utilities from freedesktop.org
xdg-utils contains utilities for integrating applications with the
desktop environment, regardless of which desktop environment is used.
.
The following utilities are included:
.

- xdg-desktop-menu - Install desktop menu items
- xdg-desktop-icon - Install icons on the user's desktop
- xdg-email - Compose a new email in the user's preferred email client,
  potentially with subject and other info filled in
- xdg-icon-resource - Install icon resources
- xdg-mime - Query and install MIME types and associations
- xdg-open - Open a URI in the user's preferred application that
  handles the respective URI or file type
- xdg-screensaver - Enable, disable, or suspend the screensaver
- xdg-settings - Get or set the default web browser and URI handlers
  Homepage: https://www.freedesktop.org/wiki/Software/xdg-utils/
  Original-Maintainer: Debian freedesktop.org maintainers <pkg-freedesktop-maintainers@lists.alioth.debian.org>

Package: xfsprogs
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 2784
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 5.13.0-1ubuntu2
Replaces: xfsdump (<< 3.0.0)
Provides: fsck-backend
Depends: libblkid1 (>= 2.17.2), libc6 (>= 2.34), libdevmapper1.02.1 (>= 2:1.02.20), libedit2 (>= 2.11-20080614-0), libicu70 (>= 70.1-1~), libinih1 (>= 53), libuuid1 (>= 2.16), python3:any
Suggests: xfsdump, acl, attr, quota
Breaks: xfsdump (<< 3.0.0)
Description: Utilities for managing the XFS filesystem
A set of commands to use the XFS filesystem, including mkfs.xfs.
.
XFS is a high performance journaling filesystem which originated
on the SGI IRIX platform. It is completely multi-threaded, can
support large files and large filesystems, extended attributes,
variable block sizes, is extent based, and makes extensive use of
Btrees (directories, extents, free space) to aid both performance
and scalability.
.
Refer to the documentation at https://xfs.wiki.kernel.org/
for complete details.
Homepage: https://xfs.wiki.kernel.org/
Original-Maintainer: XFS Development Team <linux-xfs@vger.kernel.org>

Package: xkb-data
Status: install ok installed
Priority: important
Section: x11
Installed-Size: 4236
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: xkeyboard-config
Version: 2.33-1
Breaks: libx11-6 (<< 2:1.4.3), x11-xkb-utils (<< 7.7+5)
Description: X Keyboard Extension (XKB) configuration data
This package contains configuration data used by the X Keyboard
Extension (XKB), which allows selection of keyboard layouts when
using a graphical interface.
.
Every X11 vendor provides its own XKB data files, so keyboard layout
designers have to send their layouts to several places. The
xkeyboard-config project has been launched at FreeDesktop in order
to provide a central repository that could be used by all vendors.
Original-Maintainer: Debian X Strike Force <debian-x@lists.debian.org>
Homepage: https://www.freedesktop.org/Software/XKeyboardConfig

Package: xxd
Status: install ok installed
Priority: important
Section: editors
Installed-Size: 274
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Source: vim
Version: 2:8.2.3995-1ubuntu2
Replaces: vim-common (<< 2:7.4.2347-1~)
Depends: libc6 (>= 2.34)
Breaks: vim-common (<< 2:7.4.2347-1~)
Description: tool to make (or reverse) a hex dump
xxd creates a hex dump of a given file or standard input. It can also convert
a hex dump back to its original binary form.
Homepage: https://www.vim.org/
Original-Maintainer: Debian Vim Maintainers <team+vim@tracker.debian.org>

Package: xz-utils
Status: install ok installed
Priority: standard
Section: utils
Installed-Size: 372
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 5.2.5-2ubuntu1
Replaces: lzip (<< 1.8~rc2), xz-lzma
Provides: lzma
Depends: libc6 (>= 2.34), liblzma5 (>= 5.2.2)
Breaks: lzip (<< 1.8~rc2)
Conflicts: lzma (<< 9.22-1), xz-lzma
Description: XZ-format compression utilities
XZ is the successor to the Lempel-Ziv/Markov-chain Algorithm
compression format, which provides memory-hungry but powerful
compression (often better than bzip2) and fast, easy decompression.
.
This package provides the command line tools for working with XZ
compression, including xz, unxz, xzcat, xzgrep, and so on. They can
also handle the older LZMA format, and if invoked via appropriate
symlinks will emulate the behavior of the commands in the lzma
package.
.
The XZ format is similar to the older LZMA format but includes some
improvements for general use:
.

- 'file' magic for detecting XZ files;
- crc64 data integrity check;
- limited random-access reading support;
- improved support for multithreading (not used in xz-utils);
- support for flushing the encoder.
  Homepage: https://tukaani.org/xz/
  Original-Maintainer: Jonathan Nieder <jrnieder@gmail.com>

Package: zerofree
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 30
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 1.1.1-1build3
Depends: libc6 (>= 2.34), libext2fs2 (>= 1.42)
Description: zero free blocks from ext2, ext3 and ext4 file-systems
Zerofree finds the unallocated blocks with non-zero value content in
an ext2, ext3 or ext4 file-system and fills them with zeroes
(zerofree can also work with another value than zero). This is mostly
useful if the device on which this file-system resides is a disk
image. In this case, depending on the type of disk image, a secondary
utility may be able to reduce the size of the disk image after
zerofree has been run. Zerofree requires the file-system to be
unmounted or mounted read-only.
.
The usual way to achieve the same result (zeroing the unused
blocks) is to run "dd" to create a file full of zeroes that takes up
the entire free space on the drive, and then delete this file. This
has many disadvantages, which zerofree alleviates:

- it is slow;
- it makes the disk image (temporarily) grow to its maximal extent;
- it (temporarily) uses all free space on the disk, so other
  concurrent write actions may fail.
  .
  Zerofree has been written to be run from GNU/Linux systems installed
  as guest OSes inside a virtual machine. If this is not your case, you
  almost certainly don't need this package. (One other use case would
  be to erase sensitive data a little bit more securely than with a
  simple "rm").
  Homepage: https://frippery.org/uml/
  Original-Maintainer: Thibaut Paumard <thibaut@debian.org>

Package: zlib1g
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 164
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: same
Source: zlib
Version: 1:1.2.11.dfsg-2ubuntu9
Provides: libz1
Depends: libc6 (>= 2.14)
Breaks: libxml2 (<< 2.7.6.dfsg-2), texlive-binaries (<< 2009-12)
Conflicts: zlib1 (<= 1:1.0.4-7)
Description: compression library - runtime
zlib is a library implementing the deflate compression method found
in gzip and PKZIP. This package includes the shared library.
Homepage: http://zlib.net/
Original-Maintainer: Mark Brown <broonie@debian.org>

Package: zsh
Status: install ok installed
Priority: optional
Section: shells
Installed-Size: 2468
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 5.8.1-1
Depends: zsh-common (= 5.8.1-1), libc6 (>= 2.34), libcap2 (>= 1:2.10), libtinfo6 (>= 6)
Recommends: libc6 (>= 2.35), libgdbm6 (>= 1.16), libncursesw6 (>= 6), libpcre3
Suggests: zsh-doc
Description: shell with lots of features
Zsh is a UNIX command interpreter (shell) usable as an
interactive login shell and as a shell script command
processor. Of the standard shells, zsh most closely resembles
ksh but includes many enhancements. Zsh has command-line editing,
built-in spelling correction, programmable command completion,
shell functions (with autoloading), a history mechanism, and a
host of other features.
Original-Maintainer: Debian Zsh Maintainers <pkg-zsh-devel@lists.alioth.debian.org>
Homepage: https://www.zsh.org/

Package: zsh-common
Status: install ok installed
Priority: optional
Section: shells
Installed-Size: 15293
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: zsh
Version: 5.8.1-1
Replaces: zsh (<= 5.0.2-1), zsh-doc (<= 5.8-7~)
Recommends: zsh
Suggests: zsh-doc
Breaks: zsh-doc (<= 5.8-7~)
Conffiles:
/etc/zsh/newuser.zshrc.recommended dac3563a2ddd13e8027b1861d415f3d4
/etc/zsh/zlogin 48032df2ace0977f2491b016e3c421a3
/etc/zsh/zlogout b73789c3e790b855302ce10ca076037a
/etc/zsh/zprofile 58c4f65d775c055b5d80b67c1bd12838
/etc/zsh/zshenv 5a8a0ff4f6ff945a5aa6ba7f6f1e8c97
/etc/zsh/zshrc 2dae51f4d9833b4716e135ecf22c49de
Description: architecture independent files for Zsh
Zsh is a UNIX command interpreter (shell) usable as an
interactive login shell and as a shell script command
processor. Of the standard shells, zsh most closely resembles
ksh but includes many enhancements. Zsh has command-line editing,
built-in spelling correction, programmable command completion,
shell functions (with autoloading), a history mechanism, and a
host of other features.
.
This package contains the common zsh files shared by all
architectures.
Original-Maintainer: Debian Zsh Maintainers <pkg-zsh-devel@lists.alioth.debian.org>
Homepage: https://www.zsh.org/

Package: zstd
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 1655
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Source: libzstd
Version: 1.4.8+dfsg-3build1
Depends: libc6 (>= 2.34), libgcc-s1 (>= 3.3.1), liblz4-1 (>= 0.0~r127), liblzma5 (>= 5.1.1alpha+20120614), libstdc++6 (>= 12), zlib1g (>= 1:1.1.4)
Description: fast lossless compression algorithm -- CLI tool
Zstd, short for Zstandard, is a fast lossless compression algorithm, targeting
real-time compression scenarios at zlib-level compression ratio.
.
This package contains the CLI program implementing zstd.
Homepage: https://github.com/facebook/zstd
Original-Maintainer: Debian Med Packaging Team <debian-med-packaging@lists.alioth.debian.org>
