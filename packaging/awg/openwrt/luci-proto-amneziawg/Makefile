#
# luci-proto-amneziawg: the LuCI page for the "amneziawg" netifd protocol of amneziawg-tools, plus
# the generated translation package luci-i18n-amneziawg-ru.
#
# WayHop's own Makefile. The page itself (htdocs/, root/, po/) is not kept in this repository:
# scripts/awg/build-openwrt.sh copies it into the staged feed from AWG_LUCI_REPO at the pinned
# AWG_LUCI_COMMIT (packaging/awg/VERSIONS) before the SDK reads this Makefile (luci.mk finds the
# translations by listing po/ when the Makefile is parsed). Those files are Apache-2.0
# (Copyright 2022 Jo-Philipp Wich and the awg-openwrt contributors; headers kept as fetched).
#
# Version: the upstream page version (3.1.0) plus the UTC date of the pinned commit, so moving the
# pin always raises it; build-openwrt.sh refuses to build when the date does not match the commit.
# PKG_RELEASE must equal AWG_PKG_RELEASE. The translation package is selected through
# CONFIG_LUCI_LANG_ru, as luci.mk defines it.
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=Support for AmneziaWG 3.1
LUCI_DESCRIPTION:=LuCI protocol page for AmneziaWG interfaces (netifd protocol amneziawg)
LUCI_DEPENDS:=+amneziawg-tools +ucode +luci-lib-uqr +resolveip
LUCI_PKGARCH:=all

PKG_VERSION:=3.1.0.20260922
PKG_RELEASE:=2
PKG_LICENSE:=Apache-2.0
# The translation package gets the same version; luci.mk would otherwise derive one from the
# git history or, in a copied tree like ours, from file times (a different version every build).
PKG_PO_VERSION:=$(PKG_VERSION)-r$(PKG_RELEASE)

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
