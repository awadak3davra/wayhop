#
# amneziawg-tools: the AmneziaWG 3.1 control program (/usr/bin/awg) and the netifd protocol handler
# (/lib/netifd/proto/amneziawg.sh) for OpenWrt.
#
# WayHop's own OpenWrt package Makefile (built by scripts/awg/build-openwrt.sh in the official
# OpenWrt SDK). awg is GPL-2.0 (see the source's COPYING); files/amneziawg.sh is derived from
# OpenWrt's wireguard.sh and stays Apache-2.0 (header in the file).
#
# Pins: PKG_VERSION, PKG_SOURCE_VERSION and PKG_RELEASE must equal AWG_TOOLS_TAG (without the "v"),
# AWG_TOOLS_COMMIT and AWG_PKG_RELEASE in packaging/awg/VERSIONS; build-openwrt.sh refuses to build
# when they differ. Refresh PKG_MIRROR_HASH after a pin bump with
#   make package/amneziawg-tools/check FIXUP=1
#
# Deliberately NOT a dependency: kmod-amneziawg. The same awg and proto handler drive the userspace
# amneziawg-go when no matching kernel module exists (small or unusual kernels), so the tools must
# install without the kmod. Also not shipped: awg-quick (it needs bash) and the re-resolve watchdog.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=amneziawg-tools
PKG_VERSION:=3.1.20260812
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/amnezia-vpn/amneziawg-tools.git
PKG_SOURCE_VERSION:=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
PKG_MIRROR_HASH:=0c27841a3b4860c7fd085cd627c5b0f9c25653afdaef1e73fd3e350fb3445dab

PKG_LICENSE:=GPL-2.0-only Apache-2.0
PKG_LICENSE_FILES:=COPYING

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

MAKE_PATH:=src
MAKE_VARS += PLATFORM=linux

# Smallest dynamic binary: optimise for size whatever the target's default optimisation is (the
# last -O wins), and let the linker drop unused functions and data.
TARGET_CFLAGS += -Os -ffunction-sections -fdata-sections
TARGET_LDFLAGS += -Wl,--gc-sections

define Package/amneziawg-tools
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=AmneziaWG 3.1 control program (awg) and netifd protocol
  URL:=https://github.com/amnezia-vpn/amneziawg-tools
  DEPENDS:= \
	+!BUSYBOX_CONFIG_IP:ip \
	+!BUSYBOX_CONFIG_FEATURE_IP_LINK:ip
endef

define Package/amneziawg-tools/description
  AmneziaWG is WireGuard with traffic obfuscation. This package provides the
  generation 3.1 control program awg(8) and the netifd protocol handler
  "amneziawg". It works with the kernel module (kmod-amneziawg) or, when no
  module is loaded, with the userspace amneziawg-go.
endef

define Package/amneziawg-tools/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/wg $(1)/usr/bin/awg
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files/amneziawg.sh $(1)/lib/netifd/proto/
endef

$(eval $(call BuildPackage,amneziawg-tools))
