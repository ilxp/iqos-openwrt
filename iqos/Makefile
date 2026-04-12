include $(TOPDIR)/rules.mk

PKG_NAME:=iqos
PKG_VERSION:=$(iqos_VERSION)
ifeq ($(iqos_VERSION),)
     PKG_VERSION:=1.0.0
endif
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/iqos
	SECTION:=net
	CATEGORY:=Network
	TITLE:=A set of QoS scripts designed for use with iqos Web Interface
	DEPENDS:=+bash +nftables +tc-full +ip +ethtool +kmod-ifb +kmod-sched-core \
         +kmod-sched-cake +kmod-sched-connmark +kmod-sched-ctinfo +kmod-sched-flower \
         +kmod-nf-conntrack +kmod-nf-conntrack6 +kmod-nf-nat +kmod-nf-nathelper +kmod-nf-nathelper-extra \
		 +libubox +libubus +libuci
	MAINTAINER:=ilxp <lixp@live.com>
endef

define Package/iqos/description
	A set of QoS scripts designed for use with iqos Web Interface
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/qosacc/* $(PKG_BUILD_DIR)/
	#$(CP) ./src/idclass/* $(PKG_BUILD_DIR)/
endef


define Build/Configure
endef

define Build/Compile
	-$(MAKE) -C $(PKG_BUILD_DIR) clean
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I $(STAGING_DIR)/usr/include" \
		LDFLAGS="$(TARGET_LDFLAGS) -L $(STAGING_DIR)/usr/lib" \
		BUILD_DIR="$(KERNEL_BUILD_DIR)" \
		STAGING_DIR="$(STAGING_DIR)" \
		LINUX_DIR="$(LINUX_DIR)" \
		all
endef

# 重启防火墙时, 添加qos规则
define Package/iqos-firewall-util/postinst
	included=$$(cat $${IPKG_INSTROOT}/etc/config/firewall | grep 'iqos_firewall.include'  )
	if [ -z "$$included" ] ; then printf "config include 'iqos'\n\toption type script\n\toption path /usr/share/iqos/iqos_firewall.include\n\toption family any\n\toption reload 1\n\n" >> $${IPKG_INSTROOT}/etc/config/firewall ; fi
endef

define Package/iqos/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/iqos
	$(INSTALL_DIR) $(1)/usr/lib/iqos
	$(INSTALL_DIR) $(1)/usr/share/iqos
	$(INSTALL_DIR) $(1)/lib/bpf
	$(INSTALL_DIR) $(1)/usr/sbin
	
	$(INSTALL_BIN) $(CURDIR)/files/ifb.init $(1)/etc/init.d/ifb
	$(INSTALL_BIN) $(CURDIR)/files/iqos.init $(1)/etc/init.d/iqos
	$(INSTALL_BIN) $(CURDIR)/files/iqos.hotplug $(1)/etc/hotplug.d/iface/99-iqos
	$(INSTALL_CONF) $(CURDIR)/files/iqos.conf $(1)/etc/config/iqos
	$(INSTALL_BIN) $(CURDIR)/files/usr/lib/iqos/* $(1)/usr/lib/iqos/
	$(CP) -r $(CURDIR)/files/etc/iqos/. $(1)/etc/iqos/
	$(INSTALL_BIN) $(CURDIR)/files/iqos_firewall.include $(1)/usr/share/iqos/iqos_firewall.include

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/qosacc $(1)/usr/sbin/qosacc
	$(INSTALL_BIN) $(CURDIR)/files/qosacc.init $(1)/etc/init.d/qosacc
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/idclass $(1)/usr/sbin/idclass
	#$(INSTALL_DATA) $(PKG_BUILD_DIR)/idclass-bpf.o $(1)/lib/bpf/
	
endef

define Package/iqos/prerm
	$${IPKG_INSTROOT}/etc/init.d/iqos stop 2>/dev/null
	$${IPKG_INSTROOT}/etc/init.d/iqos disable 2>/dev/null
	ls >/dev/null 2>&1
endef

$(eval $(call BuildPackage,iqos))