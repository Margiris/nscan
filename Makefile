include $(TOPDIR)/rules.mk

PKG_NAME:=nscan
PKG_RELEASE:=1
PKG_VERSION:=0.2.3

include $(INCLUDE_DIR)/package.mk

define Package/nscan
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Network scanner daemon nscand and client nscanctl
endef

define Package/nscan/description
	Scans network I guess (and hope)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/nscan/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME)d $(1)/sbin/$(PKG_NAME)d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME)ctl $(1)/sbin/$(PKG_NAME)ctl
	$(INSTALL_BIN) ./files/$(PKG_NAME)d.init $(1)/etc/init.d/$(PKG_NAME)d
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
