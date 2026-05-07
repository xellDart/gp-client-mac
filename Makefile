APP_NAME := GlobalProtect
BUNDLE_ID := com.xelldart.gpclient
BUILD_DIR := build
APP_BUNDLE := $(BUILD_DIR)/$(APP_NAME).app
BIN := $(APP_BUNDLE)/Contents/MacOS/$(APP_NAME)
DMG := $(BUILD_DIR)/$(APP_NAME).dmg
SWIFT_SRC := main.swift
ICON_PNG := resources/icon.png
ICONSET := $(BUILD_DIR)/AppIcon.iconset
ICNS := $(APP_BUNDLE)/Contents/Resources/AppIcon.icns

.PHONY: all build icon bundle dmg clean install uninstall

all: dmg

build: $(BIN) $(ICNS)

$(BIN): $(SWIFT_SRC) | $(APP_BUNDLE)
	swiftc -O -parse-as-library $(SWIFT_SRC) -o $(BIN)
	codesign --force --deep --sign - $(APP_BUNDLE)

$(APP_BUNDLE):
	mkdir -p $(APP_BUNDLE)/Contents/MacOS
	mkdir -p $(APP_BUNDLE)/Contents/Resources
	cp Info.plist $(APP_BUNDLE)/Contents/Info.plist

$(ICNS): $(ICON_PNG) | $(APP_BUNDLE)
	rm -rf $(ICONSET)
	mkdir -p $(ICONSET)
	sips -z 16   16   $(ICON_PNG) --out $(ICONSET)/icon_16x16.png       >/dev/null
	sips -z 32   32   $(ICON_PNG) --out $(ICONSET)/icon_16x16@2x.png    >/dev/null
	sips -z 32   32   $(ICON_PNG) --out $(ICONSET)/icon_32x32.png       >/dev/null
	sips -z 64   64   $(ICON_PNG) --out $(ICONSET)/icon_32x32@2x.png    >/dev/null
	sips -z 128  128  $(ICON_PNG) --out $(ICONSET)/icon_128x128.png     >/dev/null
	sips -z 256  256  $(ICON_PNG) --out $(ICONSET)/icon_128x128@2x.png  >/dev/null
	sips -z 256  256  $(ICON_PNG) --out $(ICONSET)/icon_256x256.png     >/dev/null
	sips -z 512  512  $(ICON_PNG) --out $(ICONSET)/icon_256x256@2x.png  >/dev/null
	sips -z 512  512  $(ICON_PNG) --out $(ICONSET)/icon_512x512.png     >/dev/null
	cp $(ICON_PNG) $(ICONSET)/icon_512x512@2x.png
	iconutil -c icns $(ICONSET) -o $(ICNS)

dmg: build
	rm -f $(DMG)
	rm -rf $(BUILD_DIR)/dmg-staging
	mkdir -p $(BUILD_DIR)/dmg-staging
	cp -R $(APP_BUNDLE) $(BUILD_DIR)/dmg-staging/
	ln -s /Applications $(BUILD_DIR)/dmg-staging/Applications
	hdiutil create -volname "$(APP_NAME)" \
		-srcfolder $(BUILD_DIR)/dmg-staging \
		-ov -format UDZO $(DMG)
	rm -rf $(BUILD_DIR)/dmg-staging

install: build
	@echo "Installing to /Applications (requires admin)..."
	sudo rm -rf /Applications/$(APP_NAME).app
	sudo cp -R $(APP_BUNDLE) /Applications/
	@echo "Done. Launch from Applications."

uninstall:
	sudo rm -rf /Applications/$(APP_NAME).app
	sudo rm -f /etc/sudoers.d/gpclient
	@echo "Removed app and sudoers rule."

clean:
	rm -rf $(BUILD_DIR)
