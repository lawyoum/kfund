TARGET  = test-kernrw
OUTDIR ?= bin

CODESIGN = /usr/local/bin/ldid -SEnt.plist
CXX       = xcrun -sdk iphoneos clang -mios-version-min=10.0 -arch arm64

CFLAGS  = -Wall -Iinclude -I.

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)


$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): main.m | $(OUTDIR)
	$(CXX) -o $@ $^ $(CFLAGS) -framework IOKit -framework Foundation -framework UIKit -framework CoreFoundation
	strip $@
	$(CODESIGN) $@
	cp bin/test-kernrw ../binaries
	trustcache create ../binaries/test-kernrw.tc ../binaries/test-kernrw
	find .. -type f -name '.*' -delete

clean:
	rm -f $(OUTDIR)/$(TARGET) $(OUTDIR)/$(TARGET).gz
