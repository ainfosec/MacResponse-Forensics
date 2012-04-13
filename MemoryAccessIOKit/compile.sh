sudo rm -rf build /tmp/MemoryAccessIOKit.*

xcodebuild -configuration i386-RELEASE
xcodebuild -configuration x86_64-RELEASE

sudo cp -r build/i386-RELEASE/MemoryAccessIOKit.kext /tmp/MemoryAccessIOKit.i386.kext
sudo cp -r build/x86_64-RELEASE/MemoryAccessIOKit.kext /tmp/MemoryAccessIOKit.x86_64.kext


