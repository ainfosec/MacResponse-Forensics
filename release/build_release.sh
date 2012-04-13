#!/bin/sh

exec_with_verify() {
 "$@" && return 0
 echo "$@ failed!"
 exit
}

exec_with_verify cd ..
exec_with_verify cd MacResponse_Live
exec_with_verify sudo rm -rf build/
exec_with_verify xcodebuild

echo "built macresponse live successfully!"
exec_with_verify cd ..
exec_with_verify cd MemoryAccessIOKit

exec_with_verify sudo rm -rf build/
exec_with_verify xcodebuild -configuration i386-RELEASE
exec_with_verify xcodebuild -configuration x86_64-RELEASE

echo "built memoryaccessiokit successfully!"

exec_with_verify cd ..
exec_with_verify cd release

exec_with_verify rm -rf ./MacResponse_Live.app
exec_with_verify cp -r ../MacResponse_Live/build/Release/MacResponse_Live.app ./MacResponse_Live.app

exec_with_verify rm -rf ./MacResponse_Live.app/Contents/Resources/MemoryAccessIOKit.kext
exec_with_verify cp -r ../MemoryAccessIOKit/build/i386-RELEASE/MemoryAccessIOKit.kext ./MacResponse_Live.app/Contents/Resources/MemoryAccessIOKit.i386.kext
exec_with_verify cp -r ../MemoryAccessIOKit/build/x86_64-RELEASE/MemoryAccessIOKit.kext ./MacResponse_Live.app/Contents/Resources/MemoryAccessIOKit.x86_64.kext

echo "release build complete!"
