#!/bin/zsh
mkdir -p cache
rm -rf Ghidra.app

INTEL=$(sysctl -q hw.optional.arm64 | grep 'hw.optional.arm64: 1'>/dev/null; echo $?)
JDK_PLATFORM=macosx_aarch64
if [ $INTEL = 1 ]; then
	JDK_PLATFORM=macosx_x64
	ARCH=intel
	PLATFORM_CHECK="1"
else
	ARCH=arm64
	PLATFORM_CHECK="0"
fi
echo "Building for $ARCH"

curl -L "https://github.com/NationalSecurityAgency/ghidra/archive/refs/heads/stable.zip" -o cache/ghidra-stable.zip

JDK_VERSION="zulu17.38.21-ca-jdk17.0.5"
curl -L "https://cdn.azul.com/zulu/bin/$JDK_VERSION-$JDK_PLATFORM.tar.gz" -o cache/jdk.tgz

GRADLE_VERSION="gradle-7.5.1"
curl -L "https://services.gradle.org/distributions/$GRADLE_VERSION-bin.zip" -o cache/gradle.zip

curl -L "https://github.com/google/binexport/archive/refs/heads/main.zip" -o cache/binexport.zip

mkdir -p Ghidra.app/Contents/MacOS
mkdir -p Ghidra.app/Contents/Resources
cp ghidra.icns Ghidra.app/Contents/Resources/ghidra.icns


/usr/bin/swiftc ghidra.swift -o Ghidra.app/Contents/MacOS/ghidra

/usr/bin/unzip -ouqq cache/binexport.zip -d cache
/usr/bin/unzip -ouqq cache/gradle.zip -d cache/gradle
/usr/bin/unzip -ouqq cache/ghidra-stable.zip -d cache
/usr/bin/tar Jxf cache/jdk.tgz -C Ghidra.app/Contents/Resources

export JAVA_HOME="`pwd`/Ghidra.app/Contents/Resources/$JDK_VERSION-$JDK_PLATFORM"
export GRADLE_OPTIONS="-XX:+TieredCompilation -XX:TieredStopAtLevel=1"
export PATH=$PATH:`pwd`/cache/gradle/$GRADLE_VERSION/bin

cd cache/ghidra-stable
gradle -I gradle/support/fetchDependencies.gradle init --no-daemon
gradle buildGhidra --no-daemon

cd ../..
unzip -ouqq cache/ghidra-stable/build/dist/*.zip -d Ghidra.app/Contents/Resources

HOSTNAME=`hostname -s`
GHIDRA_PATH=`ls Ghidra.app/Contents/Resources | grep ghidra_`
export GHIDRA_INSTALL_DIR=$(pwd)/Ghidra.app/Contents/Resources/$GHIDRA_PATH

cd cache/binexport-main/java
gradle --no-daemon
cd ../../..
mv cache/binexport-main/java/dist/*.zip $GHIDRA_INSTALL_DIR/Extensions/Ghidra

cat << EOF > Ghidra.app/Contents/Info.plist
{
  "CFBundleDisplayName": "Ghidra",
  "CFBundleDevelopmentRegion": "English",
  "CFBundleExecutable": "ghidra",
  "CFBundleIconFile": "ghidra.icns",
  "CFBundleIdentifier": "local.$HOSTNAME.ghidra_dot_app",
  "CFBundleInfoDictionaryVersion": "6.0",
  "CFBundleName": "Ghidra",
  "CFBundlePackageType": "APPL",
  "CFBundleShortVersionString": "$GHIDRA_PATH",
  "CFBundleVersion": "$GHIDRA_PATH",
  "LSMinimumSystemVersion": "11.6.2",
}
EOF
/usr/bin/plutil -convert binary1 Ghidra.app/Contents/Info.plist

cat << EOF > Ghidra.app/Contents/Resources/ghidra.sh
#!/bin/zsh
INTEL=\$(sysctl -q hw.optional.arm64 | grep 'hw.optional.arm64: 1'>/dev/null; echo \$?)
if [ ! \$INTEL = $PLATFORM_CHECK ]; then
        osascript -e 'display dialog "This Ghidra.app not built to support your platform.\nPlease rebuild it."'
        exit
fi
ROOT_DIR=\`dirname \$0\`/../../
export JAVA_HOME="\$ROOT_DIR/Contents/Resources/$JDK_VERSION-$JDK_PLATFORM"
export PATH="\${JAVA_HOME}/bin:\${PATH}"
export MAXMEM=\$((\$(sysctl -n hw.memsize)/1024/1024/1024))G
exec "\$ROOT_DIR/Contents/Resources/$GHIDRA_PATH/ghidraRun"
EOF

chmod +x Ghidra.app/Contents/Resources/ghidra.sh
codesign --force --deep -s - Ghidra.app
