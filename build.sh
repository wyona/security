#!/bin/sh

echo "INFO: Build Security ..."

# ----- Parameters

# ----- Check for JAVA_HOME
JAVA_HOME="$JAVA_HOME"
if [ "$JAVA_HOME" = "" ];then
  echo "ERROR: No JAVA_HOME set!"
  echo "       Have you installed JDK (Java Development Kit)? If so, then set JAVA_HOME ..."
  echo "       MacOS X : setenv JAVA_HOME /Library/Java/JavaVirtualMachines/jdk1.8.0_25.jdk/Contents/Home"
  echo "       Linux   : export JAVA_HOME=/usr/local/jdk-1.5.0 (whereas 1.5.0 is just an example path)"
  echo "       Windows : Click Start ..."
  exit 1
fi

# ----- Check Java version
# TODO: ....

# ----- Set Environment Variables
ORIGINAL_ANT_HOME=$ANT_HOME
unset ANT_HOME
export ANT_HOME=$PWD/tools/apache-ant
#echo $ANT_HOME
OUR_ANT="ant -lib tools/apache-ant_extras"

ORIGINAL_PATH=$PATH
PATH=$PWD/tools/maven-2.0.4/bin:$ANT_HOME/bin:$PATH
#echo $PATH

# ----- Build Security ...
#mvn --version
$OUR_ANT -version
$OUR_ANT -f build.xml $@

# ----- Reset Environment Variables
export ANT_HOME=$ORIGINAL_ANT_HOME
#echo $ANT_HOME
PATH=$ORIGINAL_PATH
#echo $PATH
