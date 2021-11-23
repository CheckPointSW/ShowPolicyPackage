#!/bin/bash
export JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8
java -jar $MDS_FWDIR/api/samples/lib/web_api_show_package-jar-with-dependencies.jar "$@"