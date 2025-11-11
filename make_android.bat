set CREDACASH_BUILD=%cd:\=/%
set CPPFLAGS=-O3 -g1 -pthread -fPIC -fstack-protector-strong %ACPPFLAGS% ^
 -Wno-#warnings
set CFLAGS=%ACFLAGS%
set CXXFLAGS=-Wno-deprecated-copy %ACXXFLAGS%
set LDFLAGS=-shared -static-libstdc++ -llog -pthread -fstack-protector --no-undefined %ALDFLAGS%
rem ; --gc-sections -z,now
set LDLIBS=
cd source/3rdparty/Release
make all
cd ../../..
cd source/cccommon/Release
del *.a
make all
cd ../../..
cd source/cclib/Release
del *.a
make all
cd ../../..
cd source/ccwallet/Release
del *.exe
del *.dll
make all
cd ../../..
echo CredaCash build done.
